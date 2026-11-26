package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jt-wang/tailpocket/connectpush"
)

const (
	maxBody = 8 << 10

	ipPerMinute     = 600 // register, revoke and send per source address
	regPerIPPerHour = 20  // register and revoke per source address
	devPerMinute    = 10  // sends per device token
	devPerDay       = 300

	maxSending  = 256 // pushes in flight to APNs and FCM at once
	limiterKeys = 1 << 16
	deviceKeys  = 1 << 18
)

var collapseRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type app struct {
	id     string
	ph     placeholder
	apns   *apnsSender
	fcm    *fcmSender
	attest map[byte]attester // by platform; none means strict mode
	regLim *limiter          // register and revoke per hour, all sources
}

func (a *app) has(plat byte) bool {
	return plat == platAPNs && a.apns != nil || plat == platFCM && a.fcm != nil
}

// loadApps reads the credentials of every app. The upstream addresses are
// fixed here, from up, and nothing later changes them.
func loadApps(c *config, up upstream, gens *genStore, warn func(string, ...any)) (map[string]*app, error) {
	m := map[string]*app{}
	for _, ac := range c.Apps {
		a := &app{
			id:     ac.ID,
			ph:     ac.Placeholder,
			attest: map[byte]attester{},
			regLim: newLimiter(ac.RegisterPerHour, time.Hour, 6, 1),
		}
		if p := ac.APNs; p != nil {
			k, err := loadP8(p.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("app %s: apns: %w", ac.ID, err)
			}
			if othersCanRead(p.KeyFile) {
				warn("warning: %s is readable by other users; chmod 600 it", p.KeyFile)
			}
			base := up.apnsProduction
			if p.Env == "sandbox" {
				base = up.apnsSandbox
			}
			a.apns = &apnsSender{base: base, topic: p.Topic, teamID: p.TeamID, keyID: p.KeyID, key: k}
		}
		if p := ac.FCM; p != nil {
			auth, err := newGoogleAuth(p.CredentialsFile, up.oauth, fcmScope)
			if err != nil {
				return nil, fmt.Errorf("app %s: fcm: %w", ac.ID, err)
			}
			if othersCanRead(p.CredentialsFile) {
				warn("warning: %s is readable by other users; chmod 600 it", p.CredentialsFile)
			}
			a.fcm = &fcmSender{base: up.fcm, project: p.ProjectID, auth: auth}
		}
		if at := ac.Attest; at != nil {
			env := attestEnv{app: &ac, dir: c.dir, up: up, state: gens}
			for _, x := range []struct {
				name string
				plat byte
				raw  json.RawMessage
			}{{"ios", platAPNs, at.IOS}, {"android", platFCM, at.Android}} {
				if len(x.raw) == 0 {
					continue
				}
				v, err := attestVerifiers[x.name](x.raw, env)
				if err != nil {
					return nil, fmt.Errorf("app %s: attest.%s: %w", ac.ID, x.name, err)
				}
				a.attest[x.plat] = v
			}
		}
		m[ac.ID] = a
	}
	return m, nil
}

type server struct {
	apps  map[string]*app
	keys  *handleKeys
	gens  *genStore
	hc    *http.Client
	trust []netip.Prefix
	ttl   time.Duration
	log   *log.Logger
	now   func() time.Time

	ipLim    *limiter
	regIPLim *limiter
	devMin   *limiter
	devDay   *limiter
	logLim   *limiter
	bad      *badTokens
	fails    *attestFails // sources whose attestation keeps failing
	ch       *challenges
	sending  chan struct{}
}

func newServer(c *config, keys *handleKeys, gens *genStore, apps map[string]*app, up upstream, logger *log.Logger) *server {
	hc := *up.client
	hc.CheckRedirect = noRedirect // a redirect would choose where the gateway connects
	return &server{
		apps:     apps,
		keys:     keys,
		gens:     gens,
		hc:       &hc,
		trust:    c.trust,
		ttl:      time.Duration(c.HandleTTLDays) * 24 * time.Hour,
		log:      logger,
		now:      time.Now,
		ipLim:    newLimiter(ipPerMinute, time.Minute, 6, limiterKeys),
		regIPLim: newLimiter(regPerIPPerHour, time.Hour, 6, limiterKeys),
		devMin:   newLimiter(devPerMinute, time.Minute, 6, deviceKeys),
		devDay:   newLimiter(devPerDay, 24*time.Hour, 24, deviceKeys),
		logLim:   newLimiter(10, time.Minute, 6, 1024),
		bad:      newBadTokens(limiterKeys),
		fails:    newAttestFails(limiterKeys),
		ch:       newChallenges(keys.chKey),
		sending:  make(chan struct{}, maxSending),
	}
}

func (s *server) sweepEvery(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := s.now()
			for _, l := range []*limiter{s.ipLim, s.regIPLim, s.devMin, s.devDay, s.logLim} {
				l.sweep(now)
			}
			s.bad.sweep(now)
			s.ch.sweep(now)
			s.fails.sweep(now)
			if err := s.gens.sweep(now); err != nil {
				s.log.Printf("state-sweep-failed")
			}
		}
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	// The gateway is never a proxy: no CONNECT, no absolute URL
	// (GET http://host/), no authority in the request target.
	if r.Method == http.MethodConnect || !strings.HasPrefix(r.RequestURI, "/") || r.URL.IsAbs() || r.URL.Host != "" {
		s.refuse(w, http.StatusBadRequest, "proxy_request", nil)
		return
	}
	switch r.URL.Path {
	case "/healthz":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			h.Set("Allow", "GET, HEAD")
			s.refuse(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
			return
		}
		h.Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	case "/v1/register", "/v1/revoke", "/v1/send", "/v1/challenge":
		if r.Method != http.MethodPost {
			h.Set("Allow", "POST")
			s.refuse(w, http.StatusMethodNotAllowed, "method_not_allowed", nil)
			return
		}
		s.api(w, r)
	default:
		s.refuse(w, http.StatusNotFound, "not_found", nil)
	}
}

// logf keys are fixed words; values are configured app ids, platform
// names, handle hashes and plain reason words, never request text.
type logf map[string]string

func (s *server) refuse(w http.ResponseWriter, status int, code string, kv logf) {
	switch {
	case code == "blocked":
		w.Header().Set("Retry-After", strconv.Itoa(int(badBlock/time.Second)))
	case status == http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, status, map[string]string{"error": code})
	if s.logLim.allow(code, s.now()) {
		s.log.Printf("refused %d %s%s", status, code, kv)
	}
}

func (kv logf) String() string {
	var b strings.Builder
	for _, k := range []string{"app", "platform", "handle", "reason"} {
		if v, ok := kv[k]; ok {
			fmt.Fprintf(&b, " %s=%s", k, v)
		}
	}
	return b.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	b, _ := json.Marshal(v)
	w.Write(append(b, '\n'))
}

func (s *server) api(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	addr := addrKey(clientIP(r, s.trust))
	if !s.ipLim.allow(addr, now) {
		s.refuse(w, http.StatusTooManyRequests, "rate_limited", nil)
		return
	}
	src := s.keys.srcTag(addr)
	if s.bad.blocked(src, now) {
		s.refuse(w, http.StatusTooManyRequests, "blocked", nil)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		s.refuse(w, http.StatusUnsupportedMediaType, "unsupported_media_type", nil)
		return
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.refuse(w, http.StatusRequestEntityTooLarge, "too_large", nil)
		} else {
			s.refuse(w, http.StatusBadRequest, "bad_request", nil)
		}
		return
	}
	switch r.URL.Path {
	case "/v1/send":
		s.send(w, r, b, src, now)
	case "/v1/challenge":
		s.challenge(w, b, now)
	default:
		s.device(w, r, b, addr, src, now)
	}
}

// challenge answers POST /v1/challenge {app} with a one-time challenge for
// attestation evidence, for an app that checks attestation.
func (s *server) challenge(w http.ResponseWriter, body []byte, now time.Time) {
	var q struct {
		App string `json:"app"`
	}
	if err := decodeStrict(body, &q); err != nil {
		s.refuse(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	a := s.apps[q.App]
	if a == nil {
		s.refuse(w, http.StatusBadRequest, "unknown_app", nil)
		return
	}
	if len(a.attest) == 0 {
		s.refuse(w, http.StatusBadRequest, "attest_not_configured", logf{"app": a.id})
		return
	}
	ch, exp, err := s.ch.issue(a.id, now)
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, "internal", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"challenge": ch, "expires": exp})
}

type deviceReq struct {
	App        string          `json:"app"`
	Platform   string          `json:"platform"`
	Token      string          `json:"token"`
	Generation uint64          `json:"generation"`
	Attest     json.RawMessage `json:"attest,omitempty"`
}

// device handles /v1/register and /v1/revoke.
func (s *server) device(w http.ResponseWriter, r *http.Request, body []byte, addr string, src srcTag, now time.Time) {
	op := strings.TrimPrefix(r.URL.Path, "/v1/")
	var q deviceReq
	if err := decodeStrict(body, &q); err != nil {
		s.refuse(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	a := s.apps[q.App]
	if a == nil {
		s.refuse(w, http.StatusBadRequest, "unknown_app", nil)
		return
	}
	kv := logf{"app": a.id}
	if !s.regIPLim.allow(addr, now) {
		s.refuse(w, http.StatusTooManyRequests, "rate_limited", kv)
		return
	}
	plat, tok, err := parseToken(q.Platform, q.Token)
	if err != nil {
		s.refuse(w, http.StatusBadRequest, "bad_token", kv)
		return
	}
	kv["platform"] = platName(plat)
	if !a.has(plat) {
		s.refuse(w, http.StatusBadRequest, "platform_not_configured", kv)
		return
	}
	if q.Generation < 1 || q.Generation > maxGeneration {
		s.refuse(w, http.StatusBadRequest, "bad_generation", kv)
		return
	}
	// The app's own hourly budget: an attested platform pays only once its evidence passed, so
	// requests without evidence cannot use up its real phones' registrations.
	appLimited := func() bool {
		if a.regLim.allow("", now) {
			return false
		}
		s.refuse(w, http.StatusTooManyRequests, "rate_limited", kv)
		return true
	}
	v := a.attest[plat]
	if v == nil && appLimited() {
		return
	}
	if v != nil {
		// Attested apps: evidence bound to this request and to a one-time
		// challenge, or nothing happens.
		var ev struct {
			Challenge string `json:"challenge"`
		}
		if len(q.Attest) == 0 || json.Unmarshal(q.Attest, &ev) != nil || ev.Challenge == "" {
			s.refuse(w, http.StatusUnauthorized, "attestation_required", kv)
			return
		}
		if !s.fails.enter(addr, now) {
			s.refuse(w, http.StatusTooManyRequests, "blocked", kv)
			return
		}
		if !s.ch.take(a.id, ev.Challenge, now) {
			s.fails.release(addr)
			s.refuse(w, http.StatusUnauthorized, "bad_challenge", kv)
			return
		}
		// The check runs to its end even if the client hangs up: a decode it already paid for must
		// count as a pass or a failure, not as the 503 a cancelled call would give (PG7).
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), upstreamTimeout)
		err := v.Verify(ctx, attestRequest{App: a.id, Platform: q.Platform, Op: op, Token: q.Token, Generation: q.Generation,
			Evidence: q.Attest, Now: now,
			ClientDataHash: connectpush.AttestHash(op, a.id, q.Platform, q.Token, q.Generation, ev.Challenge)})
		cancel()
		if err != nil {
			s.ch.give(ev.Challenge)
			kv["reason"] = attestReason(err)
			var ae *attestError
			switch {
			case isUnknownKey(err):
				s.fails.release(addr)
				s.refuse(w, http.StatusUnauthorized, "attest_key_unknown", kv)
			case errors.As(err, &ae):
				if s.fails.fail(addr, now) && s.logLim.allow("attest-blocked", now) {
					s.log.Printf("source-blocked attest app=%s for=%s", a.id, attestFailBlock)
				}
				s.refuse(w, http.StatusUnauthorized, "attestation_failed", kv)
			default:
				s.fails.release(addr)
				s.refuse(w, http.StatusServiceUnavailable, "attestation_unavailable", kv)
			}
			return
		}
		s.fails.pass(addr)
		if appLimited() {
			return
		}
	}
	dk := deviceKey(a.id, plat, tok)
	if op == "revoke" {
		err = s.gens.revoke(dk, q.Generation, now)
	} else {
		err = s.gens.register(dk, q.Generation, now)
	}
	switch {
	case errors.Is(err, errStale):
		// The phone lost its generation (or someone with the token raised
		// it): say where to start, so it can revoke that and register above.
		writeJSON(w, http.StatusConflict, map[string]any{"error": "stale_generation", "min_generation": s.gens.min(dk)})
		if s.logLim.allow("stale_generation", now) {
			s.log.Printf("refused 409 stale_generation%s", kv)
		}
		return
	case err != nil:
		s.log.Printf("state-write-failed app=%s", a.id)
		s.refuse(w, http.StatusServiceUnavailable, "state_unavailable", kv)
		return
	}
	if op == "revoke" {
		s.log.Printf("revoke app=%s platform=%s gen=%d", a.id, platName(plat), q.Generation)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h, err := s.keys.seal(handle{
		app:     a.id,
		plat:    plat,
		issued:  now.Unix(),
		expires: now.Add(s.ttl).Unix(),
		gen:     q.Generation,
		src:     src,
		token:   tok,
	})
	if err != nil {
		s.refuse(w, http.StatusInternalServerError, "internal", kv)
		return
	}
	s.log.Printf("register app=%s platform=%s handle=%s gen=%d", a.id, platName(plat), handleHash(h), q.Generation)
	writeJSON(w, http.StatusOK, map[string]any{"handle": h, "expires": now.Add(s.ttl).Unix()})
}

type sendReq struct {
	Handle   string  `json:"handle"`
	CT       string  `json:"ct"`
	Collapse string  `json:"collapse"`
	Priority *string `json:"priority"`
}

func (s *server) send(w http.ResponseWriter, r *http.Request, body []byte, src srcTag, now time.Time) {
	var q sendReq
	if err := decodeStrict(body, &q); err != nil {
		s.refuse(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	// The handle first: until it opens, the request gets nothing but 403
	// and the gateway connects nowhere.
	h, ok := s.keys.open(q.Handle)
	if !ok {
		s.refuse(w, http.StatusForbidden, "forbidden", logf{"handle": handleHash(q.Handle)})
		return
	}
	a := s.apps[h.app]
	kv := logf{"app": h.app, "platform": platName(h.plat), "handle": handleHash(q.Handle)}
	if a == nil || !a.has(h.plat) {
		// Made for an app or platform since taken out of the config.
		s.refuse(w, http.StatusForbidden, "not_configured", logf{"platform": platName(h.plat), "handle": kv["handle"]})
		return
	}
	switch {
	case h.expires <= now.Unix():
		s.refuse(w, http.StatusForbidden, "expired", kv)
		return
	case h.issued > now.Add(handleSkew).Unix() || h.expires-h.issued > int64(maxHandleTTL/time.Second):
		s.refuse(w, http.StatusForbidden, "forbidden", kv)
		return
	}
	if h.src != src && s.bad.blocked(h.src, now) {
		// Registered by a source now blocked: not usable from elsewhere either.
		s.refuse(w, http.StatusTooManyRequests, "blocked", kv)
		return
	}
	dk := deviceKey(h.app, h.plat, h.token)
	if h.gen < s.gens.min(dk) {
		s.refuse(w, http.StatusForbidden, "revoked", kv)
		return
	}
	if len(q.CT) > connectpush.MaxCiphertext {
		s.refuse(w, http.StatusRequestEntityTooLarge, "too_large", kv)
		return
	}
	if connectpush.Check(q.CT) != nil {
		s.refuse(w, http.StatusBadRequest, "bad_ct", kv)
		return
	}
	if q.Collapse != "" && !collapseRe.MatchString(q.Collapse) {
		s.refuse(w, http.StatusBadRequest, "bad_collapse", kv)
		return
	}
	high := true
	if q.Priority != nil {
		switch *q.Priority {
		case "high":
		case "normal":
			high = false
		default:
			s.refuse(w, http.StatusBadRequest, "bad_priority", kv)
			return
		}
	}
	if !s.devMin.allow(dk, now) || !s.devDay.allow(dk, now) {
		s.refuse(w, http.StatusTooManyRequests, "rate_limited", kv)
		return
	}
	select {
	case s.sending <- struct{}{}:
		defer func() { <-s.sending }()
	default:
		s.refuse(w, http.StatusServiceUnavailable, "busy", kv)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()
	var res result
	var why string
	if h.plat == platAPNs {
		res, why = a.apns.send(ctx, s.hc, now, a.ph, h.token, q.CT, q.Collapse, high)
	} else {
		res, why = a.fcm.send(ctx, s.hc, now, h.token, q.CT, q.Collapse, high)
	}
	if res != failed {
		for _, t := range uniq(src, h.src) {
			if s.bad.note(t, res == gone, now) {
				s.log.Printf("source-blocked app=%s for=%s", h.app, badBlock)
			}
		}
	}
	// Upstream text never goes back: only these codes.
	switch res {
	case sent:
		s.log.Printf("send app=%s platform=%s handle=%s result=sent", h.app, platName(h.plat), kv["handle"])
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
	case gone:
		s.log.Printf("send app=%s platform=%s handle=%s result=gone reason=%s", h.app, platName(h.plat), kv["handle"], why)
		writeJSON(w, http.StatusGone, map[string]string{"error": "gone"})
	default:
		s.log.Printf("send app=%s platform=%s handle=%s result=failed reason=%s", h.app, platName(h.plat), kv["handle"], why)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "upstream_failed"})
	}
}

func uniq(a, b srcTag) []srcTag {
	if a == b {
		return []srcTag{a}
	}
	return []srcTag{a, b}
}
