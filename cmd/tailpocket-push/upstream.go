package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// upstream is where pushes go. Only these fixed addresses are ever dialed:
// nothing in a request chooses a host, a port or a path prefix. Tests
// replace them with local servers.
type upstream struct {
	client         *http.Client
	apnsProduction string
	apnsSandbox    string
	fcm            string
	oauth          string
	// playIntegrity is dialed only for an app with attest.android set.
	playIntegrity string
}

const (
	apnsProductionURL = "https://api.push.apple.com"
	apnsSandboxURL    = "https://api.sandbox.push.apple.com"
	fcmURL            = "https://fcm.googleapis.com"
	// oauthURL is always used for FCM tokens, and the JWT audience. The
	// token_uri in a service account file is ignored, so the file cannot
	// send the gateway anywhere else either.
	oauthURL = "https://oauth2.googleapis.com/token"
	fcmScope = "https://www.googleapis.com/auth/firebase.messaging"
	// playIntegrityURL is used only for apps with attest.android.
	playIntegrityURL   = "https://playintegrity.googleapis.com"
	playIntegrityScope = "https://www.googleapis.com/auth/playintegrity"

	upstreamTimeout = 15 * time.Second
	apnsJWTLife     = 50 * time.Minute
	// pushTTL matches connectpush.MaxAge: the phone drops older notes.
	pushTTL = 24 * time.Hour
)

func defaultUpstream() upstream {
	tr := &http.Transport{
		Proxy:               nil, // never from the environment
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	return upstream{
		client:         &http.Client{Transport: tr, Timeout: upstreamTimeout},
		apnsProduction: apnsProductionURL,
		apnsSandbox:    apnsSandboxURL,
		fcm:            fcmURL,
		oauth:          oauthURL,
		playIntegrity:  playIntegrityURL,
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

type result int

const (
	sent result = iota
	gone        // the token is no longer valid
	failed
)

var reasonRe = regexp.MustCompile(`^[A-Za-z_]{1,64}$`)

// reason keeps only a plain word from an upstream answer for the log.
func reason(s string) string {
	if reasonRe.MatchString(s) {
		return s
	}
	return "other"
}

// netReason names a failed request without its error text: a *url.Error
// holds the URL, and an APNs URL holds the device token.
func netReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	return "network"
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwtPart(v any) string {
	b, _ := json.Marshal(v)
	return b64(b)
}

// ---- APNs ----

type apnsSender struct {
	base   string
	topic  string
	teamID string
	keyID  string
	key    *ecdsa.PrivateKey

	mu   sync.Mutex
	jwt  string
	made time.Time
}

func loadP8(path string) (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("%s is not a PEM PRIVATE KEY (.p8)", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not a P-256 key", path)
	}
	return ec, nil
}

// token is the provider JWT, made again after 50 minutes (Apple takes one
// for up to an hour and refuses new ones more often than every 20 minutes).
func (s *apnsSender) token(now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwt != "" && !now.Before(s.made) && now.Sub(s.made) < apnsJWTLife {
		return s.jwt, nil
	}
	in := jwtPart(map[string]string{"alg": "ES256", "kid": s.keyID}) + "." +
		jwtPart(map[string]any{"iss": s.teamID, "iat": now.Unix()})
	d := sha256.Sum256([]byte(in))
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	s.jwt, s.made = in+"."+b64(sig), now
	return s.jwt, nil
}

func (s *apnsSender) forget(jwt string) {
	s.mu.Lock()
	if s.jwt == jwt {
		s.jwt = ""
	}
	s.mu.Unlock()
}

type apnsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type apnsPayload struct {
	APS struct {
		Alert   apnsAlert `json:"alert"`
		Mutable int       `json:"mutable-content"`
		Sound   string    `json:"sound"`
	} `json:"aps"`
	TP string `json:"tp"`
}

func (s *apnsSender) send(ctx context.Context, hc *http.Client, now time.Time, ph placeholder, token []byte, ct, collapse string, high bool) (result, string) {
	jwt, err := s.token(now)
	if err != nil {
		return failed, "jwt"
	}
	var p apnsPayload
	p.APS.Alert = apnsAlert{Title: ph.Title, Body: ph.Body}
	p.APS.Mutable = 1
	p.APS.Sound = "default"
	p.TP = ct
	body, err := json.Marshal(p)
	if err != nil {
		return failed, "payload"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/3/device/"+hex.EncodeToString(token), bytes.NewReader(body))
	if err != nil {
		return failed, "request"
	}
	req.Header.Set("authorization", "bearer "+jwt)
	req.Header.Set("apns-topic", s.topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", map[bool]string{true: "10", false: "5"}[high])
	req.Header.Set("apns-expiration", strconv.FormatInt(now.Add(pushTTL).Unix(), 10))
	if collapse != "" {
		req.Header.Set("apns-collapse-id", collapse)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return failed, netReason(err)
	}
	defer resp.Body.Close()
	var e struct {
		Reason string `json:"reason"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	_ = json.Unmarshal(b, &e)
	switch {
	case resp.StatusCode == http.StatusOK:
		return sent, ""
	case resp.StatusCode == http.StatusGone,
		resp.StatusCode == http.StatusBadRequest && (e.Reason == "BadDeviceToken" || e.Reason == "Unregistered"):
		return gone, reason(e.Reason)
	case resp.StatusCode == http.StatusForbidden && (e.Reason == "ExpiredProviderToken" || e.Reason == "InvalidProviderToken"):
		s.forget(jwt)
	}
	return failed, fmt.Sprintf("apns-%d-%s", resp.StatusCode, reason(e.Reason))
}

// ---- FCM ----

type fcmSender struct {
	base    string
	project string
	auth    *googleAuth
}

// googleAuth gets OAuth access tokens for one service account and scope.
type googleAuth struct {
	oauth string
	email string
	keyID string
	key   *rsa.PrivateKey
	scope string

	mu     sync.Mutex
	access string
	exp    time.Time
}

type serviceAccount struct {
	Type         string `json:"type"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
}

func loadServiceAccount(path string) (*serviceAccount, *rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var sa serviceAccount
	if err := json.Unmarshal(b, &sa); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" {
		return nil, nil, fmt.Errorf("%s is not a service account key (type service_account, with client_email)", path)
	}
	blk, _ := pem.Decode([]byte(sa.PrivateKey))
	if blk == nil {
		return nil, nil, fmt.Errorf("%s: private_key is not PEM", path)
	}
	var k any
	k, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		k, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("%s: private_key: %w", path, err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("%s: private_key is not an RSA key", path)
	}
	return &sa, rk, nil
}

// newGoogleAuth reads a service account file for scope; tokens come from
// oauth (always Google's fixed token URL outside tests).
func newGoogleAuth(path, oauth, scope string) (*googleAuth, error) {
	sa, k, err := loadServiceAccount(path)
	if err != nil {
		return nil, err
	}
	return &googleAuth{oauth: oauth, email: sa.ClientEmail, keyID: sa.PrivateKeyID, key: k, scope: scope}, nil
}

// token is an OAuth token, kept until a minute before it expires.
func (s *googleAuth) token(ctx context.Context, hc *http.Client, now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.access != "" && now.Before(s.exp) {
		return s.access, nil
	}
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		hdr["kid"] = s.keyID
	}
	in := jwtPart(hdr) + "." + jwtPart(map[string]any{
		"iss":   s.email,
		"scope": s.scope,
		"aud":   oauthURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, d[:])
	if err != nil {
		return "", errors.New("sign")
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {in + "." + b64(sig)},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.oauth, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", errors.New("request")
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	resp, err := hc.Do(req)
	if err != nil {
		return "", errors.New(netReason(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status-%d", resp.StatusCode)
	}
	var t struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" || !printable(t.AccessToken) {
		return "", errors.New("bad-answer")
	}
	s.access = t.AccessToken
	s.exp = now.Add(time.Duration(t.ExpiresIn)*time.Second - time.Minute)
	return s.access, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

func (s *googleAuth) forget(tok string) {
	s.mu.Lock()
	if s.access == tok {
		s.access = ""
	}
	s.mu.Unlock()
}

type fcmAndroid struct {
	Priority    string `json:"priority"`
	CollapseKey string `json:"collapse_key,omitempty"`
	TTL         string `json:"ttl"`
}

type fcmMessage struct {
	Message struct {
		Token   string            `json:"token"`
		Data    map[string]string `json:"data"`
		Android fcmAndroid        `json:"android"`
	} `json:"message"`
}

func (s *fcmSender) send(ctx context.Context, hc *http.Client, now time.Time, token []byte, ct, collapse string, high bool) (result, string) {
	at, err := s.auth.token(ctx, hc, now)
	if err != nil {
		return failed, "oauth-" + err.Error()
	}
	var m fcmMessage
	m.Message.Token = string(token)
	m.Message.Data = map[string]string{"tp": ct}
	m.Message.Android = fcmAndroid{Priority: map[bool]string{true: "high", false: "normal"}[high], CollapseKey: collapse, TTL: strconv.Itoa(int(pushTTL.Seconds())) + "s"}
	body, err := json.Marshal(m)
	if err != nil {
		return failed, "payload"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/v1/projects/"+s.project+"/messages:send", bytes.NewReader(body))
	if err != nil {
		return failed, "request"
	}
	req.Header.Set("authorization", "Bearer "+at)
	req.Header.Set("content-type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return failed, netReason(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if resp.StatusCode == http.StatusOK {
		return sent, ""
	}
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Details []struct {
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &e)
	code := ""
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
			break
		}
	}
	if resp.StatusCode == http.StatusNotFound || code == "UNREGISTERED" {
		return gone, reason(code)
	}
	if resp.StatusCode == http.StatusUnauthorized {
		s.auth.forget(at)
	}
	return failed, fmt.Sprintf("fcm-%d-%s-%s", resp.StatusCode, reason(e.Error.Status), reason(code))
}
