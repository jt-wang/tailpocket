package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Play Integrity (Android). The app asks Google Play for an integrity token
// whose request hash (standard request) or nonce (classic request) is
// connectpush.AttestRequestHash(…), which includes the gateway's one-time
// challenge. The gateway has Google decrypt it with the publisher's service
// account:
//
//	POST https://playintegrity.googleapis.com/v1/<package>:decodeIntegrityToken {"integrity_token": …}
//
// and checks the verdict: requestDetails (package, requestHash or nonce,
// timestamp within the window), appIntegrity (PLAY_RECOGNIZED, package name,
// a configured signing certificate digest) and deviceIntegrity
// (MEETS_DEVICE_INTEGRITY). playintegrity.googleapis.com is dialed only for
// apps with attest.android set.

const (
	scopePlayIntegrity = playIntegrityScope
	// piMaxAge and piMaxSkew bound requestDetails.timestampMillis.
	piMaxAge  = 10 * time.Minute
	piMaxSkew = time.Minute
)

var packageRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

type playIntegrityConfig struct {
	// PackageName is the Android application id.
	PackageName string `json:"package_name"`
	// CertificateSHA256 are the SHA-256 digests of the certificates the app
	// is signed with as Google Play delivers it (Play Console, Test and
	// release, App integrity, App signing key certificate): hex with or
	// without colons, or base64url.
	CertificateSHA256 []string `json:"certificate_sha256"`
	// CredentialsFile is a service account of the Google Cloud project
	// linked to the app in Play Console. Default: fcm.credentials_file.
	CredentialsFile string `json:"credentials_file"`
	// DecodePerHour caps the decodeIntegrityToken calls the gateway makes for this app, so requests
	// with made-up tokens cannot use up the Google Cloud project's Play Integrity quota. Over it,
	// register and revoke answer 503 attestation_unavailable without calling Google. Keep 24 × this
	// below the project's daily quota. Default 400.
	DecodePerHour int `json:"decode_per_hour"`
	// DecryptionKeyFile and VerificationKeyFile are the response encryption keys the publisher
	// manages (Play Console → Play Integrity API settings → Manage response encryption). With them
	// the gateway decodes classic tokens itself, never calls Google and has no decode budget; the
	// app must make classic requests (TailPocketPlayIntegrity.classic). Without them it asks
	// Google's decodeIntegrityToken, capped by DecodePerHour.
	DecryptionKeyFile   string `json:"decryption_key_file"`
	VerificationKeyFile string `json:"verification_key_file"`
}

const (
	defaultDecodePerHour = 400
	maxDecodePerHour     = 1 << 20
)

var errDecodeBudget = errors.New("play integrity: decode_per_hour used up")

type playIntegrity struct {
	pkg    string
	certs  []string // base64url without padding, as Google reports them
	base   string
	auth   *googleAuth
	client *http.Client
	decode *limiter   // decodeIntegrityToken calls per hour (DecodePerHour)
	local  *localKeys // set: classic tokens are decoded here, Google is never called
}

func newPlayIntegrity(raw json.RawMessage, env attestEnv) (attester, error) {
	var c playIntegrityConfig
	if err := decodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if !packageRe.MatchString(c.PackageName) || len(c.PackageName) > 255 {
		return nil, errors.New("package_name (the Android application id) is required")
	}
	if c.DecodePerHour == 0 {
		c.DecodePerHour = defaultDecodePerHour
	}
	if c.DecodePerHour < 0 || c.DecodePerHour > maxDecodePerHour {
		return nil, errors.New("decode_per_hour must be between 1 and 1048576")
	}
	if len(c.CertificateSHA256) == 0 {
		return nil, errors.New("certificate_sha256 needs the app signing certificate's SHA-256")
	}
	hc := *env.up.client
	hc.CheckRedirect = noRedirect // a redirect would choose where the gateway connects
	p := &playIntegrity{pkg: c.PackageName, base: env.up.playIntegrity, client: &hc,
		decode: newLimiter(c.DecodePerHour, time.Hour, 6, 1)}
	for _, d := range c.CertificateSHA256 {
		b, err := parseDigest(d)
		if err != nil {
			return nil, fmt.Errorf("certificate_sha256 %q: %w", d, err)
		}
		p.certs = append(p.certs, base64.RawURLEncoding.EncodeToString(b))
	}
	if c.DecryptionKeyFile != "" || c.VerificationKeyFile != "" {
		k, err := loadLocalKeys(env.dir, c.DecryptionKeyFile, c.VerificationKeyFile)
		if err != nil {
			return nil, err
		}
		p.local = k
		return p, nil // no Google call, so no service account
	}
	file := c.CredentialsFile
	switch {
	case file == "" && env.app.FCM != nil:
		file = env.app.FCM.CredentialsFile
	case file == "":
		return nil, errors.New("credentials_file is required")
	case !filepath.IsAbs(file):
		file = filepath.Join(env.dir, file)
	}
	auth, err := newGoogleAuth(file, env.up.oauth, scopePlayIntegrity)
	if err != nil {
		return nil, err
	}
	p.auth = auth
	return p, nil
}

// parseDigest reads a SHA-256 digest as hex (colons allowed) or base64url.
func parseDigest(s string) ([]byte, error) {
	h := strings.ReplaceAll(s, ":", "")
	if b, err := hex.DecodeString(h); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "=")); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("not a SHA-256 digest")
}

type playIntegrityEvidence struct {
	Challenge string `json:"challenge"`
	Token     string `json:"token"`
}

type integrityVerdict struct {
	TokenPayloadExternal integrityPayload `json:"tokenPayloadExternal"`
}

// integrityPayload is the verdict itself: decodeIntegrityToken's tokenPayloadExternal, or the
// payload of a locally decoded classic token.
type integrityPayload struct {
	RequestDetails struct {
		RequestPackageName string `json:"requestPackageName"`
		RequestHash        string `json:"requestHash"`
		Nonce              string `json:"nonce"`
		TimestampMillis    string `json:"timestampMillis"`
	} `json:"requestDetails"`
	AppIntegrity struct {
		AppRecognitionVerdict   string   `json:"appRecognitionVerdict"`
		PackageName             string   `json:"packageName"`
		CertificateSha256Digest []string `json:"certificateSha256Digest"`
	} `json:"appIntegrity"`
	DeviceIntegrity struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
}

func (p *playIntegrity) Verify(ctx context.Context, req attestRequest) error {
	var ev playIntegrityEvidence
	if err := decodeStrict(req.Evidence, &ev); err != nil || ev.Token == "" || len(ev.Token) > 8192 || !printable(ev.Token) {
		return attestFail("evidence")
	}
	var t integrityPayload
	if p.local != nil {
		b, err := p.local.decode(ev.Token)
		if err != nil {
			return err
		}
		if json.Unmarshal(b, &t) != nil {
			return attestFail("token")
		}
	} else {
		if !p.decode.allow("", req.Now) {
			return errDecodeBudget
		}
		v, err := p.decodeToken(ctx, ev.Token, req.Now)
		if err != nil {
			return err
		}
		t = v.TokenPayloadExternal
	}
	want := base64.RawURLEncoding.EncodeToString(req.ClientDataHash[:])
	// A classic request returns the nonce as the app sent it; accept it
	// with or without padding.
	if t.RequestDetails.RequestHash != want && strings.TrimRight(t.RequestDetails.Nonce, "=") != want {
		return attestFail("request-hash")
	}
	if t.RequestDetails.RequestPackageName != p.pkg || t.AppIntegrity.PackageName != p.pkg {
		return attestFail("package")
	}
	ms, err := strconv.ParseInt(t.RequestDetails.TimestampMillis, 10, 64)
	if err != nil {
		return attestFail("timestamp")
	}
	at := time.UnixMilli(ms)
	if at.Before(req.Now.Add(-piMaxAge)) || at.After(req.Now.Add(piMaxSkew)) {
		return attestFail("timestamp")
	}
	if t.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		return attestFail("app-not-recognized")
	}
	if len(t.AppIntegrity.CertificateSha256Digest) == 0 {
		return attestFail("certificate")
	}
	for _, d := range t.AppIntegrity.CertificateSha256Digest {
		if !slices.Contains(p.certs, strings.TrimRight(d, "=")) {
			return attestFail("certificate")
		}
	}
	if !slices.Contains(t.DeviceIntegrity.DeviceRecognitionVerdict, "MEETS_DEVICE_INTEGRITY") {
		return attestFail("device")
	}
	return nil
}

// decodeToken has Google decrypt and verify the token. Google's answer text is
// never passed on or logged.
func (p *playIntegrity) decodeToken(ctx context.Context, token string, now time.Time) (integrityVerdict, error) {
	at, err := p.auth.token(ctx, p.client, now)
	if err != nil {
		return integrityVerdict{}, errors.New("play integrity: no access token") // the gateway, not the evidence
	}
	body, _ := json.Marshal(map[string]string{"integrity_token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/v1/"+p.pkg+":decodeIntegrityToken", bytes.NewReader(body))
	if err != nil {
		return integrityVerdict{}, errors.New("play integrity: request")
	}
	req.Header.Set("authorization", "Bearer "+at)
	req.Header.Set("content-type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return integrityVerdict{}, fmt.Errorf("play integrity: %s", netReason(err))
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		p.auth.forget(at)
		return integrityVerdict{}, fmt.Errorf("play integrity: status 401")
	case resp.StatusCode == http.StatusBadRequest:
		return integrityVerdict{}, attestFail("token") // a token Google cannot decode
	case resp.StatusCode != http.StatusOK:
		return integrityVerdict{}, fmt.Errorf("play integrity: status %d", resp.StatusCode)
	}
	var v integrityVerdict
	if err := json.Unmarshal(b, &v); err != nil {
		return integrityVerdict{}, fmt.Errorf("play integrity: bad answer")
	}
	return v, nil
}
