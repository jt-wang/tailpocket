package connectpush

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrGone means the gateway answered 410: APNs or FCM says the device token
// behind the handle is no longer valid. Delete the handle.
var ErrGone = errors.New("connectpush: push handle is gone")

// Error is any other answer from the gateway that is not success.
type Error struct {
	Status int    // HTTP status
	Code   string // the gateway's "error" field, such as "rate_limited"
	// MinGeneration is the lowest generation the gateway takes for this
	// token, with Code "stale_generation" (409) from Register.
	MinGeneration uint64
}

func (e *Error) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("connectpush: gateway answered %d", e.Status)
	}
	return fmt.Sprintf("connectpush: gateway answered %d %s", e.Status, e.Code)
}

// SendOptions are sent next to the sealed note. Both are visible to the
// gateway and to Apple or Google.
type SendOptions struct {
	// Collapse replaces an earlier push with the same value still waiting
	// on the device: at most 64 characters of A-Z a-z 0-9 . _ -. Use an
	// opaque value, not a title.
	Collapse string
	// Priority is "high" or "normal"; empty means "high".
	Priority string
}

// Client talks to a tailpocket-push gateway.
type Client struct {
	// URL is the gateway, such as https://push.example.com. http:// is only
	// allowed for a loopback address.
	URL string
	// HTTP is used for requests; nil means a client with a 30-second
	// timeout. Redirects are never followed.
	HTTP *http.Client
}

// Device names one device token of one app for Register and Revoke.
type Device struct {
	App        string `json:"app"`
	Platform   string `json:"platform"` // "apns" or "fcm"
	Token      string `json:"token"`
	Generation uint64 `json:"generation"`
	// Attest is the attestation evidence, for a gateway that checks it for
	// this app (docs/PUSH.md §7): {"challenge":…, …} bound to the other
	// fields by AttestClientData. Leave it nil otherwise.
	Attest json.RawMessage `json:"attest,omitempty"`
}

// Registration is the gateway's answer to Register.
type Registration struct {
	Handle  string `json:"handle"`
	Expires int64  `json:"expires"` // unix seconds; register again before then
}

// Register asks the gateway for a handle for a device token of app
// ("apns" or "fcm" for platform). generation starts at 1 and is kept by
// the phone; registering with a higher one makes every handle with a lower
// one stop working. The gateway answers 409 (an *Error with Code
// "stale_generation") for a generation below one it has seen.
func (c *Client) Register(ctx context.Context, app, platform, token string, generation uint64) (handle string, err error) {
	r, err := c.RegisterDevice(ctx, Device{App: app, Platform: platform, Token: token, Generation: generation})
	return r.Handle, err
}

// RegisterDevice is Register with attestation evidence and the expiry.
func (c *Client) RegisterDevice(ctx context.Context, d Device) (Registration, error) {
	var out Registration
	if err := c.post(ctx, "/v1/register", d, &out); err != nil {
		return Registration{}, err
	}
	if out.Handle == "" {
		return Registration{}, errors.New("connectpush: gateway answered without a handle")
	}
	return out, nil
}

// Revoke makes every handle for the token with a generation up to and
// including generation stop working. Register again with generation+1 or
// more for a new handle.
func (c *Client) Revoke(ctx context.Context, app, platform, token string, generation uint64) error {
	return c.RevokeDevice(ctx, Device{App: app, Platform: platform, Token: token, Generation: generation})
}

// RevokeDevice is Revoke with attestation evidence.
func (c *Client) RevokeDevice(ctx context.Context, d Device) error {
	return c.post(ctx, "/v1/revoke", d, nil)
}

// Challenge asks the gateway for a one-time challenge for app's
// attestation evidence. It is valid for a few minutes and one request.
func (c *Client) Challenge(ctx context.Context, app string) (string, error) {
	var out struct {
		Challenge string `json:"challenge"`
	}
	if err := c.post(ctx, "/v1/challenge", map[string]string{"app": app}, &out); err != nil {
		return "", err
	}
	if out.Challenge == "" || len(out.Challenge) > 256 || !IsBase64URL(out.Challenge) {
		return "", errors.New("connectpush: gateway answered without a challenge")
	}
	return out.Challenge, nil
}

// Send passes the sealed note ct to the device behind handle. The gateway
// takes the app and platform from the handle. It returns ErrGone when the
// gateway says the handle is gone, and *Error for any other refusal, such
// as Code "expired" or "revoked" (403): ask the phone for a new handle.
func (c *Client) Send(ctx context.Context, handle, ct string, opt SendOptions) error {
	if len(ct) > MaxCiphertext {
		return ErrTooLarge
	}
	req := struct {
		Handle   string `json:"handle"`
		CT       string `json:"ct"`
		Collapse string `json:"collapse,omitempty"`
		Priority string `json:"priority,omitempty"`
	}{handle, ct, opt.Collapse, opt.Priority}
	return c.post(ctx, "/v1/send", req, nil)
}

func (c *Client) base() (*url.URL, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("connectpush: gateway URL %q is not a plain http(s) URL", c.URL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("connectpush: gateway URL %q must be https:// (http:// only for loopback)", c.URL)
		}
	default:
		return nil, fmt.Errorf("connectpush: gateway URL %q must be https://", c.URL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u, nil
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	u, err := c.base()
	if err != nil {
		return err
	}
	u.Path += path
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := http.Client{Timeout: 30 * time.Second}
	if c.HTTP != nil {
		hc = *c.HTTP
	}
	// A redirect would carry the handle somewhere else.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusGone:
		return ErrGone
	case resp.StatusCode/100 != 2:
		var e struct {
			Error         string `json:"error"`
			MinGeneration uint64 `json:"min_generation"`
		}
		_ = json.Unmarshal(b, &e)
		return &Error{Status: resp.StatusCode, Code: e.Error, MinGeneration: e.MinGeneration}
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("connectpush: bad gateway answer: %w", err)
		}
	}
	return nil
}
