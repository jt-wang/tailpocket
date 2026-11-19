package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const defaultListen = "127.0.0.1:8443"

// config is the JSON file given with --config. Unknown fields are an error,
// so a misspelled field cannot quietly leave something unset.
type config struct {
	Listen        string      `json:"listen"`
	TLSCert       string      `json:"tls_cert"`
	TLSKey        string      `json:"tls_key"`
	HandleKeyFile string      `json:"handle_key_file"`
	HandleKeyID   int         `json:"handle_key_id"`
	OldHandleKeys []oldKey    `json:"old_handle_keys"`
	HandleTTLDays int         `json:"handle_ttl_days"`
	StateFile     string      `json:"state_file"`
	TrustProxy    []string    `json:"trust_proxy"`
	Apps          []appConfig `json:"apps"`

	trust []netip.Prefix
}

// oldKey is a retired handle key: handles made with it still open, new
// handles use handle_key_file.
type oldKey struct {
	ID   int    `json:"id"`
	File string `json:"file"`
}

type appConfig struct {
	ID              string        `json:"id"`
	Placeholder     placeholder   `json:"placeholder"`
	APNs            *apnsConfig   `json:"apns"`
	FCM             *fcmConfig    `json:"fcm"`
	RegisterPerHour int           `json:"register_per_hour"`
	Attest          *attestConfig `json:"attest"`
}

// attestConfig turns on device attestation for register and revoke. Each
// part is passed as it is to the verifier for that platform; this build
// has none (see attest.go), so setting either stops the gateway at start.
type attestConfig struct {
	IOS     json.RawMessage `json:"ios"`
	Android json.RawMessage `json:"android"`
}

type placeholder struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type apnsConfig struct {
	TeamID  string `json:"team_id"`
	KeyID   string `json:"key_id"`
	KeyFile string `json:"key_file"`
	Topic   string `json:"topic"`
	Env     string `json:"env"`
}

type fcmConfig struct {
	ProjectID       string `json:"project_id"`
	CredentialsFile string `json:"credentials_file"`
}

const (
	maxPlaceholderTitle = 128
	maxPlaceholderBody  = 256

	defaultRegisterPerHour = 1000
	maxHandleTTLDays       = 30
)

var (
	// App ids go into the associated data of handles and sealed notes, so
	// they have no NUL; topics go into an HTTP header.
	appIDRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$`)
	appleIDRe = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	projectRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

func loadConfig(path string) (*config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseConfig(b, filepath.Dir(path))
}

// parseConfig checks the config and makes its file names absolute, taking
// relative ones from dir (the config file's directory).
func parseConfig(b []byte, dir string) (*config, error) {
	var c config
	if err := decodeStrict(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	abs := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(dir, p)
	}
	if c.Listen == "" {
		c.Listen = defaultListen
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return nil, errors.New("config: tls_cert and tls_key go together")
	}
	c.TLSCert, c.TLSKey = abs(c.TLSCert), abs(c.TLSKey)
	if c.HandleKeyFile == "" {
		return nil, errors.New("config: handle_key_file is required (the gateway creates it on first start)")
	}
	c.HandleKeyFile = abs(c.HandleKeyFile)
	if c.HandleKeyID == 0 {
		c.HandleKeyID = 1
	}
	if c.HandleKeyID < 1 || c.HandleKeyID > 255 {
		return nil, errors.New("config: handle_key_id must be 1 to 255")
	}
	ids := map[int]bool{c.HandleKeyID: true}
	for i := range c.OldHandleKeys {
		k := &c.OldHandleKeys[i]
		if k.ID < 1 || k.ID > 255 || ids[k.ID] {
			return nil, fmt.Errorf("config: old_handle_keys[%d]: id must be 1 to 255 and differ from handle_key_id and the others", i)
		}
		if k.File == "" {
			return nil, fmt.Errorf("config: old_handle_keys[%d]: file is required", i)
		}
		ids[k.ID] = true
		k.File = abs(k.File)
	}
	if c.HandleTTLDays == 0 {
		c.HandleTTLDays = maxHandleTTLDays
	}
	if c.HandleTTLDays < 1 || c.HandleTTLDays > maxHandleTTLDays {
		return nil, fmt.Errorf("config: handle_ttl_days must be 1 to %d", maxHandleTTLDays)
	}
	if c.StateFile == "" {
		return nil, errors.New("config: state_file is required (the gateway creates it; it holds revoked handle generations)")
	}
	c.StateFile = abs(c.StateFile)
	for _, s := range c.TrustProxy {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return nil, fmt.Errorf("config: trust_proxy: %w", err)
		}
		c.trust = append(c.trust, p.Masked())
	}
	if len(c.Apps) == 0 {
		return nil, errors.New("config: apps is empty")
	}
	seen := map[string]bool{}
	for i := range c.Apps {
		a := &c.Apps[i]
		if !appIDRe.MatchString(a.ID) {
			return nil, fmt.Errorf("config: apps[%d]: id %q must be 1 to 255 of A-Z a-z 0-9 . _ -", i, a.ID)
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("config: app %s is listed twice", a.ID)
		}
		seen[a.ID] = true
		if a.Placeholder.Title == "" || len(a.Placeholder.Title) > maxPlaceholderTitle || a.Placeholder.Body == "" || len(a.Placeholder.Body) > maxPlaceholderBody {
			return nil, fmt.Errorf("config: app %s: placeholder needs a title (at most %d bytes) and a body (at most %d bytes)", a.ID, maxPlaceholderTitle, maxPlaceholderBody)
		}
		if a.APNs == nil && a.FCM == nil {
			return nil, fmt.Errorf("config: app %s has neither apns nor fcm", a.ID)
		}
		if a.RegisterPerHour == 0 {
			a.RegisterPerHour = defaultRegisterPerHour
		}
		if a.RegisterPerHour < 1 {
			return nil, fmt.Errorf("config: app %s: register_per_hour must be above 0", a.ID)
		}
		if at := a.Attest; at != nil {
			if len(at.IOS) == 0 && len(at.Android) == 0 {
				return nil, fmt.Errorf("config: app %s: attest needs ios or android", a.ID)
			}
			if len(at.IOS) > 0 && a.APNs == nil || len(at.Android) > 0 && a.FCM == nil {
				return nil, fmt.Errorf("config: app %s: attest.ios needs apns and attest.android needs fcm", a.ID)
			}
		}
		if p := a.APNs; p != nil {
			if !appleIDRe.MatchString(p.TeamID) || !appleIDRe.MatchString(p.KeyID) {
				return nil, fmt.Errorf("config: app %s: apns team_id and key_id are 10 characters of A-Z 0-9", a.ID)
			}
			if p.KeyFile == "" {
				return nil, fmt.Errorf("config: app %s: apns key_file (the .p8 file) is required", a.ID)
			}
			if !appIDRe.MatchString(p.Topic) {
				return nil, fmt.Errorf("config: app %s: apns topic (the bundle id) is required", a.ID)
			}
			switch p.Env {
			case "":
				p.Env = "production"
			case "production", "sandbox":
			default:
				return nil, fmt.Errorf("config: app %s: apns env must be production or sandbox", a.ID)
			}
			p.KeyFile = abs(p.KeyFile)
		}
		if p := a.FCM; p != nil {
			if !projectRe.MatchString(p.ProjectID) {
				return nil, fmt.Errorf("config: app %s: fcm project_id %q is not a Firebase project id", a.ID, p.ProjectID)
			}
			if p.CredentialsFile == "" {
				return nil, fmt.Errorf("config: app %s: fcm credentials_file (the service account JSON) is required", a.ID)
			}
			p.CredentialsFile = abs(p.CredentialsFile)
		}
	}
	return &c, nil
}

// decodeStrict decodes one JSON value with no unknown fields and nothing
// after it.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("data after the JSON value")
	}
	return nil
}
