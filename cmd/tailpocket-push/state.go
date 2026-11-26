package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// genStore is the gateway's only lasting state: for each device (see
// deviceKey), the lowest handle generation still valid. A phone raises it
// by registering with a higher generation or with /v1/revoke, and every
// handle it got before then stops working. For apps with App Attest it also
// holds each attested key's public key and last counter.
//
// It is one JSON file, written whole to a temporary file and renamed over
// the old one, so a crash leaves either the old file or the new one. A
// change is on disk before the request that made it is answered.
type genStore struct {
	path string
	max  int

	mu     sync.Mutex
	m      map[string]genEntry
	attest map[string]attestKey // App Attest key id (base64url) -> key
}

// attestKey is one App Attest key the gateway has seen attested.
type attestKey struct {
	App     string `json:"app"`
	Pub     string `json:"pub"` // uncompressed P-256 point, base64url
	Counter uint32 `json:"counter"`
	At      int64  `json:"at"` // unix seconds of the last use
}

type genEntry struct {
	Min uint64 `json:"min"`
	At  int64  `json:"at"` // unix seconds of the last raise
}

type stateFile struct {
	Version       int                  `json:"version"`
	MinGeneration map[string]genEntry  `json:"min_generation"`
	AttestKeys    map[string]attestKey `json:"attest_keys,omitempty"`
}

// maxGenEntries bounds the file (about 100 bytes an entry), and
// maxAttestKeys its App Attest keys (about 180 bytes each). An attest key
// unused for attestKeyLife is forgotten; the phone attests a new one.
const (
	maxGenEntries = 200_000
	maxAttestKeys = 200_000
	attestKeyLife = 180 * 24 * time.Hour
)

var (
	errStale     = errors.New("generation below the lowest valid one")
	errStateFull = errors.New("state is full")

	errAttestKnown   = errors.New("app attest key already attested")
	errAttestUnknown = errors.New("app attest key unknown")
	errAttestCounter = errors.New("app attest counter not above the last")
)

func loadGenStore(path string) (*genStore, error) {
	g := &genStore{path: path, max: maxGenEntries, m: map[string]genEntry{}, attest: map[string]attestKey{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		// Write it now, so a state_file that cannot be written stops the
		// start instead of the first revoke.
		if err := g.saveLocked(); err != nil {
			return nil, err
		}
		return g, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var f stateFile
	if err := decodeStrict(b, &f); err != nil || f.Version != 1 {
		// Starting empty would bring revoked handles back.
		return nil, fmt.Errorf("state %s is not a version 1 state file; fix or restore it", path)
	}
	for k, e := range f.MinGeneration {
		g.m[k] = e
	}
	for k, e := range f.AttestKeys {
		g.attest[k] = e
	}
	return g, nil
}

// getAttestKey returns the App Attest key with id.
func (g *genStore) getAttestKey(id string) (attestKey, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k, ok := g.attest[id]
	return k, ok
}

// addAttestKey stores a newly attested key, on disk before it returns. A
// key is attested once: a second attestation of the same id is refused.
func (g *genStore) addAttestKey(id string, k attestKey) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.attest[id]; ok {
		return errAttestKnown
	}
	if len(g.attest) >= maxAttestKeys {
		return errStateFull
	}
	g.attest[id] = k
	if err := g.saveLocked(); err != nil {
		delete(g.attest, id)
		return err
	}
	return nil
}

// useAttestKey raises the key's counter to counter, which must be above
// the stored one, on disk before it returns. Checking and raising under one
// lock means two requests can never both pass with the same counter.
func (g *genStore) useAttestKey(id, app string, counter uint32, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	k, ok := g.attest[id]
	if !ok || k.App != app {
		return errAttestUnknown
	}
	if counter <= k.Counter {
		return errAttestCounter
	}
	old := k
	k.Counter, k.At = counter, now.Unix()
	g.attest[id] = k
	if err := g.saveLocked(); err != nil {
		g.attest[id] = old
		return err
	}
	return nil
}

// min is the lowest valid generation for device key k (0 when none).
func (g *genStore) min(k string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.m[k].Min
}

// register accepts generation gen for k: it fails with errStale when gen
// is below the lowest valid one, and otherwise raises that to gen.
func (g *genStore) register(k string, gen uint64, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cur := g.m[k].Min
	if gen < cur {
		return errStale
	}
	if gen == cur || cur == 0 && gen == 1 {
		return nil // nothing to remember: 1 is where every device starts
	}
	return g.setLocked(k, gen, now)
}

// revoke makes every generation up to gen invalid for k.
func (g *genStore) revoke(k string, gen uint64, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if gen+1 <= g.m[k].Min {
		return nil
	}
	return g.setLocked(k, gen+1, now)
}

func (g *genStore) setLocked(k string, min uint64, now time.Time) error {
	old, had := g.m[k]
	if !had && len(g.m) >= g.max {
		return errStateFull
	}
	g.m[k] = genEntry{Min: min, At: now.Unix()}
	if err := g.saveLocked(); err != nil {
		if had {
			g.m[k] = old
		} else {
			delete(g.m, k)
		}
		return err
	}
	return nil
}

// sweep forgets entries raised more than maxHandleTTL and a day ago. Every
// handle below such an entry was made before the raise, so it has expired.
func (g *genStore) sweep(now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	cut := now.Add(-maxHandleTTL - 24*time.Hour).Unix()
	var gone map[string]genEntry
	for k, e := range g.m {
		if e.At < cut {
			if gone == nil {
				gone = map[string]genEntry{}
			}
			gone[k] = e
			delete(g.m, k)
		}
	}
	var goneKeys map[string]attestKey
	keyCut := now.Add(-attestKeyLife).Unix()
	for k, e := range g.attest {
		if e.At < keyCut {
			if goneKeys == nil {
				goneKeys = map[string]attestKey{}
			}
			goneKeys[k] = e
			delete(g.attest, k)
		}
	}
	if gone == nil && goneKeys == nil {
		return nil
	}
	if err := g.saveLocked(); err != nil {
		for k, e := range gone {
			g.m[k] = e
		}
		for k, e := range goneKeys {
			g.attest[k] = e
		}
		return err
	}
	return nil
}

func (g *genStore) saveLocked() error {
	b, err := json.Marshal(stateFile{Version: 1, MinGeneration: g.m, AttestKeys: g.attest})
	if err != nil {
		return err
	}
	dir := filepath.Dir(g.path)
	f, err := os.CreateTemp(dir, ".tailpocket-push-state-*")
	if err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("write state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(tmp, g.path); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	ok = true
	syncDir(dir)
	return nil
}
