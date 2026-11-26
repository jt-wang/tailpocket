package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

// App Attest (iOS). The app makes a key with DCAppAttestService, and the
// first time it registers it sends Apple's attestation of that key; the
// gateway checks it and keeps the key's public key and counter in the state
// file. Every later register or revoke carries an assertion signed by the
// key, with a counter above the last. Both are bound to the request through
// clientDataHash = connectpush.AttestHash(…), which includes the gateway's
// one-time challenge.
//
// Steps as Apple documents them ("Validating apps that connect to your
// server", 2024):
//
// Attestation (CBOR {fmt: "apple-appattest", attStmt: {x5c, receipt}, authData}):
//  1. x5c[0] (credCert) chains through x5c[1:] to the App Attest root CA.
//  2. nonce = SHA-256(authData || clientDataHash) equals the octet string in
//     credCert's extension 1.2.840.113635.100.8.2.
//  3. SHA-256 of credCert's public key (uncompressed point) is the key id.
//  4. authData's RP ID hash is SHA-256(team id + "." + bundle id).
//  5. Its counter is 0.
//  6. Its AAGUID is "appattestdevelop" (development) or "appattest" and seven
//     zero bytes (production), as configured.
//  7. Its credential id is the key id.
//
// Assertion (CBOR {signature, authenticatorData}):
//  1. signature is an ECDSA P-256 / SHA-256 signature by the stored key over
//     nonce = SHA-256(authenticatorData || clientDataHash).
//  2. authenticatorData's RP ID hash is the app's.
//  3. Its counter is above the stored one, which then becomes it.
//
// Not checked: the receipt (Apple's fraud-risk metric needs another call to
// Apple), so the gateway cannot tell how many keys one device has made.

// appleAppAttestRootPEM is Apple App Attestation Root CA, from
// https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
// (SHA-256 fingerprint 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32,
// valid 2020-03-18 to 2045-03-15).
const appleAppAttestRootPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
`

// appAttestRoots is the trust root for attestations. Only tests replace it.
var appAttestRoots = func() *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(appleAppAttestRootPEM)) {
		panic("tailpocket-push: bad App Attest root")
	}
	return p
}()

var (
	oidAppAttestNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}
	aaguidProduction  = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't'}
	aaguidDevelopment = [16]byte{'a', 'p', 'p', 'a', 't', 't', 'e', 's', 't', 'd', 'e', 'v', 'e', 'l', 'o', 'p'}
	bundleIDRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)
)

type appAttestConfig struct {
	// TeamID and BundleID default to apns.team_id and apns.topic.
	TeamID   string `json:"team_id"`
	BundleID string `json:"bundle_id"`
	// Env is "production" (default) or "development": the App Attest
	// environment entitlement of the build (com.apple.developer.devicecheck.appattest-environment).
	Env string `json:"env"`
}

type appAttest struct {
	app      string
	rpIDHash [32]byte
	aaguid   [16]byte
	state    *genStore
}

func newAppAttest(raw json.RawMessage, env attestEnv) (attester, error) {
	var c appAttestConfig
	if err := decodeStrict(raw, &c); err != nil {
		return nil, err
	}
	if env.app.APNs != nil {
		if c.TeamID == "" {
			c.TeamID = env.app.APNs.TeamID
		}
		if c.BundleID == "" {
			c.BundleID = env.app.APNs.Topic
		}
	}
	if !appleIDRe.MatchString(c.TeamID) || !bundleIDRe.MatchString(c.BundleID) {
		return nil, errors.New("team_id (10 characters of A-Z 0-9) and bundle_id are required")
	}
	a := &appAttest{app: env.app.ID, rpIDHash: sha256.Sum256([]byte(c.TeamID + "." + c.BundleID)), state: env.state}
	switch c.Env {
	case "", "production":
		a.aaguid = aaguidProduction
	case "development":
		a.aaguid = aaguidDevelopment
	default:
		return nil, errors.New(`env must be "production" or "development"`)
	}
	return a, nil
}

type appAttestEvidence struct {
	Challenge   string `json:"challenge"`
	KeyID       string `json:"key_id"`      // as DCAppAttestService gives it: standard base64
	Attestation string `json:"attestation"` // standard base64 of the attestation object, the first time
	Assertion   string `json:"assertion"`   // standard base64 of an assertion, every later time
}

func decodeB64(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.Strict().DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

func (a *appAttest) Verify(_ context.Context, req attestRequest) error {
	var ev appAttestEvidence
	if err := decodeStrict(req.Evidence, &ev); err != nil {
		return attestFail("evidence")
	}
	keyID, err := decodeB64(ev.KeyID)
	if err != nil || len(keyID) != sha256.Size {
		return attestFail("key-id")
	}
	id := base64.RawURLEncoding.EncodeToString(keyID)
	switch {
	case ev.Attestation != "" && ev.Assertion == "":
		obj, err := decodeB64(ev.Attestation)
		if err != nil {
			return attestFail("attestation")
		}
		pub, err := a.checkAttestation(obj, keyID, req)
		if err != nil {
			return err
		}
		switch err := a.state.addAttestKey(id, attestKey{App: a.app, Pub: base64.RawURLEncoding.EncodeToString(pub), At: req.Now.Unix()}); {
		case errors.Is(err, errAttestKnown):
			return attestFail("key-already-attested")
		case err != nil:
			return fmt.Errorf("state: %w", err)
		}
		return nil
	case ev.Assertion != "" && ev.Attestation == "":
		obj, err := decodeB64(ev.Assertion)
		if err != nil {
			return attestFail("assertion")
		}
		k, ok := a.state.getAttestKey(id)
		if !ok || k.App != a.app {
			return &attestError{reason: "key-unknown", unknownKey: true}
		}
		counter, err := a.checkAssertion(obj, k, req)
		if err != nil {
			return err
		}
		switch err := a.state.useAttestKey(id, a.app, counter, req.Now); {
		case errors.Is(err, errAttestCounter):
			return attestFail("counter")
		case errors.Is(err, errAttestUnknown):
			return &attestError{reason: "key-unknown", unknownKey: true}
		case err != nil:
			return fmt.Errorf("state: %w", err)
		}
		return nil
	}
	return attestFail("evidence")
}

// checkAttestation returns the attested key's public key (uncompressed point).
func (a *appAttest) checkAttestation(obj, keyID []byte, req attestRequest) ([]byte, error) {
	v, err := decodeCBOR(obj)
	m, ok := v.(map[string]any)
	if err != nil || !ok || m["fmt"] != "apple-appattest" {
		return nil, attestFail("format")
	}
	stmt, _ := m["attStmt"].(map[string]any)
	authData, _ := m["authData"].([]byte)
	x5c, _ := stmt["x5c"].([]any)
	if len(x5c) < 2 || len(authData) < 37+16+2 {
		return nil, attestFail("format")
	}
	var certs []*x509.Certificate
	for _, c := range x5c {
		der, ok := c.([]byte)
		if !ok {
			return nil, attestFail("format")
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, attestFail("certificate")
		}
		certs = append(certs, cert)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: appAttestRoots, Intermediates: inter, CurrentTime: req.Now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, attestFail("chain")
	}

	nonce := sha256.Sum256(append(append([]byte(nil), authData...), req.ClientDataHash[:]...))
	var got []byte
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidAppAttestNonce) {
			var seq struct {
				Nonce []byte `asn1:"explicit,tag:1"`
			}
			if rest, err := asn1.Unmarshal(ext.Value, &seq); err != nil || len(rest) != 0 {
				return nil, attestFail("nonce")
			}
			got = seq.Nonce
		}
	}
	if !bytes.Equal(got, nonce[:]) {
		return nil, attestFail("nonce")
	}

	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, attestFail("key")
	}
	point, err := pub.Bytes()
	if err != nil {
		return nil, attestFail("key")
	}
	if h := sha256.Sum256(point); !bytes.Equal(h[:], keyID) {
		return nil, attestFail("key-id")
	}

	if !bytes.Equal(authData[:32], a.rpIDHash[:]) {
		return nil, attestFail("rp-id")
	}
	if authData[32]&0x40 == 0 { // AT: attested credential data present
		return nil, attestFail("auth-data")
	}
	if binary.BigEndian.Uint32(authData[33:37]) != 0 {
		return nil, attestFail("counter")
	}
	if !bytes.Equal(authData[37:53], a.aaguid[:]) {
		return nil, attestFail("environment")
	}
	n := int(binary.BigEndian.Uint16(authData[53:55]))
	if len(authData) < 55+n || !bytes.Equal(authData[55:55+n], keyID) {
		return nil, attestFail("credential-id")
	}
	return point, nil
}

// checkAssertion returns the assertion's counter, once its signature and RP ID check.
func (a *appAttest) checkAssertion(obj []byte, k attestKey, req attestRequest) (uint32, error) {
	v, err := decodeCBOR(obj)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return 0, attestFail("format")
	}
	sig, _ := m["signature"].([]byte)
	authData, _ := m["authenticatorData"].([]byte)
	if len(sig) == 0 || len(authData) < 37 {
		return 0, attestFail("format")
	}
	point, err := base64.RawURLEncoding.DecodeString(k.Pub)
	if err != nil {
		return 0, attestFail("key")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return 0, attestFail("key")
	}
	nonce := sha256.Sum256(append(append([]byte(nil), authData...), req.ClientDataHash[:]...))
	digest := sha256.Sum256(nonce[:]) // the key signs nonce with ECDSA-SHA256
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return 0, attestFail("signature")
	}
	if !bytes.Equal(authData[:32], a.rpIDHash[:]) {
		return 0, attestFail("rp-id")
	}
	return binary.BigEndian.Uint32(authData[33:37]), nil
}
