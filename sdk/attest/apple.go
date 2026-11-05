package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// OIDAppleNonce is the App Attest nonce extension.
var OIDAppleNonce = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// AppleNonce is the DER structure inside OIDAppleNonce.
type AppleNonce struct {
	Nonce []byte `asn1:"tag:1,explicit"`
}

// AppleAttestationObject is the CBOR attestation object.
type AppleAttestationObject struct {
	Fmt     string `cbor:"fmt"`
	AttStmt struct {
		X5C     [][]byte `cbor:"x5c"`
		Receipt []byte   `cbor:"receipt"`
	} `cbor:"attStmt"`
	AuthData []byte `cbor:"authData"`
}

// Apple verifies Apple App Attest attestations.
type Apple struct {
	Roots *x509.CertPool
	// AppIDs are "<team id>.<bundle id>" values allowed to register.
	AppIDs []string
	// AllowDevelopment accepts the development environment AAGUID.
	AllowDevelopment bool
}

// Format implements Verifier.
func (a *Apple) Format() string { return "apple-appattest" }

var (
	aaguidProd = []byte("appattest\x00\x00\x00\x00\x00\x00\x00")
	aaguidDev  = []byte("appattestdevelop")
)

// Verify implements Verifier, following Apple's server validation steps.
func (a *Apple) Verify(att api.Attestation, challenge, publicKey []byte, alg offline.Alg, now time.Time) (Result, error) {
	var obj AppleAttestationObject
	if err := cbor.Unmarshal(att.Object, &obj); err != nil {
		return Result{}, fmt.Errorf("%w: attestation object: %v", ErrInvalid, err)
	}
	if obj.Fmt != "apple-appattest" {
		return Result{}, fmt.Errorf("%w: fmt %q", ErrInvalid, obj.Fmt)
	}
	certs, err := parseChain(obj.AttStmt.X5C)
	if err != nil {
		return Result{}, err
	}
	if err := verifyChain(certs, a.Roots, now); err != nil {
		return Result{}, err
	}
	leaf := certs[0]
	// Two shapes: the App Attest key itself is the device key (no assertion),
	// or (the real iOS pattern) a separate Secure Enclave key is the device
	// key and the App Attest key vouches for it with an assertion.
	attestedKey := publicKey
	if len(att.Assertion) > 0 {
		aaKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return Result{}, fmt.Errorf("%w: App Attest key is not P-256", ErrInvalid)
		}
		if err := verifyAppleAssertion(aaKey, att.Assertion, challenge, publicKey, a.AppIDs); err != nil {
			return Result{}, err
		}
		if attestedKey, err = aaKey.Bytes(); err != nil {
			return Result{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
	} else if err := leafKeyMatches(leaf, publicKey, alg); err != nil {
		return Result{}, err
	}
	if alg != offline.AlgP256 {
		return Result{}, fmt.Errorf("%w: Secure Enclave keys are P-256", ErrInvalid)
	}
	// nonce = SHA256(authData || SHA256(challenge)) must be in the leaf extension.
	cdh := sha256.Sum256(challenge)
	want := sha256.Sum256(append(append([]byte(nil), obj.AuthData...), cdh[:]...))
	var got []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(OIDAppleNonce) {
			var n AppleNonce
			if _, err := asn1.Unmarshal(e.Value, &n); err != nil {
				return Result{}, fmt.Errorf("%w: nonce extension: %v", ErrInvalid, err)
			}
			got = n.Nonce
		}
	}
	if !bytes.Equal(got, want[:]) {
		return Result{}, fmt.Errorf("%w: nonce does not match the challenge", ErrInvalid)
	}
	// authData: rpIdHash(32) flags(1) signCount(4) aaguid(16) credIdLen(2) credId.
	ad := obj.AuthData
	if len(ad) < 55 {
		return Result{}, fmt.Errorf("%w: authData too short", ErrInvalid)
	}
	appOK := false
	for _, id := range a.AppIDs {
		h := sha256.Sum256([]byte(id))
		if bytes.Equal(ad[:32], h[:]) {
			appOK = true
		}
	}
	if !appOK {
		return Result{}, fmt.Errorf("%w: attestation is for another app", ErrInvalid)
	}
	if binary.BigEndian.Uint32(ad[33:37]) != 0 {
		return Result{}, fmt.Errorf("%w: sign count must be zero at attestation", ErrInvalid)
	}
	aaguid := ad[37:53]
	if !bytes.Equal(aaguid, aaguidProd) && !(a.AllowDevelopment && bytes.Equal(aaguid, aaguidDev)) {
		return Result{}, fmt.Errorf("%w: unexpected App Attest environment", ErrInvalid)
	}
	n := int(binary.BigEndian.Uint16(ad[53:55]))
	if len(ad) < 55+n {
		return Result{}, fmt.Errorf("%w: credential id truncated", ErrInvalid)
	}
	keyID := sha256.Sum256(attestedKey)
	if !bytes.Equal(ad[55:55+n], keyID[:]) {
		return Result{}, fmt.Errorf("%w: credential id is not the registered key", ErrInvalid)
	}
	return Result{Trust: offline.TrustHardwareKey, Kind: "ios-secure-enclave", Note: "App Attest verified"}, nil
}

// AppleAssertion is an App Attest assertion (CBOR).
type AppleAssertion struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// verifyAppleAssertion checks the App Attest key signed clientData =
// challenge || device public key, binding the device key to this app instance.
func verifyAppleAssertion(aaKey *ecdsa.PublicKey, raw, challenge, devicePub []byte, appIDs []string) error {
	var as AppleAssertion
	if err := cbor.Unmarshal(raw, &as); err != nil {
		return fmt.Errorf("%w: assertion: %v", ErrInvalid, err)
	}
	if len(as.AuthenticatorData) < 37 {
		return fmt.Errorf("%w: assertion authenticator data too short", ErrInvalid)
	}
	okApp := false
	for _, id := range appIDs {
		h := sha256.Sum256([]byte(id))
		if bytes.Equal(as.AuthenticatorData[:32], h[:]) {
			okApp = true
		}
	}
	if !okApp {
		return fmt.Errorf("%w: assertion is for another app", ErrInvalid)
	}
	cdh := sha256.Sum256(append(append([]byte(nil), challenge...), devicePub...))
	digest := sha256.Sum256(append(append([]byte(nil), as.AuthenticatorData...), cdh[:]...))
	if !ecdsa.VerifyASN1(aaKey, digest[:], as.Signature) {
		return fmt.Errorf("%w: App Attest assertion does not verify", ErrInvalid)
	}
	return nil
}

// SIM verifies a SIM or embedded secure element applet's certificate chain.
// The applet holds the key, balance and counter, so it earns applet trust.
// Freshness comes from the registration proof the applet signs.
type SIM struct{ Roots *x509.CertPool }

// Format implements Verifier.
func (s *SIM) Format() string { return "sim-x509" }

// Verify implements Verifier.
func (s *SIM) Verify(att api.Attestation, challenge, publicKey []byte, alg offline.Alg, now time.Time) (Result, error) {
	certs, err := parseChain(att.Chain)
	if err != nil {
		return Result{}, err
	}
	if err := verifyChain(certs, s.Roots, now); err != nil {
		return Result{}, err
	}
	if err := leafKeyMatches(certs[0], publicKey, alg); err != nil {
		return Result{}, err
	}
	return Result{Trust: offline.TrustSecureApplet, Kind: "sim-applet", Note: "SIM applet certificate verified"}, nil
}
