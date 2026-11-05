package attest

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// OIDAndroidKeyDescription is the key attestation extension.
var OIDAndroidKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Android security levels.
const (
	AndroidSoftware  = 0
	AndroidTEE       = 1
	AndroidStrongBox = 2
)

// KeyDescription is the leading part of Android's attestation extension.
type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

// Android verifies Android Keystore key attestation.
type Android struct {
	Roots *x509.CertPool
	// RequireStrongBox rejects TEE-only keys as hardware (they register as software).
	RequireStrongBox bool
}

// Format implements Verifier.
func (a *Android) Format() string { return "android-key" }

// Verify implements Verifier. A chain that verifies but reports a software
// security level registers the device with software trust.
func (a *Android) Verify(att api.Attestation, challenge, publicKey []byte, alg offline.Alg, now time.Time) (Result, error) {
	certs, err := parseChain(att.Chain)
	if err != nil {
		return Result{}, err
	}
	if err := verifyChain(certs, a.Roots, now); err != nil {
		return Result{}, err
	}
	leaf := certs[0]
	if err := leafKeyMatches(leaf, publicKey, alg); err != nil {
		return Result{}, err
	}
	var raw []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(OIDAndroidKeyDescription) {
			raw = e.Value
		}
	}
	if raw == nil {
		return Result{}, fmt.Errorf("%w: no key description extension", ErrInvalid)
	}
	var kd KeyDescription
	if _, err := asn1.Unmarshal(raw, &kd); err != nil {
		return Result{}, fmt.Errorf("%w: key description: %v", ErrInvalid, err)
	}
	if !bytes.Equal(kd.AttestationChallenge, challenge) {
		return Result{}, fmt.Errorf("%w: attestation challenge does not match", ErrInvalid)
	}
	switch kd.AttestationSecurityLevel {
	case AndroidStrongBox:
		return Result{Trust: offline.TrustHardwareKey, Kind: "android-strongbox", Note: "StrongBox key attestation verified"}, nil
	case AndroidTEE:
		if a.RequireStrongBox {
			return Result{Trust: offline.TrustSoftware, Kind: "android-tee", Note: "TEE key; StrongBox required for hardware trust"}, nil
		}
		return Result{Trust: offline.TrustHardwareKey, Kind: "android-tee", Note: "TEE key attestation verified"}, nil
	}
	return Result{Trust: offline.TrustSoftware, Kind: "android-software", Note: "Keystore reports a software key"}, nil
}
