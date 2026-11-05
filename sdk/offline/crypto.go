package offline

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// Alg is a device signature algorithm. Software wallets and SIM applets use
// Ed25519; Android StrongBox/TEE and the iOS Secure Enclave only offer
// ECDSA P-256. Both produce 64-byte signatures, so the record size is fixed.
type Alg byte

const (
	AlgEd25519 Alg = 1
	AlgP256    Alg = 2
)

func (a Alg) String() string {
	switch a {
	case AlgEd25519:
		return "ed25519"
	case AlgP256:
		return "p256"
	}
	return fmt.Sprintf("alg(%d)", byte(a))
}

// ParseAlg parses "ed25519" or "p256".
func ParseAlg(s string) (Alg, error) {
	switch s {
	case "ed25519":
		return AlgEd25519, nil
	case "p256":
		return AlgP256, nil
	}
	return 0, fmt.Errorf("offline: unknown algorithm %q", s)
}

// PublicKeySize returns the encoded public key size for an algorithm:
// 32 bytes for Ed25519, 65 bytes (uncompressed point) for P-256.
func (a Alg) PublicKeySize() int {
	switch a {
	case AlgEd25519:
		return ed25519.PublicKeySize
	case AlgP256:
		return 65
	}
	return 0
}

// Trust is how strongly a device protects its signing key and wallet state.
type Trust byte

const (
	// TrustSoftware: key and state protected by the PIN in app storage. Used
	// when a device has no usable secure hardware.
	TrustSoftware Trust = 1
	// TrustHardwareKey: key in StrongBox, TEE or Secure Enclave, proven by
	// platform attestation; balance and counter sealed in app storage.
	TrustHardwareKey Trust = 2
	// TrustSecureApplet: key, balance and counter all inside a SIM or
	// embedded secure element applet.
	TrustSecureApplet Trust = 3
)

func (t Trust) String() string {
	switch t {
	case TrustSoftware:
		return "software"
	case TrustHardwareKey:
		return "hardware-key"
	case TrustSecureApplet:
		return "secure-applet"
	}
	return fmt.Sprintf("trust(%d)", byte(t))
}

// ErrSignature reports a signature that does not verify.
var ErrSignature = errors.New("offline: signature does not verify")

// VerifySignature checks a 64-byte signature over msg.
func VerifySignature(alg Alg, pub, msg, sig []byte) error {
	if len(sig) != 64 {
		return fmt.Errorf("%w: signature must be 64 bytes", ErrSignature)
	}
	switch alg {
	case AlgEd25519:
		if len(pub) != ed25519.PublicKeySize || !ed25519.Verify(pub, msg, sig) {
			return ErrSignature
		}
		return nil
	case AlgP256:
		key, err := ecdsa.ParseUncompressedPublicKey(ellipticP256(), pub)
		if err != nil {
			return fmt.Errorf("%w: bad P-256 key: %v", ErrSignature, err)
		}
		digest := sha256.Sum256(msg)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(key, digest[:], r, s) {
			return ErrSignature
		}
		return nil
	}
	return fmt.Errorf("%w: unknown algorithm %d", ErrSignature, alg)
}

// SignP256 signs msg with a P-256 key and returns the 64-byte r||s form.
func SignP256(key *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// ECDSADERToRaw converts an ASN.1 DER ECDSA signature (what Android Keystore
// and iOS Security framework return) into the 64-byte r||s form records use.
func ECDSADERToRaw(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil {
		return nil, fmt.Errorf("offline: malformed DER ECDSA signature")
	}
	if sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, fmt.Errorf("offline: ECDSA signature out of range")
	}
	out := make([]byte, 64)
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}

// P256PublicKey encodes a P-256 public key as a 65-byte uncompressed point.
func P256PublicKey(pub *ecdsa.PublicKey) ([]byte, error) { return pub.Bytes() }
