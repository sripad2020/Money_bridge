// Package attest verifies platform attestation: evidence that a device's
// signing key was generated inside secure hardware. The server uses it at
// registration to decide a device's trust level and offline limits.
//
// Formats:
//   - "none": no evidence; the device registers with software trust.
//   - "android-key": Android Keystore/KeyMint key attestation (TEE or StrongBox).
//   - "apple-appattest": Apple App Attest (Secure Enclave).
//   - "sim-x509": a SIM or embedded secure element applet certificate chain.
//
// Trust roots are configuration: production deployments load Google's
// hardware attestation roots, Apple's App Attest root and the telecom
// partner's SIM CA. Tests use roots minted by sdk/wallet/emulator.
package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// ErrInvalid means evidence was supplied but is wrong: a different key, a
// stale challenge or an untrusted chain. The server rejects the registration,
// because broken evidence is an attack signal, not missing hardware.
var ErrInvalid = errors.New("attest: invalid attestation")

// Result is what verified evidence proves.
type Result struct {
	Trust offline.Trust
	Kind  string // android-tee | android-strongbox | ios-secure-enclave | sim-applet | software
	Note  string
}

// Verifier checks one attestation format.
type Verifier interface {
	Format() string
	Verify(att api.Attestation, challenge, publicKey []byte, alg offline.Alg, now time.Time) (Result, error)
}

// Registry dispatches on the attestation format.
type Registry struct{ byFormat map[string]Verifier }

// NewRegistry builds a registry from verifiers.
func NewRegistry(vs ...Verifier) *Registry {
	r := &Registry{byFormat: map[string]Verifier{}}
	for _, v := range vs {
		r.byFormat[v.Format()] = v
	}
	return r
}

// Verify checks evidence. Absent evidence ("none" or empty) yields software
// trust, never an error, so devices without secure hardware still register.
func (r *Registry) Verify(att api.Attestation, challenge, publicKey []byte, alg offline.Alg, now time.Time) (Result, error) {
	if att.Format == "" || att.Format == "none" {
		return Result{Trust: offline.TrustSoftware, Kind: "software", Note: "no hardware attestation supplied"}, nil
	}
	v, ok := r.byFormat[att.Format]
	if !ok {
		return Result{}, fmt.Errorf("%w: format %q is not configured on this server", ErrInvalid, att.Format)
	}
	return v.Verify(att, challenge, publicKey, alg, now)
}

// Formats lists configured formats.
func (r *Registry) Formats() []string {
	var out []string
	for f := range r.byFormat {
		out = append(out, f)
	}
	return out
}

// ---------------------------------------------------------------- helpers

func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("%w: empty certificate chain", ErrInvalid)
	}
	out := make([]*x509.Certificate, 0, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: certificate %d: %v", ErrInvalid, i, err)
		}
		out = append(out, c)
	}
	return out, nil
}

func verifyChain(certs []*x509.Certificate, roots *x509.CertPool, now time.Time) error {
	if roots == nil {
		return fmt.Errorf("%w: no trust roots configured", ErrInvalid)
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return fmt.Errorf("%w: chain does not lead to a trusted root: %v", ErrInvalid, err)
	}
	return nil
}

// leafKeyMatches checks that the attested key is the key being registered.
func leafKeyMatches(leaf *x509.Certificate, publicKey []byte, alg offline.Alg) error {
	switch k := leaf.PublicKey.(type) {
	case *ecdsa.PublicKey:
		b, err := k.Bytes()
		if err != nil || alg != offline.AlgP256 || !bytes.Equal(b, publicKey) {
			return fmt.Errorf("%w: attested key is not the registered key", ErrInvalid)
		}
	case ed25519.PublicKey:
		if alg != offline.AlgEd25519 || !bytes.Equal(k, publicKey) {
			return fmt.Errorf("%w: attested key is not the registered key", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: unsupported attested key type %T", ErrInvalid, leaf.PublicKey)
	}
	return nil
}

// PoolFromPEM builds a root pool from PEM bytes.
func PoolFromPEM(pem []byte) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(pem) {
		return nil, errors.New("attest: no certificates in PEM")
	}
	return p, nil
}
