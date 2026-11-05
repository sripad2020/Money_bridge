// Package emulator provides software stand-ins for secure hardware so apps
// and servers can be tested without real devices: an Android Keystore
// (StrongBox or TEE) with key attestation, an iOS Secure Enclave with App
// Attest, and a SIM applet element. Their attestations chain to a test Root
// that the server must be configured to trust.
//
// Emulators are for development and tests only. They prove nothing about
// real hardware.
package emulator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"

	"pstcopay/sdk/attest"
	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// Root is a test attestation root CA.
type Root struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	PEM  []byte
}

// NewRoot creates a self-signed test root.
func NewRoot(name string) (*Root, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, _ := x509.ParseCertificate(der)
	return &Root{Cert: c, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// Pool returns a pool holding the root.
func (r *Root) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(r.Cert)
	return p
}

func (r *Root) issue(pub any, exts []pkix.Extension) ([]byte, error) {
	tmpl := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "attested key"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: exts}
	return x509.CreateCertificate(rand.Reader, tmpl, r.Cert, pub, r.Key)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

// hwSealer simulates a non-exportable hardware AES key.
type hwSealer struct{ key []byte }

func newSealer() hwSealer {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	return hwSealer{key: k}
}

func (s hwSealer) Seal(p []byte) ([]byte, error) {
	b, _ := aes.NewCipher(s.key)
	g, _ := cipher.NewGCM(b)
	n := make([]byte, g.NonceSize())
	_, _ = rand.Read(n)
	return g.Seal(n, n, p, nil), nil
}

func (s hwSealer) Unseal(c []byte) ([]byte, error) {
	b, _ := aes.NewCipher(s.key)
	g, _ := cipher.NewGCM(b)
	if len(c) < g.NonceSize() {
		return nil, errors.New("emulator: bad ciphertext")
	}
	return g.Open(nil, c[:g.NonceSize()], c[g.NonceSize():], nil)
}

// ---------------------------------------------------------------- Android

// AndroidKeyStore emulates an Android Keystore P-256 key with key attestation.
type AndroidKeyStore struct {
	hwSealer
	root  *Root
	key   *ecdsa.PrivateKey
	level int
}

// NewAndroidKeyStore creates a key at a security level (attest.AndroidStrongBox or attest.AndroidTEE).
func NewAndroidKeyStore(root *Root, level int) (*AndroidKeyStore, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AndroidKeyStore{hwSealer: newSealer(), root: root, key: k, level: level}, nil
}

func (a *AndroidKeyStore) Kind() string {
	if a.level == attest.AndroidStrongBox {
		return "android-strongbox"
	}
	return "android-tee"
}
func (a *AndroidKeyStore) Alg() offline.Alg              { return offline.AlgP256 }
func (a *AndroidKeyStore) PublicKey() ([]byte, error)    { return a.key.PublicKey.Bytes() }
func (a *AndroidKeyStore) Sign(m []byte) ([]byte, error) { return offline.SignP256(a.key, m) }

// Attest returns a key attestation chain whose leaf carries the challenge.
func (a *AndroidKeyStore) Attest(challenge []byte) (api.Attestation, error) {
	empty := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	kd, err := asn1.Marshal(attest.KeyDescription{AttestationVersion: 200, AttestationSecurityLevel: asn1.Enumerated(a.level),
		KeyMintVersion: 200, KeyMintSecurityLevel: asn1.Enumerated(a.level), AttestationChallenge: challenge,
		UniqueID: []byte{}, SoftwareEnforced: empty, HardwareEnforced: empty})
	if err != nil {
		return api.Attestation{}, err
	}
	der, err := a.root.issue(&a.key.PublicKey, []pkix.Extension{{Id: attest.OIDAndroidKeyDescription, Value: kd}})
	if err != nil {
		return api.Attestation{}, err
	}
	return api.Attestation{Format: "android-key", Chain: [][]byte{der}}, nil
}

// ------------------------------------------------------------------ Apple

// AppleKeyStore emulates the real iOS pattern: a Secure Enclave P-256 key
// signs payments, and a separate App Attest key attests the app instance and
// vouches for the Secure Enclave key with an assertion.
type AppleKeyStore struct {
	hwSealer
	root  *Root
	key   *ecdsa.PrivateKey // Secure Enclave signing key
	aa    *ecdsa.PrivateKey // App Attest key (DCAppAttestService)
	appID string
}

// NewAppleKeyStore creates the keys for appID ("<team>.<bundle>").
func NewAppleKeyStore(root *Root, appID string) (*AppleKeyStore, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	aa, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &AppleKeyStore{hwSealer: newSealer(), root: root, key: k, aa: aa, appID: appID}, nil
}

func (a *AppleKeyStore) Kind() string                  { return "ios-secure-enclave" }
func (a *AppleKeyStore) Alg() offline.Alg              { return offline.AlgP256 }
func (a *AppleKeyStore) PublicKey() ([]byte, error)    { return a.key.PublicKey.Bytes() }
func (a *AppleKeyStore) Sign(m []byte) ([]byte, error) { return offline.SignP256(a.key, m) }

// Attest returns the App Attest attestation of the App Attest key plus an
// assertion over challenge || Secure Enclave public key.
func (a *AppleKeyStore) Attest(challenge []byte) (api.Attestation, error) {
	aaPub, _ := a.aa.PublicKey.Bytes()
	sePub, _ := a.key.PublicKey.Bytes()
	rp := sha256.Sum256([]byte(a.appID))
	keyID := sha256.Sum256(aaPub)
	ad := append([]byte(nil), rp[:]...)
	ad = append(ad, 0x40)
	ad = binary.BigEndian.AppendUint32(ad, 0)
	ad = append(ad, []byte("appattest\x00\x00\x00\x00\x00\x00\x00")...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(keyID)))
	ad = append(ad, keyID[:]...)
	cdh := sha256.Sum256(challenge)
	nonce := sha256.Sum256(append(append([]byte(nil), ad...), cdh[:]...))
	ext, err := asn1.Marshal(attest.AppleNonce{Nonce: nonce[:]})
	if err != nil {
		return api.Attestation{}, err
	}
	der, err := a.root.issue(&a.aa.PublicKey, []pkix.Extension{{Id: attest.OIDAppleNonce, Value: ext}})
	if err != nil {
		return api.Attestation{}, err
	}
	obj := attest.AppleAttestationObject{Fmt: "apple-appattest", AuthData: ad}
	obj.AttStmt.X5C = [][]byte{der}
	obj.AttStmt.Receipt = []byte{}
	b, err := cbor.Marshal(obj)
	if err != nil {
		return api.Attestation{}, err
	}
	// Assertion: authenticatorData = rpIdHash || flags || counter(1).
	asAD := append(append([]byte(nil), rp[:]...), 0x00)
	asAD = binary.BigEndian.AppendUint32(asAD, 1)
	clientHash := sha256.Sum256(append(append([]byte(nil), challenge...), sePub...))
	digest := sha256.Sum256(append(append([]byte(nil), asAD...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.aa, digest[:])
	if err != nil {
		return api.Attestation{}, err
	}
	as, err := cbor.Marshal(attest.AppleAssertion{Signature: sig, AuthenticatorData: asAD})
	if err != nil {
		return api.Attestation{}, err
	}
	return api.Attestation{Format: "apple-appattest", Object: b, Assertion: as}, nil
}
