package offline

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseINR(t *testing.T) {
	good := map[string]int64{"1": 100, "123": 12300, "123.4": 12340, "123.45": 12345, "0.01": 1, "0.5": 50,
		"10995116277.75": MaxAmountPaise}
	for in, want := range good {
		got, err := ParseINR(in)
		if err != nil || got != want {
			t.Errorf("ParseINR(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	bad := []string{"", "0", "0.00", "-1", "+1", " 1", "1 ", "1,234.00", "₹10", "1.234", "1.", ".5", "01",
		"1e3", "10995116277.76", "99999999999999999999", "12a", "0x10"}
	for _, in := range bad {
		if v, err := ParseINR(in); err == nil {
			t.Errorf("ParseINR(%q) = %d, want error", in, v)
		}
	}
}

func FuzzParseINR(f *testing.F) {
	for _, s := range []string{"1", "123.45", "0.01", "10995116277.75", "1,000", "-5", "1.999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseINR(s)
		if err != nil {
			return
		}
		if p <= 0 || p > MaxAmountPaise {
			t.Fatalf("ParseINR(%q) = %d out of range", s, p)
		}
		// Every accepted input round-trips through encoding.
		b := make([]byte, 5)
		if err := PutAmount(b, p); err != nil {
			t.Fatal(err)
		}
		if q, err := Amount(b); err != nil || q != p {
			t.Fatalf("round trip %d -> %d %v", p, q, err)
		}
		if again, err := ParseINR(FormatRupees(p)); err != nil || again != p {
			t.Fatalf("FormatRupees(%d)=%q does not parse back: %d %v", p, FormatRupees(p), again, err)
		}
	})
}

func TestAmountEncoding(t *testing.T) {
	b := make([]byte, 5)
	if err := PutAmount(b, 12345); err != nil || hex.EncodeToString(b) != "0000003039" {
		t.Fatalf("12345 -> %x %v", b, err)
	}
	if err := PutAmount(b, 0); err == nil {
		t.Fatal("zero accepted")
	}
	if err := PutAmount(b, MaxAmountPaise+1); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, err := Amount(make([]byte, 5)); err == nil {
		t.Fatal("zero decoded")
	}
}

type golden struct {
	Amounts []struct {
		Input string `json:"input"`
		Paise int64  `json:"paise"`
		Hex   string `json:"hex"`
	} `json:"amounts"`
	PayeeIDs []struct {
		Phone string `json:"phone"`
		ID    string `json:"id"`
	} `json:"payee_ids"`
	Records []struct {
		DeviceID    uint64 `json:"device_id"`
		Counter     uint32 `json:"counter"`
		AmountPaise int64  `json:"amount_paise"`
		PayeeID     uint64 `json:"payee_id"`
		Timestamp   uint32 `json:"timestamp"`
		Expiry      uint32 `json:"expiry"`
		PrevHash    string `json:"prev_hash"`
		SignedHex   string `json:"signed_hex"`
		HashZeroSig string `json:"hash_zero_sig"`
	} `json:"records"`
}

// TestPythonInterop checks Go against vectors written by testdata/golden.py.
func TestPythonInterop(t *testing.T) {
	raw, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var g golden
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	for _, a := range g.Amounts {
		p, err := ParseINR(a.Input)
		b := make([]byte, 5)
		_ = PutAmount(b, p)
		if err != nil || p != a.Paise || hex.EncodeToString(b) != a.Hex {
			t.Errorf("amount %q: go %d %x, python %d %s", a.Input, p, b, a.Paise, a.Hex)
		}
	}
	for _, p := range g.PayeeIDs {
		id, err := PayeeIDForPhone(p.Phone)
		if err != nil || FormatID(id) != p.ID {
			t.Errorf("payee id %s: go %016x, python %s", p.Phone, id, p.ID)
		}
	}
	for _, v := range g.Records {
		r := &Record{Version: RecordV1, DeviceID: v.DeviceID, Counter: v.Counter, AmountPaise: v.AmountPaise,
			PayeeID: v.PayeeID, Timestamp: v.Timestamp, Expiry: v.Expiry}
		ph, _ := hex.DecodeString(v.PrevHash)
		copy(r.PrevHash[:], ph)
		sb, err := r.SignedBytes()
		if err != nil || hex.EncodeToString(sb) != v.SignedHex {
			t.Fatalf("signed bytes differ:\n go %x\npy  %s", sb, v.SignedHex)
		}
		full, _ := r.Marshal()
		h := RecordHash(full)
		if hex.EncodeToString(h[:]) != v.HashZeroSig {
			t.Fatalf("record hash differs: %x vs %s", h, v.HashZeroSig)
		}
		back, err := ParseRecord(full)
		if err != nil || *back != *r {
			t.Fatalf("parse round trip: %+v %v", back, err)
		}
	}
}

func signRecord(t *testing.T, r *Record, sign func([]byte) []byte) []byte {
	t.Helper()
	sb, err := r.SignedBytes()
	if err != nil {
		t.Fatal(err)
	}
	copy(r.Signature[:], sign(SigningMessage(sb)))
	raw, _ := r.Marshal()
	return raw
}

func TestPaymentVerificationBothAlgorithmsAndTampering(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	caSign := func(m []byte) []byte { return ed25519.Sign(caPriv, m) }
	now := time.Unix(1793000000, 0)
	payee, _ := PayeeIDForPhone("9876543210")

	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p256Pub, _ := P256PublicKey(&p256.PublicKey)

	devices := []struct {
		alg  Alg
		pub  []byte
		sign func([]byte) []byte
	}{
		{AlgEd25519, edPub, func(m []byte) []byte { return ed25519.Sign(edPriv, m) }},
		{AlgP256, p256Pub, func(m []byte) []byte { s, _ := SignP256(p256, m); return s }},
	}
	for i, d := range devices {
		cert := &DeviceCert{Version: CertV1, DeviceID: uint64(100 + i), OwnerPayee: 7, Alg: d.alg,
			Trust: TrustHardwareKey, PerPaymentLimit: 50000, MaxReserve: 200000,
			IssuedAt: uint32(now.Unix()) - 10, ExpiresAt: uint32(now.Unix()) + 86400, PublicKey: d.pub}
		if err := cert.Sign(caSign); err != nil {
			t.Fatal(err)
		}
		certRaw, _ := cert.Marshal()
		r := &Record{Version: RecordV1, DeviceID: cert.DeviceID, Counter: 1, AmountPaise: 12345, PayeeID: payee,
			Timestamp: uint32(now.Unix()), Expiry: uint32(now.Unix()) + 3600}
		raw := signRecord(t, r, d.sign)

		qr := EncodePaymentQR(raw, certRaw)
		gotRec, gotCert, err := DecodePaymentQR(qr)
		if err != nil || !bytes.Equal(gotRec, raw) || !bytes.Equal(gotCert, certRaw) {
			t.Fatalf("%s: QR round trip failed: %v", d.alg, err)
		}
		if _, _, err := VerifyPayment(raw, certRaw, caPub, payee, now); err != nil {
			t.Fatalf("%s: valid payment rejected: %v", d.alg, err)
		}
		// Every single-byte change in the signed part is caught.
		for i := 0; i < SignedSize; i++ {
			bad := bytes.Clone(raw)
			bad[i] ^= 0x01
			if _, _, err := VerifyPayment(bad, certRaw, caPub, payee, now); err == nil {
				t.Fatalf("%s: byte %d flipped and still accepted", d.alg, i)
			}
		}
		if _, _, err := VerifyPayment(raw, certRaw, caPub, payee+1, now); !errors.Is(err, ErrPayment) {
			t.Fatalf("%s: wrong payee accepted", d.alg)
		}
		if _, _, err := VerifyPayment(raw, certRaw, caPub, payee, now.Add(2*time.Hour)); err == nil {
			t.Fatalf("%s: expired payment accepted", d.alg)
		}
		otherCA, _, _ := ed25519.GenerateKey(rand.Reader)
		if _, _, err := VerifyPayment(raw, certRaw, otherCA, payee, now); err == nil {
			t.Fatalf("%s: certificate from another CA accepted", d.alg)
		}
	}
}

func TestReserveAndDirectory(t *testing.T) {
	caPub, caPriv, _ := ed25519.GenerateKey(rand.Reader)
	sign := func(m []byte) []byte { return ed25519.Sign(caPriv, m) }
	r := &Reserve{Version: ReserveV1, ReserveID: 9, DeviceID: 5, AmountPaise: 200000, CounterStart: 1,
		PerPaymentLimit: 50000, Expiry: 1795592000, IssuedAt: 1793000000}
	if err := r.Sign(sign); err != nil {
		t.Fatal(err)
	}
	raw, _ := r.Marshal()
	if len(raw) != ReserveSize {
		t.Fatalf("reserve size %d", len(raw))
	}
	back, err := ParseReserve(raw)
	if err != nil || back.Verify(caPub) != nil || *back != *r {
		t.Fatalf("reserve round trip: %v", err)
	}
	raw[20] ^= 1
	if tampered, err := ParseReserve(raw); err == nil && tampered.Verify(caPub) == nil {
		t.Fatal("tampered reserve verified")
	}

	d := &Directory{Version: 3, Entries: []DirectoryEntry{{PayeeID: "00000000000000aa", Phone: "+919876543210", Name: "Lakshmi Stores"}},
		Revoked: []string{FormatID(42)}}
	sd, err := SignDirectory(d, sign)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sd.Open(caPub)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := opened.Lookup("98765 43210"); !ok || e.Name != "Lakshmi Stores" {
		t.Fatal("directory lookup failed")
	}
	if !opened.IsRevoked(42) || opened.IsRevoked(43) {
		t.Fatal("revocation list wrong")
	}
	sd.Payload = []byte(strings.Replace(string(sd.Payload), "Lakshmi", "Mallory", 1))
	if _, err := sd.Open(caPub); err == nil {
		t.Fatal("tampered directory opened")
	}
}

func TestPhoneAndPayeeCards(t *testing.T) {
	for in, want := range map[string]string{"9876543210": "+919876543210", "+91 98765-43210": "+919876543210",
		"919876543210": "+919876543210", "+14155550100": "+14155550100"} {
		if got, err := NormalizePhone(in); err != nil || got != want {
			t.Errorf("NormalizePhone(%q) = %q %v", in, got, err)
		}
	}
	for _, in := range []string{"12345", "abc", "0876543210", "+1"} {
		if _, err := NormalizePhone(in); err == nil {
			t.Errorf("NormalizePhone(%q) accepted", in)
		}
	}
	qr, _ := EncodePayeeQR("9876543210", "Ravi: Tea Stall")
	c, err := DecodePayeeQR(qr)
	if err != nil || c.Phone != "+919876543210" || c.Name != "Ravi: Tea Stall" {
		t.Fatalf("payee card: %+v %v", c, err)
	}
}

func TestECDSADERToRaw(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub, _ := P256PublicKey(&k.PublicKey)
	msg := []byte("hello")
	der, _ := ecdsa.SignASN1(rand.Reader, k, sha256Sum(msg))
	raw, err := ECDSADERToRaw(der)
	if err != nil || VerifySignature(AlgP256, pub, msg, raw) != nil {
		t.Fatalf("DER conversion: %v", err)
	}
}
