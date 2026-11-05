package wallet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"pstcopay/sdk/client"
	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
	"pstcopay/sdk/rasp"
)

// Delivery methods.
const (
	DeliverQR  = "qr"  // QR code or NFC: payee verifies on the spot, no signal needed
	DeliverSMS = "sms" // queued SMS to the payee's mobile number
)

// Config configures a Wallet.
type Config struct {
	Dir     string         // where the local store lives (the element may share it)
	Element Element        // secure element
	Client  *client.Client // offline API client; nil for offline-only use
	Guard   rasp.Guard     // runtime protection; nil uses rasp.New(rasp.Config{})
	// BlockOnCritical refuses Unlock and Pay on a critical RASP finding (default true).
	AllowCompromised bool
	KDF              KDF
	Now              func() time.Time
	Model            string // device model, reported at registration
	AppVersion       string
	// ServerShortCode is the SMS number that receives records for sync over GSM.
	ServerShortCode string
	// ApprovalTTL is how long an approval stays valid (default 60 s).
	ApprovalTTL time.Duration
	// Biometric, when set, lets Approve accept an empty PIN after the host
	// app's own biometric prompt succeeds for the intent.
	Biometric func(Intent) error
}

// Wallet is the device-side SDK entry point.
type Wallet struct {
	cfg   Config
	el    Element
	guard rasp.Guard
	now   func() time.Time

	mu         sync.Mutex
	store      *localStore
	regToken   string
	approvals  map[[32]byte]pendingApproval
	violations int
	pinFails   int
}

// New creates a wallet. Call Unlock before anything else.
func New(cfg Config) (*Wallet, error) {
	if cfg.Element == nil {
		return nil, errors.New("wallet: Config.Element is required")
	}
	if cfg.Dir == "" {
		return nil, errors.New("wallet: Config.Dir is required")
	}
	if cfg.Guard == nil {
		cfg.Guard = rasp.New(rasp.Config{})
	}
	if cfg.KDF == (KDF{}) {
		cfg.KDF = DefaultKDF
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Wallet{cfg: cfg, el: cfg.Element, guard: cfg.Guard, now: cfg.Now}, nil
}

// Element returns the wallet's secure element.
func (w *Wallet) Element() Element { return w.el }

func (w *Wallet) protect() error {
	if w.cfg.AllowCompromised {
		return nil
	}
	if r := w.guard.Check(); r.Critical() {
		return fmt.Errorf("%w: %v", ErrCompromised, r.Findings)
	}
	return nil
}

// Unlock opens the element and the local store with the PIN.
func (w *Wallet) Unlock(pin string) error {
	if err := w.protect(); err != nil {
		return err
	}
	if err := w.el.Unlock(pin); err != nil {
		return err
	}
	s, err := openLocalStore(w.cfg.Dir, pin, w.cfg.KDF)
	if err != nil {
		w.el.Lock()
		return err
	}
	w.mu.Lock()
	w.store = s
	w.mu.Unlock()
	return nil
}

// Lock wipes keys and pending approvals from memory.
func (w *Wallet) Lock() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.lockLocked()
}

func (w *Wallet) data() (*localData, error) {
	if w.store == nil {
		return nil, ErrLocked
	}
	return w.store.data, nil
}

func (w *Wallet) api() (*client.Client, error) {
	if w.cfg.Client == nil {
		return nil, errors.New("wallet: no server client configured")
	}
	return w.cfg.Client, nil
}

func (w *Wallet) deviceAPI(d *localData) (*client.Client, error) {
	c, err := w.api()
	if err != nil {
		return nil, err
	}
	if d.DeviceID == 0 {
		return nil, ErrNotProvisioned
	}
	return c.WithDevice(d.DeviceID, w.el), nil
}

// ------------------------------------------------------------ onboarding

// StartAccount asks the server to send an OTP to phone. listed puts the
// account in the payee directory (shops). It returns the OTP only when the
// server runs in development mode.
func (w *Wallet) StartAccount(ctx context.Context, phone, name string, listed bool) (string, error) {
	c, err := w.api()
	if err != nil {
		return "", err
	}
	r, err := c.StartAccount(ctx, api.AccountStartRequest{Phone: phone, Name: name, Listed: listed})
	if err != nil {
		return "", err
	}
	return r.DevOTP, nil
}

// VerifyAccount confirms the OTP.
func (w *Wallet) VerifyAccount(ctx context.Context, phone, otp string) error {
	c, err := w.api()
	if err != nil {
		return err
	}
	r, err := c.VerifyAccount(ctx, api.AccountVerifyRequest{Phone: phone, OTP: otp})
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return err
	}
	p, _ := offline.NormalizePhone(phone)
	payee, _ := offline.ParseID(r.PayeeID)
	d.AccountID, d.Phone, d.PayeeID = r.AccountID, p, payee
	w.regToken = r.RegistrationToken
	return w.store.save()
}

// Register registers this device's key, with hardware attestation when the
// element has secure hardware and software trust otherwise.
func (w *Wallet) Register(ctx context.Context) (*api.RegisterResponse, error) {
	c, err := w.api()
	if err != nil {
		return nil, err
	}
	if w.regToken == "" {
		return nil, errors.New("wallet: verify the account first")
	}
	ch, err := c.Challenge(ctx, w.regToken)
	if err != nil {
		return nil, err
	}
	// Attest first: Android Keystore binds the challenge at key generation,
	// so the key may be (re)created by Attest, and the public key sent must
	// be the attested one.
	att, err := w.el.Attest(ch.Challenge)
	if err != nil {
		return nil, fmt.Errorf("wallet: attestation: %w", err)
	}
	pub, err := w.el.PublicKey()
	if err != nil {
		return nil, err
	}
	proof, err := w.el.SignAuth(api.RegisterMessage(ch.Challenge, w.regToken, pub))
	if err != nil {
		return nil, err
	}
	info := w.el.Info()
	resp, err := c.Register(ctx, api.RegisterRequest{
		RegistrationToken: w.regToken, Challenge: ch.Challenge, Algorithm: info.Alg.String(), ElementKind: info.Kind,
		PublicKey: pub, Proof: proof, Attestation: att, RASP: w.guard.Check().Findings,
		Model: w.cfg.Model, AppVersion: w.cfg.AppVersion,
	})
	if err != nil {
		return nil, err
	}
	if err := w.el.Provision(resp.Certificate, resp.CAPublicKey); err != nil {
		return nil, fmt.Errorf("wallet: provisioning: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil, err
	}
	dev, _ := offline.ParseID(resp.DeviceID)
	payee, _ := offline.ParseID(resp.PayeeID)
	d.DeviceID, d.AccountID, d.PayeeID = dev, resp.AccountID, payee
	d.Cert, d.CAPublicKey, d.Trust, d.TrustNote, d.Limits = resp.Certificate, resp.CAPublicKey, resp.Trust, resp.TrustNote, resp.Limits
	d.ReceiptKey = resp.ReceiptKey
	w.regToken = ""
	return resp, w.store.save()
}

// ------------------------------------------------------------ online money

// Deposit funds the online wallet (simulated bank top-up in development).
func (w *Wallet) Deposit(ctx context.Context, amountPaise int64, approval *Approval) (*api.WalletResponse, error) {
	w.mu.Lock()
	d, err := w.data()
	if err == nil {
		err = w.consumeLocked(approval, Intent{Op: OpDeposit, AmountPaise: amountPaise})
	}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c, err := w.deviceAPI(d)
	if err != nil {
		return nil, err
	}
	return c.Deposit(ctx, amountPaise, client.NewIdempotencyKey())
}

// OnlineWallet returns the server-side balances.
func (w *Wallet) OnlineWallet(ctx context.Context) (*api.WalletResponse, error) {
	w.mu.Lock()
	d, err := w.data()
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	c, err := w.deviceAPI(d)
	if err != nil {
		return nil, err
	}
	return c.Wallet(ctx)
}

// CreateReserve moves money from the online wallet into the offline balance.
// It syncs first, because the server only issues a reserve once it holds
// every record the device has signed. A lost response is retried safely with
// the same idempotency key.
func (w *Wallet) CreateReserve(ctx context.Context, amountPaise int64, approval *Approval) (*api.ReserveResponse, error) {
	w.mu.Lock()
	if _, err := w.data(); err != nil {
		w.mu.Unlock()
		return nil, err
	}
	if err := w.consumeLocked(approval, Intent{Op: OpReserve, AmountPaise: amountPaise}); err != nil {
		w.mu.Unlock()
		return nil, err
	}
	w.mu.Unlock()
	if _, err := w.Sync(ctx); err != nil {
		return nil, fmt.Errorf("wallet: sync before reserve: %w", err)
	}
	w.mu.Lock()
	d, err := w.data()
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	if d.PendingRsvKey == "" || d.PendingRsvAmt != amountPaise {
		d.PendingRsvKey, d.PendingRsvAmt = client.NewIdempotencyKey(), amountPaise
		if err := w.store.save(); err != nil {
			w.mu.Unlock()
			return nil, err
		}
	}
	key := d.PendingRsvKey
	w.mu.Unlock()

	st, err := w.el.State()
	if err != nil {
		return nil, err
	}
	c, err := w.deviceAPI(d)
	if err != nil {
		return nil, err
	}
	resp, err := c.CreateReserve(ctx, api.ReserveRequest{AmountPaise: amountPaise, NextCounter: st.NextCounter,
		ChainHead: st.ChainHead[:]}, key)
	if err != nil {
		return nil, err
	}
	if err := w.el.LoadReserve(resp.Instruction); err != nil {
		return nil, fmt.Errorf("wallet: load reserve: %w", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d.PendingRsvKey, d.PendingRsvAmt = "", 0
	return resp, w.store.save()
}

// ------------------------------------------------------------ paying

// Quote resolves a phone number to a payee, with the listed name when the
// saved directory knows it. Show Name to the user before paying; Listed false
// means the number is not a known shop.
type Quote struct {
	PayeeID uint64
	Phone   string
	Name    string
	Listed  bool
}

// QuotePhone resolves a mobile number offline.
func (w *Wallet) QuotePhone(phone string) (*Quote, error) {
	p, err := offline.NormalizePhone(phone)
	if err != nil {
		return nil, err
	}
	id, _ := offline.PayeeIDForPhone(p)
	q := &Quote{PayeeID: id, Phone: p}
	w.mu.Lock()
	defer w.mu.Unlock()
	if dir := w.directoryLocked(); dir != nil {
		if e, ok := dir.Lookup(p); ok {
			q.Name, q.Listed = e.Name, true
		}
	}
	return q, nil
}

func (w *Wallet) directoryLocked() *offline.Directory {
	d, err := w.data()
	if err != nil || d.Directory == nil {
		return nil
	}
	dir, err := d.Directory.Open(d.CAPublicKey)
	if err != nil {
		return nil
	}
	return dir
}

// Payment is a signed offline payment ready to hand to the payee.
type Payment struct {
	Counter     uint32
	AmountPaise int64
	PayeeID     uint64
	Record      []byte
	// QR is the payload to show as a QR code or send over NFC.
	QR string
	// SMS is set when delivery is by SMS; the host app sends it.
	SMS *OutgoingSMS
}

// Pay signs an offline payment to a quoted payee. It needs no signal: the
// balance is deducted in the element at once.
func (w *Wallet) Pay(q *Quote, amountPaise int64, delivery string, approval *Approval) (*Payment, error) {
	if err := w.protect(); err != nil {
		return nil, err
	}
	if delivery != DeliverQR && delivery != DeliverSMS {
		return nil, fmt.Errorf("wallet: unknown delivery %q", delivery)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil, err
	}
	if d.DeviceID == 0 {
		return nil, ErrNotProvisioned
	}
	if q.PayeeID == d.PayeeID {
		return nil, errors.New("wallet: cannot pay yourself")
	}
	if delivery == DeliverSMS && q.Phone == "" {
		return nil, errors.New("wallet: SMS delivery needs the payee's phone number")
	}
	if err := w.consumeLocked(approval, Intent{Op: OpPay, AmountPaise: amountPaise, PayeeID: q.PayeeID}); err != nil {
		return nil, err
	}
	now := w.now()
	raw, err := w.el.Pay(q.PayeeID, amountPaise, now)
	if err != nil {
		return nil, err
	}
	rec, _ := offline.ParseRecord(raw)
	sp := &SentPayment{Counter: rec.Counter, Raw: raw, PayeeID: q.PayeeID, PayeePhone: q.Phone, PayeeName: q.Name,
		AmountPaise: amountPaise, Delivery: delivery, CreatedAt: now}
	d.Sent = append(d.Sent, sp)
	p := &Payment{Counter: rec.Counter, AmountPaise: amountPaise, PayeeID: q.PayeeID, Record: raw,
		QR: offline.EncodePaymentQR(raw, d.Cert)}
	if delivery == DeliverSMS {
		m := &OutgoingSMS{ID: newID(), To: q.Phone, Payload: append(append([]byte(nil), raw...), d.Cert...),
			Purpose: "payee", Counter: rec.Counter, QueuedAt: now}
		d.Outbox = append(d.Outbox, m)
		p.SMS = m
	}
	// The element already holds the deduction; a failure here only loses
	// the local copy, which Sync's counter check would surface.
	if err := w.store.save(); err != nil {
		return p, fmt.Errorf("wallet: payment signed but local history not saved: %w", err)
	}
	return p, nil
}

// PayPhone quotes and pays a mobile number in one call.
func (w *Wallet) PayPhone(phone string, amountPaise int64, delivery string, approval *Approval) (*Payment, error) {
	q, err := w.QuotePhone(phone)
	if err != nil {
		return nil, err
	}
	return w.Pay(q, amountPaise, delivery, approval)
}

// PayCard pays a payee whose QR card was scanned.
func (w *Wallet) PayCard(qr string, amountPaise int64, approval *Approval) (*Payment, error) {
	c, err := offline.DecodePayeeQR(qr)
	if err != nil {
		return nil, err
	}
	q, err := w.QuotePhone(c.Phone)
	if err != nil {
		return nil, err
	}
	if q.Name == "" {
		q.Name = c.Name
	}
	return w.Pay(q, amountPaise, DeliverQR, approval)
}

// PayeeQR returns this account's card for others to scan.
func (w *Wallet) PayeeQR() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return "", err
	}
	if d.Phone == "" {
		return "", errors.New("wallet: account not verified")
	}
	return offline.EncodePayeeQR(d.Phone, d.Name)
}

// SetDisplayName sets the name shown on this account's payee card.
func (w *Wallet) SetDisplayName(name string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return err
	}
	d.Name = name
	return w.store.save()
}

// ------------------------------------------------------------ receiving

// Accept verifies a payment received by QR, NFC or SMS with no signal and
// stores it for sync. It rejects forged, expired, revoked, misaddressed and
// repeated payments.
func (w *Wallet) Accept(payload string) (*ReceivedPayment, error) {
	record, cert, err := offline.DecodePaymentQR(payload)
	if err != nil {
		return nil, err
	}
	return w.AcceptBytes(append(record, cert...))
}

// AcceptBytes accepts a binary payment (record followed by certificate), the
// form delivered by SMS.
func (w *Wallet) AcceptBytes(b []byte) (*ReceivedPayment, error) {
	if len(b) <= offline.RecordSize {
		return nil, offline.ErrPayment
	}
	record, cert := b[:offline.RecordSize], b[offline.RecordSize:]
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil, err
	}
	if d.PayeeID == 0 {
		return nil, errors.New("wallet: account not verified")
	}
	r, c, err := offline.VerifyPayment(record, cert, d.CAPublicKey, d.PayeeID, w.now())
	if err != nil {
		return nil, err
	}
	if dir := w.directoryLocked(); dir != nil && dir.IsRevoked(r.DeviceID) {
		return nil, fmt.Errorf("%w: payer device is revoked", offline.ErrPayment)
	}
	for _, got := range d.Received {
		if got.DeviceID == r.DeviceID && got.Counter == r.Counter {
			return nil, fmt.Errorf("%w: payment already received", offline.ErrPayment)
		}
	}
	rp := &ReceivedPayment{DeviceID: r.DeviceID, Counter: r.Counter, Raw: record, Cert: cert,
		AmountPaise: r.AmountPaise, PayerPayee: c.OwnerPayee, ReceivedAt: w.now()}
	d.Received = append(d.Received, rp)
	return rp, w.store.save()
}

// ------------------------------------------------------------ SMS queue

// PendingSMS returns messages waiting for signal.
func (w *Wallet) PendingSMS() []OutgoingSMS {
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil
	}
	var out []OutgoingSMS
	for _, m := range d.Outbox {
		if !m.Sent {
			out = append(out, *m)
		}
	}
	return out
}

// MarkSMSSent confirms the host app sent a message; failed attempts are
// recorded with sent=false so the app can back off.
func (w *Wallet) MarkSMSSent(id string, sent bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return err
	}
	for _, m := range d.Outbox {
		if m.ID == id {
			m.Attempts++
			m.Sent = sent
			return w.store.save()
		}
	}
	return fmt.Errorf("wallet: no queued SMS %s", id)
}

// QueueServerSMS queues every unsynced record for sync over GSM to the
// server's short code (one 114-byte record per binary SMS).
func (w *Wallet) QueueServerSMS() (int, error) {
	if w.cfg.ServerShortCode == "" {
		return 0, errors.New("wallet: no server short code configured")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return 0, err
	}
	queued := map[uint32]bool{}
	for _, m := range d.Outbox {
		if m.Purpose == "server" {
			queued[m.Counter] = true
		}
	}
	n := 0
	for _, s := range d.Sent {
		if !s.Synced && !queued[s.Counter] {
			d.Outbox = append(d.Outbox, &OutgoingSMS{ID: newID(), To: w.cfg.ServerShortCode, Payload: s.Raw,
				Purpose: "server", Counter: s.Counter, QueuedAt: w.now()})
			n++
		}
	}
	return n, w.store.save()
}

// ------------------------------------------------------------ sync

// SyncReport summarises one sync.
type SyncReport struct {
	Uploaded  int
	Accepted  int
	Duplicate int
	Rejected  int
	// BadReceipts counts results whose server receipt did not verify; those
	// payments stay unsynced and are uploaded again next time.
	BadReceipts int
	Results     []api.SyncResult
}

// Sync uploads this device's unsynced payments and the payments it received,
// then refreshes the payee directory and revocation list.
func (w *Wallet) Sync(ctx context.Context) (*SyncReport, error) {
	w.mu.Lock()
	d, err := w.data()
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	c, err := w.deviceAPI(d)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	var records [][]byte
	for _, s := range d.Sent {
		if !s.Synced {
			records = append(records, s.Raw)
		}
	}
	for _, r := range d.Received {
		if !r.Synced {
			records = append(records, r.Raw)
		}
	}
	w.mu.Unlock()

	rep := &SyncReport{Uploaded: len(records)}
	if len(records) > 0 {
		resp, err := c.Sync(ctx, api.SyncRequest{Records: records, RASP: w.guard.Check().Findings})
		if err != nil {
			return nil, err
		}
		rep.Results = resp.Results
		w.mu.Lock()
		for _, res := range resp.Results {
			dev, _ := offline.ParseID(res.DeviceID)
			switch res.Status {
			case api.StatusAccepted, api.StatusSettled:
				rep.Accepted++
			case api.StatusDuplicate:
				rep.Duplicate++
			default:
				rep.Rejected++
			}
			// An accepted or duplicate result counts only with a valid
			// server receipt for these exact bytes.
			proven := func(raw []byte) bool {
				if res.Status != api.StatusAccepted && res.Status != api.StatusDuplicate {
					return true
				}
				if len(d.ReceiptKey) == 0 {
					return true
				}
				if _, err := offline.VerifyReceipt(res.Receipt, raw, d.ReceiptKey); err != nil {
					rep.BadReceipts++
					return false
				}
				return true
			}
			for _, s := range d.Sent {
				if dev == d.DeviceID && s.Counter == res.Counter && proven(s.Raw) {
					s.Synced, s.Status, s.Reason, s.Receipt = true, res.Status, res.Reason, res.Receipt
				}
			}
			for _, r := range d.Received {
				if r.DeviceID == dev && r.Counter == res.Counter && proven(r.Raw) {
					r.Synced, r.Status, r.Reason, r.Receipt = true, res.Status, res.Reason, res.Receipt
				}
			}
		}
		w.mu.Unlock()
	}
	dirResp, err := c.Directory(ctx)
	w.mu.Lock()
	defer w.mu.Unlock()
	if err == nil {
		sd := &offline.SignedDirectory{Payload: dirResp.Payload, Signature: dirResp.Signature}
		if nd, verr := sd.Open(d.CAPublicKey); verr == nil {
			// Never go back to an older directory: that would roll back the
			// revocation list and re-trust revoked devices.
			if cur := w.directoryLocked(); cur == nil || nd.Version >= cur.Version {
				d.Directory = sd
			}
		}
	}
	d.LastSync = w.now()
	return rep, w.store.save()
}

// ------------------------------------------------------------ status

// Balance is the device's local view.
type Balance struct {
	OfflinePaise     int64
	PerPaymentLimit  int64
	ReserveExpiresAt time.Time
	NextCounter      uint32
	UnsyncedSent     int
	UnsyncedReceived int
	ReceivedPaise    int64
	Trust            string
	DeviceID         uint64
	PayeeID          uint64
}

// Balance returns the local balance and sync backlog.
func (w *Wallet) Balance() (*Balance, error) {
	st, err := w.el.State()
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil, err
	}
	b := &Balance{OfflinePaise: st.BalancePaise, PerPaymentLimit: st.PerPaymentLimit, NextCounter: st.NextCounter,
		Trust: d.Trust, DeviceID: d.DeviceID, PayeeID: d.PayeeID}
	if st.Expiry != 0 {
		b.ReserveExpiresAt = time.Unix(int64(st.Expiry), 0)
	}
	for _, s := range d.Sent {
		if !s.Synced {
			b.UnsyncedSent++
		}
	}
	for _, r := range d.Received {
		b.ReceivedPaise += r.AmountPaise
		if !r.Synced {
			b.UnsyncedReceived++
		}
	}
	return b, nil
}

// History returns copies of sent and received payments.
func (w *Wallet) History() (sent []SentPayment, received []ReceivedPayment, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	d, err := w.data()
	if err != nil {
		return nil, nil, err
	}
	for _, s := range d.Sent {
		sent = append(sent, *s)
	}
	for _, r := range d.Received {
		received = append(received, *r)
	}
	return sent, received, nil
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
