// Package client is the Go client for the PSTCO-Pay offline HTTP API. It
// signs device requests with the secure element and uses one persistent
// HTTP/2 connection over TLS 1.3.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pstcopay/sdk/offline"
	"pstcopay/sdk/offline/api"
)

// Signer signs API authentication messages (a wallet Element).
type Signer interface {
	SignAuth(msg []byte) ([]byte, error)
}

// Error is a non-2xx API response.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("pstco api %d %s: %s", e.Status, e.Code, e.Message)
}

// IsCode reports whether err is an API error with the given code.
func IsCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Client calls the offline API.
type Client struct {
	base     string
	hc       *http.Client
	deviceID uint64
	signer   Signer
	now      func() time.Time
}

// New creates a client for baseURL (e.g. https://pay.example.com:8444).
// hc may be nil for the default TLS 1.3 client.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = NewHTTPClient(nil)
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), hc: hc, now: time.Now}
}

// NewHTTPClient returns an HTTP/2 client restricted to TLS 1.3. caPEM pins a
// private CA (nil uses the system roots).
func NewHTTPClient(caPEM []byte) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13}
	if caPEM != nil {
		p := x509.NewCertPool()
		p.AppendCertsFromPEM(caPEM)
		cfg.RootCAs = p
	}
	tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 5 * time.Minute, TLSHandshakeTimeout: 10 * time.Second}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// WithDevice returns a copy that authenticates as a registered device.
func (c *Client) WithDevice(deviceID uint64, s Signer) *Client {
	cp := *c
	cp.deviceID, cp.signer = deviceID, s
	return &cp
}

// SetClock replaces the clock used for request timestamps (tests).
func (c *Client) SetClock(now func() time.Time) { c.now = now }

// NewIdempotencyKey returns a random key for retry-safe requests.
func NewIdempotencyKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any, signed bool, idem string) error {
	return c.doNonce(ctx, method, path, in, out, signed, idem, "")
}

// doMoney performs a money-moving request: it first obtains an unpredictable
// single-use server nonce for the purpose and signs the request with it.
func (c *Client) doMoney(ctx context.Context, purpose, path string, in, out any, idem string) error {
	n, err := c.AuthNonce(ctx, purpose)
	if err != nil {
		return err
	}
	return c.doNonce(ctx, http.MethodPost, path, in, out, true, idem, n.Nonce)
}

// AuthNonce asks the server for a single-use nonce bound to this device and purpose.
func (c *Client) AuthNonce(ctx context.Context, purpose string) (*api.AuthNonceResponse, error) {
	out := new(api.AuthNonceResponse)
	return out, c.do(ctx, http.MethodPost, api.PathAuthNonce, &api.AuthNonceRequest{Purpose: purpose}, out, true, "")
}

func (c *Client) doNonce(ctx context.Context, method, path string, in, out any, signed bool, idem, serverNonce string) error {
	var body []byte
	if in != nil {
		// Checkpoint before sending: the same value rules the server enforces.
		if c, ok := in.(interface{ Check() error }); ok {
			if err := c.Check(); err != nil {
				return fmt.Errorf("client: request rejected before sending: %w", err)
			}
		}
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if idem != "" {
		req.Header.Set(api.HeaderIdempotency, idem)
	}
	if signed {
		if c.signer == nil || c.deviceID == 0 {
			return errors.New("client: device not registered")
		}
		ts := c.now().Unix()
		nonce := serverNonce
		if nonce == "" {
			nonce = NewIdempotencyKey()
		}
		sig, err := c.signer.SignAuth(api.RequestMessage(method, path, ts, nonce, body))
		if err != nil {
			return err
		}
		req.Header.Set(api.HeaderDevice, offline.FormatID(c.deviceID))
		req.Header.Set(api.HeaderTimestamp, strconv.FormatInt(ts, 10))
		req.Header.Set(api.HeaderNonce, nonce)
		req.Header.Set(api.HeaderSignature, encodeB64(sig))
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e api.Error
		_ = json.Unmarshal(data, &e)
		return &Error{Status: resp.StatusCode, Code: e.Code, Message: e.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

// StartAccount begins phone verification.
func (c *Client) StartAccount(ctx context.Context, r api.AccountStartRequest) (*api.AccountStartResponse, error) {
	out := new(api.AccountStartResponse)
	return out, c.do(ctx, http.MethodPost, api.PathAccountStart, &r, out, false, "")
}

// VerifyAccount confirms the OTP and returns a registration token.
func (c *Client) VerifyAccount(ctx context.Context, r api.AccountVerifyRequest) (*api.AccountVerifyResponse, error) {
	out := new(api.AccountVerifyResponse)
	return out, c.do(ctx, http.MethodPost, api.PathAccountVerify, &r, out, false, "")
}

// Challenge fetches a registration challenge.
func (c *Client) Challenge(ctx context.Context, token string) (*api.ChallengeResponse, error) {
	out := new(api.ChallengeResponse)
	return out, c.do(ctx, http.MethodPost, api.PathChallenge, &api.ChallengeRequest{RegistrationToken: token}, out, false, "")
}

// Register registers a device key.
func (c *Client) Register(ctx context.Context, r api.RegisterRequest) (*api.RegisterResponse, error) {
	out := new(api.RegisterResponse)
	return out, c.do(ctx, http.MethodPost, api.PathRegister, &r, out, false, "")
}

// CA returns the bank CA public key.
func (c *Client) CA(ctx context.Context) (*api.CAResponse, error) {
	out := new(api.CAResponse)
	return out, c.do(ctx, http.MethodGet, api.PathCA, nil, out, false, "")
}

// Deposit funds the online wallet.
func (c *Client) Deposit(ctx context.Context, amountPaise int64, idem string) (*api.WalletResponse, error) {
	out := new(api.WalletResponse)
	return out, c.doMoney(ctx, api.PurposeDeposit, api.PathDeposit, &api.DepositRequest{AmountPaise: amountPaise}, out, idem)
}

// Wallet returns the online wallet view.
func (c *Client) Wallet(ctx context.Context) (*api.WalletResponse, error) {
	out := new(api.WalletResponse)
	return out, c.do(ctx, http.MethodGet, api.PathWallet, nil, out, true, "")
}

// CreateReserve moves money into a new offline reserve.
func (c *Client) CreateReserve(ctx context.Context, r api.ReserveRequest, idem string) (*api.ReserveResponse, error) {
	out := new(api.ReserveResponse)
	return out, c.doMoney(ctx, api.PurposeReserve, api.PathReserves, &r, out, idem)
}

// Sync uploads records.
func (c *Client) Sync(ctx context.Context, r api.SyncRequest) (*api.SyncResponse, error) {
	out := new(api.SyncResponse)
	return out, c.do(ctx, http.MethodPost, api.PathSync, &r, out, true, "")
}

// Directory downloads the signed payee directory.
func (c *Client) Directory(ctx context.Context) (*api.DirectoryResponse, error) {
	out := new(api.DirectoryResponse)
	return out, c.do(ctx, http.MethodGet, api.PathDirectory, nil, out, true, "")
}

// Payment returns the server's view of one offline payment.
func (c *Client) Payment(ctx context.Context, deviceID uint64, counter uint32) (*api.PaymentResponse, error) {
	out := new(api.PaymentResponse)
	path := fmt.Sprintf("%s%s/%d", api.PathPaymentPrefix, offline.FormatID(deviceID), counter)
	return out, c.do(ctx, http.MethodGet, path, nil, out, true, "")
}

// SyncAsync submits records for background verification and returns a job.
func (c *Client) SyncAsync(ctx context.Context, r api.SyncRequest) (*api.SyncJob, error) {
	out := new(api.SyncJob)
	return out, c.do(ctx, http.MethodPost, api.PathSync+"?async=1", &r, out, true, "")
}

// SyncJob polls a background sync job.
func (c *Client) SyncJob(ctx context.Context, id string) (*api.SyncJob, error) {
	out := new(api.SyncJob)
	return out, c.do(ctx, http.MethodGet, api.PathSyncJobs+id, nil, out, true, "")
}

// WaitSyncJob polls a job until it is DONE or ctx ends.
func (c *Client) WaitSyncJob(ctx context.Context, id string, every time.Duration) (*api.SyncJob, error) {
	if every <= 0 {
		every = 200 * time.Millisecond
	}
	for {
		j, err := c.SyncJob(ctx, id)
		if err != nil || j.Status == "DONE" {
			return j, err
		}
		t := time.NewTimer(every)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
}

// Async runs fn in the background and delivers its result on the returned
// channel, so callers can overlap network calls without managing goroutines.
func Async[T any](ctx context.Context, fn func(context.Context) (T, error)) <-chan Result[T] {
	ch := make(chan Result[T], 1)
	go func() {
		v, err := fn(ctx)
		ch <- Result[T]{Value: v, Err: err}
	}()
	return ch
}

// Result is the outcome of an Async call.
type Result[T any] struct {
	Value T
	Err   error
}
