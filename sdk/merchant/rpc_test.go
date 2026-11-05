package merchant

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"pstcopay/internal/acquirer"
	"pstcopay/internal/chain"
	"pstcopay/internal/controller"
	"pstcopay/internal/engine"
	"pstcopay/internal/model"
	"pstcopay/internal/nonce"
	"pstcopay/internal/risk"
	"pstcopay/internal/store"
	"pstcopay/internal/transport"
)

const secret = "rpc-test-secret"

type env struct {
	addr  string
	certs string
	ln    *transport.Listener
	acq   *acquirer.Acquirer
}

func startServer(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := transport.GenerateDevPKI(certs, []string{"localhost", "127.0.0.1"},
		[]string{"merchant-demo", "other-merchant", "pstco-admin", "envoy-gateway"}); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "pstco.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	for _, m := range []*model.Merchant{
		{ID: "merchant_demo", Secret: secret, Principal: "merchant-demo", Active: true, MaxAmountMinor: 1e12},
		{ID: "merchant_other", Secret: secret, Principal: "other-merchant", Active: true, MaxAmountMinor: 1e12},
	} {
		if err := st.UpsertMerchant(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	acq := acquirer.New(acquirer.Config{Latency: func(acquirer.Op) time.Duration { return time.Millisecond }})
	ctl := controller.New(controller.DefaultConfig())
	nonces := nonce.New(time.Minute)
	t.Cleanup(nonces.Close)
	cfg := engine.DefaultConfig()
	cfg.AnchorFile = filepath.Join(dir, "anchors.jsonl")
	eng := engine.New(cfg, engine.Deps{Store: st, Keys: chain.NewEphemeralKeyRing(), Nonces: nonces,
		Acquirer: acq, Risk: risk.New(risk.DefaultConfig()), Controller: ctl, Logger: log})

	tlsCfg, err := transport.ServerTLSConfig(filepath.Join(certs, "server.pem"), filepath.Join(certs, "server-key.pem"),
		filepath.Join(certs, "ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := transport.Listen("127.0.0.1:0", "", ctl, log)
	if err != nil {
		t.Fatal(err)
	}
	g := NewServer(eng, nil, ServerOptions{GatewayCN: "envoy-gateway", AdminCN: "pstco-admin"}).GRPCServer(tlsCfg)
	go func() { _ = g.Serve(ln) }()
	t.Cleanup(g.Stop)
	return &env{addr: ln.Addr().String(), certs: certs, ln: ln, acq: acq}
}

func (e *env) client(t *testing.T, cert string, pool int) *Client {
	t.Helper()
	c, err := DialCertDir(e.addr, e.certs, cert, pool, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func newReq(merchant, key string, amount int64) *CreatePaymentRequest {
	now := time.Now()
	r := &CreatePaymentRequest{MerchantID: merchant, CustomerID: "cust_1", IdempotencyKey: key, AmountMinor: amount,
		Currency: "INR", CardToken: "tok_visa_ok", ClientTimeMS: now.UnixMilli(),
		ExpiresAtMS: now.Add(time.Hour).UnixMilli(), DeadlineMS: 5000}
	r.Sign(secret)
	return r
}

func TestPaymentOverMutualTLS13(t *testing.T) {
	e := startServer(t)
	c := e.client(t, "merchant-demo", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req := newReq("merchant_demo", "rpc-1", 1234_00)
	v, err := c.CreatePayment(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if v.State != string(model.StateSettlementPending) || !v.Final() {
		t.Fatalf("state %s %s %s", v.State, v.FailureCode, v.FailureReason)
	}
	again, err := c.CreatePayment(ctx, req) // a client retry resends the identical request
	if err != nil || again.PaymentID != v.PaymentID {
		t.Fatalf("idempotent replay: %v %s", err, again.PaymentID)
	}
	// The same key with a different body is rejected rather than silently replayed.
	if _, err := c.CreatePayment(ctx, newReq("merchant_demo", "rpc-1", 999_00)); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("want AlreadyExists for key reuse, got %v", err)
	}
	g, err := c.GetExecutionGraph(ctx, v.PaymentID)
	if err != nil || !g.Verified || len(g.Events) < 8 {
		t.Fatalf("graph: %v verified=%t events=%d %s", err, g.Verified, len(g.Events), g.VerificationError)
	}
	got, err := c.GetPayment(ctx, &GetPaymentRequest{MerchantID: "merchant_demo", IdempotencyKey: "rpc-1"})
	if err != nil || got.PaymentID != v.PaymentID {
		t.Fatalf("get by key: %v", err)
	}
}

func TestManyConcurrentPaymentsShareOneConnection(t *testing.T) {
	e := startServer(t)
	c := e.client(t, "merchant-demo", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const n = 200
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, err := c.CreatePayment(ctx, newReq("merchant_demo", fmt.Sprintf("mux-%d", i), int64(100_00+i)))
			if err != nil {
				errs <- err
				return
			}
			if v.State != string(model.StateSettlementPending) {
				errs <- fmt.Errorf("payment %d state %s %s", i, v.State, v.FailureReason)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	e.ln.Sample()
	tr, err := c.GetTransportState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Transport.ActiveConns != 1 {
		t.Fatalf("server saw %d TCP connections, want 1", tr.Transport.ActiveConns)
	}
	if got := e.acq.Effects(acquirer.OpCapture); got != n {
		t.Fatalf("captures %d, want %d", got, n)
	}
}

func TestRejectsClientsWithoutCertificateOrBelowTLS13(t *testing.T) {
	e := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	base, err := transport.ClientTLSConfig(filepath.Join(e.certs, "merchant-demo.pem"),
		filepath.Join(e.certs, "merchant-demo-key.pem"), filepath.Join(e.certs, "ca.pem"), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	noCert := base.Clone()
	noCert.GetClientCertificate = nil
	tls12 := base.Clone()
	tls12.MinVersion, tls12.MaxVersion = tls.VersionTLS12, tls.VersionTLS12

	for name, cfg := range map[string]*tls.Config{"no client cert": noCert, "TLS 1.2": tls12} {
		c, err := Dial(DialOptions{Addr: e.addr, TLS: cfg})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.CreatePayment(ctx, newReq("merchant_demo", "rej-"+name, 100))
		c.Close()
		if err == nil {
			t.Fatalf("%s: request succeeded", name)
		}
	}
}

func TestIdentityIsBoundToMerchant(t *testing.T) {
	e := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	demo := e.client(t, "merchant-demo", 1)
	other := e.client(t, "other-merchant", 1)
	admin := e.client(t, "pstco-admin", 1)

	v, err := demo.CreatePayment(ctx, newReq("merchant_demo", "own-1", 100_00))
	if err != nil {
		t.Fatal(err)
	}
	// Another merchant's certificate cannot read it...
	if _, err := other.GetPayment(ctx, &GetPaymentRequest{PaymentID: v.PaymentID}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
	// ...nor pay on its behalf, even with a valid signature.
	imp, err := other.CreatePayment(ctx, newReq("merchant_demo", "imposter-1", 100_00))
	if err != nil {
		t.Fatal(err)
	}
	if imp.State != string(model.StateDeclined) || imp.FailureCode != string(model.FailAuthentication) {
		t.Fatalf("imposter payment state %s %s", imp.State, imp.FailureCode)
	}
	// Admin can read, reconcile and verify anchors; merchants cannot.
	if _, err := admin.GetPayment(ctx, &GetPaymentRequest{PaymentID: v.PaymentID}); err != nil {
		t.Fatal(err)
	}
	if _, err := demo.Reconcile(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("merchant reconcile: %v", err)
	}
	ar, err := admin.VerifyAnchors(ctx)
	if err != nil || len(ar.Report.Problems) != 0 || ar.Report.Anchors == 0 {
		t.Fatalf("anchors: %v %+v", err, ar)
	}
}

func TestWatchStreamsUntilFinal(t *testing.T) {
	e := startServer(t)
	c := e.client(t, "merchant-demo", 2)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, err := c.CreatePayment(ctx, newReq("merchant_demo", "watch-1", 100_00))
	if err != nil {
		t.Fatal(err)
	}
	refundDone := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, err := c.RefundPayment(ctx, &RefundRequest{PaymentID: v.PaymentID, MerchantID: "merchant_demo", Reason: "test"})
		refundDone <- err
	}()
	var states []string
	err = c.WatchPayment(ctx, v.PaymentID, func(ev *WatchEvent) bool {
		states = append(states, ev.State)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := <-refundDone; err != nil {
		t.Fatal(err)
	}
	if states[len(states)-1] != string(model.StateCompensated) {
		t.Fatalf("watched states %v", states)
	}
}

func TestGatewayForwardedIdentity(t *testing.T) {
	e := startServer(t)
	gw := e.client(t, "envoy-gateway", 1)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Without a forwarded client certificate the gateway identity is refused.
	if _, err := gw.CreatePayment(ctx, newReq("merchant_demo", "gw-0", 100)); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("want Unauthenticated, got %v", err)
	}
	fwd := metadata.AppendToOutgoingContext(ctx, "x-forwarded-client-cert",
		`By=spiffe://pstco/gateway;Hash=abc;Subject="CN=merchant-demo,O=PSTCO-Pay";URI=`)
	v, err := gw.CreatePayment(fwd, newReq("merchant_demo", "gw-1", 100_00))
	if err != nil {
		t.Fatal(err)
	}
	if v.State != string(model.StateSettlementPending) {
		t.Fatalf("state %s %s", v.State, v.FailureReason)
	}
}

func TestXFCCParsing(t *testing.T) {
	cases := map[string]string{
		`Hash=1;Subject="CN=merchant-demo,O=X";URI=`:               "merchant-demo",
		`Subject="O=X,CN=a";Hash=1,By=b;Subject="CN=closest";URI=`: "closest",
		`Hash=1;URI=spiffe://x`:                                    "",
	}
	for in, want := range cases {
		if got := xfccSubjectCN(in); got != want {
			t.Errorf("xfccSubjectCN(%q) = %q, want %q", in, got, want)
		}
	}
}
