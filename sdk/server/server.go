// Package server runs the complete PSTCO-Pay backend from one Config, so it
// can be embedded in any Go program or run through cmd/pstco-server:
//
//   - the merchant gRPC API (HTTP/2, TLS 1.3 mutual TLS, persistent connections)
//   - the offline payment HTTPS API for wallet devices (TLS 1.3, HTTP/2)
//   - the SMS gateway webhook for records synced over GSM
//   - the orchestration engine, CSDR recovery, settlement, reconciliation,
//     anchoring and offline settlement loops
//   - Prometheus metrics and health checks
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pstcopay/internal/acquirer"
	"pstcopay/internal/bank"
	"pstcopay/internal/chain"
	"pstcopay/internal/controller"
	"pstcopay/internal/coord"
	"pstcopay/internal/engine"
	"pstcopay/internal/metrics"
	"pstcopay/internal/model"
	"pstcopay/internal/nonce"
	"pstcopay/internal/offlinesvc"
	"pstcopay/internal/risk"
	"pstcopay/internal/store"
	"pstcopay/internal/transport"
	"pstcopay/sdk/attest"
	"pstcopay/sdk/merchant"
)

// Config configures a server. Zero values take the defaults shown.
type Config struct {
	GRPCAddr    string // merchant gRPC API, default 127.0.0.1:8443
	OfflineAddr string // offline HTTPS API for devices, default 127.0.0.1:8444; "-" disables
	MetricsAddr string // metrics and health, default 127.0.0.1:9464; "-" disables
	DataDir     string // database, service keys, anchors, simulator state; default "data"
	CertDir     string // ca.pem, server.pem, server-key.pem; default "certs"

	Congestion  string // bbr | cubic | "" (Linux only)
	Durability  string // full | normal
	RedisURL    string // nonces, locks, merchant cache; empty = in-process
	Faults      string // simulated processor faults: none | flaky | chaos
	LatencyMS   float64
	MaxInflight int64
	MaxStreams  uint32
	GatewayCN   string
	AdminCN     string

	MerchantSecret string // demo merchant signing secret; required outside development
	KeyPassphrase  string // encrypts service-keys.json at rest (Argon2id + AES-256-GCM)

	// Offline payments.
	DevOTP           bool     // return OTPs in API responses (development only)
	SMSGatewaySecret string   // HMAC secret shared with the SMS aggregator
	AndroidRootsPEM  string   // Google hardware attestation roots
	AppleRootsPEM    string   // Apple App Attest root
	AppleAppIDs      []string // <team>.<bundle> allowed to register
	AppleDevelopment bool
	SIMRootsPEM      string // telecom SIM applet CA
	RequireHardware  bool   // refuse devices without verified secure hardware
	PublicRateLimit  int    // public requests per minute per IP (0 = 30, -1 = off)
	OfflinePolicy    *offlinesvc.Policy
	SMS              offlinesvc.SMSSender
	Logger           *slog.Logger
}

func (c *Config) defaults() {
	set := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	set(&c.GRPCAddr, "127.0.0.1:8443")
	set(&c.OfflineAddr, "127.0.0.1:8444")
	set(&c.MetricsAddr, "127.0.0.1:9464")
	set(&c.DataDir, "data")
	set(&c.CertDir, "certs")
	set(&c.Durability, store.DurabilityFull)
	set(&c.Faults, "none")
	set(&c.AdminCN, "pstco-admin")
	if c.LatencyMS == 0 {
		c.LatencyMS = 2
	}
	if c.MaxInflight == 0 {
		c.MaxInflight = 512
	}
	if c.MaxStreams == 0 {
		c.MaxStreams = 1000
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

func attestRegistry(c *Config) (*attest.Registry, []string, error) {
	var vs []attest.Verifier
	var formats []string
	read := func(path string) ([]byte, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("attestation roots %s: %w", path, err)
		}
		return b, nil
	}
	if c.AndroidRootsPEM != "" {
		b, err := read(c.AndroidRootsPEM)
		if err != nil {
			return nil, nil, err
		}
		p, err := attest.PoolFromPEM(b)
		if err != nil {
			return nil, nil, err
		}
		vs, formats = append(vs, &attest.Android{Roots: p}), append(formats, "android-key")
	}
	if c.AppleRootsPEM != "" {
		b, err := read(c.AppleRootsPEM)
		if err != nil {
			return nil, nil, err
		}
		p, err := attest.PoolFromPEM(b)
		if err != nil {
			return nil, nil, err
		}
		vs = append(vs, &attest.Apple{Roots: p, AppIDs: c.AppleAppIDs, AllowDevelopment: c.AppleDevelopment})
		formats = append(formats, "apple-appattest")
	}
	if c.SIMRootsPEM != "" {
		b, err := read(c.SIMRootsPEM)
		if err != nil {
			return nil, nil, err
		}
		p, err := attest.PoolFromPEM(b)
		if err != nil {
			return nil, nil, err
		}
		vs, formats = append(vs, &attest.SIM{Roots: p}), append(formats, "sim-x509")
	}
	return attest.NewRegistry(vs...), formats, nil
}

// Run starts the server and blocks until ctx is cancelled, then shuts down
// gracefully and persists simulator state.
func Run(ctx context.Context, c Config) error {
	c.defaults()
	log := c.Logger
	// No built-in secrets outside development mode.
	switch {
	case c.MerchantSecret == "" && c.DevOTP:
		c.MerchantSecret = "demo-merchant-secret"
		log.Warn("development mode: using the demo merchant secret")
	case c.MerchantSecret == "":
		return errors.New("PSTCO_MERCHANT_SECRET is required (or run with -dev-otp for development)")
	case len(c.MerchantSecret) < 16 && !c.DevOTP:
		return errors.New("PSTCO_MERCHANT_SECRET must be at least 16 characters")
	}
	if c.KeyPassphrase == "" && !c.DevOTP {
		log.Warn("PSTCO_KEY_PASSPHRASE not set: service signing keys are stored unencrypted; use an HSM/KMS or set a passphrase")
	}
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return err
	}
	dbPath := filepath.Join(c.DataDir, "pstco.db")
	st, err := store.OpenWith(dbPath, c.Durability)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, p := range []string{dbPath, dbPath + "-wal", dbPath + "-shm"} {
		_ = os.Chmod(p, 0o600) // payment data readable by the service user only
	}
	keys, err := chain.LoadOrCreateKeyRingWith(filepath.Join(c.DataDir, "service-keys.json"), c.KeyPassphrase)
	if err != nil {
		return err
	}
	if err := st.UpsertMerchant(ctx, &model.Merchant{ID: "merchant_demo", Secret: c.MerchantSecret,
		Principal: "merchant-demo", Active: true, MaxAmountMinor: 50_00_000_00, AllowReauth: true}); err != nil {
		return err
	}

	var inj acquirer.FaultInjector = acquirer.NoFaults{}
	switch c.Faults {
	case "none":
	case "flaky":
		inj = acquirer.RandomFaults{Unavailable: 0.05, LostResponse: 0.03}
	case "chaos":
		inj = acquirer.RandomFaults{Unavailable: 0.20, LostResponse: 0.10}
	default:
		return fmt.Errorf("unknown fault profile %q", c.Faults)
	}
	lat := time.Duration(c.LatencyMS * float64(time.Millisecond))
	acq := acquirer.New(acquirer.Config{Faults: inj, Latency: func(acquirer.Op) time.Duration { return lat }})
	acqSnap := filepath.Join(c.DataDir, "processor-sim.json")
	if err := acq.LoadSnapshot(acqSnap); err != nil {
		return fmt.Errorf("load processor snapshot: %w", err)
	}
	bk := bank.New()
	bankSnap := filepath.Join(c.DataDir, "bank-sim.json")
	if err := bk.Load(bankSnap); err != nil {
		return fmt.Errorf("load bank snapshot: %w", err)
	}

	ccfg := controller.DefaultConfig()
	ccfg.MaxInflight = c.MaxInflight
	ctl := controller.New(ccfg)
	met := metrics.New(ctl)

	ecfg := engine.DefaultConfig()
	ecfg.AnchorFile = filepath.Join(c.DataDir, "anchors.jsonl")
	deps := engine.Deps{Store: st, Keys: keys, Acquirer: acq, Risk: risk.New(risk.DefaultConfig()),
		Controller: ctl, Metrics: met, Logger: log}
	var rd *coord.Redis
	var offLocker offlinesvc.Locker
	coordination := "in-process"
	if c.RedisURL != "" {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		// The merchant cache is encrypted with a key derived from the service
		// keys, so a Redis compromise alone does not expose merchant secrets.
		rd, err = coord.Dial(dctx, c.RedisURL, coord.Options{CacheKey: keys.DeriveKey("redis-cache")})
		cancel()
		if err != nil {
			return err
		}
		defer rd.Close()
		_ = rd.Invalidate(ctx, "merchant_demo")
		deps.Nonces, deps.Locker, deps.Merchants = rd, rd, rd
		offLocker, coordination = rd, "redis"
	} else {
		n := nonce.New(2 * time.Minute)
		defer n.Close()
		deps.Nonces = n
	}
	eng := engine.New(ecfg, deps)

	reg, formats, err := attestRegistry(&c)
	if err != nil {
		return err
	}
	pol := offlinesvc.DefaultPolicy()
	if c.OfflinePolicy != nil {
		pol = *c.OfflinePolicy
	}
	if c.RequireHardware {
		pol.AllowSoftware = false
	}
	sms := c.SMS
	if sms == nil {
		sms = offlinesvc.LogSMS{Log: log, ShowSecrets: c.DevOTP}
	}
	off := offlinesvc.New(offlinesvc.Config{Policy: pol, Attest: reg, DevOTP: c.DevOTP, GatewaySecret: []byte(c.SMSGatewaySecret),
		PublicRateLimit: c.PublicRateLimit},
		offlinesvc.Deps{Store: st, Keys: keys, Bank: bk, SMS: sms, Locker: offLocker, Logger: log})

	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	if n := eng.RecoverAll(runCtx); n > 0 {
		log.Info("startup recovery", "payments", n)
	}
	eng.Start(runCtx)
	off.Start(runCtx)

	certFile, keyFile, caFile := filepath.Join(c.CertDir, "server.pem"), filepath.Join(c.CertDir, "server-key.pem"),
		filepath.Join(c.CertDir, "ca.pem")
	tlsCfg, err := transport.ServerTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		return fmt.Errorf("tls: %w (run certgen first)", err)
	}
	ln, err := transport.Listen(c.GRPCAddr, c.Congestion, ctl, log)
	if err != nil {
		return err
	}
	go ln.RunSampler(runCtx, time.Second)
	g := merchant.NewServer(eng, met, merchant.ServerOptions{GatewayCN: c.GatewayCN, AdminCN: c.AdminCN,
		MaxConcurrentStreams: c.MaxStreams}).GRPCServer(tlsCfg)
	errCh := make(chan error, 3)
	go func() { errCh <- g.Serve(ln) }()

	var servers []*http.Server
	if c.OfflineAddr != "-" {
		// Devices authenticate with their registered key, not a client
		// certificate, so this listener is TLS 1.3 without mTLS.
		otls := tlsCfg.Clone()
		otls.ClientAuth = tls.NoClientCert
		otls.ClientCAs = nil
		otls.NextProtos = []string{"h2", "http/1.1"}
		hs := &http.Server{Addr: c.OfflineAddr, Handler: off.Handler(), TLSConfig: otls,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 5 * time.Minute, MaxHeaderBytes: 16 << 10}
		oln, err := net.Listen("tcp", c.OfflineAddr)
		if err != nil {
			return err
		}
		servers = append(servers, hs)
		go func() { errCh <- hs.ServeTLS(oln, "", "") }()
	}
	if c.MetricsAddr != "-" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", met.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			if err := st.Ping(r.Context()); err != nil {
				http.Error(w, "database: "+err.Error(), http.StatusServiceUnavailable)
				return
			}
			if rd != nil {
				if err := rd.Ping(r.Context()); err != nil {
					http.Error(w, err.Error(), http.StatusServiceUnavailable)
					return
				}
			}
			_, _ = w.Write([]byte("ok\n"))
		})
		mux.HandleFunc("/transport", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"transport": ctl.Transport(), "ops": ctl.Ops()})
		})
		ms := &http.Server{Addr: c.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		servers = append(servers, ms)
		go func() { errCh <- ms.ListenAndServe() }()
	}

	if len(formats) == 0 {
		formats = []string{"none"}
	}
	log.Info("pstco-server listening", "grpc", c.GRPCAddr, "offline_https", c.OfflineAddr, "metrics", c.MetricsAddr,
		"tls", "1.3", "congestion", orDefault(c.Congestion), "durability", c.Durability, "coordination", coordination,
		"attestation", strings.Join(formats, ","), "software_devices", pol.AllowSoftware, "dev_otp", c.DevOTP)

	var serveErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case serveErr = <-errCh:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	done := make(chan struct{})
	go func() { g.GracefulStop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		g.Stop()
	}
	for _, s := range servers {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = s.Shutdown(sctx)
		cancel()
	}
	stop()
	eng.Wait()
	off.Wait()
	if err := acq.SaveSnapshot(acqSnap); err != nil {
		log.Warn("save processor snapshot", "err", err)
	}
	if err := bk.Save(bankSnap); err != nil {
		log.Warn("save bank snapshot", "err", err)
	}
	return serveErr
}

func orDefault(cc string) string {
	if strings.TrimSpace(cc) == "" {
		return "os-default"
	}
	return cc
}
