# PSTCO-Pay

A working implementation of the PSTCO-Pay architecture, packaged as an SDK. It does two jobs:

- **Online payments.** A payment engine runs the full card payment lifecycle over persistent, multiplexed TLS 1.3 connections. Every stage is recorded in a hash-linked, signed execution graph. When something fails, Cryptographic Stage Dependency Recovery (CSDR) resumes the payment from the last verified point instead of restarting it.
- **Offline payments.** Users register, deposit, load an offline balance, and then pay shops with no internet or signal, by QR code, NFC or SMS. Money settles at the bank when either phone syncs.

Devices with secure hardware get hardware trust. Devices without it still register, with lower limits.

**To add it to another app, follow [INTEGRATION.md](INTEGRATION.md). The SDK reference is [SDK.md](SDK.md), and production setup is [DEPLOY.md](DEPLOY.md).**

## Project layout

| Folder | What it is | Who uses it |
|---|---|---|
| `sdk/` | The public SDK: everything an app or another Go program imports | App developers |
| `internal/` | The server's private engine, which Go stops outside code from importing | Only this project |
| `cmd/` | Small `main` programs that become the executables | Anyone running PSTCO-Pay |
| `bin/` | Build output: compiled `.exe` files from `cmd/`. Safe to delete and rebuild | Created by `go build` |
| `native/` | The C network library, `pstconet` | Go through cgo, Python through ctypes |
| `python/` | The Python SDK and its tests | Python developers |
| `ml/` | Python deadline-prediction models | Operators tuning latency |
| `deploy/` | Example Envoy, Docker and Prometheus configs. Not run here | Operators |
| `proto/` | The gRPC merchant API contract | Merchant integrators |
| `scripts/` | Demo, benchmark and native build scripts | Developers |
| `examples/` | Working integrations: a Go shop app, a Python kiosk, and Android and iOS key bridges | App developers |

Inside `cmd/`: `pstco-server` is the backend, `pstco-wallet` is a developer wallet, `pstco-cli` is a merchant client, `pstco-loadgen` is a load tester, `certgen` makes development certificates, and `devredis` is a development Redis server.

Inside `internal/`:

| Package | Job |
|---|---|
| `engine` | Online payment pipeline and CSDR recovery |
| `offlinesvc` | Offline payment server |
| `store` | SQLite database |
| `chain` | Signed, hash-linked event graph |
| `coord` | Redis |
| `bank`, `acquirer` | Bank and card processor simulators |
| `transport` | TLS and TCP |
| `controller` | Admission control and backoff |
| `fsm` | Payment state machine |
| `metrics` | Prometheus metrics |
| `risk` | Fraud rules |
| `model` | Shared types |
| `nonce` | In-memory nonces |

**Stack:** Go, gRPC over HTTP/2, HTTPS with TLS 1.3, SQLite as the authoritative store, Redis for coordination and caching, and Python with LightGBM and XGBoost.

| Offline piece | Where |
|---|---|
| 114-byte record, 40-bit paise amounts, certificates, reserves, directory, QR codes | [sdk/offline](sdk/offline) |
| Device wallet with or without secure hardware, PIN lockout and wipe, SMS queue, sync | [sdk/wallet](sdk/wallet) |
| Android key attestation, Apple App Attest, SIM applet verification | [sdk/attest](sdk/attest) |
| Runtime self-protection | [sdk/rasp](sdk/rasp) |
| Server: OTP accounts, registration, reserves, sync, double-spend detection, settlement, expiry, reconciliation, SMS gateway | [internal/offlinesvc](internal/offlinesvc) |
| Android and iOS bindings | [sdk/mobile](sdk/mobile) |
| Developer wallet CLI | [cmd/pstco-wallet](cmd/pstco-wallet) |

```
client ──one persistent TCP conn (BBR/CUBIC on Linux)──► TLS 1.3 mTLS ──► HTTP/2 + gRPC streams
   │                                                                           │
   │                      [optional Envoy gateway: rate limit, admission, circuit breaking]
   ▼                                                                           ▼
 pstco-server ─► PSTCO controller (admission, backpressure, deadline, congestion-aware backoff)
             ─► orchestrator state machine ─► validate → authenticate ∥ risk → authorize → capture
             ─► cryptographic execution graph (SHA-256 links, Ed25519 signatures, Merkle anchors)
             ─► CSDR recovery engine (crypto → business → execution → financial verification)
             ─► durable settlement outbox ─► settlement worker ─► reconciliation

 SQLite  : payments, execution events, idempotency, outbox, settlements, reconciliation (authoritative)
 Redis   : execution nonces, distributed per-payment locks, merchant cache (temporary only)
```

## Quick start (Windows PowerShell)

Requires Go 1.26+. Python 3.10+ is optional and only needed for the ML models.

```powershell
cd pstco-pay
go test ./...                                                     # 85 Go tests
python -m pytest python/tests                                     # 22 Python tests
powershell -ExecutionPolicy Bypass -File scripts\demo.ps1          # full end-to-end demo
```

The demo uses a Redis server if one is already listening on port 6379. Otherwise it starts `devredis`, a small in-memory Redis server for development.

Step by step:

```powershell
go build -o bin\ ./cmd/...
.\bin\certgen.exe -out certs
.\bin\devredis.exe                                                # or a real Redis; leave running
$env:PSTCO_MERCHANT_SECRET = "change-me"
.\bin\pstco-server.exe -certs certs -data data -faults flaky -redis redis://127.0.0.1:6379/0

# in another terminal (same PSTCO_MERCHANT_SECRET)
.\bin\pstco-cli.exe pay -amount 1234.00 -watch
.\bin\pstco-cli.exe graph -id <payment_id>
.\bin\pstco-cli.exe refund -id <payment_id>
.\bin\pstco-cli.exe status -key <idempotency_key> -resolve      # reconnect after a drop
.\bin\pstco-cli.exe reconcile                                    # admin certificate
.\bin\pstco-cli.exe anchors                                      # admin certificate
.\bin\pstco-loadgen.exe -n 3000 -c 64 -conns 1 -out loadgen.csv
```

Without `-redis`, the server uses in-process nonces and locks, which is fine for a single instance. With Docker, run `deploy/docker-compose.yml` to get the server, real Redis, Envoy, and Prometheus together.

Keep `-data` on a local disk, not inside a OneDrive-synced folder. Sync clients interfere with SQLite's write-ahead log.

Test card tokens: `tok_decline_*` (issuer decline), `tok_stolen_*`, `tok_lowbal_*` (insufficient funds), and `tok_fraud_*` (risk decline). Any other `tok_*` value is approved.

## What Redis does, and does not do

Redis holds only temporary coordination data, as section 7.2 of the spec requires.

- **Execution nonces.** Each nonce is stored with `SET NX EX`. A Lua script checks the scope and marks the nonce used in one atomic step, so a replayed instruction is rejected even across instances.
- **Per-payment locks.** Each lock is a `SET NX PX` key with a random token. Only the holder can release it, and a watchdog renews it while it is held. If an instance crashes, its lock expires on its own. On each instance, an in-process lock runs in front of Redis.
- **Merchant cache.** Merchant records are cached for 30 seconds in front of SQLite. The record includes the signing secret, so production Redis must use ACLs and TLS (`rediss://`).

Losing Redis loses no payment data. If Redis is down, payments fail before any money moves, because the payment lock cannot be acquired. A test proves this.

With Redis, several server instances can share one SQLite database. A test runs two engines against the same database file and the same Redis. Duplicate requests split across them still produce exactly one authorization and one capture. Concurrent settlement workers settle each payment exactly once.

## How the spec maps to code

| Spec section | Where |
|---|---|
| 3. Lifecycle and state model | [internal/fsm](internal/fsm/fsm.go) is the transition table, enforced on every write. [internal/engine/pipeline.go](internal/engine/pipeline.go) holds the stages. |
| 3.1 Authentication and risk in parallel | `authenticateAndAssess` in pipeline.go. Authorization depends on both events. |
| `UNKNOWN_OUTCOME` | A lost or timed-out response is recorded as unknown. CSDR then queries the processor by the original idempotency key before doing anything else. |
| 4.1 Persistent TCP and connection pool | [internal/rpc/client.go](internal/rpc/client.go) keeps N persistent HTTP/2 connections and fails idempotent calls over between them. |
| 4.2 BBR and CUBIC | [internal/transport](internal/transport/tcp_linux.go) sets `TCP_CONGESTION` and reads `TCP_INFO` on Linux. Elsewhere it uses the OS default and application-measured RTT. |
| 4.3 TLS 1.3 mTLS | [internal/transport/tls.go](internal/transport/tls.go) accepts TLS 1.3 only and requires client certificates. Certificates hot-reload for rotation. Go's TLS stack does not implement 0-RTT. |
| 4.4 HTTP/2 multiplexing | Each RPC is a stream. A test runs 200 concurrent payments over one TCP connection. |
| 4.5 Envoy | [deploy/envoy.yaml](deploy/envoy.yaml) has downstream and upstream mTLS, x-forwarded-client-cert, rate limiting, admission control, circuit breakers, and deliberately no retries. |
| 5. Execution graph | [internal/chain](internal/chain/graph.go) uses canonical JSON, SHA-256 links, dependency and retry edges, and per-service Ed25519 keys with per-stage signer rules. |
| 5.2 Append-only and Merkle anchors | SQLite triggers block UPDATE and DELETE on events. [anchor.go](internal/engine/anchor.go) writes signed Merkle roots to an external log. |
| 6. CSDR | [internal/engine/csdr.go](internal/engine/csdr.go) runs four verification layers and records each decision as a signed RECOVERY event. |
| 6.4 Idempotency and nonces | The `payment_idempotency` table in SQLite, plus nonces in Redis ([internal/coord](internal/coord/redis.go)) or in memory ([internal/nonce](internal/nonce/nonce.go)). |
| 6.5 Compensation | [compensate.go](internal/engine/compensate.go) voids before capture, refunds after capture, and treats a refund after settlement as a separate adjustment. |
| 7.2 Tables and transactional outbox | [internal/store](internal/store/store.go) has all six tables in SQLite. The capture result and its outbox row commit in one transaction. |
| Redis caching and coordination | [internal/coord](internal/coord/redis.go) |
| Settlement and reconciliation | [settlement.go](internal/engine/settlement.go) and [reconcile.go](internal/engine/reconcile.go) detect all five discrepancy kinds from section 3.1. |
| PSTCO controller | [internal/controller](internal/controller/controller.go) does admission control, latency estimates, deadline-bounded stage timeouts, and congestion-scaled backoff. |
| Observability | Prometheus metrics at `:9464/metrics`, `/transport` JSON, and `/healthz`, which also checks Redis. |
| Python ML | [ml/deadline_model.py](ml/deadline_model.py) trains a LightGBM latency regressor and a deadline-breach classifier, compares against XGBoost, and serves `/predict`. |

## What the tests prove

`go test ./...` covers these behaviors:

- **Happy path.** Signed events form a graph that verifies, the payment settles, reconciliation finds nothing, and the anchors verify.
- **Lost capture response.** The payment is reconciled from the processor with exactly one capture call.
- **Retries.** An unavailable capture is retried with a linked attempt, and earlier stages are not repeated.
- **Crash recovery.** A process crash mid-capture is resolved after restart without a second capture.
- **Expired authorization.** The payment is re-authorized automatically.
- **Declines.** Issuer and risk declines are never retried.
- **Retry limits.** Exhausted authorization ends as FAILED. Exhausted capture is compensated with a void.
- **Refunds.** A refund before settlement cancels the outbox row. A refund after settlement is a separate adjustment.
- **Tampering.** A payload edit, a forged signature, a broken link, or a missing dependency each produces a specific error, and CSDR stops. The Merkle anchors catch rewritten hashes.
- **Redis primitives.** Nonces are single-use, scoped, and expiring. Locks are exclusive and renewed, and twenty concurrent holders never overlap. The merchant cache honours its TTL and invalidation.
- **Two instances.** Two engines sharing SQLite and Redis process duplicate requests exactly once.
- **Redis outage.** A payment fails safely before any money moves.
- **Transport and identity.** Clients without certificates or on TLS 1.2 are rejected, merchant isolation holds, and gateway-forwarded identity works.

## Measured performance (this Windows machine, simulator latency 2 ms per call)

| Scenario | p50 | p99 | Throughput |
|---|---|---|---|
| 1 worker, full durability | 10.6 ms | 17.6 ms | 89/s |
| 1 worker, normal durability | 7.9 ms | 16.6 ms | 117/s |
| 32 workers, Redis coordination, 5%+3% faults | 184 ms | 549 ms | 152/s |
| 64 workers, full durability, 5%+3% faults | 396 ms | 1066 ms | 148/s |
| 64 workers, normal durability, 5%+3% faults | 233 ms | 652 ms | 247/s |

No payment missed its deadline, and about 15% were recovered by CSDR. Under load, the bottleneck is SQLite's single writer and its per-commit disk sync, not the transport or Redis. `-durability normal` survives a process crash but can lose the last commits on power loss.

## Limitations

- **Simulated processor.** The acquirer, network, and clearing house are an in-process simulator. Two separate server processes each have their own simulated processor, so a real multi-process deployment needs a real processor integration in [internal/acquirer](internal/acquirer/acquirer.go). The two-instance test shares one simulator inside one process.
- **devredis.** It is in-memory and for development only. Use real Redis in production with ACLs and TLS.
- **Shared SQLite.** Instances that share SQLite must run on the same host, because SQLite needs a local file.
- **Keys.** Service signing keys live in `data/service-keys.json` with mode 0600. Production should use an HSM or KMS.
- **No protobuf code generation.** The gRPC service uses a JSON codec, and [proto/pstco/v1/payment.proto](proto/pstco/v1/payment.proto) documents the same contract.
- **Not run here.** BBR, CUBIC, and TCP_INFO only work on Linux. The code cross-compiles but was not run on Linux. Envoy, Docker Compose, and Prometheus configs are provided but were not run here.
