# PSTCO-Pay SDK

The PSTCO-Pay SDK lets any app take offline payments: a user registers, deposits money, loads part of it as an offline balance, and then pays shops or people with no internet and no signal. Money moves at the bank when either phone next connects, by internet or SMS.

Devices with secure hardware (Android StrongBox or TEE, the iOS Secure Enclave, a SIM applet) register with hardware trust. Devices without it still register, with a software-protected key and lower limits.

## What is in the SDK

| Package | Use it for |
|---|---|
| [sdk/wallet](sdk/wallet) | The device wallet: register, deposit, reserve, pay, accept, SMS queue, sync |
| [sdk/wallet/emulator](sdk/wallet/emulator) | Emulated StrongBox, TEE, Secure Enclave and SIM applet for tests |
| [sdk/mobile](sdk/mobile) | gomobile facade for Android (`.aar`) and iOS (`.xcframework`) |
| [sdk/offline](sdk/offline) | Wire formats: 114-byte record, amounts, certificates, reserves, directory, QR codes, offline verification |
| [sdk/offline/api](sdk/offline/api) | HTTP API types, paths and request signing, for clients in any language |
| [sdk/client](sdk/client) | Go client for the offline HTTP API |
| [sdk/attest](sdk/attest) | Server-side attestation verifiers: Android key attestation, Apple App Attest, SIM |
| [sdk/rasp](sdk/rasp) | Runtime self-protection: debugger, root or jailbreak, hooking, binary integrity |
| [sdk/merchant](sdk/merchant) | Merchant gRPC API, server and client, for online card payments |
| [sdk/server](sdk/server) | The whole backend in one `Run(ctx, Config)` call |
| [sdk/validate](sdk/validate) | Strict type and value checkpoints for every request |
| [sdk/netprobe](sdk/netprobe) | Concurrent TCP probes, socket tuning and kernel TCP statistics, in C through cgo or pure Go |
| [python/pstco](python) | The Python SDK: formats, checkpoints, sync and asyncio clients, software wallet |
| [native/pstconet](native/pstconet) | The C network library behind `sdk/netprobe` and `pstco.native` |

## Guardrails

- **Approval per money operation.** Unlocking a wallet authenticates the user for a session but authorises nothing. Every payment, deposit and reserve needs `w.Approve(intent, pin)`, which returns a 256-bit token from the OS random generator. The token is bound to the exact operation, amount and payee, works once, and expires after 60 seconds.
- **Violations lock the wallet.** A missing, used, expired, forged or mismatched token is refused. Three of them lock the wallet, and five wrong PINs at approval lock it too.
- **Server nonce for money requests.** Deposits and reserves must carry a nonce from `POST /v1/auth/nonce`: 256 bits, bound to one device and purpose, single use, valid for 2 minutes. A request with a client-made nonce is refused. The SDKs do this for you.
- **Lockout and rate limits.** Five failed authentications lock a device for 15 minutes. Public endpoints allow 30 requests per minute per IP by default. Lockouts, frozen devices, rejected attestations and RASP blocks are recorded in the `security_events` table.
- **Strict types.** Integer fields accept only JSON integers, so `100.5`, `1e2`, `"100"` and `true` are all rejected. Unknown and duplicate fields are rejected too. The Go client and the Python SDK run the same checks before sending.

## Async

- **Async sync.** `POST /v1/sync?async=1` returns `202` with a job ID at once. A worker pool verifies the records, and `GET /v1/sync/jobs/{id}` returns the results. In Go use `client.SyncAsync` and `WaitSyncJob`; in Python, `AsyncClient.sync_async`.
- **Concurrent server work.** Records from different devices are verified concurrently, and settlements run on a worker pool.
- **Overlapping calls.** `client.Async(ctx, fn)` in Go and `asyncio.gather` in Python overlap network calls.

## Use it from Go

```go
el, err := wallet.CreateSealedElement(dir, pin, nil, wallet.ElementOptions{}) // nil: no secure hardware
w, err := wallet.New(wallet.Config{Dir: dir, Element: el,
    Client: client.New("https://pay.example.com:8444", client.NewHTTPClient(caPEM))})
err = w.Unlock(pin)

otp, _ := w.StartAccount(ctx, "9876500001", "Asha", false) // the user receives the OTP by SMS
err = w.VerifyAccount(ctx, "9876500001", otpFromUser)
reg, err := w.Register(ctx) // reg.Trust is "software", "hardware-key" or "secure-applet"

_, err = w.Deposit(ctx, 1000_00)       // paise
_, err = w.CreateReserve(ctx, 500_00)  // offline balance

// Offline from here.
q, _ := w.QuotePhone("9876500002")     // q.Name from the signed directory, q.Listed
p, err := w.Pay(q, 123_45, wallet.DeliverQR)
showQR(p.QR)

// On the shop's phone, also offline.
received, err := shop.Accept(scannedCode)

// Whenever there is signal.
report, err := w.Sync(ctx)
```

To use secure hardware, pass a `wallet.KeyStore` instead of `nil`. A KeyStore signs with a non-exportable P-256 key and returns platform attestation. If it also implements `wallet.Sealer`, the wallet file is bound to that device: a copy will not open elsewhere, even with the PIN.

## Use it from Android and iOS

The mobile facade needs Go, gomobile, and the Android NDK or Xcode:

```
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
gomobile bind -target=android -o pstco.aar ./sdk/mobile
gomobile bind -target=ios -o Pstco.xcframework ./sdk/mobile
```

The app implements `mobile.NativeKeyStore` natively and passes it to `mobile.NewWallet`. Pass `null`/`nil` on devices without secure hardware.

| Method | Android (Kotlin) | iOS (Swift) |
|---|---|---|
| `Kind()` | `"android-strongbox"` or `"android-tee"` | `"ios-secure-enclave"` |
| `PublicKey()` | `KeyPairGenerator` EC P-256 with `setIsStrongBoxBacked(true)`; 65-byte uncompressed point | `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave`; `SecKeyCopyExternalRepresentation` |
| `SignDER(msg)` | `Signature("SHA256withECDSA")` | `SecKeyCreateSignature(.ecdsaSignatureMessageX962SHA256)` |
| `AttestationJSON(ch)` | `setAttestationChallenge(ch)`, then the certificate chain as `{"format":"android-key","chain":[...]}` | `DCAppAttestService.attestKey(clientDataHash: SHA256(ch))` as `{"format":"apple-appattest","object":"..."}` |

Complex results come back as JSON strings, for example `wallet.payPhone("9876500002", "123.45", "qr")`.

## Use it from any language

The offline API is HTTPS with JSON over TLS 1.3 and HTTP/2. Binary fields are standard base64. IDs are 16 hex digits.

| Method and path | Auth | Purpose |
|---|---|---|
| `POST /v1/accounts/start` | none | Send an OTP to a phone |
| `POST /v1/accounts/verify` | none | Check the OTP; returns a single-use registration token |
| `POST /v1/devices/challenge` | registration token | Single-use challenge to attest and sign |
| `POST /v1/devices/register` | registration token and proof | Register the device key; returns its certificate |
| `GET /v1/ca` | none | Bank CA public key that signs certificates, reserves and the directory |
| `POST /v1/wallet/deposit` | device, `Idempotency-Key` | Fund the online wallet |
| `GET /v1/wallet` | device | Balances, active reserve, device status |
| `POST /v1/reserves` | device, `Idempotency-Key` | Move money into a new offline reserve |
| `POST /v1/sync` | device | Upload records the device signed or received |
| `GET /v1/directory` | device | Signed payee directory and device revocation list |
| `GET /v1/offline-payments/{device}/{counter}` | device | One payment with its signed server event chain |
| `POST /v1/sms/inbound` | gateway HMAC | Records delivered to the short code by an SMS aggregator |

**Device authentication.** Each device request carries four headers:

- `X-Pstco-Device`: the device ID.
- `X-Pstco-Timestamp`: Unix seconds, within 5 minutes of server time.
- `X-Pstco-Nonce`: a fresh random value of 16 to 64 characters.
- `X-Pstco-Signature`: base64 of the device key's signature over the message below.

```
PSTCO-REQ-1\n<METHOD>\n<path?query>\n<timestamp>\n<nonce>\n<hex SHA-256 of body>
```

Each nonce is accepted once. The proof at registration signs this message:

```
PSTCO-REG-1\n<hex challenge>\n<hex SHA-256 of token>\n<hex public key>
```

A secure element must refuse to sign anything without one of these two prefixes. That rule keeps API signatures from ever passing as payment records.

**The payment record** is 114 bytes, specified in [sdk/offline/record.go](sdk/offline/record.go). [sdk/offline/testdata/golden.py](sdk/offline/testdata/golden.py) is an independent Python encoder whose output the Go tests check byte for byte.

## Run the server

```powershell
go build -o bin\ ./cmd/...
.\bin\certgen.exe -out certs
.\bin\pstco-server.exe -certs certs -data data -dev-otp
.\bin\pstco-wallet.exe register -phone 9876500001 -name Asha -dir w1 -ca certs\ca.pem
```

Or embed it with `server.Run(ctx, server.Config{...})`. These are the production settings:

| Flag | Meaning |
|---|---|
| `-android-roots`, `-apple-roots`, `-apple-app-ids`, `-sim-roots` | Trust roots for hardware attestation. Without them, every device registers with software trust |
| `-require-hardware` | Refuse devices without verified secure hardware |
| `-redis` | Share nonces, locks and the merchant cache across server instances |
| `-sms-gateway-secret` | Enable the SMS webhook |
| `-dev-otp` | Return OTPs in responses. Development only, never in production |

## Trust levels and default limits

| Trust | Earned by | Per payment | Offline balance | Reserve lasts |
|---|---|---|---|---|
| software | No secure hardware, or no attestation | ₹200 | ₹500 | 7 days |
| hardware-key | Verified StrongBox, TEE or Secure Enclave key | ₹500 | ₹2,000 | 30 days |
| secure-applet | Verified SIM or embedded secure element applet | ₹500 | ₹2,000 | 30 days |

These limits are placeholders, set in `offlinesvc.Policy`. Confirm the current RBI offline payment caps before production.

Evidence that is present but wrong is rejected outright, not downgraded to software trust. That covers an attestation over a stale challenge, an attested key that differs from the registered key, and a chain to an untrusted root.

## How money stays safe offline

- **Fixed counter and chain.** The element deducts the balance, advances the counter and links each record to the previous one in one step, and saves before releasing the record.
- **Rollback detection.** Someone who restores old wallet files on a software device can sign a second record with a used counter. The server detects two records with one counter and freezes the device.
- **Capped loss.** The bank locked the reserve at deposit time, so the reserve caps any loss.
- **Revocation.** Registering a new phone revokes the old one. Valid payments the old phone already gave to shops are still paid from its reserve until expiry.
- **Unregistered payees.** Payments to numbers that have not registered wait, and settle when that person joins.
- **No double settlement.** Bank calls are idempotent by key. A lost response is resolved by querying the bank, never by paying twice.
