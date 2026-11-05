# Integrating PSTCO-Pay into your app

This guide shows how to add offline payments to an existing app: a customer wallet, a shop app, a kiosk, or a backend. Each path has a working example in [examples/](examples).

## 1. Pick your integration

| Your app | Integrate with | Working example |
|---|---|---|
| Android app | `sdk/mobile`, bound with gomobile, plus a Keystore bridge | [examples/android/StrongBoxKeyStore.kt](examples/android/StrongBoxKeyStore.kt) |
| iOS app | `sdk/mobile`, bound with gomobile, plus a Secure Enclave bridge | [examples/ios/SecureEnclaveKeyStore.swift](examples/ios/SecureEnclaveKeyStore.swift) |
| Go service, CLI or desktop app | `sdk/wallet` and `sdk/client` | [examples/go-shop](examples/go-shop/main.go) |
| Python service, kiosk or POS | `python/pstco` | [examples/python-kiosk](examples/python-kiosk/kiosk.py) |
| Any other language | The HTTPS API (section 7) | Request signing recipe below |
| Online card payments | The gRPC merchant API in `sdk/merchant` | `cmd/pstco-cli` |

The Go and Python examples run end to end against a development server. The Android and iOS files are reference bridges: written against the platform APIs, but not compiled here.

## 2. Before you start

Run a development server. `-dev-otp` returns the SMS code in the API response, so you can test without an SMS provider.

```powershell
go build -o bin\ ./cmd/...
.\bin\certgen.exe -out certs
.\bin\pstco-server.exe -certs certs -data data -dev-otp
go run ./examples/go-shop -ca certs\ca.pem          # proves your setup works
```

From your app you need two values:

- **Server URL.** The offline API, for example `https://pay.example.com:8444`.
- **Server CA certificate.** Needed only for a private CA such as the development one. Production servers use a public certificate.

## 3. The lifecycle every integration follows

1. **Create the wallet once per install.** Give it a directory in app-private storage. On a phone with secure hardware, also pass the platform key store.
2. **Unlock.** Call it with the user's PIN, at least 6 digits.
3. **Verify the phone.** `StartAccount(phone, name, listed)` sends an SMS code, and `VerifyAccount(phone, code)` confirms it. Set `listed` for shops, so customers see their name offline.
4. **Register the device.** The server records whether the key is in secure hardware: `trust` comes back as `software`, `hardware-key` or `secure-applet`, with matching limits.
5. **Fund it.** Approve, then `Deposit`. Approve again, then `CreateReserve` to load the offline balance.
6. **Pay, offline.** `QuotePhone`, or scan the shop's card, then show the name. Approve, then `Pay`, and display the returned QR code or let the SDK queue an SMS.
7. **Accept, offline, on the shop side.** `Accept(code)` verifies the payment with no network.
8. **Sync whenever there is signal.** Each accepted payment comes back with a signed receipt, which is the shop's proof.

**Approvals are mandatory.** Every deposit, reserve and payment needs `Approve(intent, pin)` first. The approval is a single-use 256-bit token for that exact amount and payee, valid for 60 seconds. Show the amount and payee name, ask for the PIN or biometric, approve, then call the operation. Never cache approvals.

## 4. Go

```go
el, _ := wallet.CreateSealedElement(dir, pin, nil, wallet.ElementOptions{}) // or OpenSealedElement on later starts
w, _ := wallet.New(wallet.Config{Dir: dir, Element: el,
    Client: client.New(serverURL, client.NewHTTPClient(caPEM))})
_ = w.Unlock(pin)

otp, _ := w.StartAccount(ctx, phone, "Asha", false) // the user types the SMS code in production
_ = w.VerifyAccount(ctx, phone, otp)
reg, _ := w.Register(ctx)

a, _ := w.Approve(wallet.Intent{Op: wallet.OpDeposit, AmountPaise: 1000_00}, pin)
_, _ = w.Deposit(ctx, 1000_00, a)
a, _ = w.Approve(wallet.Intent{Op: wallet.OpReserve, AmountPaise: 500_00}, pin)
_, _ = w.CreateReserve(ctx, 500_00, a)

q, _ := w.QuotePhone(shopPhone) // q.Name, q.Listed
a, _ = w.Approve(wallet.Intent{Op: wallet.OpPay, AmountPaise: 149_50, PayeeID: q.PayeeID}, pin)
p, _ := w.Pay(q, 149_50, wallet.DeliverQR, a) // p.QR to display

// Shop app, offline:
got, err := shop.Accept(scannedCode)
// Later, online:
rep, _ := shop.Sync(ctx) // rep.Accepted, rep.BadReceipts
```

A device with secure hardware passes a `wallet.KeyStore` instead of `nil`. For tests, `sdk/wallet/emulator` provides StrongBox, TEE, Secure Enclave and SIM applet emulators.

## 5. Python

```python
from pstco import Client, SoftwareWallet            # or AsyncClient / AsyncSoftwareWallet

w = SoftwareWallet.create("wallet-dir", pin, Client(server_url, ca_file))
w.verify_account(phone, w.start_account(phone, "Kiosk", listed=True) or code_from_user)
w.register()
w.deposit(1000_00, w.approve("deposit", 1000_00, pin))
w.create_reserve(500_00, w.approve("reserve", 500_00, pin))
q = w.quote_phone(shop_phone)
p = w.pay(q, 149_50, "qr", w.approve("pay", 149_50, pin, q["payee_id"]))
shop.accept(code); shop.sync()
```

Amounts are `int` paise or `str` rupees such as `"149.50"`. Floats are refused. Wrong argument types raise `pstco.CheckError` naming the field.

## 6. Android and iOS

**1. Bind the SDK.** This needs Go, gomobile, and the Android NDK or Xcode.

```
go install golang.org/x/mobile/cmd/gomobile@latest && gomobile init
gomobile bind -target=android -o pstco.aar ./sdk/mobile
gomobile bind -target=ios -o Pstco.xcframework ./sdk/mobile
```

**2. Add the key bridge.** Copy [StrongBoxKeyStore.kt](examples/android/StrongBoxKeyStore.kt) or [SecureEnclaveKeyStore.swift](examples/ios/SecureEnclaveKeyStore.swift) into your app:

- **Android.** The bridge uses StrongBox when the phone has it, and the TEE otherwise.
- **iOS.** The bridge creates a Secure Enclave key for signing, and uses App Attest to prove the app and bind that key.
- **No secure hardware.** Pass `null` or `nil`. The device then registers with software trust and lower limits.

**3. Call the wallet** off the UI thread. It returns JSON strings.

```kotlin
val w = Mobile.newWallet(filesDir.path + "/pstco", serverUrl, "", pin, StrongBoxKeyStore())
w.unlock(pin)
val otp = w.startAccount(phone, name, false)        // "" in production: read the SMS code
w.verifyAccount(phone, codeFromUser)
val reg = JSONObject(w.register())                   // reg.getString("trust")
w.deposit("1000", pin)
w.createReserve("500", pin)
val quote = JSONObject(w.quotePhone(shopPhone))      // show quote.getString("Name")
val pay = JSONObject(w.payPhone(shopPhone, "149.50", "qr", pin))
showQr(pay.getString("QR"))
// Shop side:
w.accept(scannedCode)
w.sync()
// SMS delivery: send each w.pendingSMS() entry with SmsManager, then w.markSMSSent(id, true).
```

The facade methods that move money take the PIN and approve internally, one operation at a time.

## 7. Any other language (HTTPS API)

Use TLS 1.3 and JSON bodies. Binary fields are standard base64, and IDs are 16 hex digits. The full endpoint table is in [SDK.md](SDK.md).

**Sign every device request** with the device's private key:

```
message   = "PSTCO-REQ-1\n" + METHOD + "\n" + path_with_query + "\n" + unix_seconds + "\n" + nonce + "\n" + hex(sha256(body))
headers   = X-Pstco-Device: <device id>   X-Pstco-Timestamp: <unix_seconds>
            X-Pstco-Nonce: <nonce>        X-Pstco-Signature: base64(sign(message))
```

- **Ordinary requests.** `nonce` is 16 or more random hex characters, new for every request.
- **Deposits and reserves.** First call `POST /v1/auth/nonce` with `{"purpose":"deposit"}` or `{"purpose":"reserve"}`. Use the returned 64-hex nonce as `nonce`, and send an `Idempotency-Key` header.
- **Types are exact.** `amount_paise` must be a JSON integer, so `100.5`, `"100"` and `1e2` are rejected. Unknown fields are rejected too.

**To build or verify offline records** in your language, follow [sdk/offline/record.go](sdk/offline/record.go). Check your bytes against [sdk/offline/testdata/golden.json](sdk/offline/testdata/golden.json).

## 8. The shop side: acceptance, receipts and settlement

- **Accept offline.** `Accept(code)` checks the bank's signature on the payer's certificate, the payer's signature, the per-payment limit, the expiry, that the payment is addressed to this shop, the revocation list, and duplicates. Hand over goods once it succeeds.
- **Sync to get paid.** On sync, the server answers each payment with a 98-byte receipt signed by its key. The SDK verifies the receipt against the exact payment bytes and stores it. `BadReceipts > 0` means a receipt failed; the payment stays unsynced and is retried.
- **Settlement.** It follows within seconds. Check `OnlineWallet()`, or `GET /v1/offline-payments/{device}/{counter}` for one payment with its signed server event chain.
- **Registration order.** A payment sent to a number that hasn't registered yet settles automatically once that number registers.

## 9. Errors your app should handle

| Code | Meaning | What to do |
|---|---|---|
| `invalid_request` | Wrong field type, unknown field or out-of-range value | Fix the request; the message names the field |
| `otp_invalid`, `otp_expired`, `otp_locked`, `otp_rate_limited` | SMS code problems | Ask again, or wait |
| `attestation_invalid` | Hardware evidence present but wrong | Do not retry; the device may be tampered with |
| `rasp_blocked` | Rooted or jailbroken device, or a debugger attached | Explain; the device cannot register |
| `server_nonce_required`, `server_nonce_invalid` | Money request without a fresh server nonce | Use the SDK, or fetch `/v1/auth/nonce` |
| `sync_required` | A top-up was requested before every payment synced | Call `Sync`, then retry |
| `over_limit`, `insufficient_funds` | Above the trust-level limit or the balance | Show the limit |
| `device_frozen`, `chain_broken` | Double spend or a broken payment chain detected | Send the user to support |
| `device_revoked` | The account registered a newer phone | Use the new phone |
| `device_locked`, `rate_limited` | Too many failures or requests | Back off |
| `bank_error`, `busy` | Temporary | Retry with the same `Idempotency-Key` |

Wallet-side errors: `ErrApprovalRequired`, `ErrApprovalInvalid` (approve again), `ErrAccessDenied` (wallet locked; unlock again), `ErrOverLimit`, `ErrInsufficient`, `ErrReserveExpired` (sync and reserve again), and `ErrLockedOut` or `ErrWiped` (wrong PINs).

## 10. Integration checklist

- [ ] Keep the wallet directory in app-private storage, excluded from cloud backups
- [ ] Never log PINs, approval tokens, OTPs or payment codes
- [ ] Show the payee name and amount before asking for the PIN
- [ ] Pass the platform key store on phones that have secure hardware
- [ ] Run sync in the background whenever connectivity returns
- [ ] Production builds never rely on `-dev-otp`, and read the SMS code from the user
- [ ] Use `sdk/wallet/emulator` in your app's automated tests
