# TOTP Bridge

**A single-file, offline OTP migration and quick-access tool.** Import encrypted Authy GDPR exports, Ente or Aegis backups, or Passbolt/KeePass KDBX files. Recover setup keys and QR codes, check current and next OTPs, and export selected tokens.

No account, backend, CDN, telemetry, localStorage or IndexedDB. Runtime libraries, the cryptographic worker, this rendered manual and license notices are embedded in the HTML. Opening the source links is optional and requires Internet; using the tool does not.

## Download

[Download the standalone HTML](https://github.com/n3me5is-git/totp-bridge/releases/latest/download/TOTP-Bridge.html) and save it as `TOTP-Bridge.html`. Open the saved file in your browser. The complete app and this guide are embedded; no installation is needed. On the GitHub file page, use **Download raw file**, not **Save page as** on the GitHub preview.

Source code, dependency lockfile and build scripts are included in this repository. The committed `dist/TOTP-Bridge.html` is the ready-to-run build.

## Quick start

1. Open `TOTP-Bridge.html` in a current browser. No installation or Node.js is required for the distributed HTML. If your browser blocks Web Crypto or Blob workers for local files, use the optional localhost server described below.
2. For HOTP, Steam or mOTP, first select **Activate compatibility with other formats**. The checkbox is off by default; changing it clears the current session. Select or drop a backup. Each new file replaces the current session. Maximum file size: 10 MB.
3. Enter the **backup password**. For Authy this is the password under Accounts → Backups, not your Twilio login password, app PIN or an OTP.
4. Compare the account count and codes with the source application. Authy rows that fail remain visible and cannot be exported.
5. Use **OTP** for quick access to the current and next code. The next code is intended for the next period, not immediate use. Time-based codes update at rollover. All code views hide after 30 seconds or when you switch tabs. HOTP uses an explicit counter; see the compatibility section before using it.
6. Use **Show key** to request the setup key and QR. A confirmation appears first. After confirmation, the key view hides after 60 seconds or when the page goes into the background.
7. Select tokens and choose **Export backup**. Encrypted exports require a new password of at least 12 characters; plaintext requires an explicit acknowledgment.
8. Import into the destination application and verify the codes before removing your original setup. **Clear session** ends the worker and removes the active data from the interface.

The demo uses public dummy secrets. Never enroll a real account with them. Your device clock must be correct for OTP generation.

## Requesting an Authy GDPR export

### Before requesting

Keep access to the phone number and email associated with Authy. Locate your Authy ID if available and confirm that you know your backup password. The tool cannot recover that password or reconstruct secrets absent from the export. Keep Authy available until the migration is verified.

### Email addresses and original request template

The [reference project's GDPR request instructions](https://github.com/serbbil/Authy-GDPR-Export-Decryption#-step-1-request-your-data-the-legal-way) list `privacy@twilio.com` or `support@twilio.zendesk.com`. You can send the request to **support@twilio.zendesk.com** and put **privacy@twilio.com** in **CC**. Alternatively, send it directly to the privacy address.

The subject and message below reproduce the reference project's wording exactly (MIT-licensed). The To/CC arrangement is an additional sending option documented here; the original project lists the two addresses as alternatives.

**To:** `support@twilio.zendesk.com`  
**CC:** `privacy@twilio.com`

**Subject:**

```text
GDPR Data Request - Authy Account Data Portability
```

**Body:**

```text
I am writing to request a full export of my personal data associated with my Authy account under Article 20 of the GDPR (Right to Data Portability).

Specifically, I require the encrypted secret seeds (TOTP tokens) for all accounts registered in my Authy app, along with the associated salt and iv values required to decrypt them.
```

This requests access/export, not account deletion. An account/profile report containing only names or devices is insufficient: this app needs the CSV token records with `name`, `encrypted_seed`, `salt`, and `iv`. If those records are missing from the response, ask for them in a follow-up.

Twilio may require identity verification. Follow the verified request thread and instructions from its official service; do not provide your backup password or unrelated account OTPs. Keep the request reference and submission date. Do not upload your export to online conversion sites.

Where GDPR applies, Article 12(3) generally requires a response within one month. A further two months may be allowed for complexity or number of requests, with notice and reasons within the first month. Portability has conditions under Article 20 and does not automatically cover every data category. See the [official GDPR text](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng). If the response is incomplete, identify the missing records in a follow-up to the privacy team.

### When the files arrive

Download using the delivery instructions in the verified request. The reference project describes a token file named similar to `Authy Personal Information Request - Exported Tokens (1).csv`; filenames and delivery methods can change.

Find the file whose header includes:

```csv
name,encrypted_seed,salt,iv
```

Load the original CSV directly. Standard quoted fields, commas, semicolons, multiline names and a UTF-8 BOM are supported. A legacy extra wrapper around the entire CSV is also recognized. Do not manually remove ordinary CSV quotes or re-save through a spreadsheet unless necessary; that can alter values. Preserve the original file separately.

If the token columns are missing, ask Twilio specifically for the encrypted token records. If some accounts are absent, resolve them individually with Twilio or the service concerned. This app only processes supplied standard TOTP seeds; it does not export Authy-specific push approvals or recover omitted credentials.

## Format support

| Format                              | Import | Export               | Notes                                             |
| ----------------------------------- | ------ | -------------------- | ------------------------------------------------- |
| Authy GDPR CSV                      | Yes    | No                   | Per-row encrypted seeds; backup password required |
| Plaintext otpauth / Ente plain text | Yes    | Yes                  | One TOTP URI per line; contains readable secrets  |
| Ente encrypted export v1            | Yes    | Yes                  | Argon2id + XChaCha20-Poly1305 secretstream        |
| Aegis vault v1, encrypted           | Yes    | Yes                  | scrypt + AES-256-GCM password slots               |
| Aegis vault v1, plaintext           | Yes    | Via encrypted export | Database versions 1, 2 and 3; export database v3  |
| Passbolt / KeePass KDBX             | Yes    | Yes                  | Import v3/v4; export v3 with AES-KDF              |

SHA1, SHA256 and SHA512 TOTP are supported, with 6–8 digits and periods of 1–86,400 seconds. Destination apps can impose narrower limits. HOTP, Steam and mOTP are available with the compatibility checkbox enabled. Yandex and other unlisted OTP types are not implemented. Unsupported OTP entries fail the relevant backup import instead of being silently discarded. Authy deliberately processes rows independently and reports failures.

Aegis groups, notes and icons are retained when exporting back to Aegis. Other conversions prioritize token names, issuer, secret, algorithm, digits and period. Additional URI parameters are retained in the otpauth/Ente path. Backups for 2FAS, andOTP, Bitwarden, Google Authenticator, LastPass, OTP Auth, Proton and Raivo are not implemented; use the standard QR where the destination supports its parameters.

### Passbolt and KeePass

Passbolt exports KDBX and several CSV dialects. Its documentation states that CSV export is disabled by default from v5.10; administrators can configure it. TOTP Bridge implements **KDBX**, not Passbolt's CSV dialects. See [Passbolt export](https://www.passbolt.com/docs/user/basic-features/browser/export/) and [KeePass import](https://www.passbolt.com/docs/user/basic-features/browser/import/keepass-kdbx/).

In Passbolt, choose either KeePass or KeePassXC/other KDBX export and load it here. In the other direction, export **Passbolt / KeePass · encrypted KDBX**, then import the file in Passbolt. The instance must support the relevant TOTP resource type.

Both protected `otp` URI fields and `TimeOtp-Secret-Base32`, `TimeOtp-Algorithm`, `TimeOtp-Length`, `TimeOtp-Period` fields are supported. The export writes both representations. Password-only KDBX files are supported; leave the password empty for an unprotected input. Keyfiles and hardware challenge-response are not supported.

KDBX import also accepts HOTP/Steam `otp` URIs and native KeePass `HmacOtp-Secret-Base32` + `HmacOtp-Counter` fields when compatibility is enabled. Other native HOTP secret encodings or multiple OTP definitions in one entry are rejected. The Passbolt-targeted KDBX export remains TOTP-only. Entries without recognized OTP fields are counted and excluded; recycle-bin entries and history are not imported. Login passwords, attachments, sharing permissions, folders and other vault metadata are not exported. KDBX is an OTP transport here, not a full password-manager backup converter.

## Optional HOTP, Steam and mOTP compatibility

Select **Activate compatibility with other formats** before loading a backup. Standard mode rejects an entire unsupported backup instead of silently dropping non-TOTP entries. Changing the checkbox clears the session; it is never persisted in browser storage. The demo includes HOTP, Steam and mOTP when enabled.

| Destination                   | TOTP | HOTP                   | Steam                       | mOTP                |
| ----------------------------- | ---- | ---------------------- | --------------------------- | ------------------- |
| Aegis encrypted backup        | Yes  | Yes, counter preserved | Yes                         | Yes, PIN preserved  |
| Ente encrypted export         | Yes  | Yes, counter preserved | Yes                         | Rejected            |
| Plaintext / QR otpauth        | Yes  | Yes, counter included  | `otpauth://steam` extension | Rejected; use Aegis |
| Passbolt-targeted KDBX export | Yes  | Rejected               | Rejected                    | Rejected            |

Unsupported selections disable the download button and identify the incompatible types. The exporter also checks again before encryption. Deselect incompatible entries explicitly or choose Aegis; there is no implicit conversion to TOTP and no silent omission. An Aegis backup containing mOTP is suitable for Aegis, **not** for Ente's Aegis importer.

### HOTP: preserve and manage the counter

HOTP follows RFC 4226 and uses a counter rather than time. Opening the code or key view does not advance it. The next code is a preview of counter + 1. After using the current code, press **Advance HOTP counter after use** once. The changed counter is included in subsequent exports and can be edited in the key parameters if resynchronization is needed.

Counter updates exist only in the active session: **export an updated backup before closing or clearing the session**. Importing an old file restores its old counter. Avoid using the same HOTP token from several apps simultaneously. Counters must be exact nonnegative integers no larger than 9,007,199,254,740,991; larger JSON values are rejected instead of rounded. A counter is required on import.

### Steam

Steam uses SHA1, a 30-second period and a five-character encoding with the alphabet `23456789BCDFGHJKMNPQRTVWXY`. The code starts from the same dynamically truncated HMAC value as TOTP, then encodes it with this alphabet. Nonstandard parameter combinations are rejected. Steam URIs use `otpauth://steam`; the importer also recognizes `encoder=steam` on a TOTP URI. These are extensions, not universally supported TOTP QR codes. This only migrates an existing OTP secret; it does not enroll a Steam device or migrate confirmations/recovery credentials.

### mOTP

mOTP uses MD5, six hexadecimal characters and a ten-second period. Following Aegis's representation, the vault secret is Base32-encoded bytes and the PIN is a four-digit string, preserving leading zeros. Code generation hashes the UTF-8 concatenation of the decimal time step, lowercase hexadecimal secret bytes and PIN, then takes the first six hexadecimal characters. Different parameters or a missing PIN are rejected.

The confirmation-protected key view displays the hexadecimal secret and PIN. No misleading standard TOTP QR is generated. Use an Aegis encrypted backup to preserve the full configuration; Ente/plaintext/KDBX exports reject it. The PIN is cleared from the view when the dialog closes or the page goes into the background.

Compatibility was checked against the [Aegis vault specification](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md), [Aegis mOTP implementation](https://github.com/beemdevelopment/Aegis/blob/master/app/src/main/java/com/beemdevelopment/aegis/crypto/otp/MOTP.java), [Ente supported code types](https://github.com/ente-io/ente/blob/main/mobile/apps/auth/lib/models/code.dart) and [KeePass OTP fields](https://keepass.info/help/base/placeholders.html#otp). These are format-level checks; import into every installed client/version has not been tested.

## Architecture and local data flow

```text
Selected file → format detection → worker decrypts/parses → normalized tokens
                                                        ↙              ↘
                                             key/QR/OTP views       export worker
                                                                        ↓
                                                              local Blob download
```

- `src/index.html` and `src/style.css`: accessible forms, dialogs and layout.
- `src/app.js`: in-memory session, selection, format detection, confirmation and timed views. Untrusted token names are inserted with `textContent` rather than HTML.
- `src/worker.js`: small request/response dispatcher with job IDs. Expensive KDF and backup operations run off the UI thread.
- `src/core.js`: normalization, CSV/URI parsing, Authy/Ente/Aegis adapters and TOTP/HOTP/Steam/mOTP generation.
- `src/kdbx.js`: Passbolt/KeePass adapter using kdbxweb, with bounded KDF parameters.
- `build.mjs`: bundles readable JavaScript and libraries, renders this Markdown to static HTML, includes licenses, and computes the Content Security Policy script hash.

The worker source is embedded as an inert readable text block. The app creates a local Blob worker from it; no remote script is loaded. A generation counter ignores stale asynchronous results after a reset. The worker is terminated and restarted when the session is cleared. Password fields and sensitive dialog content are cleared after use or dismissal.

The CSP blocks network requests with `connect-src 'none'` and permits only the hashed application script, local Blob workers, embedded styles/images and the WebAssembly used by crypto libraries. External links in the guide navigate only when deliberately opened. The optional development server serves the HTML and receives no backup content.

## How decryption and OTP generation work

### Authy GDPR

1. Encode the backup password and the CSV salt as UTF-8. **The salt is used literally, not decoded from Base64.**
2. Derive a 32-byte key using PBKDF2-HMAC-SHA1 with 100,000 iterations.
3. Decode `iv` from hexadecimal and `encrypted_seed` from Base64.
4. Decrypt using AES-256-CBC. Web Crypto handles PKCS#7 padding.
5. Interpret the plaintext as Base32 where valid, otherwise hexadecimal text or raw seed bytes. Convert to canonical Base32 for authenticator interoperability. Ambiguous Base32/hex values are flagged and can be reprocessed with an explicit encoding.
6. Use SHA1 / 6 digits / 30 seconds as defaults. Verify against the original and edit the parameters in the key view if needed.

CBC provides no authentication tag: valid padding does not establish that the password or decrypted token is correct. Comparing live codes is essential. The displayed key is the equivalent canonical Base32 secret, not necessarily the original byte-for-byte textual representation.

### Ente encrypted export v1

Argon2id derives a 32-byte key from the password and 16-byte random salt, using parallelism 1. Export uses 64 MiB and 3 iterations. The JSON stores memory in bytes. Newline-separated otpauth URIs are encrypted in one sodium secretstream message with XChaCha20-Poly1305 and a FINAL tag. Import verifies authentication and requires that final tag before parsing.

Import bounds: up to 1 GiB of KDF memory and 20 iterations. The single-message Ente backup representation is supported, not arbitrary multi-chunk secretstream files.

### Aegis encrypted vault v1

Export creates a random 32-byte master key. scrypt derives a password wrapping key with N=32,768, r=8, p=1 and a random 32-byte salt. AES-256-GCM wraps the master key in a password slot; a separate AES-256-GCM operation encrypts the vault JSON with the master key. Each operation uses a fresh 12-byte nonce and a 16-byte authentication tag stored separately from ciphertext.

Import tries supported password slots, verifies the wrapped key and then the vault. Biometric-only slots are not supported. Costs and slot count are bounded before processing.

### KDBX

kdbxweb handles the encrypted container, protected fields, compression and integrity checks. Export uses KDBX 3.1, AES-256-CBC and AES-KDF with 600,000 rounds. Import also accepts KDBX v4, including Argon2d/id v1.3. AES-KDF is limited to 100 million rounds; Argon2 is limited to 1 GiB, 20 iterations and parallelism 16. Password validation/container checks happen before entries are exposed.

### Current and next OTP

For a time snapshot, compute `floor(unixSeconds / period)`, encode the counter as 8 big-endian bytes and HMAC it with the decoded secret using SHA1, SHA256 or SHA512. RFC 4226 dynamic truncation followed by modulo `10^digits` yields the zero-padded code (RFC 6238). The next code uses the next period boundary. Generating it does not advance or change the device clock.

## Security boundaries and troubleshooting

- All decrypted tokens stay in process memory for the session. This is not a persistent authenticator vault. Browser extensions, malware, screen capture and a compromised device are outside its protection.
- JavaScript cannot guarantee erasure of every memory copy. Reset removes references and terminates the worker; downloaded files and clipboard contents are not erased by the app.
- Plaintext files and setup QR codes expose reusable secrets. The explicit warning/confirmation is intentional. Encrypted exports need a strong password stored separately.
- Wrong password: use the password belonging to that backup. An older export may use an older password. The app cannot recover it.
- Code mismatch: check clock, issuer/account, algorithm, digits, period and Authy seed encoding. Do not remove the original until verified.
- Unsupported or oversized file: keep the original and inspect the reported format. KDF bounds reject unusually expensive backups; clear the session to terminate a long-running job.
- This implementation has not received an independent security audit. Format-level and cryptographic tests do not prove compatibility with every installed application/version.

## Development and verification

Node.js 22+ is needed only to rebuild or run the optional local server:

```sh
npm ci
npm test
npm run build
npm start
# Open http://127.0.0.1:4173
```

The build produces `dist/TOTP-Bridge.html`. The distributed `TOTP-Bridge.html` is that same standalone artifact. Bundles are not minified; module boundaries, descriptive names and crypto comments remain readable. The worker is not hidden in an escaped JSON string. README Markdown is converted during build, not by a runtime network dependency.

Tests cover RFC 6238 and RFC 4226 vectors, Steam and mOTP against independent Node crypto, mixed Aegis round-trips preserving counter/PIN, opt-in enforcement, incompatible export rejection, URI round-trips, CSV quoting, independently generated Authy ciphertext, Ente/libsodium interoperability, Aegis with independent Node scrypt/GCM decryption, wrong passwords, altered ciphertext, QR decoding by jsQR, KDBX fields and a public Passbolt test fixture. Browser checks use synthetic data only. Verified in Chrome on localhost: Authy CSV, encrypted Ente/Aegis and the official Passbolt KDBX fixture; wrong Ente password rejection; key confirmation and cancellation; current/next OTP rollover and 30-second hiding. Encrypted export generation completes in the UI; the automation download event times out, so the final browser download location has not been independently verified. Direct `file://` navigation cannot be exercised by the browser automation policy, so browser automation uses localhost; manual double-click testing remains separate. Live import into installed Passbolt/Ente/Aegis clients has not been performed.

## Libraries, licenses and credits

The original project-specific TOTP Bridge code is distributed under MIT (see `LICENSE`). Bundled dependencies retain their own licenses; full notices are included at the bottom of the HTML and in `THIRD-PARTY-NOTICES.txt`.

| Library                                  | Purpose                                    | License    |
| ---------------------------------------- | ------------------------------------------ | ---------- |
| libsodium-wrappers-sumo / libsodium-sumo | Ente secretstream authenticated encryption | ISC        |
| hash-wasm                                | Argon2 and scrypt KDFs                     | MIT        |
| Papa Parse                               | CSV parsing                                | MIT        |
| qrcode                                   | Offline QR generation                      | MIT        |
| kdbxweb                                  | KeePass / Passbolt container import/export | MIT        |
| @xmldom/xmldom                           | XML in the crypto worker                   | MIT        |
| fflate                                   | KDBX compression dependency                | MIT        |
| esbuild                                  | Build-time bundling                        | MIT        |
| marked                                   | Build-time Markdown rendering              | MIT        |
| Prettier                                 | Build/source formatting                    | MIT        |
| jsQR                                     | Test-only independent QR decoding          | Apache-2.0 |

Exact versions are pinned in `package-lock.json`. The source archive includes a public test fixture from Passbolt's AGPL-3.0 repository with its attribution and license; that fixture is not embedded in the application. No Passbolt implementation source is bundled.

The Authy decryption workflow is based on [serbbil/Authy-GDPR-Export-Decryption](https://github.com/serbbil/Authy-GDPR-Export-Decryption), whose README identifies MIT licensing. Additional references:

- [Ente migration imports](https://ente.com/help/auth/migration/import) and [exports](https://ente.com/help/auth/migration/export).
- [Ente source](https://github.com/ente-io/ente) for encrypted backup adapters.
- [Aegis vault specification](https://github.com/beemdevelopment/Aegis/blob/master/docs/vault.md).
- [Passbolt browser extension source](https://github.com/passbolt/passbolt_browser_extension) for KDBX field mappings and the public test fixture.
- [kdbxweb](https://github.com/keeweb/kdbxweb).

Privacy-request guidance and format documentation checked on 11 November 2026. Provider procedures and supported formats may change; use the linked official sources for updates.
