## 1. Project Structure

```
webcli_passkey/
├── main.cpp            — HTTP server, all /api/* route handlers
├── wallet.hpp          — Wallet struct, file I/O, encrypt/decrypt, passkey support, account manifest
├── crypto_utils.hpp    — SHA256, AES-256-GCM, PBKDF2, base64, base58, ed25519
├── rpc_client.hpp      — JSON-RPC calls to the Octra node
├── lib/
│   ├── httplib.h       — embedded HTTP server
│   ├── json.hpp        — nlohmann JSON
│   ├── tweetnacl.h     — ed25519 / x25519 crypto
│   ├── tx_builder.hpp  — transaction construction
│   ├── pvac_bridge.hpp — FHE (encrypted balance) bridge
│   ├── stealth.hpp     — stealth address crypto
│   └── txcache.hpp     — local LevelDB tx cache
├── static/
│   ├── index.html      — single-page app shell
│   ├── wallet.js       — all frontend JS
│   └── style.css       — styles
└── data/               — runtime directory (created on first run)
    ├── accounts.json        — account manifest (list of all imported accounts)
    ├── wallet_<addr>.oct    — per-account encrypted wallet file (PIN wallets)
    ├── wallet_<addr>.oct    — per-account passkey wallet file (plain JSON, no privkey)
    └── txcache_XXXXXXXX     — SQLite tx cache per address
```

## 2. Wallet Storage Format

### A. Legacy wallet (`wallet.json` — plain JSON, unencrypted)

Old format stored in the working directory. The app reads it on first run and migrates it to the encrypted format.

```json
{
  "priv": "<base64-encoded 32-byte seed or 64-byte sk>",
  "addr": "oct...",
  "rpc":  "https://..."
}
```

### B. Encrypted wallet (`data/wallet_<addr>.oct` — binary blob, PIN-protected)

Binary layout:

```
[32 bytes]  random salt
[12 bytes]  AES-GCM nonce
[N bytes]   AES-256-GCM ciphertext of: {"priv":"...","addr":"...","rpc":"...","explorer":"..."}
[16 bytes]  GCM authentication tag
```

Key derivation: PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output, PIN as password.

Detection: file exists AND first byte is not `{`.

### C. Passkey wallet (`data/wallet_<addr>.oct` — plain JSON, no private key stored)

```json
{
  "type":     "passkey",
  "addr":     "oct...",
  "pub":      "<base64 Ed25519 public key>",
  "rpc":      "http://...",
  "explorer": "https://..."
}
```

The private key is never written to disk. On registration, a random 32-byte seed is generated client-side and stored as the WebAuthn `user.id` inside the credential (resident/discoverable). On every unlock, `credentials.get()` returns the seed via `response.userHandle`, from which the Ed25519 keypair is re-derived. The wallet file stores only the public key and address for verification.

The credential's `user.name` and `user.displayName` are both set to the full wallet address, so each passkey is clearly labeled in the OS passkey manager.

Detection: file exists AND first byte is `{`.

### D. Account manifest (`data/accounts.json`)

A JSON array tracking all imported accounts. Created automatically on first import/create.

```json
[
  { "addr": "oct...", "type": "pin",     "file": "data/wallet_3QQZWJ5U.oct" },
  { "addr": "oct...", "type": "passkey", "file": "data/wallet_FJcGXP7R.oct" }
]
```

- Each entry has `addr` (full Octra address), `type` (`pin` or `passkey`), and `file` (path to the wallet file).
- Entries are upserted automatically on every successful unlock, import, and create.
- The manifest is never cleared on logout — it persists so accounts can be listed on the lock screen.

## 3. Multi-Account Management

### Lock screen flow

After logout (or on first load), `init()` calls `GET /api/wallet/status`. If the `accounts` array is non-empty, the **account selection screen** is shown instead of the old single-wallet PIN prompt.

```
Page load / after logout
    └── init() → GET /api/wallet/status
         ├── loaded=true          → loadWalletInfo() → main app
         ├── accounts non-empty   → modal-accounts (account list)
         │       ├── click PIN account   → modal-pin (unlock that account)
         │       │       └── modalUnlock() → POST /wallet/unlock { pin, addr }
         │       ├── click passkey acct  → modal-webauthn-unlock
         │       │       └── doWebauthnUnlock() → credentials.get() → userHandle=seed
         │       │               → POST /wallet/unlock-passkey { seed_b64, addr }
         │       └── "add account"       → modal-import-choice
         │             ├── private key   → modal-import → modal-pin-setup(action='import')
         │             └── passkey       → deriveAddressFromSeed() → WebAuthn create → POST /wallet/import-passkey
         └── accounts empty (first run / no manifest)
               ├── needs_webauthn  → modal-webauthn-unlock
               ├── needs_pin       → modal-pin  (or modal-pin-setup if has_legacy)
               └── needs_create    → modal-btns (import / create new)
```

### Switching accounts

1. Click **logout** — wallet is locked (keys zeroed in memory).
2. The account list is shown — all previously imported accounts appear.
3. Click any account to unlock it with its PIN or passkey.
4. Or click **add account** to import/create a new one.

### Removing an account

Click the **×** button on any account row in the list. This calls `DELETE /api/wallet/account { addr }` and removes the entry from the manifest. The wallet file on disk is kept (not deleted).

## 4. Login/Unlock Flow

`POST /api/wallet/unlock { pin, addr? }`

- If `addr` is provided: looks up the wallet file from the manifest and loads it.
- If `addr` is omitted: falls back to `data/wallet.oct` (legacy single-wallet path).
- After any successful unlock the account is automatically upserted into the manifest.

`POST /api/wallet/unlock-passkey { seed_b64, addr? }`

- Same logic: if `addr` is given, the matching passkey wallet file is loaded; otherwise uses the default path.

**Legacy migration path:**

If `wallet.json` exists and no encrypted wallet is present, setting a PIN migrates the plaintext key to the encrypted format and registers the account in the manifest.

## 5. Logout/Lock Flow

`doLogout()` in JS:

1. `flushWalletState()` — kills the refresh timer and clears all cached UI state immediately (before the HTTP call).
2. `POST /api/wallet/lock` — backend zeros `g_wallet.sk`, `g_wallet.pk`, `g_pin`; resets `g_wallet_loaded = false`, pvac, detaches txcache.
3. Frontend: clears header, shows modal, re-runs `init()` → account list appears.

**Performance notes:**
- `flushWalletState()` runs first to prevent background refresh requests from queuing up behind `g_mtx`.
- The LevelDB txcache is closed (`delete db`) in a detached background thread so the lock response returns instantly rather than waiting for LevelDB compaction (which can take 10-20s).
- `GET /api/balance` snapshots `addr`, `pub_b64`, and pre-computes all signatures under `g_mtx`, then releases the mutex before any RPC calls. This prevents the balance handler from blocking the lock handler during concurrent refresh/logout.

## 6. Import Flows

### Import by Private Key (PIN-protected)

```
add account → "import private key"
  → paste base64 key → modalDoImport() stores key in _pendingPriv
  → modal-pin-setup (action='import')
  → modalFinishSetup() → POST /api/wallet/import { priv, pin }
  → saves to data/wallet_<addr>.oct, upserts manifest, auto-login
```

### Create New Passkey Wallet (WebAuthn)

```
add account → "create with passkey"
  → webauthnRegisterPasskey()
  → crypto.getRandomValues(32) → seed
  → deriveAddressFromSeed(seed) [client-side: Ed25519 pubkey → SHA-256 → base58] → address
  → navigator.credentials.create({ user.id=seed, user.name=address, user.displayName=address })
  → POST /api/wallet/import-passkey { seed_b64 }
  → saves passkey JSON to data/wallet_<addr>.oct, upserts manifest, auto-login
  → credId stored in localStorage('octra_cred_map')[address] and localStorage('octra_cred_id')
```

### Import Existing Passkey Wallet

```
add account → "import existing passkey"
  → webauthnGetExistingPasskey()
  → navigator.credentials.get({ allowCredentials: [] }) → user picks credential
  → seed = response.userHandle (32 bytes)
  → POST /api/wallet/import-passkey { seed_b64 }
  → saves passkey JSON to data/wallet_<addr>.oct, upserts manifest, auto-login
  → credId stored in localStorage('octra_cred_map')[address] and localStorage('octra_cred_id')
```

### Create New Wallet

```
add account → "create new" → "create with PIN"
  → modal-pin-setup (action='create')
  → POST /api/wallet/create { pin }
  → generates keypair, saves to data/wallet_<addr>.oct, upserts manifest, auto-login
```

## 7. PIN Management

- Exactly 6 decimal digits, validated on both frontend and backend.
- Stored in memory as `g_pin` (mlock'd against swap), never logged or written to disk directly.
- Disk representation: only as the PBKDF2 password.
- **Confirm PIN** (`POST /api/wallet/confirm-pin`): verifies `{ pin }` against in-memory `g_pin`. Used by the frontend before every transaction on PIN accounts. Returns 403 on wrong PIN. Not available for passkey wallets.
- **Change PIN** (`POST /api/wallet/change-pin`): verifies `current_pin == g_pin`, re-encrypts with new PIN, fresh salt and nonce. Not available for passkey wallets.

## 8. API Endpoints

### Account management (new)

| Method   | Endpoint                  | Description                                      |
|----------|---------------------------|--------------------------------------------------|
| GET      | `/api/wallet/accounts`    | List all accounts from manifest                  |
| DELETE   | `/api/wallet/account`     | Remove account from manifest `{ addr }`          |

### Wallet / Auth

| Method | Endpoint                  | Description                                      |
|--------|---------------------------|--------------------------------------------------|
| GET    | `/api/wallet/status`      | Wallet state + `accounts` array from manifest    |
| GET    | `/api/wallet`             | Address, pub key, RPC URL, explorer URL, `is_passkey` |
| POST   | `/api/wallet/create`      | Create new wallet + PIN                          |
| POST   | `/api/wallet/import`      | Import private key + PIN                         |
| POST   | `/api/wallet/import-passkey` | Import passkey wallet from seed               |
| POST   | `/api/wallet/unlock`      | Unlock with PIN, optional `addr` field           |
| POST   | `/api/wallet/unlock-passkey` | Unlock passkey wallet via seed, optional `addr` |
| POST   | `/api/wallet/lock`        | Lock (zeros all key material in memory)          |
| POST   | `/api/wallet/confirm-pin` | Verify PIN against in-memory `g_pin` (PIN wallets only) |
| POST   | `/api/wallet/change-pin`  | Re-encrypt under new PIN                         |
| POST   | `/api/settings`           | Update RPC/explorer URLs                         |

### Blockchain

| Method | Endpoint                  | Description                                      |
|--------|---------------------------|--------------------------------------------------|
| GET    | `/api/balance`            | Public + encrypted balance + nonce               |
| GET    | `/api/history`            | Paginated tx history                             |
| GET    | `/api/tx?hash=`           | Single transaction detail                        |
| GET    | `/api/keys`               | Address, pubkey, privkey (null if passkey), view pubkey |
| GET    | `/api/fee`                | Recommended fees for all op types                |
| POST   | `/api/send`               | Standard transfer                                |
| POST   | `/api/encrypt`            | Encrypt public funds (FHE)                       |
| POST   | `/api/decrypt`            | Decrypt encrypted funds                          |
| POST   | `/api/stealth/send`       | Stealth transfer (8-step ZKP)                    |
| GET    | `/api/stealth/scan`       | Scan for owned stealth outputs                   |
| POST   | `/api/stealth/claim`      | Claim stealth outputs                            |

### Contracts / Tokens

| Method | Endpoint                     | Description                              |
|--------|------------------------------|------------------------------------------|
| POST   | `/api/contract/compile`      | Compile `.oasm` assembly                 |
| POST   | `/api/contract/compile-aml`  | Compile AppliedML source                 |
| POST   | `/api/contract/address`      | Predict contract address                 |
| POST   | `/api/contract/deploy`       | Deploy contract                          |
| POST   | `/api/contract/call`         | Call contract method (on-chain tx)       |
| GET    | `/api/contract/view`         | Read-only contract method call           |
| POST   | `/api/contract/verify`       | Verify contract source against on-chain  |
| GET    | `/api/contract/info`         | Contract metadata                        |
| GET    | `/api/contract/receipt`      | Contract tx receipt                      |
| GET    | `/api/contract-storage`      | Read raw contract storage key            |
| GET    | `/api/tokens`                | List tokens with balance (30s cache)     |
| POST   | `/api/token/transfer`        | Transfer ERC20-style token               |
| POST   | `/api/fhe/encrypt`           | FHE encrypt integer                      |
| POST   | `/api/fhe/decrypt`           | FHE decrypt ciphertext                   |
