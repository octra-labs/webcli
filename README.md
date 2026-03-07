This is a fork of [Octra WebCLI](https://github.com/octra-labs/webcli) with passkey (WebAuthn) support and multi-account wallet management. This is only tested with latest Chrome 145.0.7632.160 (64-bit).
Full structure of the fork is described in STRUCTURE.md.

## TLDR:
1. Added passkey support via user.id being used as a seed (yes, the private key is sitting in the tab's memory, it is a temporary problem that needs to be addressed at protocol level to accept native webAuthn rich signatures).
2. Added the management of multiple accounts (both imported via private keys and passkeys) so you can test transactions between accounts
3. Optimized logout to be instant. The rpc was being called every 15 seconds or tab switching for the balance checks, and the user had to wait untill its finished. Plus leveldb had to finish the compaction in the same thread so the user had to wait for it too untill he gets the response from backend.

## Changes:
- **Account manifest** (`data/accounts.json`): every imported/created account is recorded (addr, type, file) and upserted on every unlock/import/create. Each account gets its own wallet file (`data/wallet_<addr>.oct`).
- **Account selection screen**: `GET /api/wallet/status` returns the manifest as an `accounts` array; if non-empty, the frontend shows a picker instead of a PIN prompt. `GET /api/wallet/accounts` and `DELETE /api/wallet/account` added; `/unlock` and `/unlock-passkey` accept an optional `addr` field to target a specific account.
- **Backward compatibility**: existing `wallet.oct` and legacy `wallet.json` migration still work; first unlock of a pre-existing wallet auto-registers it in the manifest.
- **Per-account TX confirmation**: PIN accounts are prompted for their 6-digit PIN before every transaction (`POST /api/wallet/confirm-pin`); passkey accounts use the WebAuthn popup. `GET /api/wallet` returns `is_passkey` so the frontend routes correctly.
- **Passkey key derivation**: random 32-byte seed stored as the WebAuthn `user.id`, recovered via `userHandle` on unlock. Private key never written to disk. Each credential is labeled with the wallet address in the OS passkey manager. Removes PRF extension requirement.
- **Per-account credential map**: `octra_cred_map` in localStorage ensures unlocking account A always uses account A's specific credential, not the last-registered one.
- **Logout optimization**: UI flushes instantly, txcache closes in a background thread, `/api/balance` releases `g_mtx` before RPC calls — eliminates 1-20s stall caused by background refresh requests holding the mutex.
