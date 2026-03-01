> Written by AJPanda

# Octra Webcli — Technical Testing Report & API Reference

## Architecture Overview
The `webcli` operates as a lightweight local server and wallet interface for the Octra Network.
- **Server:** Built on a C++17 `httplib` server.
- **Storage:** Utilizes LevelDB for local wallet data storage.
- **Security:** Implements AES-256-GCM PIN encryption to secure the wallet session.
- **Routing:** Uses a structured route registration system to map API endpoints to internal C++ handlers.

## Bug Report Section
During devnet testing, the following issues were identified:
- **Error Handler Masking:** Line 291 of `main.cpp` masks internal server errors. 500s are incorrectly returned as "unknown endpoint". A fix has been submitted in PR #2: [https://github.com/octra-labs/webcli/pull/2](https://github.com/octra-labs/webcli/pull/2).
- **Missing Endpoint:** `/api/settings` returns `404 Not Found` (Not Implemented).
- **Timeout Issue:** `/api/tokens` hangs and eventually times out.
- **PIN Rejection:** `/api/wallet/change-pin` sometimes rejects valid 6-digit PINs.
- **Stealth Send JSON Error:** Intermittent error on stealth send: `[json.exception.type_error.302] type must be string, but is null`.

## Performance Notes
- **Stealth Send Computation:** Generating FHE proofs for stealth sends is highly resource-intensive. On an ARM64 architecture, it consumes ~37% CPU and takes roughly 10-30 minutes on standard consumer hardware.

## Recommendations
- **Error Handling:** Merge PR #2 to stop masking 500 errors as 404s, which will significantly improve debugging.
- **Documentation:** Provide detailed endpoint documentation within the repository.
- **Smart Contracts:** Include example contracts using the Octra contract language to help testers utilize the compile endpoints.
- **Environment Support:** Clearly document the required dependencies for WSL2 (Windows), `apt` (Linux), and `brew` (macOS).

---

## API Reference & Testing Results

| Method | Path | Description | Status |
|--------|------|-------------|--------|
| GET | `/api/balance` | Returns public and private balances | Working |
| POST | `/api/send` | Sends public OCT | Working |
| POST | `/api/encrypt` | Encrypts public OCT to private balance | Working |
| POST | `/api/decrypt` | Decrypts private OCT to public balance | Working |
| GET | `/api/fee` | Returns current fee structure | Working |
| GET | `/api/history` | Lists transaction history | Working |
| GET | `/api/keys` | Returns public and view keys | Working |
| GET | `/api/wallet/info` | Returns wallet address, explorer, etc. | Working |
| GET | `/api/wallet/status` | Returns wallet loaded and PIN status | Working |
| POST | `/api/wallet/lock` | Locks the wallet | Working |
| POST | `/api/wallet/unlock` | Unlocks the wallet with PIN | Working |
| GET | `/api/tx` | Look up a transaction by hash | Working |
| POST | `/api/stealth/send` | Send a stealth transaction | Working (Slow) |
| GET | `/api/stealth/scan` | Scan for incoming stealth TXs | Working |
| POST | `/api/stealth/claim` | Claim stealth outputs | Working |
| POST | `/api/contract/compile` | Compile Octra smart contract | Tested |
| POST | `/api/contract/compile-aml` | Compile AML contract | Tested |
| GET | `/api/settings` | Retrieve wallet settings | **Broken (404)** |
| GET | `/api/tokens` | Retrieve token list | **Timeout** |
| POST | `/api/wallet/change-pin` | Change wallet PIN | **Broken (Rejects PINs)** |
*(Note: Remaining endpoints of the 30 total follow similar patterns and are working as expected unless noted in the bug report).*

---

## Detailed API Examples (Real Devnet Data)

**Environment Setup for Testing:**
- Wallet 1 (Validator): `oct8mvdkX3babyBsrzHYUB1cSU9a79RTbHXi7nJNfHJnUmk` (Port 8420)
- Wallet 2: `octFNWdJHotCDY9eCueP7K8efiBsgT5JrfFFHur74ZMPsFs` (Port 8421)
- RPC Node: `http://165.227.225.79:8080`

### 1. Wallet Status
```bash
curl http://localhost:8420/api/wallet/status
```
**Response:** `{"loaded":true,"needs_pin":true}`

### 2. Unlock Wallet
```bash
curl -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}' http://localhost:8420/api/wallet/unlock
```

### 3. Wallet Info
```bash
curl http://localhost:8420/api/wallet/info
```
**Response:** Returns address (`oct8mvdkX3babyBsrzHYUB1cSU9a79RTbHXi7nJNfHJnUmk`), explorer_url (`https://devnet.octrascan.io`), public_key, rpc_url.

### 4. Check Balance
```bash
curl http://localhost:8420/api/balance
```

### 5. Check Fees
```bash
curl http://localhost:8420/api/fee
```
**Response:** Returns fee structure for all tx types.

### 6. Send OCT
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"to":"octFNWdJHotCDY9eCueP7K8efiBsgT5JrfFFHur74ZMPsFs","amount":"10","ou":"3000"}' \
  http://localhost:8420/api/send
```

### 7. Encrypt OCT
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"amount":"10","ou":"3000"}' \
  http://localhost:8420/api/encrypt
```

### 8. Decrypt OCT
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"amount":"10","ou":"3000"}' \
  http://localhost:8420/api/decrypt
```

### 9. Transaction History
```bash
curl http://localhost:8420/api/history
```
**Response:** Standard, encrypt, decrypt, stealth entries — all with confirmed status.

### 10. Transaction Lookup
```bash
curl "http://localhost:8420/api/tx?hash=387454d59934c73d..."
```
**Response:** 
```json
{"hash":"387454d5...","op_type":"decrypt","amount_raw":"10000000","status":"confirmed","epoch":89290,"nonce":6}
```

### 11. Stealth Send
*Utilizes ECDH x25519 for key exchange, Bulletproofs R1CS for range proofs, PVAC-HFHE for homomorphic encryption, Pedersen commitments, and AES-GCM for payload encryption.*
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"to":"octFNWdJHotCDY9eCueP7K8efiBsgT5JrfFFHur74ZMPsFs","amount":"5","ou":"3000"}' \
  http://localhost:8420/api/stealth/send
```

### 12. Stealth Scan
```bash
curl http://localhost:8421/api/stealth/scan
```
**Response:**
```json
{"outputs":[{"amount_raw":"50000000","claimed":false,"id":121,"sender":"oct8mvdkX3babyBsrzHYUB1cSU9a79RTbHXi7nJNfHJnUmk","tx_hash":"d55375e49dc5bfb6..."}]}
```

### 13. Stealth Claim
```bash
curl -X POST -H "Content-Type: application/json" \
  -d '{"id":"121","ou":"3000"}' \
  http://localhost:8421/api/stealth/claim
```
**Response:**
```json
{"results":[{"id":"121","ok":true,"tx_hash":"4ce4803354f5f3cd..."}]}
```

### 14. Contract Compilation
```bash
curl -X POST -H "Content-Type: application/json" -d '{"source":"..."}' http://localhost:8420/api/contract/compile
```

### 15. Lock Wallet
```bash
curl -X POST http://localhost:8420/api/wallet/lock
```
