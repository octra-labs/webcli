> Written by AJPanda — active tester and community member

# Octra Network Webcli - Devnet Testing Guide

Welcome! If you're reading this, you're likely interested in testing out the Octra Network. Octra is a privacy-focused Layer 1 blockchain utilizing Fully Homomorphic Encryption (FHE), stealth transactions, and Bulletproofs to keep data secure. 

Testing the `webcli` helps the project find bugs, stress-test the network, and gets you hands-on experience (which is often a great way to qualify for potential future airdrops). This guide will walk you through setting everything up from scratch.

## 🛠 Prerequisites

Before we download the wallet, you need a few tools installed on your computer.

**For Windows (WSL2):**
Windows users should use WSL2 (Windows Subsystem for Linux) — it gives you a full Linux environment and makes building C++ projects painless.
1. Install WSL2 by following Microsoft's official guide: [Install WSL](https://learn.microsoft.com/en-us/windows/wsl/install)
2. Open your WSL terminal (Ubuntu is the default distro) and install dependencies:
   ```bash
   sudo apt update
   sudo apt install build-essential libssl-dev libleveldb-dev git
   ```
3. That's it — follow the Linux instructions from here on out.

**For Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install build-essential libssl-dev libleveldb-dev git
```

**For macOS:**
```bash
xcode-select --install
brew install openssl leveldb git
```

---

## 🚀 Step 1: Clone & Build

Now that your system is ready, let's grab the code and build it. 
*(Windows users: do this inside your WSL terminal).*

```bash
git clone https://github.com/octra-labs/webcli.git
cd webcli
make
```

**Troubleshooting Build Errors:** 
If `make` fails complaining about missing OpenSSL or LevelDB headers, ensure your paths are correctly set. On macOS, you might need to run `export LDFLAGS="-L/opt/homebrew/opt/openssl/lib"` and `export CPPFLAGS="-I/opt/homebrew/opt/openssl/include"` before running `make`.

---

## 🏃 Step 2: Start the Wallet

Once it successfully builds, you can start the wallet:

```bash
./octra_wallet 8420
```

By default, the wallet binds to `127.0.0.1` (localhost only) for security. Open your favorite web browser and navigate to:
**http://localhost:8420**

---

## 💼 Step 3: Create or Import a Wallet

You can manage your wallet either through the clean Web UI you just opened, or via the command line API.

**To Create a New Wallet:**
- **UI:** Click "Create Wallet" on the webpage.
- **API:** `curl -X POST http://localhost:8420/api/wallet/create`

**To Import an Existing Wallet:**
- **UI:** Click "Import Wallet" and paste your private key.
- **API:** `curl -X POST -H "Content-Type: application/json" -d '{"private_key":"YOUR_KEY"}' http://localhost:8420/api/wallet/import`

**Crucial Step:** You will be prompted to set a 6-digit PIN. *Write this down*, along with your generated keys. Keep them somewhere safe!

---

## 🚰 Step 4: Get Devnet OCT

To test transactions, you need some testnet tokens.
Head over to the **[Octra Devnet Faucet](https://faucet-devnet.octra.com/)**.

*Note: The faucet only runs for limited hours every day (typically 3-5 hours a day) to prevent spam. If it's down, be patient, or ask politely in the Octra community channels if someone can send you a few test tokens.*

---

## 🧪 Step 5: Testing Features

Here is where the real testing begins. You can perform these actions in the Web UI or via terminal commands using `curl`. 

### 1. Check Balance
Checks your current public and private (encrypted) balance.
* **Command:** `curl http://localhost:8420/api/balance`
* **Expected Output:**
  ```json
  {"public_balance": "5000", "private_balance": "0"}
  ```

### 2. Send OCT
Sends public OCT to another address. The `ou` parameter controls operation units (use `3000`).
* **Command:** 
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    -d '{"to":"<recipient_address>","amount":"10","ou":"3000"}' \
    http://localhost:8420/api/send
  ```
* **Expected Output:**
  ```json
  {"tx_hash":"c16eccbc76415a47..."}
  ```

### 3. Encrypt OCT
Moves OCT from your public balance into an encrypted (private) balance using FHE.
* **Command:** 
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    -d '{"amount":"10","ou":"3000"}' \
    http://localhost:8420/api/encrypt
  ```
* **Expected Output:**
  ```json
  {"tx_hash":"24f5facac0d7add4..."}
  ```

### 4. Decrypt OCT
Moves OCT from your encrypted balance back into your public balance.
* **Command:** 
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    -d '{"amount":"10","ou":"3000"}' \
    http://localhost:8420/api/decrypt
  ```
* **Expected Output:**
  ```json
  {"tx_hash":"387454d59934c73d..."}
  ```

### 5. Check Fees
Retrieves current network fee estimates.
* **Command:** `curl http://localhost:8420/api/fee`
* **Expected Output:**
  ```json
  {"standard": "100", "fast": "150"}
  ```

### 6. Transaction History
Lists your recent transactions.
* **Command:** `curl http://localhost:8420/api/history`
* **Expected Output:**
  ```json
  {"transactions": [{"txid": "...", "amount": "10", "type": "send"}]}
  ```

### 7. Stealth Send
Sends a fully private transfer using ECDH key exchange, Bulletproofs, and FHE. **⚠️ This is computationally heavy — expect 10-30+ minutes** depending on your hardware as it generates FHE range proofs.
* **Command:** 
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    -d '{"to":"<address>","amount":"5","ou":"3000"}' \
    http://localhost:8420/api/stealth/send
  ```
* **Expected Output:**
  ```json
  {"tx_hash":"d55375e49dc5bfb6..."}
  ```
* **Important:** The recipient must have a positive balance and their wallet must be unlocked for the stealth send to work (they need a registered PVAC view pubkey).

### 8. Stealth Scan
Checks the blockchain for incoming stealth transactions addressed to you. Run this on the *receiving* wallet.
* **Command:** `curl http://localhost:8420/api/stealth/scan`
* **Expected Output:**
  ```json
  {
    "outputs": [{
      "id": 121,
      "amount_raw": "50000000",
      "claimed": false,
      "sender": "oct8mvdk...",
      "tx_hash": "d55375e4..."
    }]
  }
  ```

### 9. Stealth Claim
Claims the unclaimed stealth outputs found during your scan, moving them into your balance.
* **Command:** 
  ```bash
  curl -X POST -H "Content-Type: application/json" \
    -d '{"id":"121","ou":"3000"}' \
    http://localhost:8420/api/stealth/claim
  ```
* **Expected Output:**
  ```json
  {"results":[{"id":"121","ok":true,"tx_hash":"4ce48033..."}]}
  ```

### 10. View Keys
Displays your public and private keys (make sure no one is looking over your shoulder).
* **Command:** `curl http://localhost:8420/api/keys`
* **Expected Output:**
  ```json
  {"public_key": "...", "view_key": "..."}
  ```

### 11. Lock/Unlock Wallet
Secures your wallet session.
* **Command (Lock):** `curl -X POST http://localhost:8420/api/wallet/lock`
* **Command (Unlock):** 
  ```bash
  curl -X POST -H "Content-Type: application/json" -d '{"pin":"123456"}' http://localhost:8420/api/wallet/unlock
  ```
* **Expected Output:**
  ```json
  {"status": "success", "locked": true}
  ```

### 12. Lookup Transaction
Checks the status and details of a specific transaction by its hash.
* **Command:** `curl "http://localhost:8420/api/tx?hash=<txhash>"`
* **Expected Output:**
  ```json
  {
    "hash": "387454d5...",
    "op_type": "decrypt",
    "amount_raw": "10000000",
    "from": "oct8mvdk...",
    "status": "confirmed",
    "epoch": 89290,
    "nonce": 6
  }
  ```

### 13. Smart Contracts (Experimental)
Compiles a smart contract. **Note:** Octra uses its own contract language — this is *not* Solidity. There are two compile endpoints:
* **Standard compile:** `POST /api/contract/compile` with `{"source":"<octra_code>"}`
* **AML compile:** `POST /api/contract/compile-aml` with `{"source":"<octra_aml_code>"}`

This is still early — documentation on the contract language is limited. Check with the Octra team for syntax references.

---

## 👯 Step 6: Running Two Wallets

Want to test sending back and forth? You can run a second wallet instance on the same machine.

1. Open a new terminal window.
2. Navigate to your `webcli` folder.
3. Start a new instance on a different port:
   ```bash
   ./octra_wallet 8421
   ```
4. Open `http://localhost:8421` in your browser.
5. Create a new wallet and test sending funds between `8420` and `8421`.

---

## 💡 Step 7: Tips & Troubleshooting

- **Masked Errors:** If you get an "unknown endpoint" error on an endpoint you *know* exists, it is likely masking an internal `500` server error. Open your browser's dev tools and check the response headers for `EXCEPTION_WHAT` to see the real crash reason.
- **Stealth Send Requirements:** To successfully send a stealth transaction, the recipient *must* have a registered PVAC view pubkey. This means the receiver needs to have a positive balance and their wallet must be unlocked.
- **Patience is Key:** Stealth sends rely on heavy FHE range proofs. If you are on consumer hardware, it will eat your CPU and take a while. Let it run.
- **Timeouts:** The Devnet is a work in progress. Token endpoints may sometimes timeout.
- **Contract Language:** Octra smart contracts do not use Solidity. 
- **needs_pin:** If the UI or API returns `needs_pin: true`, you need to unlock the wallet first using the `/api/wallet/unlock` endpoint.

---

## ⚠️ Known Issues
As we are testing early devnet software, keep an eye out for these known bugs:
- The `/api/settings` endpoint doesn't exist yet, but the UI might try to call it.
- `/api/tokens` may frequently time out.
- `/api/wallet/change-pin` sometimes rejects perfectly valid PINs.
- The default error handler incorrectly masks `500` errors as "unknown endpoint". A community PR has been submitted to fix this: [View PR #2](https://github.com/octra-labs/webcli/pull/2)

---

## 🔗 Useful Links

- **Devnet Explorer:** [https://devnet.octrascan.io](https://devnet.octrascan.io)
- **Devnet Faucet:** [https://faucet-devnet.octra.com/](https://faucet-devnet.octra.com/)
- **GitHub Repository:** [https://github.com/octra-labs/webcli](https://github.com/octra-labs/webcli)
- **Devnet RPC:** `http://165.227.225.79:8080`

Happy testing! 🐙
