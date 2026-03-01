> Written by AJPanda — active tester and community member

# Octra Webcli — Quick Start Guide

Welcome! If you're reading this, you're likely interested in testing out the Octra Network. Octra is a privacy-focused Layer 1 blockchain utilizing "privacy encryption" (Fully Homomorphic Encryption) to keep data secure. 

Testing the `webcli` helps the project find bugs, stress-test the network, and gets you hands-on experience (which is often a great way to qualify for potential future airdrops). This guide will walk you through setting everything up from scratch without using any complicated terminal commands!

## 🛠 Prerequisites

Before we download the wallet, you need a few tools installed on your computer.

**For Windows (WSL2):**
Windows users should use WSL2 (Windows Subsystem for Linux) — it gives you a full Linux environment and makes building projects painless.
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

---

## 🏃 Step 2: Start the Wallet

Once it successfully builds, you can start the wallet:

```bash
./octra_wallet 8420
```

By default, the wallet runs securely on your own computer. Open your favorite web browser and navigate to:
**http://localhost:8420**

---

## 💼 Step 3: Create or Import a Wallet

Everything from here on out is done through the friendly Web UI — no command line needed!

1. Open **http://localhost:8420** in your browser
2. You'll see a screen to get started:
   
   `[screenshot: wallet creation modal]`

   - **Create Wallet** — generates a brand new wallet for you
   - **Import Wallet** — paste your existing private key (if you had funds from a previous testnet, they'll still be there!)
3. Set a **6-digit PIN** — this locks your wallet securely
4. **Save your keys somewhere safe** — the wallet shows you your private key, public key, and address. Treat these like a password!

That's it — your wallet is ready to use!

---

## 🚰 Step 4: Get Devnet OCT

To test transactions, you need some testnet tokens (fake money for testing).
Head over to the **[Octra Devnet Faucet](https://faucet-devnet.octra.com/)**.

Paste your wallet address there and click to request tokens.

*Note: The faucet only runs for limited hours every day (typically 3-5 hours a day) to prevent spam. If it's down, be patient, or ask politely in the Octra community channels if someone can send you a few test tokens.*

---

## 🧪 Step 5: Testing Features

Here is where the real testing begins. Click around the Web UI to try these out:

### 1. Check Balance
Look at your dashboard to see your current public and private (encrypted) balance.

### 2. Send OCT
Click the "Send" button to transfer public OCT to another address. Just enter their address and the amount.

### 3. Encrypt OCT
Click the "Encrypt" button. This moves OCT from your public balance into an encrypted (private) balance using Octra's privacy encryption. 

### 4. Decrypt OCT
Click the "Decrypt" button to move OCT from your encrypted balance back into your public balance.

### 5. Transaction History
Check the "History" tab to see a list of your recent transactions.

---

## 💡 Tips & Tricks

- **Advanced Feature: Stealth Send:** Octra supports "Stealth Sends" for fully private transfers. This is an advanced feature that takes heavy computing power (it might take 10-30+ minutes on a normal computer!), so you don't need to test it unless you want to push your machine.
- **Lock/Unlock Wallet:** Remember to use your 6-digit PIN to lock your wallet when you step away, and unlock it when you come back!

---

## 🔗 Useful Links

- **Devnet Explorer:** [https://devnet.octrascan.io](https://devnet.octrascan.io) (to look up transactions)
- **Devnet Faucet:** [https://faucet-devnet.octra.com/](https://faucet-devnet.octra.com/) (to get test tokens)
- **GitHub Repository:** [https://github.com/octra-labs/webcli](https://github.com/octra-labs/webcli)

Happy testing! 🐙
