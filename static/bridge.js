const BRIDGE_VAULT = 'oct5MrNfjiXFNRDLwsodn8Zm9hDKNGAYt3eQDCQ52bSpCHq';
const WOCT_ADDR = '0x4647e1fE715c9e23959022C2416C71867F5a6E80';
const ETH_BRIDGE = '0xE7eD69b852fd2a1406080B26A37e8E04e7dA4caE';
const SIGNER_URL = '/api/bridge/signer';
const RECOVERY_URL = 'https://relayer-002838819188.octra.network/recovery.json';
const ETH_RPC_URL = 'https://ethereum-rpc.publicnode.com';
const MAINNET_CHAIN_ID = '0x1';
const ETHEREUM_MAINNET_PARAMS = {
  chainId: MAINNET_CHAIN_ID,
  chainName: 'Ethereum Mainnet',
  nativeCurrency: {
    name: 'Ether',
    symbol: 'ETH',
    decimals: 18
  },
  rpcUrls: ['https://ethereum-rpc.publicnode.com'],
  blockExplorerUrls: ['https://etherscan.io']
};
const ETH_CHAIN_NAMES = {
  '0x1': 'Ethereum Mainnet',
  '0x2105': 'Base',
  '0xa4b1': 'Arbitrum One',
  '0xa': 'Optimism',
  '0x89': 'Polygon',
  '0x38': 'BSC',
  '0xa86a': 'Avalanche',
  '0xfa': 'Fantom',
  '0x144': 'zkSync',
  '0xaa36a7': 'Sepolia',
  '0xaa37dc': 'OP Sepolia',
  '0x14a34': 'Base Sepolia',
  '0x66eee': 'Arbitrum Sepolia'
};
const OCT_DECIMALS = 6;
const MAX_BRIDGE_RAW = (1n << 128n) - 1n;
const CAP_SELECTORS = Object.freeze({
  mint: Object.freeze({
    perTx: '0x77ca7344',
    daily: '0x7c215818',
    used: '0xb7c140dd',
    day: '0xe27cafb9'
  }),
  burn: Object.freeze({
    perTx: '0x5af7840d',
    daily: '0xe084e7b0',
    used: '0x0ab5f7ed',
    day: '0xe1bd9ccb'
  })
});

let _currentChainId = null;

let _dir = 'o2e';
let _octraAddr = '';
let _ethAddr = '';
let _octBalance = '0';
let _woctBalance = '0';
let _ethProvider = null;
let _ethRpcId = 0;
let _capRequest = null;
let _bridgeCaps = Object.freeze({ status: 'loading', mint: null, burn: null });

const ethRpc = async (method, params) => {
  const id = ++_ethRpcId;
  const response = await fetch(ETH_RPC_URL, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id, method, params}),
    cache: 'no-store'
  });
  if (!response.ok) throw new Error('ethereum rpc unavailable');
  const body = await response.json();
  if (!body || body.id !== id || body.error || body.result === undefined) {
    throw new Error('invalid ethereum rpc response');
  }
  return body.result;
};

const uintFromHex = value => {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new Error('invalid contract value');
  }
  return BigInt(value);
};

const readContractUint = selector =>
  ethRpc('eth_call', [{to: ETH_BRIDGE, data: selector}, 'latest']).then(uintFromHex);

const capFor = direction => direction === 'o2e' ? _bridgeCaps.mint : _bridgeCaps.burn;

const capState = (perTx, daily, storedUsed, storedDay, currentDay) => {
  const used = storedDay === currentDay ? storedUsed : 0n;
  const remaining = daily > used ? daily - used : 0n;
  return Object.freeze({perTx, daily, used, remaining});
};

const readBridgeCaps = async () => {
  const mint = CAP_SELECTORS.mint;
  const burn = CAP_SELECTORS.burn;
  const values = await Promise.all([
    readContractUint(mint.perTx),
    readContractUint(mint.daily),
    readContractUint(mint.used),
    readContractUint(mint.day),
    readContractUint(burn.perTx),
    readContractUint(burn.daily),
    readContractUint(burn.used),
    readContractUint(burn.day),
    ethRpc('eth_getBlockByNumber', ['latest', false])
  ]);
  const block = values[8];
  if (!block || typeof block !== 'object') throw new Error('invalid ethereum block');
  const timestamp = uintFromHex(block.timestamp);
  const currentDay = timestamp / 86400n;
  return Object.freeze({
    status: 'ready',
    mint: capState(values[0], values[1], values[2], values[3], currentDay),
    burn: capState(values[4], values[5], values[6], values[7], currentDay)
  });
};

const renderCapacity = () => {
  const mode = _dir === 'o2e' ? 'mint' : 'burn';
  const cap = capFor(_dir);
  $('capacity-label').textContent = 'ethereum ' + mode + ' left today';
  if (_bridgeCaps.status !== 'ready' || !cap) {
    $('capacity-value').textContent = _bridgeCaps.status === 'loading' ? 'loading...' : 'unavailable';
    $('capacity-tx').textContent = 'per tx: -';
    $('capacity-meter').style.width = '0';
    return;
  }
  $('capacity-value').textContent = fmtU(cap.remaining, OCT_DECIMALS) + ' wOCT';
  $('capacity-tx').textContent = 'per tx: ' + fmtU(cap.perTx, OCT_DECIMALS) + ' wOCT';
  const basisPoints = cap.daily > 0n ? Number(cap.remaining * 10000n / cap.daily) : 0;
  $('capacity-meter').style.width = Math.max(0, Math.min(100, basisPoints / 100)) + '%';
};

const refreshBridgeCapacity = async () => {
  if (_capRequest) return _capRequest;
  _capRequest = readBridgeCaps()
    .then(state => {
      _bridgeCaps = state;
      renderCapacity();
      validateForm();
      return true;
    })
    .catch(() => {
      _bridgeCaps = Object.freeze({status: 'error', mint: null, burn: null});
      renderCapacity();
      validateForm();
      return false;
    })
    .finally(() => {
      _capRequest = null;
    });
  return _capRequest;
};

const parseAmount = value => {
  const text = String(value || '').trim();
  if (!/^(?:\d+|\d{1,3}(?:,\d{3})+)(?:\.\d{0,6})?$/.test(text)) return null;
  const normalized = text.replace(/,/g, '');
  const parts = normalized.split('.');
  if (parts[0].length > 33) return null;
  const fraction = (parts[1] || '').padEnd(OCT_DECIMALS, '0');
  const raw = BigInt(parts[0]) * 1000000n + BigInt(fraction);
  if (raw > MAX_BRIDGE_RAW) return null;
  return Object.freeze({text: normalized, raw});
};

const capError = raw => {
  if (_bridgeCaps.status === 'loading') return 'loading ethereum capacity';
  if (_bridgeCaps.status !== 'ready') return 'ethereum capacity unavailable';
  const cap = capFor(_dir);
  if (!cap) return 'ethereum capacity unavailable';
  if (raw > cap.perTx) return 'amount exceeds transaction cap';
  if (raw > cap.remaining) return 'amount exceeds daily cap';
  return '';
};

async function wcli(method, path, body) {
  var opts = { method: method, headers: {} };
  if (body) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  var res = await fetch('/api' + path, opts);
  if (!res.ok) throw new Error('WebCLI error: ' + res.status);
  return res.json();
}

async function connectOctra() {
  try {
    var st = await wcli('GET', '/wallet/status');
    if (!st.loaded) { showStatus('err', 'unlock your wallet in webcli first'); return; }
    var info = await wcli('GET', '/wallet');
    _octraAddr = info.address;
    $('octra-addr').textContent = _octraAddr.substring(0, 12) + '...' + _octraAddr.slice(-4);
    $('octra-addr').classList.remove('none');
    $('octra-dot').classList.replace('off', 'on');
    $('octra-connect-btn').textContent = 'connected';
    $('octra-connect-btn').classList.add('connected');
    await refreshBalances();
    validateForm();
  } catch(e) { showStatus('err', 'cannot connect to webcli'); }
}

var _detectedWallets = [];
var _eip6963Providers = [];

window.addEventListener('eip6963:announceProvider', function(e) {
  _eip6963Providers.push({ name: e.detail.info.name, icon: e.detail.info.icon, provider: e.detail.provider, rdns: e.detail.info.rdns });
});
window.dispatchEvent(new Event('eip6963:requestProvider'));

async function connectEth() {
  setTimeout(function() { _connectEthInner(); }, 100);
}

async function _connectEthInner() {
  if (_eip6963Providers.length > 0) {
    _detectedWallets = _eip6963Providers.map(function(w) { return { name: w.name, provider: w.provider, icon: w.icon }; });
  } else if (window.ethereum) {
    _detectedWallets = [{ name: window.ethereum.isMetaMask ? 'MetaMask' : 'Wallet', provider: window.ethereum, icon: null }];
  } else {
    showStatus('err', 'no EVM wallet found. install MetaMask.');
    return;
  }

  if (_detectedWallets.length === 1) {
    await connectWithProvider(_detectedWallets[0]);
    return;
  }

  var html = '';
  _detectedWallets.forEach(function(w, i) {
    var icon = safeIconUrl(w.icon);
    var iconHtml = icon ? '<img src="' + escAttr(icon) + '" width="20" height="20" style="vertical-align:middle;margin-right:8px;border-radius:4px">' : '';
    html += '<button data-action="selectWallet" data-arg="' + i + '" style="display:flex;align-items:center;width:100%;padding:10px;margin:4px 0;font-size:13px;font-weight:500;border:1px solid #D0D7E2;background:#fff;color:#2B3A52;cursor:pointer;text-align:left;font-family:Tahoma,arial,sans-serif">' + iconHtml + esc(w.name) + '</button>';
  });
  $('wallet-list').innerHTML = html;
  $('wallet-modal').classList.add('show');
}

function closeWalletModal() { $('wallet-modal').classList.remove('show'); }

async function selectWallet(idx) {
  $('wallet-modal').classList.remove('show');
  await connectWithProvider(_detectedWallets[idx]);
}

async function detectChainId() {
  if (!_ethProvider) return null;
  try {
    const chainId = await _ethProvider.request({ method: 'eth_chainId' });
    _currentChainId = chainId;
    return chainId;
  } catch(e) {
    return null;
  }
}

async function switchToEthereumMainnet() {
  if (!_ethProvider) return false;
  try {
    await _ethProvider.request({
      method: 'wallet_switchEthereumChain',
      params: [{ chainId: MAINNET_CHAIN_ID }]
    });
  } catch(e) {
    if (e && e.code === 4902) {
      await _ethProvider.request({
        method: 'wallet_addEthereumChain',
        params: [ETHEREUM_MAINNET_PARAMS]
      });
    } else {
      throw e;
    }
  }
  const chainId = await detectChainId();
  return chainId === MAINNET_CHAIN_ID;
}

async function ensureCorrectChain() {
  if (!_ethProvider) { showStatus('err', 'connect metamask first'); return false; }
  const chainId = await detectChainId();
  if (chainId === MAINNET_CHAIN_ID) return true;
  const name = ETH_CHAIN_NAMES[chainId] || ('chain ' + chainId);
  showStatus('info', 'switching from <b>' + name + '</b> to Ethereum Mainnet...');
  try {
    const switched = await switchToEthereumMainnet();
    if (switched) {
      showStatus('info', 'switched to Ethereum Mainnet');
      updateChainBadge();
      validateForm();
      return true;
    }
    showStatus('err', 'wallet did not switch to Ethereum Mainnet');
    return false;
  } catch(e) {
    const msg = (e && e.message) || String(e);
    showStatus('err', 'could not auto-switch: ' + msg + ' — please switch manually in your wallet');
    return false;
  }
}

function updateChainBadge() {
  var el = $('eth-chain-badge');
  if (!el) return;
  if (!_currentChainId) {
    el.textContent = '';
    el.className = 'eth-chain-badge hidden';
    return;
  }
  var name = ETH_CHAIN_NAMES[_currentChainId] || ('chain ' + _currentChainId);
  if (_currentChainId === MAINNET_CHAIN_ID) {
    el.textContent = 'Ethereum Mainnet';
    el.className = 'eth-chain-badge ok';
  } else {
    el.textContent = 'WRONG: ' + name;
    el.className = 'eth-chain-badge bad';
  }
}

async function connectWithProvider(w) {
  _ethProvider = w.provider;
  try {
    const accounts = await _ethProvider.request({ method: 'eth_requestAccounts' });
    if (!accounts.length) return;
    _ethAddr = accounts[0];
    $('eth-addr').textContent = _ethAddr.substring(0, 8) + '...' + _ethAddr.slice(-4);
    $('eth-addr').classList.remove('none');
    $('eth-dot').classList.replace('off', 'on');
    $('eth-connect-btn').textContent = w.name;
    $('eth-connect-btn').classList.add('connected');
    if (_dir === 'o2e') $('recipient').value = _ethAddr;
    else $('recipient').value = _octraAddr || '';
    try { localStorage.setItem('bridge_eth_wallet', w.name); } catch(e) {}
    await detectChainId();
    updateChainBadge();
    if (_currentChainId !== MAINNET_CHAIN_ID) await ensureCorrectChain();
    await refreshBalances();
    validateForm();
    try { recoveryFetch(true); } catch(e) {}
    _ethProvider.on('accountsChanged', function(accs) {
      if (accs.length) {
        _ethAddr = accs[0];
        $('eth-addr').textContent = _ethAddr.substring(0, 8) + '...' + _ethAddr.slice(-4);
        refreshBalances();
        validateForm();
        try { recoveryFetch(true); } catch(e) {}
      }
    });
    _ethProvider.on('chainChanged', function(cid) {
      _currentChainId = cid;
      updateChainBadge();
      if (cid === MAINNET_CHAIN_ID) {
        showStatus('ok', 'switched to Ethereum Mainnet');
      } else {
        const name = ETH_CHAIN_NAMES[cid] || ('chain ' + cid);
        showStatus('err', 'wrong network: <b>' + name + '</b>. click bridge to switch back to Ethereum Mainnet.');
      }
      refreshBalances();
      validateForm();
    });
  } catch(e) { showStatus('err', w.name + ': ' + e.message); }
}

async function refreshBalances() {
  if (_octraAddr) {
    try { var b = await wcli('GET', '/balance'); _octBalance = b.public_balance || b.balance_raw || '0'; $('bal-oct').textContent = fmtU(_octBalance, OCT_DECIMALS); } catch(e) {}
  }
  if (_ethAddr && WOCT_ADDR) {
    try {
      var data = '0x70a08231000000000000000000000000' + _ethAddr.substring(2);
      var result = await _ethProvider.request({ method: 'eth_call', params: [{ to: WOCT_ADDR, data: data }, 'latest'] });
      _woctBalance = (!result || result === '0x' || result === '0x0') ? '0' : BigInt(result).toString();
      $('bal-woct').textContent = fmtU(_woctBalance, OCT_DECIMALS);
    } catch(e) { _woctBalance = '0'; $('bal-woct').textContent = '0'; }
  }
}

function setDir(d) {
  _dir = d;
  $('tab-o2e').className = d === 'o2e' ? 'active' : '';
  $('tab-e2o').className = d === 'e2o' ? 'active' : '';
  if (d === 'o2e') {
    $('from-chain').textContent = 'octra'; $('from-token').textContent = 'OCT';
    $('to-chain').textContent = 'ethereum'; $('to-token').textContent = 'wOCT';
    $('input-token').textContent = 'OCT'; $('output-token').textContent = 'wOCT';
    $('recipient-label').textContent = 'ethereum recipient';
    $('recipient').placeholder = '0x...';
    $('recipient').value = _ethAddr || '';
    $('notice-text').textContent = 'lock OCT on octra, receive wOCT on ethereum';
  } else {
    $('from-chain').textContent = 'ethereum'; $('from-token').textContent = 'wOCT';
    $('to-chain').textContent = 'octra'; $('to-token').textContent = 'OCT';
    $('input-token').textContent = 'wOCT'; $('output-token').textContent = 'OCT';
    $('recipient-label').textContent = 'octra recipient';
    $('recipient').placeholder = 'oct...';
    $('recipient').value = _octraAddr || '';
    $('notice-text').textContent = 'burn wOCT on ethereum, receive OCT on octra';
  }
  $('bridge-amount').value = '';
  $('output-val').textContent = '0';
  clearStatus();
  renderCapacity();
  validateForm();
}

function validateForm() {
  const btn = $('bridge-btn');
  const amtStr = $('bridge-amount').value.trim();
  const recip = $('recipient').value.trim();
  const amount = parseAmount(amtStr);
  $('output-val').textContent = amount && amount.raw > 0n ? addCommas(amount.text) : '0';
  if (!_octraAddr || !_ethAddr) { btn.disabled = true; btn.textContent = 'connect both wallets'; return; }
  if (!amount || amount.raw <= 0n) { btn.disabled = true; btn.textContent = 'enter valid amount'; return; }
  const rawAmt = amount.raw;
  const capacityError = capError(rawAmt);
  if (capacityError) { btn.disabled = true; btn.textContent = capacityError; return; }
  if (_dir === 'o2e') {
    if (rawAmt > BigInt(_octBalance)) { btn.disabled = true; btn.textContent = 'insufficient OCT'; return; }
    if (!recip || !/^0x[0-9a-fA-F]{40}$/.test(recip)) { btn.disabled = true; btn.textContent = 'enter valid ETH address'; return; }
    if (_currentChainId && _currentChainId !== MAINNET_CHAIN_ID) { btn.disabled = false; btn.textContent = 'switch to ethereum mainnet'; return; }
    btn.disabled = false; btn.textContent = 'bridge ' + amtStr + ' OCT';
  } else {
    if (rawAmt > BigInt(_woctBalance)) { btn.disabled = true; btn.textContent = 'insufficient wOCT'; return; }
    if (!recip || !/^oct[1-9A-HJ-NP-Za-km-z]{44}$/.test(recip)) { btn.disabled = true; btn.textContent = 'enter valid octra address'; return; }
    if (_currentChainId && _currentChainId !== MAINNET_CHAIN_ID) { btn.disabled = false; btn.textContent = 'switch to ethereum mainnet'; return; }
    btn.disabled = false; btn.textContent = 'bridge ' + amtStr + ' wOCT';
  }
}

function setMax() {
  const balance = BigInt(_dir === 'o2e' ? _octBalance : _woctBalance);
  const cap = capFor(_dir);
  const allowed = _bridgeCaps.status === 'ready' && cap
    ? [balance, cap.perTx, cap.remaining].reduce((a, b) => a < b ? a : b)
    : balance;
  $('bridge-amount').value = fmtU(allowed, OCT_DECIMALS);
  validateForm();
}

async function doBridge() {
  if (!await ensureCorrectChain()) return;
  await refreshBridgeCapacity();
  const amt = $('bridge-amount').value.trim();
  const recip = $('recipient').value.trim();
  const amount = parseAmount(amt);
  const capacityError = amount ? capError(amount.raw) : 'enter valid amount';
  if (capacityError) {
    showStatus('err', capacityError);
    validateForm();
    return;
  }
  if (_dir === 'o2e') {
    $('cm-title').textContent = 'confirm: lock OCT';
    $('cm-action').textContent = 'lock OCT -> mint wOCT';
    $('cm-amount').textContent = amt + ' OCT';
    $('cm-from').textContent = _octraAddr.substring(0, 14) + '...';
    $('cm-to').textContent = recip;
    $('cm-receive').textContent = amt + ' wOCT';
    $('cm-warning').textContent = 'OCT will be locked on octra. Ethereum rechecks the live mint cap at claim.';
    $('cm-confirm-btn').textContent = 'lock & bridge';
  } else {
    $('cm-title').textContent = 'confirm: burn wOCT';
    $('cm-action').textContent = 'burn wOCT -> unlock OCT';
    $('cm-amount').textContent = amt + ' wOCT';
    $('cm-from').textContent = _ethAddr.substring(0, 10) + '...';
    $('cm-to').textContent = recip;
    $('cm-receive').textContent = amt + ' OCT';
    $('cm-warning').textContent = 'wOCT will be burned on ethereum. OCT will be unlocked on octra (~2 min).';
    $('cm-confirm-btn').textContent = 'burn & bridge';
  }
  $('confirm-modal').classList.add('show');
}

function closeModal() { $('confirm-modal').classList.remove('show'); }

async function confirmBridge() {
  closeModal();
  await refreshBridgeCapacity();
  const amount = parseAmount($('bridge-amount').value);
  const capacityError = amount ? capError(amount.raw) : 'enter valid amount';
  if (capacityError) {
    showStatus('err', capacityError);
    validateForm();
    return;
  }
  if (_dir === 'o2e') await doForward();
  else await doReverse();
}

var _pendingClaim = null;

var _activeHistoryId = null;

async function doForward() {
  if (!_ethProvider || !_ethAddr) { showStatus('err', 'connect metamask first'); return; }
  if (!await ensureCorrectChain()) return;
  var amt = $('bridge-amount').value.trim();
  var recip = $('recipient').value.trim();
  var rawAmt = parseU(amt, OCT_DECIMALS);
  var btn = $('bridge-btn');
  btn.disabled = true; btn.classList.add('loading'); btn.textContent = 'bridging...';
  clearStatus();

  _pendingClaim = null;
  _activeHistoryId = null;
  var oldClaimBtn = $('claim-btn');
  if (oldClaimBtn) oldClaimBtn.remove();
  showProgress([
    { id: 'lock', text: 'locking ' + amt + ' OCT on octra...' },
    { id: 'confirm', text: 'waiting for epoch confirmation...' },
    { id: 'header', text: 'waiting for bridge header on ethereum...' },
    { id: 'claim', text: 'claim wOCT (your MetaMask transaction)...' }
  ]);
  setStep('lock', 'active');
  try {
    var r = await wcli('POST', '/contract/call', {
      address: BRIDGE_VAULT, method: 'lock_to_eth', params: [recip], amount: rawAmt, ou: '1000'
    });
    if (!r.tx_hash) throw new Error('no tx_hash');
    setStep('lock', 'done'); setStep('confirm', 'active');
    showStatus('info', 'locked! <a href="https://octrascan.io/tx.html?hash=' + r.tx_hash + '" target="_blank" style="color:#3B567F">' + r.tx_hash.substring(0, 16) + '...</a>');

    _activeHistoryId = 'lock_' + r.tx_hash.substring(0, 10) + '_' + Date.now();
    historyAdd({
      id: _activeHistoryId,
      locked_at: Date.now(),
      lock_tx_hash: r.tx_hash,
      epoch: 0,
      recipient: recip,
      amount_raw: rawAmt,
      amt_display: amt,
      status: 'pending_header'
    });

    var receipt = await waitReceipt(r.tx_hash, 60);
    if (!receipt || !receipt.success) {
      if (_activeHistoryId) historyUpdate(_activeHistoryId, {last_error:'lock tx not confirmed in 60s, check refresh status later'});
      throw new Error('lock transaction failed');
    }
    setStep('confirm', 'done'); setStep('header', 'active');
    showStatus('info', 'OCT locked. waiting for bridge header (~1-2 min)...');

    var epochId = receipt.epoch || 0;
    if (!epochId) {
      var txInfo = await wcli('GET', '/transaction?hash=' + r.tx_hash);
      epochId = txInfo.epoch || 0;
    }

    if (_activeHistoryId) historyUpdate(_activeHistoryId, {epoch: epochId});

    var claimData = await waitForClaimData(epochId, recip, rawAmt);
    if (!claimData) throw new Error('bridge header not yet available, pls check history below - it will auto resume when header lands on eth');

    showStatus('info', 'signer returned header. verifying it landed on ethereum...');
    var simOk = false;
    var simAttempts = 0;
    var simMaxAttempts = 60;
    var lastSimErr = '';
    while (simAttempts < simMaxAttempts) {
      try {
        await _ethProvider.request({
          method: 'eth_call',
          params: [{ from: _ethAddr, to: ETH_BRIDGE, data: claimData.calldata }, 'latest']
        });
        simOk = true;
        break;
      } catch(simErr) {
        lastSimErr = (simErr && (simErr.message || JSON.stringify(simErr))) || 'unknown';
        simAttempts++;
        showStatus('info', 'header not yet on ethereum. waiting for relayer ' + simAttempts + '/' + simMaxAttempts + ' (retry in 5s)...');
        await new Promise(function(r) { setTimeout(r, 5000); });
      }
    }
    if (!simOk) {
      if (_activeHistoryId) historyUpdate(_activeHistoryId, {claim_data:claimData, last_error:lastSimErr});
      throw new Error('header not verified on ethereum after 5 min. your lock is in history below - click "refresh status" there once relayer submits. last error: ' + lastSimErr);
    }

    setStep('header', 'done'); setStep('claim', 'active');
    _pendingClaim = claimData;
    if (_activeHistoryId) historyUpdate(_activeHistoryId, {status:'claimable', claim_data:claimData});
    showClaimButton(amt);
    showStatus('info', 'bridge header verified on ethereum. click button to claim your wOCT:');
  } catch(e) { showStatus('err', e.message); setCurrentStepFail(); }
  btn.classList.remove('loading'); validateForm();
}

function showClaimButton(amt) {
  showStatus('info', 'bridge header ready. claim your wOCT:');
  var existing = $('claim-btn');
  if (existing) existing.remove();
  var area = $('progress-area');
  var btn = document.createElement('button');
  btn.id = 'claim-btn';
  btn.textContent = 'claim on ethereum ' + amt + ' wOCT';
  btn.style.cssText = 'width:100%;padding:12px;font-size:13px;font-weight:600;border:none;cursor:pointer;background:#3B567F;color:#fff;margin-top:10px;font-family:Tahoma,arial,sans-serif';
  btn.onclick = doClaim;
  area.appendChild(btn);
}

async function waitForReceipt(txHash, timeoutMs) {
  var start = Date.now();
  var interval = 3000;
  while (Date.now() - start < timeoutMs) {
    try {
      var receipt = await _ethProvider.request({
        method: 'eth_getTransactionReceipt',
        params: [txHash]
      });
      if (receipt && receipt.blockNumber) {
        return receipt;
      }
    } catch(e) {}
    await new Promise(function(r) { setTimeout(r, interval); });
  }
  return null;
}

async function getSafeGas() {
  var floor = 10000000000n;
  var priority = 2000000000n;
  try {
    var gasPriceHex = await _ethProvider.request({method: 'eth_gasPrice'});
    var current = BigInt(gasPriceHex);
    var doubled = current * 2n;
    var maxFee = doubled > floor ? doubled : floor;
    return {
      maxFeePerGas: '0x' + maxFee.toString(16),
      maxPriorityFeePerGas: '0x' + priority.toString(16)
    };
  } catch(e) {
    return {
      maxFeePerGas: '0x2540be400',
      maxPriorityFeePerGas: '0x77359400'
    };
  }
}

async function doClaim() {
  if (!_pendingClaim) return;
  if (!await ensureCorrectChain()) return;
  var claimBtn = $('claim-btn');
  if (claimBtn) { claimBtn.disabled = true; claimBtn.textContent = 'submitting...'; }
  var explorerBase = (typeof ETH_EXPLORER !== 'undefined' && ETH_EXPLORER) ? ETH_EXPLORER : 'https://etherscan.io';
  var claimTx = null;
  try {
    var c = _pendingClaim;

    if (claimBtn) { claimBtn.textContent = 'verifying...'; }
    try {
      await _ethProvider.request({
        method: 'eth_call',
        params: [{ from: _ethAddr, to: ETH_BRIDGE, data: c.calldata }, 'latest']
      });
    } catch(simErr) {
      if (claimBtn) { claimBtn.disabled = false; claimBtn.textContent = 'claim on ethereum (retry)'; }
      showStatus('err', 'claim would revert right now. header may have been evicted or state changed. pending claim preserved - click button to retry in a few seconds.');
      return;
    }

    if (claimBtn) { claimBtn.textContent = 'submitting to metamask...'; }
    var gas = await getSafeGas();
    claimTx = await _ethProvider.request({
      method: 'eth_sendTransaction',
      params: [{ from: _ethAddr, to: ETH_BRIDGE, data: c.calldata, gas: '0x60000', maxFeePerGas: gas.maxFeePerGas, maxPriorityFeePerGas: gas.maxPriorityFeePerGas }]
    });
  } catch(e) {
    if (claimBtn) { claimBtn.disabled = false; claimBtn.textContent = 'claim on ethereum (retry)'; }
    showStatus('err', 'claim cancelled or rejected. click button to try again.');
    return;
  }

  if (claimBtn) { claimBtn.textContent = 'waiting for confirmation...'; }
  showStatus('info', 'tx submitted: <a href="' + explorerBase + '/tx/' + claimTx + '" target="_blank" style="color:#3B567F">' + claimTx.slice(0, 10) + '...</a> waiting for confirmation');

  var receipt = await waitForReceipt(claimTx, 300000);

  if (!receipt) {
    if (claimBtn) { claimBtn.disabled = false; claimBtn.textContent = 'claim on ethereum (retry)'; }
    showStatus('err', 'tx not confirmed in 5 min. it may still land later, or was dropped. pending claim is preserved - refresh page to retry.');
    return;
  }

  if (receipt.status !== '0x1') {
    if (claimBtn) { claimBtn.disabled = false; claimBtn.textContent = 'claim on ethereum (retry)'; }
    showStatus('err', 'tx reverted on-chain. <a href="' + explorerBase + '/tx/' + claimTx + '" target="_blank" style="color:#3B567F">view on etherscan</a> - pending claim preserved, click button to retry.');
    return;
  }

  setStep('claim', 'done');
  if (claimBtn) claimBtn.remove();
  showStatus('ok', 'wOCT claimed! <a href="' + explorerBase + '/tx/' + claimTx + '" target="_blank" style="color:#3B567F">view on etherscan</a>');
  _pendingClaim = null;
  if (_activeHistoryId) {
    historyUpdate(_activeHistoryId, {status:'claimed', claim_tx_hash:claimTx});
    _activeHistoryId = null;
  }
  await refreshBalances();
  await refreshBridgeCapacity();
}

function historyLoad() {
  try {
    const rows = JSON.parse(localStorage.getItem('bridge_history') || '[]');
    return Array.isArray(rows) ? rows.slice(0, 50) : [];
  } catch(e) {
    return [];
  }
}

function historySave(arr) {
  try {
    const rows = Array.isArray(arr) ? arr.slice(0, 50) : [];
    localStorage.setItem('bridge_history', JSON.stringify(rows));
  } catch(e) {}
}

var _historyShowAll = false;
var _historyPageSize = 5;

function historyToggleShowAll() {
  _historyShowAll = !_historyShowAll;
  historyRender();
}

function historyGet(id) {
  var arr = historyLoad();
  for (var i = 0; i < arr.length; i++) if (arr[i].id === id) return arr[i];
  return null;
}

function historyAdd(entry) {
  var arr = historyLoad();
  arr.unshift(entry);
  historySave(arr);
  historyRender();
  return entry;
}

function historyUpdate(id, patch) {
  var arr = historyLoad();
  for (var i = 0; i < arr.length; i++) {
    if (arr[i].id === id) {
      for (var k in patch) arr[i][k] = patch[k];
      break;
    }
  }
  historySave(arr);
  historyRender();
}

function historyRemove(id) {
  var arr = historyLoad().filter(function(e) { return e.id !== id; });
  historySave(arr);
  historyRender();
}

function historyRender() {
  var arr = historyLoad();
  var sec = document.getElementById('history-section');
  var list = document.getElementById('history-list');
  if (!sec || !list) return;
  sec.style.display = 'block';
  list.innerHTML = '';
  if (arr.length === 0) {
    list.innerHTML = '<div style="text-align:center;color:#8C9DB6;padding:8px;font-size:11px">no bridge activity yet - your locks will appear here</div>';
    return;
  }
  var labels = {
    pending_header: 'waiting', claimable: 'claim', claiming: 'claiming...',
    claimed: 'claimed', expired: 'expired', failed: 'failed',
    burning: 'burning', burn_pending: 'unlocking...', unlocked: 'unlocked'
  };
  var visible = _historyShowAll ? arr : arr.slice(0, _historyPageSize);
  for (var i = 0; i < visible.length; i++) {
    var e = visible[i];
    var d = new Date(e.locked_at);
    var validDate = Number.isFinite(d.getTime());
    var hh = validDate ? String(d.getHours()).padStart(2, '0') : '--';
    var mm = validDate ? String(d.getMinutes()).padStart(2, '0') : '--';
    var recipient = typeof e.recipient === 'string' ? e.recipient : '';
    var toShort = recipient ? (recipient.substr(0, 6) + '...' + recipient.substr(-4)) : '';
    var cls = 'pending';
    if (e.status === 'claimable') cls = 'claimable';
    else if (e.status === 'claimed' || e.status === 'unlocked') cls = 'claimed';
    else if (e.status === 'expired') cls = 'expired';
    else if (e.status === 'failed') cls = 'failed';
    else if (e.status === 'claiming' || e.status === 'burn_pending') cls = 'claiming';
    var isReverse = e.direction === 'e2o';
    var srcToken = isReverse ? 'wOCT' : 'OCT';
    var amount = typeof e.amt_display === 'string' ? e.amt_display : '?';
    var topLine = '<div class="hs-top"><span class="hs-amount">' + esc(amount) + ' ' + srcToken + '</span> -&gt; <span class="hs-to">' + esc(toShort) + '</span></div>';
    var midLine;
    if (isReverse) {
      var burnHash = typeof e.burn_tx_hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(e.burn_tx_hash) ? e.burn_tx_hash : '';
      var burnLink = burnHash ? ('<a href="https://etherscan.io/tx/' + burnHash + '" target="_blank" rel="noopener noreferrer" style="color:#3B567F;text-decoration:none">' + hh + ':' + mm + '</a>') : (hh + ':' + mm);
      var burnTag = burnHash ? (' | burn ' + burnHash.slice(0, 8) + '...') : '';
      var validRecipient = /^oct[1-9A-HJ-NP-Za-km-z]{44}$/.test(recipient);
      var unlockInfo = e.status === 'unlocked' && validRecipient ? (' | <a href="https://octrascan.io/address.html?addr=' + recipient + '" target="_blank" rel="noopener noreferrer" style="color:#4CAF50;text-decoration:none">view</a>') : '';
      midLine = '<div class="hs-time">' + burnLink + burnTag + unlockInfo + '</div>';
    } else {
      var lockHash = typeof e.lock_tx_hash === 'string' && /^[0-9a-fA-F]{64}$/.test(e.lock_tx_hash) ? e.lock_tx_hash : '';
      var claimHash = typeof e.claim_tx_hash === 'string' && /^0x[0-9a-fA-F]{64}$/.test(e.claim_tx_hash) ? e.claim_tx_hash : '';
      var lockLink = lockHash ? ('<a href="https://octrascan.io/tx.html?hash=' + lockHash + '" target="_blank" rel="noopener noreferrer" style="color:#3B567F;text-decoration:none">' + hh + ':' + mm + '</a>') : (hh + ':' + mm);
      var claimInfo = claimHash ? (' | <a href="https://etherscan.io/tx/' + claimHash + '" target="_blank" rel="noopener noreferrer" style="color:#4CAF50;text-decoration:none">view</a>') : '';
      var epoch = Number.isSafeInteger(e.epoch) && e.epoch > 0 ? e.epoch : 0;
      var epTag = epoch ? (' | ep ' + epoch) : ' | ep pending';
      midLine = '<div class="hs-time">' + lockLink + epTag + claimInfo + '</div>';
    }
    var row = document.createElement('div');
    row.className = 'hs-item';
    row.innerHTML =
      '<div class="hs-main">' + topLine + midLine + '</div>' +
      '<div class="hs-status ' + cls + '">' + esc(labels[e.status] || 'waiting') + '</div>';
    var statusEl = row.querySelector('.hs-status');
    if (e.status === 'claimable') {
      statusEl.onclick = (function(id) { return function() { historyClaim(id); }; })(e.id);
    }
    list.appendChild(row);
  }
  if (arr.length > _historyPageSize) {
    var toggle = document.createElement('div');
    toggle.style.cssText = 'text-align:center;padding:8px 0;font-size:10px;color:#3B567F;cursor:pointer;border-top:1px solid #F0F2F5;margin-top:4px';
    if (_historyShowAll) {
      toggle.textContent = 'show less';
    } else {
      toggle.textContent = 'show all (' + (arr.length - _historyPageSize) + ' more)';
    }
    toggle.onclick = historyToggleShowAll;
    list.appendChild(toggle);
  }
}

function historyClearOld() {
  var arr = historyLoad();
  var now = Date.now();
  var kept = arr.filter(function(e) {
    if (e.status === 'claimed' || e.status === 'unlocked') return now - e.locked_at < 86400000;
    if (e.status === 'expired' || e.status === 'failed') return false;
    return true;
  });
  historySave(kept);
  historyRender();
}

async function historyCheckE2o(entry) {
  if (!entry.burn_tx_hash) { historyUpdate(entry.id, {last_checked:Date.now()}); return; }
  if (!_ethProvider) { historyUpdate(entry.id, {last_checked:Date.now()}); return; }
  try {
    var r = await _ethProvider.request({method:'eth_getTransactionReceipt', params:[entry.burn_tx_hash]});
    if (!r) { historyUpdate(entry.id, {last_checked:Date.now()}); return; }
    if (r.status === '0x0') {
      historyUpdate(entry.id, {status:'failed', last_error:'burn tx reverted', last_checked:Date.now()});
      return;
    }
    if (entry.status === 'burning') {
      historyUpdate(entry.id, {status:'burn_pending', last_checked:Date.now(), last_error:null});
    } else {
      historyUpdate(entry.id, {last_checked:Date.now()});
    }
  } catch(e) {
    historyUpdate(entry.id, {last_checked:Date.now(), last_error:(e.message || 'receipt check failed')});
  }
}

async function historyCheckOne(entry) {
  if (entry.status === 'claimed' || entry.status === 'claiming' || entry.status === 'unlocked') return;
  if (Date.now() - entry.locked_at > 86400000) {
    if (entry.status !== 'expired') historyUpdate(entry.id, {status:'expired', last_checked:Date.now()});
    return;
  }
  if (entry.direction === 'e2o') return historyCheckE2o(entry);
  if (!entry.epoch && entry.lock_tx_hash) {
    try {
      var txi = await wcli('GET', '/transaction?hash=' + entry.lock_tx_hash);
      if (txi && txi.epoch) {
        historyUpdate(entry.id, {epoch: txi.epoch});
        entry.epoch = txi.epoch;
      } else {
        historyUpdate(entry.id, {last_checked:Date.now(), last_error:'tx not finalized yet'});
        return;
      }
    } catch(e) {
      historyUpdate(entry.id, {last_checked:Date.now(), last_error:'epoch lookup failed'});
      return;
    }
  }
  if (!entry.epoch) return;
  try {
    var rpcBody = JSON.stringify({jsonrpc:'2.0',id:1,method:'bridgeHeader',params:[entry.epoch]});
    var resp = await fetch(SIGNER_URL, {method:'POST', headers:{'Content-Type':'application/json'}, body:rpcBody}).catch(function(){return null;});
    if (!resp || !resp.ok) { historyUpdate(entry.id, {last_checked:Date.now(), last_error:'signer unreachable'}); return; }
    var data = await resp.json();
    if (!data.result || !data.result.message_count) { historyUpdate(entry.id, {last_checked:Date.now()}); return; }
    var claimData = await buildClaimCalldata(entry.epoch, entry.recipient, entry.amount_raw, data.result);
    if (!claimData) { historyUpdate(entry.id, {last_checked:Date.now(), last_error:'no claim calldata'}); return; }
    if (_ethProvider && _ethAddr) {
      try {
        await _ethProvider.request({method:'eth_call', params:[{from:_ethAddr, to:ETH_BRIDGE, data:claimData.calldata}, 'latest']});
        historyUpdate(entry.id, {status:'claimable', claim_data:claimData, last_checked:Date.now(), last_error:null});
      } catch(err) {
        var m = (err && (err.message || String(err))) || '';
        var d = (err && err.data) ? (typeof err.data === 'string' ? err.data : (err.data.data || err.data.originalError && err.data.originalError.data || '')) : '';
        var ml = m.toLowerCase();
        var isReplay = ml.indexOf('already') >= 0 || ml.indexOf('replay') >= 0 || d === '0xb5a78004' || m.indexOf('0xb5a78004') >= 0;
        var isUnknownHeader = d === '0xa2ad39b9' || m.indexOf('0xa2ad39b9') >= 0;
        var isCapExceeded = d === '0xa4875a49' || m.indexOf('0xa4875a49') >= 0;
        var isInvalidProof = d === '0x09bde339' || m.indexOf('0x09bde339') >= 0;
        if (isReplay) {
          historyUpdate(entry.id, {status:'claimed', last_checked:Date.now(), last_error:null});
        } else if (isUnknownHeader) {
          historyUpdate(entry.id, {claim_data:claimData, last_checked:Date.now(), last_error:'header not yet on ethereum'});
        } else if (isCapExceeded) {
          historyUpdate(entry.id, {claim_data:claimData, last_checked:Date.now(), last_error:'bridge mint cap too low for this amount'});
        } else if (isInvalidProof) {
          historyUpdate(entry.id, {claim_data:claimData, last_checked:Date.now(), last_error:'merkle proof invalid (signer out of sync)'});
        } else {
          historyUpdate(entry.id, {claim_data:claimData, last_checked:Date.now(), last_error:m});
        }
      }
    } else {
      historyUpdate(entry.id, {claim_data:claimData, last_checked:Date.now()});
    }
  } catch(e) {
    historyUpdate(entry.id, {last_checked:Date.now(), last_error:e.message});
  }
}

async function historyCheckAll() {
  var arr = historyLoad();
  for (var i = 0; i < arr.length; i++) {
    var e = arr[i];
    if (e.status === 'claimed' || e.status === 'expired' || e.status === 'claiming' || e.status === 'unlocked') continue;
    await historyCheckOne(e);
  }
}

var _historyPollTimer = null;
var _historyPollBusy = false;

function historyHasActive() {
  var arr = historyLoad();
  for (var i = 0; i < arr.length; i++) {
    var s = arr[i].status;
    if (s !== 'claimed' && s !== 'unlocked' && s !== 'expired' && s !== 'failed') return true;
  }
  return false;
}

function startHistoryAutoPoll() {
  if (_historyPollTimer) return;
  _historyPollTimer = setInterval(async function() {
    if (_historyPollBusy) return;
    if (document.hidden) return;
    if (!historyHasActive()) return;
    _historyPollBusy = true;
    try { await historyCheckAll(); } catch(e) {}
    _historyPollBusy = false;
  }, 10000);
}

async function historyRefreshAll() {
  showStatus('info', 'refreshing history...');
  await historyCheckAll();
  var arr = historyLoad();
  var pending = arr.filter(function(e){return e.status==='pending_header';}).length;
  var claimable = arr.filter(function(e){return e.status==='claimable';}).length;
  showStatus('info', 'history refreshed: ' + claimable + ' claimable, ' + pending + ' waiting');
}

async function historyClaim(id) {
  var entry = historyGet(id);
  if (!entry) return;
  if (!_ethProvider || !_ethAddr) { showStatus('err', 'connect metamask first'); return; }
  if (!await ensureCorrectChain()) return;
  historyUpdate(id, {status:'claiming'});
  showStatus('info', 'submitting claim: ' + entry.amt_display + ' wOCT ep ' + entry.epoch);
  try {
    var claimData = await buildClaimCalldata(entry.epoch, _ethAddr, entry.amount_raw, null);
    if (!claimData) {
      historyUpdate(id, {status:'claimable', last_error:'canonical claim data unavailable'});
      showStatus('err', 'canonical claim data unavailable');
      return;
    }
    historyUpdate(id, {claim_data:claimData});
    try {
      await _ethProvider.request({method:'eth_call', params:[{from:_ethAddr, to:ETH_BRIDGE, data:claimData.calldata}, 'latest']});
    } catch(simErr) {
      var em = (simErr && (simErr.message || String(simErr))) || '';
      var ed = (simErr && simErr.data) ? (typeof simErr.data === 'string' ? simErr.data : (simErr.data.data || simErr.data.originalError && simErr.data.originalError.data || '')) : '';
      var eml = em.toLowerCase();
      var simReplay = eml.indexOf('already') >= 0 || eml.indexOf('replay') >= 0 || ed === '0xb5a78004' || em.indexOf('0xb5a78004') >= 0;
      if (simReplay) {
        historyUpdate(id, {status:'claimed', last_error:null});
        showStatus('info', 'already claimed on-chain (detected during sim). marked as claimed.');
        await refreshBalances();
        return;
      }
      historyUpdate(id, {status:'claimable', last_error:em});
      showStatus('err', 'claim would revert: ' + em);
      return;
    }
    var gasFees = await getSafeGas();
    var txReq = {from:_ethAddr, to:ETH_BRIDGE, data:claimData.calldata};
    for (var k in gasFees) txReq[k] = gasFees[k];
    var txHash = await _ethProvider.request({method:'eth_sendTransaction', params:[txReq]});
    historyUpdate(id, {claim_tx_hash:txHash});
    showStatus('info', 'tx submitted: <a href="https://etherscan.io/tx/' + txHash + '" target="_blank" style="color:#3B567F">' + txHash.slice(0,10) + '...</a>');
    var receipt = await waitForReceipt(txHash, 300000);
    if (!receipt) {
      historyUpdate(id, {status:'claimable'});
      showStatus('err', 'tx not confirmed in 5 min, will retry on refresh');
      return;
    }
    if (receipt.status === '0x0') {
      historyUpdate(id, {status:'claimable', last_error:'tx reverted'});
      showStatus('err', 'tx reverted. <a href="https://etherscan.io/tx/' + txHash + '" target="_blank" style="color:#E57373">view</a>');
      return;
    }
    historyUpdate(id, {status:'claimed', claim_tx_hash:txHash});
    showStatus('ok', 'wOCT claimed! <a href="https://etherscan.io/tx/' + txHash + '" target="_blank" style="color:#4CAF50">view</a>');
    await refreshBalances();
    await refreshBridgeCapacity();
  } catch(e) {
    historyUpdate(id, {status:'claimable', last_error:e.message});
    showStatus('err', 'claim failed: ' + e.message);
  }
}

function historyMigrateLegacy() {
  try {
    var oldLock = localStorage.getItem('bridge_pending_lock');
    if (oldLock) {
      var l = JSON.parse(oldLock);
      if (!historyGet('legacy_lock_' + l.epoch)) {
        historyAdd({
          id: 'legacy_lock_' + l.epoch + '_' + Date.now(),
          locked_at: l.started_at || Date.now(),
          lock_tx_hash: l.lock_tx_hash || '',
          epoch: l.epoch,
          recipient: l.recipient,
          amount_raw: l.amount_raw,
          amt_display: l.amt_display || String(l.amount_raw),
          status: 'pending_header'
        });
      }
      localStorage.removeItem('bridge_pending_lock');
    }
  } catch(e) {}
  try {
    var oldClaim = localStorage.getItem('bridge_pending_claim');
    if (oldClaim) {
      var c = JSON.parse(oldClaim);
      var ep = c.claim && c.claim.epoch_id ? c.claim.epoch_id : 0;
      if (ep) {
        historyAdd({
          id: 'legacy_claim_' + ep + '_' + Date.now(),
          locked_at: Date.now(),
          lock_tx_hash: '',
          epoch: ep,
          recipient: _ethAddr || '',
          amount_raw: 0,
          amt_display: c.amt || '?',
          status: 'claimable',
          claim_data: c.claim
        });
      }
      localStorage.removeItem('bridge_pending_claim');
    }
  } catch(e) {}
}

function historyHasMessage(mid, epoch, recipLower, amountRaw) {
  if (!mid && !(epoch && recipLower && amountRaw)) return false;
  var arr = historyLoad();
  for (var i = 0; i < arr.length; i++) {
    var e = arr[i];
    if (mid && e.message_id && e.message_id.toLowerCase() === mid.toLowerCase()) return true;
    if (mid && e.claim_data && e.claim_data.message && e.claim_data.message.message_id && e.claim_data.message.message_id.toLowerCase() === mid.toLowerCase()) return true;
    if (epoch && recipLower && amountRaw) {
      if (e.epoch === epoch && (e.recipient || '').toLowerCase() === recipLower && String(e.amount_raw) === String(amountRaw)) return true;
    }
  }
  return false;
}

async function recoveryFetch(silent) {
  if (!_ethAddr) {
    if (!silent) showStatus('err', 'connect metamask first to scan for recoverable bridges');
    return 0;
  }
  var target = _ethAddr.toLowerCase();
  try {
    if (!silent) showStatus('info', 'scanning recovery feed...');
    var resp = await fetch(RECOVERY_URL, {method:'GET', cache:'no-store'});
    if (!resp.ok) { if (!silent) showStatus('err', 'recovery feed unreachable (' + resp.status + ')'); return 0; }
    var data = await resp.json();
    var by = data && data.by_recipient ? data.by_recipient : {};
    var bucket = by[target] || by[_ethAddr] || [];
    if (!Array.isArray(bucket) || bucket.length === 0) {
      if (!silent) showStatus('info', 'no recoverable bridges found for ' + _ethAddr.substring(0,8) + '...' + _ethAddr.slice(-4));
      return 0;
    }
    var added = 0;
    var candidates = bucket.slice(0, 100);
    for (var i = 0; i < candidates.length; i++) {
      var m = candidates[i];
      if (!m || typeof m !== 'object') continue;
      var mid = typeof m.message_id === 'string' && /^0x[0-9a-fA-F]{64}$/.test(m.message_id) ? m.message_id : '';
      var ep = typeof m.epoch === 'number' ? m.epoch : parseInt(m.epoch, 10);
      var amtRaw = String(m.amount_raw || '');
      if (!Number.isSafeInteger(ep) || ep <= 0 || !/^[1-9]\d{0,38}$/.test(amtRaw)) continue;
      if (historyHasMessage(mid, ep, target, amtRaw)) continue;
      var amtDisplay = fmtU(amtRaw, OCT_DECIMALS);
      var foundAt = Number(m.found_at);
      var lockedAt = Number.isSafeInteger(foundAt) && foundAt > 0 ? foundAt * 1000 : Date.now();
      var txHash = typeof m.tx_hash === 'string' && /^[0-9a-fA-F]{64}$/.test(m.tx_hash) ? m.tx_hash : '';
      historyAdd({
        id: 'recovered_' + (mid ? mid.substring(2, 12) : ep + '_' + i) + '_' + Date.now(),
        locked_at: lockedAt,
        lock_tx_hash: txHash,
        epoch: ep,
        recipient: _ethAddr,
        amount_raw: amtRaw,
        amt_display: amtDisplay,
        status: 'pending_header',
        message_id: mid,
        recovered: true
      });
      added += 1;
    }
    if (added > 0) {
      if (!silent) showStatus('ok', 'imported ' + added + ' recoverable bridge' + (added === 1 ? '' : 's') + ', checking status...');
      await historyCheckAll();
      var arr2 = historyLoad();
      var claimable = arr2.filter(function(e){return e.status==='claimable';}).length;
      if (!silent) showStatus('ok', 'recovery done: ' + claimable + ' ready to claim now');
    } else {
      if (!silent) showStatus('info', 'all found bridges are already in your history');
    }
    return added;
  } catch(e) {
    if (!silent) showStatus('err', 'recovery failed: ' + (e.message || 'unknown'));
    return 0;
  }
}

async function checkPendingClaim() {
  try {
    historyMigrateLegacy();
    historyRender();
    await historyCheckAll();
    startHistoryAutoPoll();
  } catch(e) { showStatus('err', 'history check failed: ' + e.message); }
}

async function waitForClaimData(epochId, recipient, rawAmt) {
  var start = Date.now();
  while (Date.now() - start < 300000) {
    try {
      var rpcBody = JSON.stringify({jsonrpc:'2.0',id:1,method:'bridgeHeader',params:[epochId]});
      var resp = await fetch(SIGNER_URL, {
        method: 'POST', headers: {'Content-Type':'application/json'}, body: rpcBody
      }).catch(function() { return null; });
      if (resp && resp.ok) {
        var data = await resp.json();
        if (data.result && data.result.message_count > 0) {
          return await buildClaimCalldata(epochId, recipient, rawAmt, data.result);
        }
      }
    } catch(e) {}
    await sleep(5000);
  }
  return null;
}

async function buildClaimCalldata(epochId, recipient, rawAmt, headerData) {
  try {
    var msgBody = JSON.stringify({jsonrpc:'2.0',id:1,method:'bridgeMessagesByEpoch',params:[epochId]});
    var msgResp = await fetch(SIGNER_URL, {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: msgBody
    });
    var msgData = await msgResp.json();
    var messages = msgData.result.messages;
    var myMsg = messages.find(function(m) {
      return m.recipient.toLowerCase() === recipient.toLowerCase()
        && String(m.amount) === String(rawAmt);
    });
    if (!myMsg) return null;

    var cdBody = JSON.stringify({jsonrpc:'2.0',id:1,method:'bridgeClaimCalldata',params:[epochId, myMsg.leaf_index]});
    var cdResp = await fetch(SIGNER_URL, {
      method: 'POST', headers: {'Content-Type':'application/json'}, body: cdBody
    });
    var cdData = await cdResp.json();
    if (cdData.result && cdData.result.calldata) {
      return { calldata: cdData.result.calldata, epochId: epochId, message: myMsg };
    }
    return null;
  } catch(e) { return null; }
}

async function doReverse() {
  if (!_ethProvider || !_ethAddr) { showStatus('err', 'connect metamask first'); return; }
  if (!await ensureCorrectChain()) return;
  var amt = $('bridge-amount').value.trim();
  var recip = $('recipient').value.trim();
  var rawAmt = parseU(amt, OCT_DECIMALS);
  var btn = $('bridge-btn');
  btn.disabled = true; btn.classList.add('loading'); btn.textContent = 'bridging...';
  clearStatus();
  showProgress([
    { id: 'approve', text: 'approving wOCT spend...' },
    { id: 'burn', text: 'burning ' + amt + ' wOCT...' },
    { id: 'unlock', text: 'unlocking OCT on octra...' }
  ]);
  setStep('approve', 'active');
  var burnHistoryId = null;
  try {
    var gas1 = await getSafeGas();
    var approveData = '0x095ea7b3' + ETH_BRIDGE.substring(2).toLowerCase().padStart(64, '0') + BigInt(rawAmt).toString(16).padStart(64, '0');
    var approveTx = await _ethProvider.request({
      method: 'eth_sendTransaction',
      params: [{ from: _ethAddr, to: WOCT_ADDR, data: approveData, gas: '0x30000', maxFeePerGas: gas1.maxFeePerGas, maxPriorityFeePerGas: gas1.maxPriorityFeePerGas }]
    });
    var approveReceipt = await waitForReceipt(approveTx, 300000);
    if (!approveReceipt || approveReceipt.status !== '0x1') {
      showStatus('err', 'approve tx failed or dropped. your wOCT is still in the wallet - try again.');
      setCurrentStepFail();
      btn.classList.remove('loading'); validateForm();
      return;
    }
    setStep('approve', 'done'); setStep('burn', 'active');

    var gas2 = await getSafeGas();
    var burnSig = '0xe3e3aed0';
    var encoded = abiEncodeStringUint(recip, rawAmt);
    var burnData = burnSig + encoded;
    var burnTx = await _ethProvider.request({
      method: 'eth_sendTransaction',
      params: [{ from: _ethAddr, to: ETH_BRIDGE, data: burnData, gas: '0x40000', maxFeePerGas: gas2.maxFeePerGas, maxPriorityFeePerGas: gas2.maxPriorityFeePerGas }]
    });
    burnHistoryId = 'burn_' + burnTx.slice(2, 10) + '_' + Date.now();
    historyAdd({
      id: burnHistoryId,
      direction: 'e2o',
      locked_at: Date.now(),
      burn_tx_hash: burnTx,
      approve_tx_hash: approveTx,
      recipient: recip,
      amount_raw: rawAmt,
      amt_display: amt,
      status: 'burning'
    });
    var explorerBase2 = (typeof ETH_EXPLORER !== 'undefined' && ETH_EXPLORER) ? ETH_EXPLORER : 'https://etherscan.io';
    showStatus('info', 'burn tx submitted: <a href="' + explorerBase2 + '/tx/' + burnTx + '" target="_blank" style="color:#3B567F">' + burnTx.slice(0, 10) + '...</a> waiting for confirmation');
    var burnReceipt = await waitForReceipt(burnTx, 300000);
    if (!burnReceipt) {
      showStatus('err', 'burn tx not confirmed in 5 min. may still land later or was dropped. your wOCT is still in the wallet - try again.');
      setCurrentStepFail();
      if (burnHistoryId) historyUpdate(burnHistoryId, {status:'failed', last_error:'not confirmed in 5 min'});
      btn.classList.remove('loading'); validateForm();
      return;
    }
    if (burnReceipt.status !== '0x1') {
      showStatus('err', 'burn tx reverted on-chain. <a href="' + explorerBase2 + '/tx/' + burnTx + '" target="_blank" style="color:#3B567F">view on etherscan</a> - your wOCT is still in the wallet.');
      setCurrentStepFail();
      if (burnHistoryId) historyUpdate(burnHistoryId, {status:'failed', last_error:'tx reverted'});
      btn.classList.remove('loading'); validateForm();
      return;
    }
    if (burnHistoryId) historyUpdate(burnHistoryId, {status:'burn_pending'});
    await refreshBridgeCapacity();
    setStep('burn', 'done'); setStep('unlock', 'active');
    showStatus('info', 'wOCT burned. waiting for OCT unlock on octra... <a href="' + explorerBase2 + '/tx/' + burnTx + '" target="_blank" style="color:#3B567F">view tx</a>');
    var ownRecipient = recip === _octraAddr;
    var expectedOct = ownRecipient ? BigInt(_octBalance) + BigInt(rawAmt) : 0n;
    var unlocked = ownRecipient
      ? await pollUntilAtLeast(function() { return getOctBalance(); }, expectedOct, 180)
      : false;
    if (unlocked) {
      setStep('unlock', 'done');
      showStatus('ok', 'OCT unlocked! <a href="https://octrascan.io/address.html?addr=' + _octraAddr + '" target="_blank" style="color:#3B567F">view on octra</a>');
      if (burnHistoryId) historyUpdate(burnHistoryId, {status:'unlocked'});
      await refreshBalances();
    } else {
      showStatus('info', 'wOCT burned. OCT unlock may take a few minutes.');
    }
  } catch(e) {
    showStatus('err', e.message);
    setCurrentStepFail();
    if (burnHistoryId) historyUpdate(burnHistoryId, {status:'failed', last_error:(e.message || 'unknown')});
  }
  btn.classList.remove('loading'); validateForm();
}

async function waitReceipt(hash, maxWait) {
  var start = Date.now();
  while (Date.now() - start < maxWait * 1000) {
    try { var r = await wcli('GET', '/contract/receipt?hash=' + hash); if (r && r.success !== undefined) return r; } catch(e) {}
    await sleep(3000);
  }
  return null;
}

function abiEncodeStringUint(str, uint) {
  var offset = '0000000000000000000000000000000000000000000000000000000000000040';
  var uintHex = BigInt(uint).toString(16).padStart(64, '0');
  var strLen = str.length.toString(16).padStart(64, '0');
  var strHex = '';
  for (var i = 0; i < str.length; i++) strHex += str.charCodeAt(i).toString(16).padStart(2, '0');
  while (strHex.length % 64 !== 0) strHex += '0';
  return offset + uintHex + strLen + strHex;
}

var _steps = [];
function showProgress(steps) { _steps = steps; var el = $('progress-area'); el.style.display = ''; el.innerHTML = steps.map(function(s) { return '<div class="step" id="step-' + s.id + '"><span class="dot"></span>' + esc(s.text) + '</div>'; }).join(''); }
function setStep(id, state) { var el = document.getElementById('step-' + id); if (el) el.className = 'step ' + state; }
function setCurrentStepFail() { _steps.forEach(function(s) { var el = document.getElementById('step-' + s.id); if (el && el.classList.contains('active')) el.className = 'step fail'; }); }

function $(id) { return document.getElementById(id); }
function sleep(ms) { return new Promise(function(r) { setTimeout(r, ms); }); }
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function escAttr(s) {
  return String(s || '').replace(/[&<>"']/g, function(c) {
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}
function safeIconUrl(url) {
  url = String(url || '');
  if (/^data:image\/(png|jpeg|webp|gif);base64,[a-z0-9+/=]+$/i.test(url)) return url;
  if (/^https:\/\/[^\s"'<>()]+$/i.test(url)) return url;
  return '';
}
function sanitizeStatusHtml(msg) {
  var tpl = document.createElement('template');
  tpl.innerHTML = String(msg || '');
  var allowed = { A: true, B: true };
  function clean(node) {
    var children = Array.from(node.childNodes);
    children.forEach(function(child) {
      if (child.nodeType === Node.ELEMENT_NODE) {
        clean(child);
        if (!allowed[child.tagName]) {
          child.replaceWith(document.createTextNode(child.textContent || ''));
          return;
        }
        var href = child.tagName === 'A' ? (child.getAttribute('href') || '') : '';
        Array.from(child.attributes).forEach(function(attr) { child.removeAttribute(attr.name); });
        if (child.tagName === 'A') {
          try {
            var u = new URL(href, window.location.href);
            if (u.protocol === 'http:' || u.protocol === 'https:') {
              child.setAttribute('href', u.href);
              child.setAttribute('target', '_blank');
              child.setAttribute('rel', 'noopener noreferrer');
            }
          } catch (e) {}
          if (!child.getAttribute('href')) child.replaceWith(document.createTextNode(child.textContent || ''));
        }
      } else if (child.nodeType !== Node.TEXT_NODE) {
        child.remove();
      }
    });
  }
  clean(tpl.content);
  return tpl.innerHTML;
}
async function getWoctBalance() {
  if (!_ethAddr || !_ethProvider || !WOCT_ADDR) return '0';
  try {
    var data = '0x70a08231000000000000000000000000' + _ethAddr.substring(2);
    var result = await _ethProvider.request({ method: 'eth_call', params: [{ to: WOCT_ADDR, data: data }, 'latest'] });
    if (!result || result === '0x' || result === '0x0') return '0';
    return BigInt(result).toString();
  } catch(e) { return '0'; }
}

async function getOctBalance() {
  if (!_octraAddr) return '0';
  try { var b = await wcli('GET', '/balance'); return b.public_balance || '0'; } catch(e) { return '0'; }
}

async function pollUntilAtLeast(getFn, target, maxSec) {
  var start = Date.now();
  while (Date.now() - start < maxSec * 1000) {
    await sleep(5000);
    var cur = await getFn();
    if (BigInt(cur) >= target) return true;
  }
  return false;
}

function showStatus(type, msg) { var el = $('status-area'); el.className = 'status-msg ' + type; el.innerHTML = sanitizeStatusHtml(msg); }
function clearStatus() { $('status-area').className = 'status-msg'; $('status-area').textContent = ''; $('progress-area').style.display = 'none'; }
function fmtU(raw, dec) { var s = raw.toString().padStart(dec + 1, '0'); var i = s.slice(0, s.length - dec) || '0'; var f = s.slice(s.length - dec).replace(/0+$/, ''); return f ? addCommas(i) + '.' + f : addCommas(i); }
function parseU(value, dec) {
  if (dec !== OCT_DECIMALS) throw new Error('unsupported amount precision');
  const amount = parseAmount(value);
  if (!amount || amount.raw <= 0n) throw new Error('invalid amount');
  return amount.raw.toString();
}
function addCommas(s) { var p = s.split('.'); p[0] = p[0].replace(/\B(?=(\d{3})+(?!\d))/g, ','); return p.join('.'); }

connectOctra().catch(function(){});
checkPendingClaim();
refreshBridgeCapacity();
setInterval(function() { refreshBalances(); }, 10000);
setInterval(function() { refreshBridgeCapacity(); }, 60000);
setTimeout(function() {
  var saved = null;
  try { saved = localStorage.getItem('bridge_eth_wallet'); } catch(e) {}
  if (saved && _eip6963Providers.length > 0) {
    var match = _eip6963Providers.find(function(p) { return p.name === saved; });
    if (match) connectWithProvider({ name: match.name, provider: match.provider, icon: match.icon }).catch(function(){});
  }
}, 300);

(function() {
  var actions = {
    connectOctra, connectEth, setDir, validateForm, setMax, doBridge,
    historyRefreshAll, historyClearOld, closeModal, confirmBridge, closeWalletModal,
    selectWallet,
    recoveryFetch: function() { recoveryFetch(false); }
  };
  function run(e, attr) {
    var el = e.target.closest('[' + attr + ']');
    if (!el) return;
    var fn = actions[el.getAttribute(attr)];
    if (!fn) return;
    if (el.getAttribute('data-prevent') === '1') e.preventDefault();
    fn(el.getAttribute('data-arg'), el, e);
  }
  document.addEventListener('click', function(e) { run(e, 'data-action'); });
  document.addEventListener('input', function(e) { run(e, 'data-input'); });
})();