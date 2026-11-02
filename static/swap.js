// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// NikBel0x ヽ(*・ω・)ﾉ
// Julia L.
// Review: Vadim S.

var SWAP_ADDR = 'octBjnQBicZs6iMwcRxrdzLYAzyVTi91KEiA8RGkVjco2w6';
var TOKEN_ADDR = 'oct6J37Wx7Rb1putvfwFrFbGUStE8hGzsb33fhLgUdpTx6d';
var SCANNER_URL = 'https://devnet.octrascan.io';
var TOKEN_SYMBOL = 'tUSD';
var TOKEN_DECIMALS = 6;
var OCT_DECIMALS = 6;
var SWAP_FEE_OU = '100000';
var GRANT_FEE_OU = '1000';

var _dir = 'buy';
var _walletAddr = '';
var _reserveOct = '0';
var _reserveToken = '0';
var _balOctRaw = '0';
var _balTokenRaw = '0';
var _refreshId = null;
var _swapPending = false;

function $(id) { return document.getElementById(id); }

function esc(s) {
  var d = document.createElement('div');
  d.appendChild(document.createTextNode(s));
  return d.innerHTML;
}

async function api(method, path, body, session) {
  var opts = { method: method, headers: {} };
  if (session) {
    opts.headers['X-Webcli-Wallet'] = session.address;
    opts.headers['X-Webcli-Generation'] = String(session.generation);
  }
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  var res = await fetch('/api' + path, opts);
  var text = await res.text();
  if (!text || text.length === 0) throw new Error('empty response');
  var j;
  try { j = JSON.parse(text); } catch (e) { throw new Error('bad response'); }
  if (!res.ok) throw new Error(j.error || j.message || 'request failed');
  return j;
}

function addCommas(s) {
  var parts = s.split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return parts.join('.');
}

function formatUnits(rawStr, decimals) {
  return AmountUnits.format(rawStr, decimals);
}

function parseUnits(humanStr, decimals) {
  return AmountUnits.parse(humanStr, decimals);
}

function bigMul(a, b) {
  return String(BigInt(a) * BigInt(b));
}

function bigDiv(a, b) {
  if (b === '0') return '0';
  return String(BigInt(a) / BigInt(b));
}

function bigAdd(a, b) {
  return String(BigInt(a) + BigInt(b));
}

function bigSub(a, b) {
  var r = BigInt(a) - BigInt(b);
  return r < 0n ? '0' : String(r);
}

function bigGt(a, b) {
  return BigInt(a) > BigInt(b);
}

function bigGte(a, b) {
  return BigInt(a) >= BigInt(b);
}

function calcOutput(reserveIn, reserveOut, amountIn) {
  if (amountIn === '0' || reserveIn === '0') return '0';
  return bigDiv(bigMul(reserveOut, amountIn), bigAdd(reserveIn, amountIn));
}

function calcPriceImpact(reserveIn, amountIn) {
  if (reserveIn === '0' || amountIn === '0') return 0;
  return (Number(amountIn) / Number(amountIn) + Number(reserveIn)) * 100;
}

function txUrl(hash) {
  return SCANNER_URL + '/tx.html?hash=' + encodeURIComponent(hash);
}

async function checkWallet() {
  try {
    var st = await api('GET', '/wallet/status');
    if (st.loaded) {
      var info = await api('GET', '/wallet');
      _walletAddr = info.address || '';
      $('unlock-view').style.display = 'none';
      $('swap-view').style.display = 'block';
      $('wallet-addr').textContent = _walletAddr.slice(0, 8) + '...' + _walletAddr.slice(-6);
      loadAll();
      _refreshId = setInterval(loadAll, 10000);
      return;
    }
    if (st.has_encrypted || st.has_legacy) {
      $('unlock-view').style.display = 'block';
      $('swap-view').style.display = 'none';
      return;
    }
    $('unlock-view').style.display = 'block';
    $('swap-view').style.display = 'none';
    $('unlock-err').textContent = 'no wallet found. create one in the main wallet app first.';
    $('unlock-err').className = 'status-msg err';
  } catch (e) {
    $('unlock-view').style.display = 'block';
    $('swap-view').style.display = 'none';
    $('unlock-err').textContent = 'cannot connect to wallet';
    $('unlock-err').className = 'status-msg err';
  }
}

async function doUnlock() {
  const pin = $('pin-input').value;
  if (!pin.length) return;
  $('pin-input').value = '';
  try {
    await api('POST', '/wallet/unlock', { pin: pin });
    $('unlock-err').className = 'status-msg';
    checkWallet();
  } catch (e) {
    $('unlock-err').textContent = e.message || 'wrong pin';
    $('unlock-err').className = 'status-msg err';
  }
}

async function loadAll() {
  await Promise.all([loadReserves(), loadBalances()]);
  updatePrice();
  onInputChange();
}

async function loadReserves() {
  try {
    var r = await api('GET', '/contract/view?address=' + SWAP_ADDR + '&method=get_reserves&params=[]');
    var v = r.result || r.value || '';
    var parts = String(v).split(':');
    if (parts.length === 2) {
      _reserveOct = parts[0];
      _reserveToken = parts[1];
    }
    $('pool-info').textContent = addCommas(formatUnits(_reserveOct, OCT_DECIMALS)) + ' OCT / ' + addCommas(formatUnits(_reserveToken, TOKEN_DECIMALS)) + ' ' + TOKEN_SYMBOL;
  } catch (e) {
    $('pool-info').textContent = 'failed to load reserves';
  }
}

async function loadBalances() {
  try {
    var bal = await api('GET', '/balance');
    _balOctRaw = String(bal.public_balance || '0');
    $('bal-oct').textContent = addCommas(formatUnits(_balOctRaw, OCT_DECIMALS));
  } catch (e) {}
  try {
    var r = await api('GET', '/contract/view?address=' + TOKEN_ADDR + '&method=balance_of&params=["' + _walletAddr + '"]');
    _balTokenRaw = String(r.result || '0');
    $('bal-tusd').textContent = addCommas(formatUnits(_balTokenRaw, TOKEN_DECIMALS));
  } catch (e) {}
}

function updatePrice() {
  if (_reserveToken === '0') {
    $('price-display').textContent = '...';
    return;
  }
  var price = Number(_reserveToken) / Number(_reserveOct);
  $('price-display').textContent = price.toFixed(6) + ' ' + TOKEN_SYMBOL;
}

function setDir(d) {
  _dir = d;
  $('tab-buy').className = d === 'buy' ? 'active' : '';
  $('tab-sell').className = d === 'sell' ? 'active' : '';
  $('swap-input').value = '';
  if (d === 'buy') {
    $('input-label').textContent = 'you pay';
    $('input-token').textContent = 'OCT';
    $('output-token').textContent = TOKEN_SYMBOL;
  } else {
    $('input-label').textContent = 'you pay';
    $('input-token').textContent = TOKEN_SYMBOL;
    $('output-token').textContent = 'OCT';
  }
  onInputChange();
}

function setMax() {
  if (_dir === 'buy') {
    var maxOct = bigSub(_balOctRaw, parseUnits('100', OCT_DECIMALS));
    if (bigGt('0', maxOct)) maxOct = '0';
    $('swap-input').value = formatUnits(maxOct, OCT_DECIMALS);
  } else {
    $('swap-input').value = formatUnits(_balTokenRaw, TOKEN_DECIMALS);
  }
  onInputChange();
}

function onInputChange() {
  if (_swapPending) {
    $('swap-btn').disabled = true;
    return;
  }
  var raw = $('swap-input').value.trim();
  var btn = $('swap-btn');
  if (!raw || raw === '0' || raw === '0.0') {
    $('output-val').textContent = '0';
    $('impact-val').textContent = '-';
    btn.textContent = 'enter amount';
    btn.disabled = true;
    return;
  }
  let amountRaw;
  try {
    amountRaw = parseUnits(raw, _dir === 'buy' ? OCT_DECIMALS : TOKEN_DECIMALS);
  } catch (_) {
    $('output-val').textContent = '0';
    $('impact-val').textContent = '-';
    btn.textContent = 'invalid amount';
    btn.disabled = true;
    return;
  }
  if (_dir === 'buy') {
    if (bigGt(amountRaw, _balOctRaw)) {
      btn.textContent = 'insufficient OCT';
      btn.disabled = true;
      $('output-val').textContent = '0';
      return;
    }
    var outRaw = calcOutput(_reserveOct, _reserveToken, amountRaw);
    $('output-val').textContent = addCommas(formatUnits(outRaw, TOKEN_DECIMALS));
    var impact = (Number(amountRaw) / (Number(amountRaw) + Number(_reserveOct))) * 100;
    $('impact-val').textContent = impact.toFixed(2) + '%';
    btn.textContent = 'swap OCT -> ' + TOKEN_SYMBOL;
    btn.disabled = false;
  } else {
    if (bigGt(amountRaw, _balTokenRaw)) {
      btn.textContent = 'insufficient ' + TOKEN_SYMBOL;
      btn.disabled = true;
      $('output-val').textContent = '0';
      return;
    }
    var outRawS = calcOutput(_reserveToken, _reserveOct, amountRaw);
    $('output-val').textContent = addCommas(formatUnits(outRawS, OCT_DECIMALS));
    var impactS = (Number(amountRaw) / (Number(amountRaw) + Number(_reserveToken))) * 100;
    $('impact-val').textContent = impactS.toFixed(2) + '%';
    btn.textContent = 'swap ' + TOKEN_SYMBOL + ' -> OCT';
    btn.disabled = false;
  }
}

function doSwap() {
  if (_swapPending) return;
  var raw = $('swap-input').value.trim();
  if (!raw) return;
  var amountRaw, outRaw, payStr, receiveStr;
  if (_dir === 'buy') {
    amountRaw = parseUnits(raw, OCT_DECIMALS);
    outRaw = calcOutput(_reserveOct, _reserveToken, amountRaw);
    payStr = addCommas(formatUnits(amountRaw, OCT_DECIMALS)) + ' OCT';
    receiveStr = '~' + addCommas(formatUnits(outRaw, TOKEN_DECIMALS)) + ' ' + TOKEN_SYMBOL;
  } else {
    amountRaw = parseUnits(raw, TOKEN_DECIMALS);
    outRaw = calcOutput(_reserveToken, _reserveOct, amountRaw);
    payStr = addCommas(formatUnits(amountRaw, TOKEN_DECIMALS)) + ' ' + TOKEN_SYMBOL;
    receiveStr = '~' + addCommas(formatUnits(outRaw, OCT_DECIMALS)) + ' OCT';
  }
  $('confirm-detail').innerHTML =
    '<div class="cd-row"><span>you pay</span><span class="cd-val">' + esc(payStr) + '</span></div>' +
    '<div class="cd-row"><span>you receive</span><span class="cd-val">' + esc(receiveStr) + '</span></div>' +
    '<div class="cd-row"><span>fee</span><span class="cd-val">0.1 OCT</span></div>';
  $('confirm-modal').className = 'modal-bg show';
}

function cancelSwap() {
  $('confirm-modal').className = 'modal-bg';
}

function showProgress(steps) {
  var el = $('progress-area');
  var h = '';
  for (var i = 0; i < steps.length; i++) {
    var s = steps[i];
    if (s.link) {
      h += '<div class="step ' + s.cls + '">' + esc(s.text) + ' <a href="' + esc(s.link) + '" target="_blank" style="color:inherit;border-bottom:1px solid #D0D7E2;text-decoration:none;font-family:monospace;font-size:10px">' + esc(s.linkText || 'view tx') + '</a></div>';
    } else {
      h += '<div class="step ' + s.cls + '">' + esc(s.text) + '</div>';
    }
  }
  el.innerHTML = h;
  el.style.display = 'block';
}

function showStatus(msg, cls) {
  var el = $('status-area');
  el.textContent = msg;
  el.className = 'status-msg ' + cls;
}

function clearStatus() {
  $('status-area').className = 'status-msg';
  $('progress-area').style.display = 'none';
}

async function waitReceipt(txHash) {
  for (var i = 0; i < 60; i++) {
    try {
      var r = await api('GET', '/contract/receipt?hash=' + encodeURIComponent(txHash));
      if (r && r.success !== undefined) return r;
    } catch (e) {}
    await new Promise(function(ok) { setTimeout(ok, 1000); });
  }
  throw new Error('timeout waiting for receipt');
}

async function confirmSwap() {
  if (_swapPending) return;
  $('confirm-modal').className = 'modal-bg';
  _swapPending = true;
  $('swap-btn').className = 'swap-btn loading';
  $('swap-btn').textContent = 'processing...';
  $('swap-btn').disabled = true;
  clearStatus();
  const raw = $('swap-input').value.trim();
  try {
    if (_dir === 'buy') {
      await doBuySwap(raw);
    } else {
      await doSellSwap(raw);
    }
    $('swap-input').value = '';
  } catch (e) {
    showStatus(e.message || 'swap failed', 'err');
  }
  try {
    await loadAll();
  } finally {
    _swapPending = false;
    $('swap-btn').className = 'swap-btn';
    onInputChange();
  }
}

async function doBuySwap(humanAmount) {
  var amountRaw = parseUnits(humanAmount, OCT_DECIMALS);
  showProgress([{ text: 'swapping OCT -> ' + TOKEN_SYMBOL + '...', cls: 'active' }]);
  const r = await pinCall(api, {
    address: SWAP_ADDR,
    method: 'swap_oct_to_token',
    params: [],
    amount: amountRaw,
    ou: SWAP_FEE_OU
  }, 'swap ' + humanAmount + ' OCT for ' + TOKEN_SYMBOL + '\nfee: '
    + AmountUnits.format(SWAP_FEE_OU, 6) + ' OCT\ntotal OCT debit: '
    + AmountUnits.format((BigInt(amountRaw) + BigInt(SWAP_FEE_OU)).toString(), 6));
  if (!r.tx_hash) throw new Error('no tx_hash');
  showProgress([{ text: 'swapping OCT -> ' + TOKEN_SYMBOL + '... tx: ' + r.tx_hash.slice(0, 10), cls: 'active' }]);
  var receipt = await waitReceipt(r.tx_hash);
  if (!receipt.success) throw new Error(receipt.error || 'swap reverted');
  showProgress([{ text: 'swap complete', cls: 'done', link: txUrl(r.tx_hash), linkText: r.tx_hash.slice(0, 16) + '...' }]);
}

async function doSellSwap(humanAmount) {
  const amountRaw = parseUnits(humanAmount, TOKEN_DECIMALS);
  const amountValue = Number(amountRaw);
  if (!Number.isSafeInteger(amountValue) || String(amountValue) !== amountRaw) {
    throw new Error('swap amount exceeds exact JSON integer range');
  }
  showProgress([
    { text: '1/2 granting ' + TOKEN_SYMBOL + ' access...', cls: 'active' },
    { text: '2/2 swap ' + TOKEN_SYMBOL + ' -> OCT', cls: '' }
  ]);
  const g = await pinCall(api, {
    address: TOKEN_ADDR,
    method: 'grant',
    params: [SWAP_ADDR, amountValue],
    ou: GRANT_FEE_OU
  }, 'grant ' + humanAmount + ' ' + TOKEN_SYMBOL + ' to ' + SWAP_ADDR + '\nfee: '
    + AmountUnits.format(GRANT_FEE_OU, 6) + ' OCT\ntotal fees for grant and swap: '
    + AmountUnits.format((BigInt(GRANT_FEE_OU) + BigInt(SWAP_FEE_OU)).toString(), 6) + ' OCT');
  if (!g.tx_hash) throw new Error('grant: no tx_hash');
  var gr = await waitReceipt(g.tx_hash);
  if (!gr.success) throw new Error('grant failed: ' + (gr.error || 'reverted'));
  showProgress([
    { text: '1/2 grant approved', cls: 'done', link: txUrl(g.tx_hash), linkText: g.tx_hash.slice(0, 16) + '...' },
    { text: '2/2 swapping ' + TOKEN_SYMBOL + ' -> OCT...', cls: 'active' }
  ]);
  const r = await pinCall(api, {
    address: SWAP_ADDR,
    method: 'swap_token_to_oct',
    params: [amountValue],
    ou: SWAP_FEE_OU
  }, 'grant confirmed; swap ' + humanAmount + ' ' + TOKEN_SYMBOL + ' for OCT\nfee: '
    + AmountUnits.format(SWAP_FEE_OU, 6) + ' OCT\ntotal OCT debit for this transaction: '
    + AmountUnits.format(SWAP_FEE_OU, 6));
  if (!r.tx_hash) throw new Error('swap: no tx_hash');
  showProgress([
    { text: '1/2 grant approved', cls: 'done', link: txUrl(g.tx_hash), linkText: g.tx_hash.slice(0, 16) + '...' },
    { text: '2/2 swapping... tx: ' + r.tx_hash.slice(0, 10), cls: 'active' }
  ]);
  var receipt = await waitReceipt(r.tx_hash);
  if (!receipt.success) throw new Error('swap reverted: ' + (receipt.error || ''));
  showProgress([
    { text: '1/2 grant approved', cls: 'done', link: txUrl(g.tx_hash), linkText: g.tx_hash.slice(0, 16) + '...' },
    { text: '2/2 swap complete', cls: 'done', link: txUrl(r.tx_hash), linkText: r.tx_hash.slice(0, 16) + '...' }
  ]);
}

$('pin-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') doUnlock();
});

checkWallet();

(function() {
  var actions = { doUnlock, setDir, onInputChange, setMax, doSwap, cancelSwap, confirmSwap };
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