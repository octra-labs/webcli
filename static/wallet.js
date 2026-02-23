/*
    This file is part of Octra Wallet (webcli).

    Octra Wallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Octra Wallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Octra Wallet.  If not, see <http://www.gnu.org/licenses/>.

    This program is released under the GPL with the additional exemption
    that compiling, linking, and/or using OpenSSL is allowed.
    You are free to remove this exemption from derived works.

    Copyright 2025-2026 Octra Labs
              2025-2026 David A.
              2025-2026 Alex T.
              2025-2026 Vadim S.
              2025-2026 Julia L.
*/

var _walletAddr = '';
var _historyOffset = 0;
var _historyLimit = 20;
var _refreshTimer = null;
var _prevView = 'dashboard';
var _cachedBal = null;
var _encryptedBalanceRaw = 0;
var _unclaimedCount = 0;
var _pendingClaimIds = {};
var _explorerUrl = 'https://devnet.octrascan.io';




function $(id) { return document.getElementById(id); }

function updateStealthBadge(count) {  _unclaimedCount = count;
  var badge = $('stealth-badge');
  if (!badge) return;
  if (count > 0) {
    badge.textContent = count;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }
}

async function bgStealthScan() {
  try {
    var res = await api('GET', '/stealth/scan');
    var outputs = res.outputs || [];
    var unclaimed = 0;
    for (var i = 0; i < outputs.length; i++) {
      if (outputs[i].claimed) { delete _pendingClaimIds[String(outputs[i].id)]; continue; }
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
  } catch (e) {}
}

async function fetchBalance() {
  try {
    var bal = await api('GET', '/balance');
    _cachedBal = bal;
    var pub = bal.public_balance || '0';
    var enc = bal.encrypted_balance || '0';
    _encryptedBalanceRaw = parseInt(enc) || 0;
    if ($('st-balance')) $('st-balance').textContent = fmtOct(pub);
    if ($('st-enc-balance')) $('st-enc-balance').textContent = fmtOct(enc);
    if ($('st-nonce')) $('st-nonce').textContent = bal.nonce || '0';
    if ($('st-staging')) $('st-staging').textContent = bal.staging || '0';
    if ($('send-bal')) $('send-bal').textContent = fmtOct(pub);
    if ($('enc-pub-bal')) $('enc-pub-bal').textContent = fmtOct(pub);
    if ($('enc-enc-bal')) $('enc-enc-bal').textContent = fmtOct(enc);
    if ($('st-enc-bal-info')) $('st-enc-bal-info').textContent = fmtOct(enc);
    $('hdr-status').textContent = 'online';
    $('hdr-status').className = 'right online';
    return bal;
  } catch (e) {
    $('hdr-status').textContent = 'offline';
    $('hdr-status').className = 'right error';
    return null;
  }
}

async function api(method, path, body) {
  var opts = { method: method, headers: {} };

// test





  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  var res = await fetch('/api' + path, opts);
  var j = await res.json();
  if (!res.ok) throw new Error(j.error || j.message || 'request failed');
  return j;
}

function switchView(name) {
  if (name !== 'tx') _prevView = name;
  var views = document.querySelectorAll('.view');
  for (var i = 0; i < views.length; i++) views[i].classList.remove('active');
  var target = $('view-' + name);
  if (target) target.classList.add('active');
  var tabs = document.querySelectorAll('.nav-tabs a');
  for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
  for (var i = 0; i < tabs.length; i++) {
    var t = tabs[i].textContent.trim();
var tabId = tabs[i].getAttribute('data-view');
    if (tabId === name) {
      tabs[i].classList.add('active');
      break;
    }
  }
  if (name === 'dashboard') loadDashboard();
  if (name === 'history') { _historyOffset = 0; loadHistory(); }
  if (name === 'keys') showKeys();
  if (name === 'settings') loadSettings();
  if (name === 'send') refreshSendBalance();
  if (name === 'encrypt') refreshEncryptBalances();
  if (name === 'stealth') refreshStealthBalance();
}

function goBack() {
  switchView(_prevView || 'dashboard');
}

function addCommas(s) {
  var parts = s.split('.');
  parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return parts.join('.');
}

function fmtOct(raw) {
  var v = parseFloat(raw);
  if (v === 0 || isNaN(v)) return '0 oct';
  var n = v / 1000000;
  var s = n.toFixed(6).replace(/\.?0+$/, '');
  return addCommas(s) + ' oct';
}

function fmtOctCompact(raw) {
  var v = parseFloat(raw);
  if (v === 0 || isNaN(v)) return '-';
  var n = v / 1000000;
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M oct';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K oct';
  var s = n.toFixed(6).replace(/\.?0+$/, '');
  return s + ' oct';
}

function fmtDate(ts) {
  if (ts == null || ts <= 0) return '';
  var d = new Date(ts * 1000);
  var pad = function(v) { return String(v).padStart(2, '0'); };
  return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
}

function short(s) {
  if (!s || s.length <= 25) return s || '';
  return s.slice(0, 11) + '...' + s.slice(-11);
}

function addrLink(addr) {
  if (!addr || addr === 'stealth' || addr === 'coinbase') return '<span class="gray">' + (addr || '-') + '</span>';
  var display = short(addr);
  var url = _explorerUrl + '/address.html?addr=' + addr;
  return '<a class="mono addr" href="' + url + '" target="_blank" title="' + addr + '">' + display + '</a>';
}

function txLink(hash) {
  if (!hash) return '<span class="gray">-</span>';
  return '<a class="mono hash" href="javascript:void(0)" onclick="showTx(\'' + hash + '\')">' + short(hash) + '</a>';
}

function opTag(op) {
  if (op === 'stealth') return '<span class="stealth-tag">stealth</span>';
  if (op === 'claim') return '<span class="private-tag">claim</span>';
  if (op === 'encrypt') return '<span class="private-tag">encrypt</span>';
  if (op === 'decrypt') return '<span class="private-tag">decrypt</span>';
  if (op === 'private_transfer') return '<span class="private-tag">private</span>';
  return '';
}

function statusTag(st) {
  if (st === 'confirmed') return '<span class="private-tag">confirmed</span>';
  if (st === 'rejected') return '<span class="stealth-tag">rejected</span>';
  if (st === 'pending') return '<span class="pending-tag">pending</span>';
  return '<span class="pending-tag">' + (st || 'pending') + '</span>';
}

function showResult(elId, ok, msg) {
  var el = $(elId);
  if (!el) return;
  el.innerHTML = '<div class="result-msg ' + (ok ? 'result-ok' : 'result-error') + '">' + msg + '</div>';
}

function clearResult(elId) {
  var el = $(elId);
  if (el) el.innerHTML = '';
}

function validAddr(addr) {
  return /^oct[1-9A-HJ-NP-Za-km-z]{44}$/.test(addr);
}

function logStealth(msg, cls) {
  var el = $('stealth-log');
  if (!el) {
    var btn = document.querySelector('button[onclick="doStealthSend()"]');
    if (!btn) return;
    var row = btn.closest('.action-row') || btn.parentNode;
    el = document.createElement('div');
    el.id = 'stealth-log';
    row.parentNode.insertBefore(el, row.nextSibling);
  }
  el.innerHTML += '<div class="log-line' + (cls ? ' ' + cls : '') + '">' + msg + '</div>';
  el.scrollTop = el.scrollHeight;
}

function clearStealthLog() {
  var el = $('stealth-log');
  if (el) el.remove();
}

function txStatusTag(st) {
  if (st === 'rejected') return '<span class="rejected-tag">rejected</span>';
  if (st === 'confirmed') return '<span class="confirmed-tag">confirmed</span>';
  if (st === 'pending') return '<span class="pending-tag">pending</span>';
  return '<span class="pending-tag">' + (st || 'pending') + '</span>';
}

function txRow(tx) {
  var amt = tx.amount_raw ? fmtOctCompact(tx.amount_raw) : '';
  var dir = '';
  if (tx.from === _walletAddr) dir = ' red';
  else if ((tx.to_ || tx.to) === _walletAddr) dir = ' green';
    var st = tx.status || 'pending';
    var h = '<tr>';
  h += '<td>' + txLink(tx.hash) + '</td>';
  h += '<td>' + addrLink(tx.from) + '</td>';
  h += '<td>' + addrLink(tx.to_ || tx.to) + '</td>';
  h += '<td class="mono amount' + dir + '">' + amt + '</td>';
  h += '<td>' + txStatusTag(st) + '</td>';
  h += '<td class="gray">' + fmtDate(tx.timestamp) + '</td>';
  h += '</tr>';
  return h;
}

function txCardHtml(tx) {
  var amt = tx.amount_raw ? fmtOctCompact(tx.amount_raw) : '';
  var dir = '';
  if (tx.from === _walletAddr) dir = ' red';
  else if ((tx.to_ || tx.to) === _walletAddr) dir = ' green';
  var st = tx.status || 'pending';
  var c = '<div class="tx-card">';
  c += '<div class="card-row"><span class="card-label">tx</span><span class="card-val">' + txLink(tx.hash) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">from</span><span class="card-val">' + addrLink(tx.from) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">to</span><span class="card-val">' + addrLink(tx.to_ || tx.to) + '</span></div>';
  if (amt) c += '<div class="card-row"><span class="card-label">amount</span><span class="card-val mono amount' + dir + '">' + amt + '</span></div>';
  c += '<div class="card-row"><span class="card-label">status</span><span class="card-val">' + txStatusTag(st) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">time</span><span class="card-val gray">' + fmtDate(tx.timestamp) + '</span></div>';
  c += '</div>';



  return c;
}

async function showTx(hash) {
  switchView('tx');
  $('tx-detail').innerHTML = '<div class="loading">loading...</div>';
  try {
    var res = await api('GET', '/tx?hash=' + encodeURIComponent(hash));
    var st = res.status || 'pending';
    var h = '<table class="detail-table">';




    var fullHash = res.hash || hash;
    var explorerLink = _explorerUrl + '/tx.html?hash=' + fullHash;
    h += '<tr><td>hash</td><td class="mono">' + fullHash + ' <a href="' + explorerLink + '" target="_blank" style="font-size:10px;color:#8C9DB6;margin-left:4px">explorer</a></td></tr>';
    h += '<tr><td>status</td><td>' + txStatusTag(st) + '</td></tr>';
    if (res.reject_reason) h += '<tr><td>reason</td><td class="result-error">' + escapeHtml(res.reject_reason) + '</td></tr>';
      h += '<tr><td>from</td><td>' + addrLink(res.from || '') + '</td></tr>';
      h += '<tr><td>to</td><td>' + addrLink(res.to || res.to_ || '') + '</td></tr>';
       var amtRaw = res.amount_raw || res.amount || '0';
      h += '<tr><td>amount</td><td class="mono">' + fmtOct(amtRaw) + '</td></tr>';
      h += '<tr><td>amount (raw)</td><td class="mono gray">' + addCommas(String(amtRaw)) + '</td></tr>';
      var op = res.op_type || 'standard';
      h += '<tr><td>type</td><td>' + (opTag(op) || op) + '</td></tr>';
      if (res.epoch) h += '<tr><td>epoch</td><td>' + res.epoch + '</td></tr>';
      if (res.block_height) h += '<tr><td>block</td><td>' + res.block_height + '</td></tr>';
    h += '<tr><td>nonce</td><td>' + (res.nonce || '') + '</td></tr>';
    if (res.ou) h += '<tr><td>ou (fee)</td><td class="mono">' + fmtOct(res.ou) + '</td></tr>';
    h += '<tr><td>time</td><td>' + fmtDate(res.timestamp) + '</td></tr>';

    if (res.signature) h += '<tr><td>signature</td><td class="mono">' + res.signature + '</td></tr>';
    if (res.public_key) h += '<tr><td>public key</td><td class="mono">' + res.public_key + '</td></tr>';
    h += '</table>';
    if (res.message && res.message !== 'null' && res.message !== '') {
      h += '<div class="section-title">message</div>';
      h += '<div class="msg-box">' + escapeHtml(res.message) + '</div>';
    }
    $('tx-detail').innerHTML = h;
  } catch (e) {
    $('tx-detail').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function escapeHtml(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

async function loadDashboard() {
  await fetchBalance();
  try {
     var hist = await api('GET', '/history?limit=10&offset=0');
    var txs = hist.transactions || [];
    if (txs.length === 0) {

      $('dash-txs').innerHTML = '<div class="mempool-empty">no transactions yet</div>';
      return;
    }
    var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < txs.length; i++) {
      h += txRow(txs[i]);
      cards += txCardHtml(txs[i]);
    }
    h += '</table>';
        cards += '</div>';
    $('dash-txs').innerHTML = h + cards;
  } catch (e) {
    $('dash-txs').innerHTML = '<div class="mempool-empty">no transactions yet</div>';
  }
}

async function refreshSendBalance() {
  await fetchBalance();
}

async function doSend() {
  clearResult('send-result');
  var to = $('send-to').value.trim();
  var amount = $('send-amount').value.trim();
  var msg = $('send-msg') ? $('send-msg').value.trim() : '';
  if (!validAddr(to)) { showResult('send-result', false, 'invalid recipient address'); return; }
  if (!amount || isNaN(parseFloat(amount)) || parseFloat(amount) <= 0) { showResult('send-result', false, 'invalid amount'); return; }
  try {
    var body = { to: to, amount: amount };
    if (msg) body.message = msg;
    var res = await api('POST', '/send', body);
    showResult('send-result', true, 'sent ' + amount + ' oct - tx: ' + short(res.hash || res.tx_hash || ''));
    $('send-to').value = '';
    $('send-amount').value = '';
    if ($('send-msg')) $('send-msg').value = '';
    loadDashboard();
    refreshSendBalance();
  } catch (e) {
    showResult('send-result', false, e.message);
  }
}

async function refreshEncryptBalances() {
  await fetchBalance();
}

async function refreshStealthBalance() {
  await fetchBalance();
}

async function doEncrypt() {
  clearResult('enc-result');
  var amount = $('enc-amount').value.trim();
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { showResult('enc-result', false, 'invalid amount'); return; }
  try {
    var res = await api('POST', '/encrypt', { amount: amount });
    showResult('enc-result', true, 'encrypted ' + amount + ' oct - tx: ' + short(res.hash || res.tx_hash || ''));
      $('enc-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    showResult('enc-result', false, e.message);
  }
}

async function doDecrypt() {
  clearResult('dec-result');
  var amount = $('dec-amount').value.trim();
    if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { showResult('dec-result', false, 'invalid amount'); return; }
    var needRaw = Math.round(parseFloat(amount) * 1000000);
    if (_encryptedBalanceRaw <= 0) { showResult('dec-result', false, 'no encrypted balance to decrypt'); return; }
    if (needRaw > _encryptedBalanceRaw) { showResult('dec-result', false, 'insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct'); return; }
  try {
    var res = await api('POST', '/decrypt', { amount: amount });
    showResult('dec-result', true, 'decrypted ' + amount + ' oct - tx: ' + short(res.hash || res.tx_hash || ''));
    $('dec-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    showResult('dec-result', false, e.message);
  }
}

async function doStealthSend() {
  clearStealthLog();
  var to = $('stealth-to').value.trim();
  var amount = $('stealth-amount').value.trim();
  if (!validAddr(to)) { logStealth('error: invalid recipient address', 'log-err'); return; }
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logStealth('error: invalid amount', 'log-err'); return; }
  var needRaw = Math.round(parseFloat(amount) * 1000000);
  if (_encryptedBalanceRaw <= 0) { logStealth('error: no encrypted balance - encrypt funds first', 'log-err'); return; }
  if (needRaw > _encryptedBalanceRaw) { logStealth('error: insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct', 'log-err'); return; }
  logStealth('initiating stealth send...', 'log-info');




  
  logStealth('to: ' + to, 'log-info');
  logStealth('amount: ' + amount + ' oct', 'log-info');
  logStealth('', '');
  try {
    var res = await api('POST', '/stealth/send', { to: to, amount: amount });
    if (res.steps) {
      for (var i = 0; i < res.steps.length; i++) logStealth(res.steps[i], 'log-info');
    }
    logStealth('', '');
    logStealth('stealth send complete', 'log-ok');
    if (res.tx_hash || res.hash) logStealth('tx: ' + (res.tx_hash || res.hash), 'log-ok');
    $('stealth-to').value = '';
    $('stealth-amount').value = '';
    loadDashboard();
    refreshStealthBalance();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  }
}

async function doStealthScan() {
  $('stealth-outputs').innerHTML = '<div class="loading">scanning...</div>';
  try {
    var res = await api('GET', '/stealth/scan');
    var outputs = res.outputs || [];
    if (outputs.length === 0) {
      $('stealth-outputs').innerHTML = '<div class="mempool-empty">no stealth outputs found</div>';
      return;
    }
    var h = '<table class="desktop-table stealth-table"><tr><th></th><th>id</th><th>amount</th><th>status</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < outputs.length; i++) {
      var o = outputs[i];
      var amt = o.amount_raw ? fmtOctCompact(o.amount_raw) : '?';
      var isPending = !o.claimed && _pendingClaimIds[String(o.id)];
      var st = o.claimed ? '<span class="gray">claimed</span>' : (isPending ? '<span class="gray">claiming\u2026</span>' : '<span class="green">unclaimed</span>');
      var chk = (o.claimed || isPending) ? '' : '<input type="checkbox" class="stealth-chk" data-id="' + o.id + '">';
      h += '<tr>';
      h += '<td>' + chk + '</td>';
      h += '<td class="mono">' + (o.id || '') + '</td>';
      h += '<td class="mono amount green">' + amt + '</td>';
      h += '<td>' + st + '</td>';
      h += '</tr>';
      cards += '<div class="tx-card">';

      if (!o.claimed) cards += '<div class="card-row"><span class="card-label">select</span><span class="card-val">' + chk + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">id</span><span class="card-val mono">' + (o.id || '') + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">amount</span><span class="card-val mono amount green">' + amt + '</span></div>';
      cards += '<div class="card-row"><span class="card-label">status</span><span class="card-val">' + st + '</span></div>';
      cards += '</div>';
    }




    h += '</table>';
    cards += '</div>';
    h += cards;
    var unclaimed = 0;
    for (var i = 0; i < outputs.length; i++) {
      if (outputs[i].claimed) { delete _pendingClaimIds[String(outputs[i].id)]; continue; }
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
    if (unclaimed > 0) {
      h += '<div class="claim-row"><button class="action-btn" onclick="claimSelected()">claim selected</button></div>';
    }
    $('stealth-outputs').innerHTML = h;
  } catch (e) {
    $('stealth-outputs').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function claimSelected() {
  var checks = document.querySelectorAll('.stealth-chk:checked');
  var ids = [];
  for (var i = 0; i < checks.length; i++) ids.push(checks[i].getAttribute('data-id'));
  if (ids.length === 0) return;
  doStealthClaim(ids);
}

async function doStealthClaim(ids) {
  clearStealthLog();
  logStealth('claiming ' + ids.length + ' output(s)...', 'log-info');
  try {
    var res = await api('POST', '/stealth/claim', { ids: ids });
    logStealth('claim complete', 'log-ok');
    if (res.results) {
      for (var i = 0; i < res.results.length; i++) {
        var r = res.results[i];
        logStealth(r.id + ': ' + (r.ok ? 'ok' : 'failed - ' + (r.error || '')), r.ok ? 'log-ok' : 'log-err');
        if (r.ok) _pendingClaimIds[String(r.id)] = true;
      }
    }
    doStealthScan();
    loadDashboard();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  }
}

async function loadHistory() {
  $('history-list').innerHTML = '<div class="loading">loading...</div>';
    $('history-more').innerHTML = '';
  try {
    var res = await api('GET', '/history?limit=' + _historyLimit + '&offset=' + _historyOffset);
    var txs = res.transactions || [];
    if (txs.length === 0 && _historyOffset === 0) {
      $('history-list').innerHTML = '<div class="mempool-empty">no transactions yet</div>';
      return;
    }
    var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < txs.length; i++) {
      h += txRow(txs[i]);
      cards += txCardHtml(txs[i]);
    }
    h += '</table>';
    cards += '</div>';
    $('history-list').innerHTML = h + cards;
    if (txs.length >= _historyLimit) {
      $('history-more').innerHTML = '<button class="load-more" onclick="loadMoreHistory()">load more</button>';
    }
  } catch (e) {
    $('history-list').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

function loadMoreHistory() {
  _historyOffset += _historyLimit;
  loadHistoryAppend();
}

async function loadHistoryAppend() {
  var btn = $('history-more').querySelector('button');
  if (btn) { btn.disabled = true; btn.textContent = 'loading...'; }
  try {
    var res = await api('GET', '/history?limit=' + _historyLimit + '&offset=' + _historyOffset);
    var txs = res.transactions || [];
    if (txs.length === 0) {
      $('history-more').innerHTML = '<div class="mempool-empty">no more transactions</div>';
      return;
    }
    var tbl = $('history-list').querySelector('.desktop-table');
    var cardList = $('history-list').querySelector('.card-list');
    for (var i = 0; i < txs.length; i++) {
      if (tbl) {
        var row = tbl.insertRow(-1);
        row.innerHTML = txRow(txs[i]).replace(/<\/?tr>/g, '');
      }
      if (cardList) cardList.insertAdjacentHTML('beforeend', txCardHtml(txs[i]));
    }
    if (txs.length >= _historyLimit) {
      $('history-more').innerHTML = '<button class="load-more" onclick="loadMoreHistory()">load more</button>';
    } else {
      $('history-more').innerHTML = '';
    }
  } catch (e) {
    $('history-more').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

async function showKeys() {
  $('keys-table').innerHTML = '<div class="loading">loading...</div>';
  try {
    var res = await api('GET', '/keys');
    var h = '<table class="detail-table">';
    h += '<tr><td>address</td><td class="mono">' + (res.address || '') + '</td></tr>';
    h += '<tr><td>public key</td><td class="mono">' + (res.public_key || '') + '</td></tr>';
    h += '<tr><td>view pubkey</td><td class="mono">' + (res.view_pubkey || '-') + '</td></tr>';
    h += '<tr><td>private key</td><td class="mono">' + (res.private_key || '') + '</td></tr>';
    h += '</table>';
    $('keys-table').innerHTML = h;
  } catch (e) {
    $('keys-table').innerHTML = '<div class="error-box">' + e.message + '</div>';
  }
}

async function loadSettings() {
  try {
    var w = await api('GET', '/wallet');
    $('settings-rpc').value = w.rpc_url || 'http://165.227.225.79:8080';
    $('settings-explorer').value = w.explorer_url || 'https://devnet.octrascan.io';
  } catch (e) {}
}

async function doSaveSettings() {
  clearResult('settings-result');
  var rpc = $('settings-rpc').value.trim();
  var explorer = $('settings-explorer').value.trim();
  if (!rpc) { showResult('settings-result', false, 'rpc url required'); return; }
  try {
    await api('POST', '/settings', { rpc_url: rpc, explorer_url: explorer });
    if (explorer) _explorerUrl = explorer.replace(/\/+$/, '');
    showResult('settings-result', true, 'saved');
  } catch (e) {
    showResult('settings-result', false, e.message);
  }
}

async function doChangePin() {
  clearResult('pin-change-result');
  var cur = $('pin-current').value;
  var np = $('pin-new').value;
  var nc = $('pin-confirm-new').value;
  if (!/^\d{6}$/.test(cur)) { showResult('pin-change-result', false, 'current PIN must be 6 digits'); return; }
  if (!/^\d{6}$/.test(np)) { showResult('pin-change-result', false, 'new PIN must be 6 digits'); return; }
  if (np !== nc) { showResult('pin-change-result', false, 'PINs do not match'); return; }
  if (cur === np) { showResult('pin-change-result', false, 'new PIN must be different'); return; }
  try {
    await api('POST', '/wallet/change-pin', { current_pin: cur, new_pin: np });
    showResult('pin-change-result', true, 'PIN changed successfully');
    $('pin-current').value = '';
    $('pin-new').value = '';
    $('pin-confirm-new').value = '';
  } catch (e) {
    showResult('pin-change-result', false, e.message);
  }
}

var _pendingAction = null;
var _pendingPriv = '';

function hideAllModalPanels() {
  $('modal-btns').style.display = 'none';
  $('modal-import').style.display = 'none';
  $('modal-pin').style.display = 'none';
  $('modal-pin-setup').style.display = 'none';
  $('modal-result').innerHTML = '';
}

function showPinEntry() {
  hideAllModalPanels();
  $('modal-pin').style.display = 'block';
  $('modal-pin-input').value = '';
  $('modal-pin-input').focus();
}

function showPinSetup(action) {
  _pendingAction = action;
  hideAllModalPanels();
  $('modal-pin-setup').style.display = 'block';
  $('modal-pin-new').value = '';
  $('modal-pin-confirm').value = '';
  $('modal-pin-new').focus();
}

function modalShowImport() {
  hideAllModalPanels();
  $('modal-import').style.display = 'block';
}

function modalBack() {
  hideAllModalPanels();
  $('modal-btns').style.display = 'flex';
}

function modalBackFromPin() {
  _pendingAction = null;
  _pendingPriv = '';
  hideAllModalPanels();
  $('modal-btns').style.display = 'flex';
  $('modal-sub').textContent = 'no wallet found';
}

function modalCreate() {
  showPinSetup('create');
  $('modal-sub').textContent = 'set a 6-digit PIN for your new wallet';
}

function modalDoImport() {
  var priv = $('modal-privkey').value.trim();
  if (!priv) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">private key required</div>';
    return;
  }
  _pendingPriv = priv;
  $('modal-privkey').value = '';
  showPinSetup('import');
  $('modal-sub').textContent = 'set a 6-digit PIN for your wallet';
}

async function modalUnlock() {
  var pin = $('modal-pin-input').value;
  if (!/^\d{6}$/.test(pin)) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PIN must be exactly 6 digits</div>';
    return;
  }
  $('modal-result').innerHTML = '<div class="loading">unlocking...</div>';
  try {
    await api('POST', '/wallet/unlock', { pin: pin });
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + e.message + '</div>';
    $('modal-pin-input').value = '';
    $('modal-pin-input').focus();
  }
}

async function modalFinishSetup() {
  var pin = $('modal-pin-new').value;
  var confirm = $('modal-pin-confirm').value;
  if (!/^\d{6}$/.test(pin)) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PIN must be exactly 6 digits</div>';
    return;
  }
  if (pin !== confirm) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PINs do not match</div>';
    $('modal-pin-confirm').value = '';
    return;
  }
  $('modal-result').innerHTML = '<div class="loading">processing...</div>';
  try {
    if (_pendingAction === 'create') {
      await api('POST', '/wallet/create', { pin: pin });
    } else if (_pendingAction === 'import') {
      await api('POST', '/wallet/import', { priv: _pendingPriv, pin: pin });
      _pendingPriv = '';
    } else if (_pendingAction === 'migrate') {
      await api('POST', '/wallet/unlock', { pin: pin });
    }
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + e.message + '</div>';
  }
}

async function loadWalletInfo() {
  try {
    var w = await api('GET', '/wallet');
    _walletAddr = w.address || w.addr || '';
    if (w.explorer_url) _explorerUrl = w.explorer_url.replace(/\/+$/, '');
    $('hdr-addr').innerHTML = '<span class="mono">' + _walletAddr + '</span>';
    $('hdr-logout').style.display = '';
    loadDashboard();
  } catch (e) {
    $('hdr-addr').textContent = 'error loading wallet';
    $('hdr-status').textContent = 'error';
    $('hdr-status').className = 'right error';
  }
}

async function doLogout() {
  try { await api('POST', '/wallet/lock', {}); } catch (e) {}
  if (_refreshTimer) { clearInterval(_refreshTimer); _refreshTimer = null; }
  _walletAddr = '';
  _cachedBal = null;
  _encryptedBalanceRaw = 0;
  $('hdr-logout').style.display = 'none';
  $('hdr-addr').textContent = 'locked';
  $('hdr-status').textContent = 'locked';
  $('hdr-status').className = 'right';
  $('modal-sub').textContent = 'enter PIN to unlock';
  hideAllModalPanels();
  showPinEntry();
  $('modal-overlay').style.display = 'flex';
}

function startRefreshTimer() {
  if (_refreshTimer) return;
  bgStealthScan();
  _refreshTimer = setInterval(function() {
    fetchBalance();
    bgStealthScan();
    var dash = $('view-dashboard');
    if (dash && dash.classList.contains('active')) loadDashboard();
  }, 15000);
}


async function init() {
  try {
    var st = await api('GET', '/wallet/status');
    if (st.loaded) {
      await loadWalletInfo();
      startRefreshTimer();
      return;
    }
    if (st.needs_pin) {
      if (st.has_legacy) {
        $('modal-sub').textContent = 'migrating wallet - set a PIN';
        showPinSetup('migrate');
      } else {
        $('modal-sub').textContent = 'enter PIN to unlock';
        showPinEntry();
      }
      $('modal-overlay').style.display = 'flex';
      return;
    }
    $('modal-sub').textContent = 'no wallet found';
    $('modal-btns').style.display = 'flex';
    $('modal-overlay').style.display = 'flex';
  } catch (e) {
    $('modal-overlay').style.display = 'flex';
  }
}

$('modal-pin-input').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') modalUnlock();
});
$('modal-pin-confirm').addEventListener('keydown', function(e) {
  if (e.key === 'Enter') modalFinishSetup();
});

init();
