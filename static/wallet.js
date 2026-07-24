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

function validatePin(pin) {
  if (!pin || pin.length === 0) return 'PIN required';
  if (pin.length < 8) return 'PIN must be at least 8 characters';
  if (pin.length > 64) return 'PIN too long (max 64 characters)';
  if (pin.length < 15) {
    var hasLetter = /[A-Za-z]/.test(pin);
    var hasDigit = /[0-9]/.test(pin);
    var hasSymbol = /[^A-Za-z0-9]/.test(pin);
    if (!hasLetter || !hasDigit || !hasSymbol) {
      return 'under 15 chars: must include a letter, a digit and a special symbol';
    }
  }
  return '';
}

function idePrompt(title, message, defaultVal) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + escapeHtml(title) + '</div>' +
      (message ? '<div class="modal-message">' + escapeHtml(message) + '</div>' : '') +
      '<input class="modal-input" type="text" value="' + escapeAttr(defaultVal || '') + '">' +
      '<div class="modal-buttons">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
        '<button class="modal-btn modal-btn-primary" data-action="ok">ok</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    var inp = ov.querySelector('.modal-input');
    inp.focus(); inp.select();
    inp.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { document.body.removeChild(ov); resolve(inp.value); }
      if (e.key === 'Escape') { document.body.removeChild(ov); resolve(null); }
    });
    ov.addEventListener('click', function(e) {
      var a = e.target.getAttribute('data-action');
      if (a === 'ok') { document.body.removeChild(ov); resolve(inp.value); }
      if (a === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(null); }
    });
  });
}
function ideConfirm(title, message) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + escapeHtml(title) + '</div>' +
      '<div class="modal-message">' + escapeHtml(message) + '</div>' +
      '<div class="modal-buttons">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
        '<button class="modal-btn modal-btn-primary" data-action="ok">confirm</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) {
      var a = e.target.getAttribute('data-action');
      if (a === 'ok') { document.body.removeChild(ov); resolve(true); }
      if (a === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(false); }
    });
    ov.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') { document.body.removeChild(ov); resolve(true); }
      if (e.key === 'Escape') { document.body.removeChild(ov); resolve(false); }
    });
    ov.focus();
  });
}
function ideMenu(title, options) {
  return new Promise(function(resolve) {
    var ov = document.createElement('div');
    ov.className = 'modal-overlay';
    var btns = options.map(function(o, i) {
      return '<button class="modal-btn" data-idx="' + i + '" style="width:100%;text-align:left;margin-bottom:4px">' + escapeHtml(o.label) + '</button>';
    }).join('');
    ov.innerHTML = '<div class="modal-box">' +
      '<div class="modal-title">' + escapeHtml(title) + '</div>' +
      btns +
      '<div class="modal-buttons" style="margin-top:8px">' +
        '<button class="modal-btn" data-action="cancel">cancel</button>' +
      '</div></div>';
    document.body.appendChild(ov);
    ov.addEventListener('click', function(e) {
      var idx = e.target.getAttribute('data-idx');
      if (idx !== null) { document.body.removeChild(ov); resolve(options[parseInt(idx)].value); return; }
      if (e.target.getAttribute('data-action') === 'cancel' || e.target === ov) { document.body.removeChild(ov); resolve(null); }
    });
  });
}

var _walletAddr = '';
var _historyOffset = 0;
var _historyLimit = 20;
var _refreshTimer = null;
var _prevView = 'dashboard';
var _cachedBal = null;
var _encryptedBalanceRaw = 0;
var _encPresent = false;
var _encKnown = false;
var _unclaimedCount = 0;
var _pendingClaimIds = {};
var _pendingClaimTxs = {};
var _explorerUrl = 'https://octrascan.io';
var _tokens = [];
var _selectedToken = null;
var _tokenSymbols = {};
var _tokenDecimals = {};
var _tokensLoaded = false;
var _tokTxGen = 0;
var _compiledAbi = null;
var _compiledVerification = null;
var _compiledCertificate = null;
var _fees = {};
var _rpcHost = '';
var _hasMasterSeed = false;
var _addressRuntime = {};
var _tokenMetaInflight = {};
var _pvacUpgradeStatus = null;
var _pvacUpgradeInFlight = false;
var _privateOpInFlight = false;
var _walletSwitching = false;
var HISTORY_CACHE_TTL_MS = 12000;
var HISTORY_STALE_REFRESH_MS = 3000;
var BALANCE_CACHE_TTL_MS = 5000;
var TOKEN_CACHE_TTL_MS = 15000;
var TOKEN_STALE_REFRESH_MS = 3000;
var PERSISTED_CACHE_TTL_MS = 300000;

function ensureAddressRuntime(addr) {
  if (!addr) return null;
  if (!_addressRuntime[addr]) {
    _addressRuntime[addr] = {
      balance: null,
      balanceTs: 0,
      balanceInflight: null,
      historyPages: {},
      historyTs: {},
      historyInflight: {},
      tokens: [],
      tokensLoaded: false,
      tokensTs: 0,
      tokensInflight: null,
      tokenHistory: null,
      tokenHistoryTs: 0,
      tokenHistoryInflight: null
    };
  }
  return _addressRuntime[addr];
}

function clearAddressRuntime(addr) {
  if (!addr) return;
  delete _addressRuntime[addr];
}

function clearAllAddressRuntime() {
  _addressRuntime = {};
  _tokenMetaInflight = {};
}

function persistedCachePrefix(addr) {
  return 'octra_webcli:v2:' + (_rpcHost || 'rpc') + ':' + addr + ':';
}

function persistedRead(key) {
  try {
    var raw = sessionStorage.getItem(key);
    if (!raw) return null;
    return JSON.parse(raw);
  } catch (e) {
    return null;
  }
}

function persistedWrite(key, value) {
  try {
    sessionStorage.setItem(key, JSON.stringify(value));
  } catch (e) {}
}

function persistedRemovePrefix(prefix) {
  try {
    for (var i = sessionStorage.length - 1; i >= 0; i--) {
      var key = sessionStorage.key(i);
      if (key && key.indexOf(prefix) === 0) sessionStorage.removeItem(key);
    }
  } catch (e) {}
}

function persistBalance(addr, balance) {
  if (!addr || !balance) return;
  persistedWrite(persistedCachePrefix(addr) + 'balance', {
    ts: Date.now(),
    balance: balance
  });
}

function restorePersistedBalance(addr) {
  if (!addr) return null;
  var cached = persistedRead(persistedCachePrefix(addr) + 'balance');
  if (!cached || !cached.balance || !cached.ts) return null;
  if ((Date.now() - cached.ts) > PERSISTED_CACHE_TTL_MS) return null;
  return cached.balance;
}

function persistHistoryPage(addr, limit, offset, response) {
  if (!addr || !response) return;
  persistedWrite(persistedCachePrefix(addr) + 'history:' + historyPageKey(limit, offset), {
    ts: Date.now(),
    response: response
  });
}

function restorePersistedHistoryPage(addr, limit, offset) {
  if (!addr) return null;
  var cached = persistedRead(persistedCachePrefix(addr) + 'history:' + historyPageKey(limit, offset));
  if (!cached || !cached.response || !cached.ts) return null;
  if ((Date.now() - cached.ts) > PERSISTED_CACHE_TTL_MS) return null;
  return cached;
}

function persistTokens(addr, tokens) {
  if (!addr) return;
  persistedWrite(persistedCachePrefix(addr) + 'tokens', {
    ts: Date.now(),
    tokens: tokens || []
  });
}

function persistTokenHistory(addr, payload) {
  if (!addr || !payload) return;
  persistedWrite(persistedCachePrefix(addr) + 'token-history:v2', {
    ts: Date.now(),
    payload: payload
  });
}

function restorePersistedTokens(addr) {
  if (!addr) return null;
  var cached = persistedRead(persistedCachePrefix(addr) + 'tokens');
  if (!cached || !cached.ts || !Array.isArray(cached.tokens)) return null;
  if ((Date.now() - cached.ts) > PERSISTED_CACHE_TTL_MS) return null;
  return cached;
}

function restorePersistedTokenHistory(addr) {
  if (!addr) return null;
  var cached = persistedRead(persistedCachePrefix(addr) + 'token-history:v2');
  if (!cached || !cached.ts || !cached.payload) return null;
  if ((Date.now() - cached.ts) > PERSISTED_CACHE_TTL_MS) return null;
  return cached;
}

function dropPersistedAddressRuntime(addr) {
  if (!addr) return;
  persistedRemovePrefix(persistedCachePrefix(addr));
}

function dropAllPersistedRuntime() {
  persistedRemovePrefix('octra_webcli:');
}

function historyPageKey(limit, offset) {
  return String(limit) + ':' + String(offset);
}

function peekHistoryPage(addr, limit, offset) {
  var state = ensureAddressRuntime(addr);
  if (!state) return null;
  var key = historyPageKey(limit, offset);
  if (!state.historyPages[key]) {
    var persisted = restorePersistedHistoryPage(addr, limit, offset);
    if (persisted) {
      state.historyPages[key] = persisted.response;
      state.historyTs[key] = persisted.ts;
    }
  }
  if (!state.historyPages[key]) return null;
  return {
    response: state.historyPages[key],
    ts: state.historyTs[key] || 0
  };
}

function cacheHistoryPage(addr, limit, offset, response) {
  var state = ensureAddressRuntime(addr);
  if (!state) return response;
  var key = historyPageKey(limit, offset);
  state.historyPages[key] = response;
  state.historyTs[key] = Date.now();
  persistHistoryPage(addr, limit, offset, response);
  return response;
}

async function reconcileHistoryResponse(addr, limit, offset, response) {
  if (!addr || !response || !Array.isArray(response.transactions) || response.transactions.length === 0) {
    return response;
  }
  var pending = [];
  for (var i = 0; i < response.transactions.length; i++) {
    var tx = response.transactions[i];
    if (!tx || !tx.hash) continue;
    var st = tx.status || 'pending';
    if (st === 'pending') pending.push({ index: i, hash: tx.hash });
  }
  if (pending.length === 0) return response;
  var nextTxs = response.transactions.slice();
  var changed = false;
  await Promise.all(pending.map(async function(entry) {
    try {
      var fresh = await api('GET', '/tx?hash=' + encodeURIComponent(entry.hash));
      var st = fresh.status || 'pending';
      if (!st || st === 'pending') return;
      var merged = Object.assign({}, nextTxs[entry.index], fresh);
      merged.hash = fresh.hash || nextTxs[entry.index].hash || entry.hash;
      merged.to_ = fresh.to_ || fresh.to || nextTxs[entry.index].to_ || nextTxs[entry.index].to || '';
      merged.amount_raw = fresh.amount_raw || fresh.amount || nextTxs[entry.index].amount_raw || '0';
      merged.status = st;
      nextTxs[entry.index] = merged;
      changed = true;
    } catch (e) {}
  }));
  if (!changed) return response;
  var nextResponse = Object.assign({}, response, { transactions: nextTxs });
  cacheHistoryPage(addr, limit, offset, nextResponse);
  return nextResponse;
}

async function fetchHistoryPage(limit, offset, force) {
  var addr = _walletAddr;
  if (_walletSwitching) return { transactions: [] };
  if (!addr) return { transactions: [] };
  var state = ensureAddressRuntime(addr);
  var key = historyPageKey(limit, offset);
  var cached = peekHistoryPage(addr, limit, offset);
  if (!force && cached && (Date.now() - cached.ts) < HISTORY_CACHE_TTL_MS) {
    return reconcileHistoryResponse(addr, limit, offset, cached.response);
  }
  if (state.historyInflight[key]) return state.historyInflight[key];
  state.historyInflight[key] = api('GET', '/history?limit=' + limit + '&offset=' + offset)
    .then(function(response) {
      return cacheHistoryPage(addr, limit, offset, response);
    })
    .then(function(response) {
      return reconcileHistoryResponse(addr, limit, offset, response);
    })
    .finally(function() {
      delete state.historyInflight[key];
    });
  return state.historyInflight[key];
}

function cacheAddressTokens(addr, tokens) {
  var state = ensureAddressRuntime(addr);
  if (!state) return;
  state.tokens = tokens || [];
  state.tokensLoaded = true;
  state.tokensTs = Date.now();
  persistTokens(addr, state.tokens);
}

function restoreAddressTokens(addr) {
  var state = ensureAddressRuntime(addr);
  if (!state) return false;
  if (!state.tokensLoaded) {
    var persisted = restorePersistedTokens(addr);
    if (persisted) {
      state.tokens = persisted.tokens.slice();
      state.tokensLoaded = true;
      state.tokensTs = persisted.ts;
    }
  }
  if (!state.tokensLoaded) return false;
  _tokens = state.tokens.slice();
  _tokensLoaded = true;
  hydrateTokenMaps(_tokens);
  return true;
}

function hydrateTokenMaps(tokens) {
  for (var i = 0; i < tokens.length; i++) {
    _tokenSymbols[tokens[i].address] = tokens[i].symbol;
    _tokenDecimals[tokens[i].address] = tokens[i].decimals || '0';
  }
}

function tokenHistorySummary(payload) {
  return {
    transactions: (payload && payload.transactions) ? payload.transactions : [],
    total: (payload && payload.total) ? payload.total : 0,
    incoming: (payload && payload.incoming) ? payload.incoming : 0,
    outgoing: (payload && payload.outgoing) ? payload.outgoing : 0,
    has_more: !!(payload && payload.has_more)
  };
}

async function fetchAddressTokens(force) {
  var addr = _walletAddr;
  if (!addr) return [];
  var state = ensureAddressRuntime(addr);
  if (!state) return [];
  if (!force && state.tokensLoaded && (Date.now() - state.tokensTs) < TOKEN_CACHE_TTL_MS) {
    return state.tokens.slice();
  }
  if (state.tokensInflight) return state.tokensInflight;
  state.tokensInflight = api('GET', '/tokens')
    .then(function(res) {
      var tokens = (res && res.tokens) ? res.tokens : [];
      cacheAddressTokens(addr, tokens);
      return tokens.slice();
    })
    .finally(function() {
      state.tokensInflight = null;
    });
  return state.tokensInflight;
}

async function fetchTokenHistory(force) {
  var addr = _walletAddr;
  if (!addr) return tokenHistorySummary(null);
  var state = ensureAddressRuntime(addr);
  if (!state) return tokenHistorySummary(null);
  if (!force && state.tokenHistory && (Date.now() - state.tokenHistoryTs) < HISTORY_CACHE_TTL_MS) {
    return state.tokenHistory;
  }
  if (!force && !state.tokenHistory) {
    var persisted = restorePersistedTokenHistory(addr);
    if (persisted) {
      var summary = tokenHistorySummary(persisted.payload);
      var hasTokens = state.tokensLoaded && state.tokens && state.tokens.length > 0;
      if (!(hasTokens && summary.total === 0)) {
        state.tokenHistory = summary;
        state.tokenHistoryTs = persisted.ts;
        return state.tokenHistory;
      }
    }
  }
  if (state.tokenHistoryInflight) return state.tokenHistoryInflight;
  var suffix = force ? '&force=1' : '';
  state.tokenHistoryInflight = api('GET', '/token-history?limit=200&offset=0' + suffix)
    .then(function(response) {
      var summary = tokenHistorySummary(response);
      state.tokenHistory = summary;
      state.tokenHistoryTs = Date.now();
      persistTokenHistory(addr, summary);
      return summary;
    })
    .finally(function() {
      state.tokenHistoryInflight = null;
    });
  return state.tokenHistoryInflight;
}

function invalidateCurrentAddressState() {
  if (!_walletAddr) return;
  dropPersistedAddressRuntime(_walletAddr);
  clearAddressRuntime(_walletAddr);
  ensureAddressRuntime(_walletAddr);
  _cachedBal = null;
  _historyOffset = 0;
  _tokens = [];
  _tokensLoaded = false;
}

function setPrivateOpBusy(active) {
  _privateOpInFlight = !!active;
}

var _ideProject = null;
var _ideFiles = {};
var _ideActiveFile = null;
var _ideOpenTabs = [];
var _ideSaveTimer = null;
var _ideMode = false;

var ProjectStore = (function() {
  var DB_NAME = 'octra_ide';
  var DB_VERSION = 1;
  var db = null;

  function open() {
    return new Promise(function(resolve, reject) {
      if (db) { resolve(db); return; }
      var req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = function(e) {
        var d = e.target.result;
        if (!d.objectStoreNames.contains('projects')) {
          d.createObjectStore('projects', { keyPath: 'id' });
        }
        if (!d.objectStoreNames.contains('files')) {
          var fs = d.createObjectStore('files', { keyPath: 'key' });
          fs.createIndex('project', 'project_id', { unique: false });
        }
      };
      req.onsuccess = function(e) { db = e.target.result; resolve(db); };
      req.onerror = function(e) { reject(e.target.error); };
    });
  }

  function tx(stores, mode) {
    return db.transaction(stores, mode);
  }

  return {
    createProject: async function(name, template) {
      await open();
      var id = 'prj_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
      var proj = { id: id, name: name, created: Date.now(), template: template || 'empty' };
      return new Promise(function(resolve, reject) {
        var t = tx(['projects'], 'readwrite');
        t.objectStore('projects').put(proj);
        t.oncomplete = function() { resolve(proj); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    listProjects: async function() {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['projects'], 'readonly');
        var req = t.objectStore('projects').getAll();
        req.onsuccess = function() { resolve(req.result || []); };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    deleteProject: async function(id) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['projects', 'files'], 'readwrite');
        t.objectStore('projects').delete(id);
        var idx = t.objectStore('files').index('project');
        var cur = idx.openCursor(IDBKeyRange.only(id));
        cur.onsuccess = function(e) {
          var c = e.target.result;
          if (c) { c.delete(); c.continue(); }
        };
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    saveFile: async function(projectId, path, content) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readwrite');
        t.objectStore('files').put({ key: key, project_id: projectId, path: path, content: content });
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    getFile: async function(projectId, path) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var req = t.objectStore('files').get(key);
        req.onsuccess = function() { resolve(req.result ? req.result.content : null); };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    listFiles: async function(projectId) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var idx = t.objectStore('files').index('project');
        var req = idx.getAll(IDBKeyRange.only(projectId));
        req.onsuccess = function() {
          resolve((req.result || []).map(function(f) { return f.path; }));
        };
        req.onerror = function(e) { reject(e.target.error); };
      });
    },

    deleteFile: async function(projectId, path) {
      await open();
      var key = projectId + '::' + path;
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readwrite');
        t.objectStore('files').delete(key);
        t.oncomplete = function() { resolve(); };
        t.onerror = function(e) { reject(e.target.error); };
      });
    },

    getAllFiles: async function(projectId) {
      await open();
      return new Promise(function(resolve, reject) {
        var t = tx(['files'], 'readonly');
        var idx = t.objectStore('files').index('project');
        var req = idx.getAll(IDBKeyRange.only(projectId));
        req.onsuccess = function() {
          var map = {};
          (req.result || []).forEach(function(f) { map[f.path] = f.content; });
          resolve(map);
        };
        req.onerror = function(e) { reject(e.target.error); };
      });
    }
  };
})();

var _templateIndex = null;
async function loadTemplateIndex() {
  if (_templateIndex) return _templateIndex;
  try {
    var r = await fetch('templates/index.json');
    _templateIndex = await r.json();
  } catch (e) { _templateIndex = {}; }
  return _templateIndex;
}
async function fetchTemplateFiles(key) {
  var idx = await loadTemplateIndex();
  var tpl = idx[key];
  if (!tpl) return null;
  var files = {};
  for (var i = 0; i < tpl.files.length; i++) {
    var path = tpl.files[i];
    try {
      var r = await fetch('templates/' + key + '/' + path);
      files[path] = await r.text();
    } catch (e) { files[path] = ''; }
  }
  return { name: tpl.name, files: files };
}

var PROJECT_TEMPLATES = {
  empty: { name: 'Empty Project', files: { 'main.aml': 'Program MyProgram {\n  state { owner: address }\n  constructor() {\n    self.owner = caller\n  }\n}' } },
  token: { name: 'OCS01 Token', files: { 'main.aml': '' } },
  vault: { name: 'Vault', files: { 'main.aml': '' } }
};

async function ideOpenProject(proj) {
  _ideProject = proj;
  _ideFiles = await ProjectStore.getAllFiles(proj.id);
  _ideOpenTabs = [];
  _ideActiveFile = null;
  _ideMode = true;

  var mainFile = 'main.aml';
  if (!_ideFiles[mainFile]) {
    var paths = Object.keys(_ideFiles);
    mainFile = paths.length > 0 ? paths[0] : null;
  }
  if (mainFile) {
    _ideOpenTabs = [mainFile];
    _ideActiveFile = mainFile;
  }

  ideRenderAll();
  updateVerifyUI();
}

function updateVerifyUI() {
  var single = $('ct-verify-single');
  var proj = $('ct-verify-project');
  var projFiles = $('ct-verify-project-files');
  if (!single || !proj) return;
  if (_ideProject && _ideFiles) {
    single.style.display = 'none';
    proj.style.display = '';
    var paths = Object.keys(_ideFiles);
    projFiles.innerHTML = paths.map(function(p) { return '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(p); }).join('<br>');
  } else {
    single.style.display = '';
    proj.style.display = 'none';
  }
}

function ideRenderAll() {
  ideRenderProjectBar();
  ideRenderFileTree();
  ideRenderTabs();
  ideLoadActiveFile();
}

function ideRenderProjectBar() {
  var bar = $('ide-project-bar');
  if (!bar) return;
  if (!_ideProject) {
    bar.style.display = 'none';
    return;
  }
  bar.style.display = 'flex';
  bar.innerHTML = '<span class="ide-project-name">' + escapeHtml(_ideProject.name) + '</span>' +
    '<button class="ide-btn" data-action="ideCloseProject" title="close project"><span class="ide-icon ico-close"></span></button>' +
    '<button class="ide-btn" data-action="ideExportZip" title="export zip"><span class="ide-icon ico-download"></span></button>';
}

function ideRenderFileTree() {
  var tree = $('ide-file-tree');
  if (!tree) return;
  if (!_ideProject) {
    tree.style.display = 'none';
    return;
  }
  tree.style.display = 'block';
  var paths = Object.keys(_ideFiles).sort();
  var dirs = {};
  var rootFiles = [];
  paths.forEach(function(p) {
    var slash = p.indexOf('/');
    if (slash > 0) {
      var dir = p.substring(0, slash);
      if (!dirs[dir]) dirs[dir] = [];
      dirs[dir].push(p);
    } else {
      rootFiles.push(p);
    }
  });

  var html = '<div class="ide-tree-header">files <button class="ide-btn-small" data-action="ideNewFile"><span class="ide-icon ico-plus"></span></button>' +
    '<label class="ide-btn-small" style="cursor:pointer" title="import .aml files"><span class="ide-icon ico-upload"></span><input type="file" accept=".aml,.json,.aml-project.json" multiple style="display:none" data-change="importFiles"></label>' +
    '<label class="ide-btn-small" style="cursor:pointer" title="import folder"><span class="ide-icon ico-folder-import"></span><input type="file" webkitdirectory style="display:none" data-change="importFiles"></label></div>';
  
  
  
  
    rootFiles.forEach(function(p) {
    var cls = p === _ideActiveFile ? ' active' : '';
    html += '<div class="ide-tree-file' + cls + '" data-action="ideOpenFile" data-arg="' + escapeAttr(p) + '" data-context="fileMenu">' +
      '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(p) + '</div>';
  });
  Object.keys(dirs).sort().forEach(function(dir) {
    html += '<div class="ide-tree-dir"><span class="ide-icon ide-dir-icon"></span>' + escapeHtml(dir) + '</div>';
    dirs[dir].sort().forEach(function(p) {
      var fname = p.substring(p.indexOf('/') + 1);
      var cls = p === _ideActiveFile ? ' active' : '';
      html += '<div class="ide-tree-file ide-tree-nested' + cls + '" data-action="ideOpenFile" data-arg="' + escapeAttr(p) + '" data-context="fileMenu">' +
        '<span class="ide-icon ide-file-icon"></span>' + escapeHtml(fname) + '</div>';
    });
  });
  tree.innerHTML = html;
}

function ideRenderTabs() {
  var bar = $('ide-tabs');
  if (!bar) return;
  if (!_ideProject || _ideOpenTabs.length === 0) {
    bar.style.display = 'none';
    return;
  }
  bar.style.display = 'flex';
  var html = '';
  _ideOpenTabs.forEach(function(path) {
    var name = path.indexOf('/') >= 0 ? path.substring(path.lastIndexOf('/') + 1) : path;
    var cls = path === _ideActiveFile ? ' active' : '';
    html += '<div class="ide-tab' + cls + '" data-action="ideOpenFile" data-arg="' + escapeAttr(path) + '">' +
      escapeHtml(name) +
      '<span class="ide-tab-close" data-action="ideCloseTab" data-arg="' + escapeAttr(path) + '">×</span>' +
      '</div>';
  });
  bar.innerHTML = html;
}

function ideLoadActiveFile() {
  var ta = $('ct-source');
  if (!ta) return;
  if (_ideActiveFile && _ideFiles[_ideActiveFile] !== undefined) {
    ta.value = _ideFiles[_ideActiveFile];
  } else {
    ta.value = '';
  }
  editorUpdate();
}

function ideOpenFile(path) {
  ideSaveCurrentFile();
  if (_ideOpenTabs.indexOf(path) < 0) {
    _ideOpenTabs.push(path);
  }
  _ideActiveFile = path;
  ideRenderFileTree();
  ideRenderTabs();
  ideLoadActiveFile();
}

function ideCloseTab(path) {
  ideSaveCurrentFile();
  var idx = _ideOpenTabs.indexOf(path);
  if (idx >= 0) _ideOpenTabs.splice(idx, 1);
  if (_ideActiveFile === path) {
    _ideActiveFile = _ideOpenTabs.length > 0 ? _ideOpenTabs[Math.max(0, idx - 1)] : null;
  }
  ideRenderTabs();
  ideRenderFileTree();
  ideLoadActiveFile();
}

function ideSaveCurrentFile() {
  if (!_ideProject || !_ideActiveFile) return;
  var ta = $('ct-source');
  if (!ta) return;
  _ideFiles[_ideActiveFile] = ta.value;
  ProjectStore.saveFile(_ideProject.id, _ideActiveFile, ta.value).catch(function() {});
}

async function ideNewFile() {
  var name = await idePrompt('new file', 'e.g. utils.aml or interfaces/IToken.aml');
  if (!name || !name.trim()) return;
  name = name.trim();
  if (_ideFiles[name] !== undefined) { alert('File already exists'); return; }
  _ideFiles[name] = '';
  await ProjectStore.saveFile(_ideProject.id, name, '');
  ideOpenFile(name);
}

async function ideFileMenu(e, path) {
  e.preventDefault();
  var action = await ideMenu(path, [
    {label: 'rename', value: 'rename'},
    {label: 'delete', value: 'delete'}
  ]);
  if (action === 'rename') {
    var newName = await idePrompt('rename file', '', path);
    if (newName && newName !== path) ideRenameFile(path, newName);
  } else if (action === 'delete') {
    var ok = await ideConfirm('delete file', 'delete ' + path + '?');
    if (ok) ideDeleteFile(path);
  }
}

async function ideRenameFile(oldPath, newPath) {
  if (_ideFiles[newPath] !== undefined) { alert('File already exists'); return; }
  _ideFiles[newPath] = _ideFiles[oldPath] || '';
  delete _ideFiles[oldPath];
  await ProjectStore.saveFile(_ideProject.id, newPath, _ideFiles[newPath]);
  await ProjectStore.deleteFile(_ideProject.id, oldPath);
  var idx = _ideOpenTabs.indexOf(oldPath);
  if (idx >= 0) _ideOpenTabs[idx] = newPath;
  if (_ideActiveFile === oldPath) _ideActiveFile = newPath;
  ideRenderAll();
}

async function ideDeleteFile(path) {
  delete _ideFiles[path];
  await ProjectStore.deleteFile(_ideProject.id, path);
  var idx = _ideOpenTabs.indexOf(path);
  if (idx >= 0) _ideOpenTabs.splice(idx, 1);
  if (_ideActiveFile === path) {
    _ideActiveFile = _ideOpenTabs.length > 0 ? _ideOpenTabs[0] : null;
  }
  ideRenderAll();
}

function ideCloseProject() {
  ideSaveCurrentFile();
  _ideProject = null;
  _ideFiles = {};
  _ideActiveFile = null;
  _ideOpenTabs = [];
  _ideMode = false;
  var tree = $('ide-file-tree');
  if (tree) tree.style.display = 'none';
  var bar = $('ide-project-bar');
  if (bar) bar.style.display = 'none';
  var tabs = $('ide-tabs');
  if (tabs) tabs.style.display = 'none';
  $('ct-source').value = '';
  editorUpdate();
  updateVerifyUI();
  showProjectPicker();
}

async function showProjectPicker() {
  var projects = await ProjectStore.listProjects();
  var pp = $('ide-project-picker');
  if (!pp) return;

  var html = '<div class="ide-picker-title">projects</div>';
  html += '<div class="ide-picker-section-label">new project</div>';
  html += '<div class="ide-picker-actions">';
  html += '<button class="action-btn" data-action="ideNewProject" data-arg="empty"><span class="tpl-label">Blank</span><span class="tpl-desc">empty program</span></button>';
  html += '<button class="action-btn" data-action="ideNewProject" data-arg="token"><span class="tpl-label">OCS-01 Token</span><span class="tpl-desc">fungible token</span></button>';
  html += '<button class="action-btn" data-action="ideNewProject" data-arg="vault"><span class="tpl-label">Vault</span><span class="tpl-desc">escrow program</span></button>';
  html += '</div>';
  html += '<div class="ide-picker-import">';
  html += '<label class="action-btn" style="cursor:pointer"><span class="ide-icon ico-upload"></span> import files<input type="file" accept=".json,.aml-project.json,.aml" multiple style="display:none" data-change="importFiles"></label>';
  html += '<label class="action-btn" style="cursor:pointer"><span class="ide-icon ico-folder-import"></span> import folder<input type="file" webkitdirectory style="display:none" data-change="importFiles"></label>';
  html += '</div>';

  if (projects.length > 0) {
    html += '<div class="ide-picker-list">';
    html += '<div class="ide-picker-list-title">recent</div>';
    projects.forEach(function(p) {
      html += '<div class="ide-picker-item" data-action="ideLoadProject" data-arg="' + escapeAttr(p.id) + '">' +
        '<span class="ide-picker-name">' + escapeHtml(p.name) + '</span>' +
        '<span class="ide-picker-date">' + new Date(p.created).toLocaleDateString() + '</span>' +
        '<button class="ide-btn-small" data-action="ideDeleteProject" data-arg="' + escapeAttr(p.id) + '" title="delete"><span class="ide-icon ico-delete"></span></button>' +
        '</div>';
    });
    html += '</div>';
  }
  pp.style.display = 'block';
  pp.innerHTML = html;
}

async function ideNewProject(template) {
  var tpl = await fetchTemplateFiles(template) || PROJECT_TEMPLATES[template] || PROJECT_TEMPLATES.empty;
  var name = await idePrompt('new project', '', tpl.name);
  if (!name || !name.trim()) return;
  var proj = await ProjectStore.createProject(name.trim(), template);
  var files = tpl.files;
  for (var path in files) {
    await ProjectStore.saveFile(proj.id, path, files[path]);
  }
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function ideLoadProject(id) {
  var projects = await ProjectStore.listProjects();
  var proj = projects.find(function(p) { return p.id === id; });
  if (!proj) return;
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function ideDeleteProject(id) {
  var ok = await ideConfirm('delete project', 'delete this project? this cannot be undone.');
  if (!ok) return;
  await ProjectStore.deleteProject(id);
  showProjectPicker();
}

async function ideExportZip() {
  if (!_ideProject) return;
  ideSaveCurrentFile();
  var bundle = {
    project: { name: _ideProject.name, template: _ideProject.template },
    files: _ideFiles
  };
  var blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (_ideProject.name || 'project').replace(/[^a-zA-Z0-9_-]/g, '_') + '.aml-project.json';
  a.click();
  URL.revokeObjectURL(a.href);
}

async function ideImportFiles(fileList) {
  if (!fileList || fileList.length === 0) return;
  var files = Array.from(fileList);

  function getRelPath(f) {
    var rel = f.webkitRelativePath || '';
    if (rel) {
      var slash = rel.indexOf('/');
      if (slash >= 0) rel = rel.substring(slash + 1);
    }
    return rel || f.name;
  }

  var jsonFiles = files.filter(function(f) { return f.name.endsWith('.json'); });
  if (jsonFiles.length === 1 && files.length === 1) {
    var reader = new FileReader();
    reader.onload = async function(e) {
      try {
        var bundle = JSON.parse(e.target.result);
        if (!bundle.project || !bundle.files) { alert('Invalid project file'); return; }
        var proj = await ProjectStore.createProject(
          bundle.project.name || 'Imported',
          bundle.project.template || 'empty'
        );
        for (var path in bundle.files) {
          await ProjectStore.saveFile(proj.id, path, bundle.files[path]);
        }
        var pp = $('ide-project-picker');
        if (pp) pp.style.display = 'none';
        await ideOpenProject(proj);
      } catch (err) {
        alert('Import failed: ' + err.message);
      }
    };
    reader.readAsText(jsonFiles[0]);
    return;
  }

  var amlFiles = files.filter(function(f) { return f.name.endsWith('.aml'); });
  if (amlFiles.length === 0) { alert('Select .aml or .aml-project.json files'); return; }

  var folderName = '';
  if (amlFiles[0].webkitRelativePath) {
    folderName = amlFiles[0].webkitRelativePath.split('/')[0];
  }
  var projName = folderName || (amlFiles.length === 1 ? amlFiles[0].name.replace('.aml', '') : 'Imported');

  if (_ideProject) {
    for (var i = 0; i < amlFiles.length; i++) {
      var content = await amlFiles[i].text();
      var path = getRelPath(amlFiles[i]);
      _ideFiles[path] = content;
      await ProjectStore.saveFile(_ideProject.id, path, content);
    }
    ideRenderAll();
    return;
  }

  var proj = await ProjectStore.createProject(projName, 'empty');
  var hasMain = false;
  for (var i = 0; i < amlFiles.length; i++) {
    var content = await amlFiles[i].text();
    var path = getRelPath(amlFiles[i]);
    if (amlFiles.length === 1 && path !== 'main.aml') { path = 'main.aml'; }
    if (path === 'main.aml') hasMain = true;
    await ProjectStore.saveFile(proj.id, path, content);
  }
  if (!hasMain && amlFiles.length > 1) {
    await ProjectStore.saveFile(proj.id, 'main.aml', '');
  }
  var pp = $('ide-project-picker');
  if (pp) pp.style.display = 'none';
  await ideOpenProject(proj);
}

async function doCompileProject() {
  if (!_ideProject) { doCompile(); return; }
  ideSaveCurrentFile();
  clearResult('ct-compile-result');
  editorClearError();
  _compiledAbi = null;
  _compiledVerification = null;
  _compiledCertificate = null;
  renderVerificationReport(null);
  var abiDiv = $('ct-abi-display');
  if (abiDiv) abiDiv.style.display = 'none';

  var files = [];
  for (var path in _ideFiles) {
    files.push({ path: path, source: _ideFiles[path] });
  }
  if (files.length === 0) {
    showResult('ct-compile-result', false, 'no files in project');
    return;
  }
  try {
    var res = await api('POST', '/contract/compile-project', { files: files, main: 'main.aml' });
    var b64 = res.bytecode || '';
    $('ct-bytecode').value = b64;
    var ver = res.version ? ('AppliedML ' + res.version + ' - ') : '';
    var msg = ver + 'compiled: ' + res.instructions + ' instructions, ' + res.size + ' bytes (' + files.length + ' files)';
    showResult('ct-compile-result', true, msg);
    if (res.abi) {
      _compiledAbi = res.abi;
      if (abiDiv) {
        $('ct-abi-json').textContent = JSON.stringify(res.abi, null, 2);
        abiDiv.style.display = 'block';
      }
    }
    if (res.disasm) {
      var disEl = $('ct-disasm-code');
      if (disEl) disEl.innerHTML = highlightDisasm(res.disasm);
    }
    if (res.verification) {
      _compiledVerification = res.verification;
      _compiledCertificate = res.certificate || null;
      renderVerificationReport(res.verification, _compiledCertificate);
      msg += ' | ' + verificationLabel(res.verification);
      showResult('ct-compile-result', verificationLevel(res.verification) !== 'error', msg + (verificationLevel(res.verification) === 'error' ? ' (deploy not blocked yet)' : ''));
      logVerificationTrace(res.verification);
    }
    showBottomPanels();
    consoleLog('info', msg);
  } catch (e) {
    var errMsg = e.message || '';
    var lineMatch = errMsg.match(/line\s+(\d+)/i);
    if (lineMatch) editorMarkError(parseInt(lineMatch[1], 10));
    showResult('ct-compile-result', false, errMsg);
    consoleLog('error', 'compile error: ' + errMsg);
  }
}

async function doVerifyProject() {
  if (!_ideProject) { doVerifyContract(); return; }
  ideSaveCurrentFile();
  clearResult('ct-verify-result');
  var addr = $('ct-verify-addr').value.trim();
  if (!addr) { showResult('ct-verify-result', false, 'program address required'); return; }

  var mainSource = _ideFiles['main.aml'] || '';
  if (!mainSource.trim()) { showResult('ct-verify-result', false, 'main.aml is empty'); return; }

  var depFiles = [];
  for (var path in _ideFiles) {
    if (path !== 'main.aml') {
      depFiles.push({ path: path, source: _ideFiles[path] });
    }
  }

  try {
    var payload = { address: addr, source: mainSource };
    if (depFiles.length > 0) payload.files = depFiles;
    var res = await api('POST', '/contract/verify', payload);
    var safety = res.verification ? '<br>' + verificationResultHtml(res.verification) : '';
    showResult('ct-verify-result', true,
      'source verified - code_hash: <span class="mono">' + escapeHtml(res.code_hash || '') + '</span>' + safety);
  } catch (e) {
    showResult('ct-verify-result', false, e.message);
  }
}

function networkLabel(host) {
  if (host === 'octra.network') return 'main net';
  if (host === 'devnet.octrascan.io' || host === '165.227.225.79') return 'dev net';
  if (host === 'localhost' || host === '127.0.0.1') return 'local';
  return host;
}

function $(id) { return document.getElementById(id); }

function updateStealthBadge(count) {
  _unclaimedCount = count;
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
  if (_walletSwitching) return;
  var addr = _walletAddr;
  try {
    var res = await api('GET', '/stealth/scan');
    if (_walletSwitching || addr !== _walletAddr) return;
    var outputs = res.outputs || [];
    var unclaimed = 0;
    for (var i = 0; i < outputs.length; i++) {
      if (outputs[i].claimed) { delete _pendingClaimIds[String(outputs[i].id)]; continue; }
      if (outputs[i].claimable === false) continue;
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
  } catch (e) {}
}

function currentBalanceData() {
  var state = ensureAddressRuntime(_walletAddr);
  if (state && state.balance) return state.balance;
  return _cachedBal;
}

function mergeBalanceData(bal) {
  var prev = currentBalanceData();
  var next = Object.assign({}, bal || {});
  if (next.account_unknown && prev && !prev.account_unknown) {
    next.public_balance = prev.public_balance;
    next.nonce = prev.nonce;
    next.staging = prev.staging;
    next.account_unknown = false;
    next.account_stale = true;
  }
  if (next.encrypted_balance_unknown && next.encrypted_cipher_present !== true && prev && !prev.encrypted_balance_unknown) {
    next.encrypted_balance = prev.encrypted_balance;
    next.encrypted_balance_known = prev.encrypted_balance_known;
    next.encrypted_cipher_present = prev.encrypted_cipher_present;
    next.encrypted_balance_unknown = false;
    next.encrypted_balance_stale = true;
  }
  return next;
}

function applyBalanceData(bal) {
  var next = mergeBalanceData(bal);
  _cachedBal = next;
  var accountUnknown = !!next.account_unknown;
  var pub = accountUnknown ? '' : (next.public_balance || '0');
  var encUnknown = !!next.encrypted_balance_unknown;
  _encPresent = next.encrypted_cipher_present === true;
  _encKnown = next.encrypted_balance_known !== false && !encUnknown;
  var enc = _encKnown ? (next.encrypted_balance || '0') : '';
  _encryptedBalanceRaw = _encKnown ? (parseInt(enc) || 0) : 0;
  if ($('btn-key-switch')) {
    if (encUnknown) {
      $('btn-key-switch').style.display = 'none';
    } else {
      if (_encPresent || _encryptedBalanceRaw > 0) {
        $('btn-key-switch').textContent = 'checking encryption upgrade...';
        $('btn-key-switch').style.display = '';
      }
      refreshPvacUpgradeStatus();
    }
  }
  var encText = _encKnown ? fmtOct(enc) : (_encPresent ? 'legacy encrypted balance' : '-');
  var pubText = accountUnknown ? '-' : fmtOct(pub);
  var nonceText = accountUnknown ? '-' : (next.nonce || '0');
  if ($('st-balance')) $('st-balance').textContent = pubText;
  if ($('st-enc-balance')) $('st-enc-balance').textContent = encText;
  if ($('ct-struct-link')) $('ct-struct-link').hidden = !_encPresent;
  if ($('st-nonce')) $('st-nonce').textContent = nonceText;
  if ($('st-staging')) $('st-staging').textContent = next.staging || '0';
  if ($('send-bal')) $('send-bal').textContent = pubText;
  if ($('enc-pub-bal')) $('enc-pub-bal').textContent = pubText;
  if ($('enc-enc-bal')) $('enc-enc-bal').textContent = encText;
  if ($('st-enc-bal-info')) $('st-enc-bal-info').textContent = encText;
  if ($('ct-bal')) $('ct-bal').textContent = pubText;
  $('hdr-status').textContent = _rpcHost ? 'online | ' + networkLabel(_rpcHost) : 'online';
  $('hdr-status').className = 'right online';
  return next;
}

function resetDashboardView() {
  _cachedBal = null;
  _encryptedBalanceRaw = 0;
  _encPresent = false;
  _encKnown = false;
  _pvacUpgradeStatus = null;
  if ($('st-balance')) $('st-balance').textContent = '-';
  if ($('st-enc-balance')) $('st-enc-balance').textContent = '-';
  if ($('ct-struct-link')) $('ct-struct-link').hidden = true;
  if ($('st-nonce')) $('st-nonce').textContent = '-';
  if ($('st-staging')) $('st-staging').textContent = '-';
  if ($('send-bal')) $('send-bal').textContent = '-';
  if ($('enc-pub-bal')) $('enc-pub-bal').textContent = '-';
  if ($('enc-enc-bal')) $('enc-enc-bal').textContent = '-';
  if ($('st-enc-bal-info')) $('st-enc-bal-info').textContent = '-';
  if ($('ct-bal')) $('ct-bal').textContent = '-';
  if ($('btn-key-switch')) $('btn-key-switch').style.display = 'none';
  if ($('dash-tx-count')) $('dash-tx-count').textContent = '0';
  if ($('dash-txs')) $('dash-txs').innerHTML = '<div class="staging-empty">loading...</div>';
  if ($('dash-more')) $('dash-more').innerHTML = '';
  updateStealthBadge(0);
}

async function fetchBalance(force) {
  if (_walletSwitching) return currentBalanceData();
  var addr = _walletAddr;
  var state = ensureAddressRuntime(_walletAddr);
  if (state && state.balanceInflight) return state.balanceInflight;
  if (!force && state && state.balance && (Date.now() - state.balanceTs) < BALANCE_CACHE_TTL_MS) {
    applyBalanceData(state.balance);
    return state.balance;
  }
  if (!force && state && !state.balance) {
    var persisted = restorePersistedBalance(_walletAddr);
    if (persisted) {
      state.balance = persisted;
      state.balanceTs = Date.now();
      applyBalanceData(persisted);
    }
  }
  var request = api('GET', '/balance')
    .then(function(bal) {
      if (_walletSwitching || addr !== _walletAddr) return bal;
      var next = applyBalanceData(bal);
      if (state) {
        state.balance = next;
        state.balanceTs = Date.now();
      }
      persistBalance(addr, next);
      return next;
    })
    .catch(function() {
      if (!_walletSwitching && addr === _walletAddr) {
        $('hdr-status').textContent = 'offline';
        $('hdr-status').className = 'right error';
        if (!currentBalanceData()) resetDashboardView();
      }
      return null;
    })
    .finally(function() {
      if (state) state.balanceInflight = null;
    });
  if (state) state.balanceInflight = request;
  return request;
}

async function api(method, path, body) {
  var opts = { method: method, headers: {} };
  var timeoutMs = apiTimeoutMs(method, path);
  var controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  var timeoutId = null;
  if (controller) {
    opts.signal = controller.signal;
    timeoutId = setTimeout(function() { controller.abort(); }, timeoutMs);
  }

  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  var res;
  try {
    res = await fetch('/api' + path, opts);
  } catch (e) {
    if (e && e.name === 'AbortError') throw new Error('request timed out');
    throw e;
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
  var text = await res.text();
  if (!text || text.length === 0) throw new Error('empty response from RPC (possible timeout)');
  var j;
  try { j = JSON.parse(text); } catch (e) { throw new Error('invalid server response: ' + escapeHtml(text.substring(0, 200))); }
  if (j && j.error) throw new Error(escapeHtml(j.error || j.message || 'request failed'));
  if (!res.ok) throw new Error(escapeHtml(j.error || j.message || 'request failed'));
  return j;
}

function apiTimeoutMs(method, path) {
  if (method !== 'GET') {
    if (path === '/pvac/upgrade' || path === '/key_switch') return 900000;
    if (path === '/encrypt' || path === '/decrypt') return 900000;
    if (path === '/stealth/send' || path === '/stealth/claim') return 900000;
    return 30000;
  }
  if (path === '/stealth/scan') return 9000;
  if (path === '/pvac/upgrade_status') return 12000;
  return 10000;
}

async function fetchFees() {
  try {
    _fees = await api('GET', '/fee');
    applyFeeDefaults();
  } catch (e) {}
}

function ouToOct(ou) {
  var n = parseInt(ou);
  if (isNaN(n) || n <= 0) return '?';
  var oct = n / 1000000;
  return oct % 1 === 0 ? oct.toFixed(0) : oct.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');
}

function applyFeeDefaults() {
  var map = {
    'send-fee': 'standard',
    'enc-fee': 'encrypt',
    'dec-fee': 'decrypt',
    'stealth-fee': 'stealth',
    'ct-deploy-fee': 'deploy',
    'ct-call-fee': 'call',
    'tok-fee': 'call'
  };
  for (var id in map) {
    var input = $(id);
    var fee = _fees[map[id]];
    if (input && fee) {
      var rec = fee.recommended || fee.minimum || '';
      if (!input.value || input.value === input.getAttribute('data-prev-default')) {
        input.value = rec;
        input.setAttribute('data-prev-default', rec);
      }
      input.placeholder = 'min: ' + (fee.minimum || '?');
    }
  }
  var btnDeploy = $('btn-deploy');
  if (btnDeploy && _fees.deploy) {
    var cost = _fees.deploy.base_fee || _fees.deploy.recommended;
    btnDeploy.textContent = 'deploy (' + ouToOct(cost) + ' oct)';
  }
}

function validateFee(inputId, opType) {
  var input = $(inputId);
  if (!input) return true;
  var val = input.value.trim();
  if (!val) return true;
  var n = parseInt(val);
  if (isNaN(n) || n <= 0 || String(n) !== val) return false;
  var fee = _fees[opType];
  if (fee && fee.minimum && n < parseInt(fee.minimum)) return false;
  return true;
}

function feeError(resultId, inputId, opType) {
  var fee = _fees[opType];
  var minStr = (fee && fee.minimum) ? fee.minimum : '?';
  showResult(resultId, false, 'invalid fee - must be integer >= ' + minStr);
  if ($(inputId)) $(inputId).focus();
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
  if (name === 'dev' && !_ideProject) showProjectPicker();
  if (name === 'encrypt') refreshEncryptBalances();
  if (name === 'stealth') refreshStealthBalance();
  if (name === 'tokens') loadTokens();
  if (name === 'dev') refreshContractBalance();
  var devBtn = $('hdr-dev');
  if (devBtn) devBtn.style.background = (name === 'dev') ? '#3B567F' : '';
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

function formatUnits(rawStr, decimals) {
  var dec = parseInt(decimals) || 0;
  var s = String(rawStr).replace(/[^0-9]/g, '');
  if (s === '' || s === '0') return '0';
  if (dec === 0) return s;
  while (s.length <= dec) s = '0' + s;
  var intPart = s.slice(0, s.length - dec);
  var fracPart = s.slice(s.length - dec).replace(/0+$/, '');
  if (!intPart) intPart = '0';
  return fracPart ? intPart + '.' + fracPart : intPart;
}

function fmtTokenAmount(raw, decimals) {
  return addCommas(formatUnits(raw, decimals));
}

function fmtTokenCompact(raw, decimals) {
  var human = formatUnits(raw, decimals);
  if (human === '0') return '0';
  var n = parseFloat(human);
  if (n >= 1000000000) return (n / 1000000000).toFixed(1).replace(/\.0$/, '') + 'B';
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K';
  return addCommas(human);
}

function fmtOctCompact(raw) {
  var v = parseFloat(raw);
  if (v === 0 || isNaN(v)) return '-';
  var n = v / 1000000;
  if (n >= 1000000) return (n / 1000000).toFixed(1).replace(/\.0$/, '') + 'M oct';
  if (n >= 1000) return (n / 1000).toFixed(1).replace(/\.0$/, '') + 'K oct';
  if (n > 0 && n < 0.001) return '< 0.001 oct';
  var s = n.toFixed(1);
  if (s === '0.0' && n > 0) s = n.toFixed(3).replace(/\.?0+$/, '');
  else s = s.replace(/\.0$/, '');
  return addCommas(s) + ' oct';
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

function txLinkExt(hash) {
  if (!hash) return '';
  if (!/^[a-f0-9]{64}$/.test(hash)) return '<span class="mono gray">' + escapeHtml(hash) + '</span>';
  var url = _explorerUrl + '/tx.html?hash=' + hash;
  return '<a class="mono" href="' + url + '" target="_blank" title="' + hash + '">' + short(hash) + '</a>';
}

function addrLink(addr) {
  if (!addr || addr === 'stealth' || addr === 'coinbase') return '<span class="gray">' + (addr || '-') + '</span>';
  if (!validAddr(addr)) return '<span class="mono gray">' + escapeHtml(addr) + '</span>';
  var display = short(addr);
  var url = _explorerUrl + '/address.html?addr=' + addr;
  return '<a class="mono addr" href="' + url + '" target="_blank" title="' + addr + '">' + display + '</a>';
}

function txLink(hash) {
  if (!hash) return '<span class="gray">-</span>';
  if (!/^[a-f0-9]{64}$/.test(hash)) return '<span class="mono gray">' + escapeHtml(hash) + '</span>';
  return '<a class="mono hash" href="#" data-action="showTx" data-arg="' + hash + '" data-prevent="1">' + short(hash) + '</a>';
}

function stealthClaimStatusLabel(status) {
  if (status === 'legacy_stealth_output') return 'legacy output migration required';
  if (status === 'pvac_key_upgrade_required') return 'encryption upgrade required';
  if (status === 'pvac_key_not_confirmed') return 'PVAC key confirmation required';
  if (status === 'amount_commitment_mismatch') return 'amount commitment mismatch';
  if (status === 'amount_commitment_missing') return 'amount commitment missing';
  return status || 'not claimable';
}

function opTag(op) {
  if (op === 'stealth') return '<span class="stealth-tag">stealth</span>';
  if (op === 'claim') return '<span class="private-tag">claim</span>';
  if (op === 'encrypt') return '<span class="private-tag">encrypt</span>';
  if (op === 'decrypt') return '<span class="private-tag">decrypt</span>';
  if (op === 'private_transfer') return '<span class="private-tag">private</span>';
  if (op === 'deploy' || op === 'contract_deploy' || op === 'program_deploy') return '<span class="program-tag">program_deploy</span>';
  if (op === 'call' || op === 'contract_call' || op === 'program_call') return '<span class="program-tag">program_call</span>';
  if (op === 'key_switch') return '<span class="private-tag">key_switch</span>';
  return '';
}

function statusTag(st) {
  if (st === 'confirmed') return '<span class="private-tag">confirmed</span>';
  if (st === 'rejected') return '<span class="stealth-tag">rejected</span>';
  if (st === 'pending') return '<span class="pending-text">pending</span>';
  return '<span class="pending-text">' + escapeHtml(st || 'pending') + '</span>';
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

const networkText = value => String(value || '').replace(/\bnode\b/gi, 'network');

function validAddr(addr) {
  return /^oct[1-9A-HJ-NP-Za-km-z]{43,45}$/.test(addr);
}

const logState = cls => cls === 'log-ok' ? 'done' : (cls === 'log-err' ? 'error' : 'active');

const renderLogRow = (state, msg) => {
  const text = state === 'error' ? msg.replace(/^error:\s*/i, '') : msg;
  const caret = state === 'active' ? '<span class="caret" aria-hidden="true"></span>' : '';
  return '<div class="op-step op-' + state + '">' +
    '<span class="op-mark"></span>' +
    '<span class="op-state">' + state + '</span>' +
    '<span class="op-msg">' + text + caret + '</span>' +
    '</div>';
};

const settleActiveLog = el => {
  el.querySelectorAll('.op-active').forEach(row => {
    row.classList.remove('op-active');
    row.classList.add('op-done');
    const state = row.querySelector('.op-state');
    if (state) state.textContent = 'done';
    const caret = row.querySelector('.caret');
    if (caret) caret.remove();
  });
};

const appendPrivateLog = (id, selector, msg, cls) => {
  let el = $(id);
  if (!el) {
    const btn = document.querySelector(selector);
    if (!btn) return;
    const row = btn.closest('.action-row') || btn.parentNode;
    el = document.createElement('div');
    el.id = id;
    el.className = 'op-log';
    row.parentNode.insertBefore(el, row.nextSibling);
  }
  settleActiveLog(el);
  el.insertAdjacentHTML(
    'beforeend',
    msg ? renderLogRow(logState(cls), msg) : '<div class="op-log-gap"></div>'
  );
  el.scrollTop = el.scrollHeight;
};

function logStealth(msg, cls) {
  appendPrivateLog('stealth-log', 'button[data-action="doStealthSend"]', msg, cls);
}

function clearStealthLog() {
  var el = $('stealth-log');
  if (el) el.remove();
}

function logDecrypt(msg, cls) {
  appendPrivateLog('decrypt-log', 'button[data-action="doDecrypt"]', msg, cls);
}

function clearDecryptLog() {
  var el = $('decrypt-log');
  if (el) el.remove();
}

function logEncrypt(msg, cls) {
  appendPrivateLog('encrypt-log', 'button[data-action="doEncrypt"]', msg, cls);
}

function clearEncryptLog() {
  var el = $('encrypt-log');
  if (el) el.remove();
}

function txStatusTag(st) {
  if (st === 'rejected') return '<span class="rejected-tag">rejected</span>';
  if (st === 'confirmed') return '<span class="confirmed-tag">confirmed</span>';
  if (st === 'pending') return '<span class="pending-text">pending</span>';
  return '<span class="pending-text">' + escapeHtml(st || 'pending') + '</span>';
}

const tokenTransfer = tx => {
  const token = tx.token_address || tx.to_ || tx.to || '';
  const tagged = tx.token_transfer === true ||
    (tx.op_type === 'call' && tx.encrypted_data === 'transfer');
  if (!tagged || !token) return null;
  let recipient = tx.recipient || '';
  let amount = tx.token_amount_raw === undefined ? '' : String(tx.token_amount_raw);
  if ((!recipient || !amount) && tx.message) {
    try {
      const params = JSON.parse(tx.message);
      if (Array.isArray(params) && params.length >= 2) {
        recipient = recipient || String(params[0] || '');
        amount = amount || String(params[1]);
      }
    } catch (e) {}
  }
  if (!validAddr(recipient) || !/^[0-9]+$/.test(amount)) return null;
  return { token: token, recipient: recipient, amount: amount };
};

function txAmt(tx) {
  var transfer = tokenTransfer(tx);
  if (transfer) {
    var sym = _tokenSymbols[transfer.token] || '';
    var dec = _tokenDecimals[transfer.token] || '0';
    var cls = tx.from === _walletAddr ? ' red' : (transfer.recipient === _walletAddr ? ' green' : '');
    return {
      amt: fmtTokenCompact(transfer.amount, dec) + (sym ? ' ' + sym : ''),
      cls: cls,
      toOverride: transfer.recipient
    };
  }
  var raw = tx.amount_raw ? parseFloat(tx.amount_raw) : 0;
  if (raw > 0) {
    var dir = '';
    if (tx.from === _walletAddr) dir = ' red';
    else if ((tx.to_ || tx.to) === _walletAddr) dir = ' green';
    return { amt: fmtOctCompact(tx.amount_raw), cls: dir, toOverride: null };
  }
  return { amt: '-', cls: ' gray', toOverride: null };
}

function txRow(tx) {
  var a = txAmt(tx);
  var toAddr = a.toOverride || (tx.to_ || tx.to);
  var st = tx.status || 'pending';
  var h = '<tr>';
  h += '<td>' + txLink(tx.hash) + '</td>';
  h += '<td>' + addrLink(tx.from) + '</td>';
  h += '<td>' + addrLink(toAddr) + '</td>';
  h += '<td class="mono amount' + a.cls + '">' + escapeHtml(a.amt) + '</td>';
  h += '<td>' + txStatusTag(st) + '</td>';
  h += '<td class="gray">' + fmtDate(tx.timestamp) + '</td>';
  h += '</tr>';
  return h;
}

function txCardHtml(tx) {
  var a = txAmt(tx);
  var toAddr = a.toOverride || (tx.to_ || tx.to);
  var st = tx.status || 'pending';
  var c = '<div class="tx-card">';
  c += '<div class="card-row"><span class="card-label">tx</span><span class="card-val">' + txLink(tx.hash) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">from</span><span class="card-val">' + addrLink(tx.from) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">to</span><span class="card-val">' + addrLink(toAddr) + '</span></div>';
  c += '<div class="card-row"><span class="card-label">amount</span><span class="card-val mono amount' + a.cls + '">' + escapeHtml(a.amt) + '</span></div>';
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
    var explorerLink = _explorerUrl + '/tx.html?hash=' + encodeURIComponent(fullHash);
    h += '<tr><td>hash</td><td class="mono">' + escapeHtml(fullHash) + ' <a href="' + escapeHtml(explorerLink) + '" target="_blank" style="font-size:10px;color:#8C9DB6;margin-left:4px">explorer</a></td></tr>';
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

    if (res.signature) h += '<tr><td>signature</td><td class="mono">' + escapeHtml(res.signature) + '</td></tr>';
    if (res.public_key) h += '<tr><td>public key</td><td class="mono">' + escapeHtml(res.public_key) + '</td></tr>';
    h += '</table>';
    if (res.message && res.message !== 'null' && res.message !== '') {
      h += '<div class="tx-message">';
      h += '<div class="section-title">message</div>';
      h += '<div class="msg-box">' + escapeHtml(res.message) + '</div>';
      h += '</div>';
    }
    $('tx-detail').innerHTML = h;
  } catch (e) {
    $('tx-detail').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
  }
}

function escapeHtml(s) {
  var d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function escapeAttr(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function dashTxLimit() {
  var h = window.innerHeight;
  var overhead = 280;
  var rowH = 26;
  if (window.innerWidth < 700) { overhead = 300; rowH = 120; }
  return Math.max(5, Math.min(Math.floor((h - overhead) / rowH), 100));
}

function renderDashTxs(txs) {
  $('dash-tx-count').textContent = String(txs.length);
  var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
  var cards = '<div class="card-list">';
  for (var i = 0; i < txs.length; i++) {
    h += txRow(txs[i]);
    cards += txCardHtml(txs[i]);
  }
  h += '</table>';
  cards += '</div>';
  $('dash-txs').innerHTML = h + cards;
  $('dash-more').innerHTML = '<div class="dash-more-row"><a href="#" data-action="switchView" data-arg="history" data-prevent="1">view full history</a></div>';
}

async function loadDashboard() {
  if (_walletSwitching) return;
  fetchBalance(false);
  var rendered = false;
  try {
    var lim = dashTxLimit();
    var cached = peekHistoryPage(_walletAddr, lim, 0);
    var cachedEmpty = false;
    if (cached) {
      rendered = true;
      var cachedTxs = cached.response.transactions || [];
      if (cachedTxs.length === 0) {
        cachedEmpty = true;
        $('dash-tx-count').textContent = '0';
        $('dash-txs').innerHTML = '<div class="staging-empty">no transactions yet</div>';
        $('dash-more').innerHTML = '';
      } else {
        renderDashTxs(cachedTxs);
        fetchMissingSymbols(cachedTxs).then(function() { renderDashTxs(cachedTxs); });
      }
      if (!cachedEmpty && (Date.now() - cached.ts) <= HISTORY_STALE_REFRESH_MS) return;
    }
    var hist = await fetchHistoryPage(lim, 0, cachedEmpty);
    var txs = hist.transactions || [];
    if (txs.length === 0) {
      $('dash-tx-count').textContent = '0';
      $('dash-txs').innerHTML = '<div class="staging-empty">no transactions yet</div>';
      $('dash-more').innerHTML = '';
      return;
    }
    renderDashTxs(txs);
    fetchMissingSymbols(txs).then(function() { renderDashTxs(txs); });
  } catch (e) {
    if (!rendered && $('dash-txs') && !$('dash-txs').innerHTML.trim()) {
      $('dash-txs').innerHTML = '<div class="error-box">history temporarily unavailable</div>';
    }
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
  if (!validateFee('send-fee', 'standard')) { feeError('send-result', 'send-fee', 'standard'); return; }
  try {
    var pin = await modalPrompt('confirm send', 'enter PIN to send ' + amount + ' oct to ' + to, { pin: true, btnText: 'send' });
    if (!pin) { showResult('send-result', false, 'send cancelled'); return; }
    var body = { to: to, amount: amount, pin: pin };
    if (msg) body.message = msg;
    var fee = $('send-fee') ? $('send-fee').value.trim() : '';
    if (fee) body.ou = fee;
    var res = await api('POST', '/send', body);
    var txHash = res.hash || res.tx_hash || '';
    invalidateCurrentAddressState();
    showResult('send-result', true, 'sent ' + amount + ' oct - tx: ' + txLink(txHash));
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

async function refreshPvacUpgradeStatus() {
  if (_walletSwitching) return _pvacUpgradeStatus;
  try {
    const st = await api('GET', '/pvac/upgrade_status');
    _pvacUpgradeStatus = st;
    const btn = $('btn-key-switch');
    if (!btn) return st;
    if (_pvacUpgradeInFlight || st.upgrade_inflight) {
      btn.textContent = 'upgrade in progress...';
      btn.disabled = true;
      btn.style.display = '';
      return st;
    }
    if (st.mode === 'upgrade_recent') {
      btn.textContent = 'upgrade submitted';
      btn.disabled = true;
      btn.style.display = '';
      return st;
    }
    btn.disabled = false;
    const resetMode = st.mode === 'legacy_zero_reset';
    const upgradeMode = st.mode === 'key_bound_migration' || st.mode === 'legacy_public_migration' || st.mode === 'legacy_commitment_migration';
    const repairMode = st.repair_required === true;
    const compactMode = st.compact_refresh === true;
    if (st.can_submit) {
      btn.textContent = resetMode ? 'reset encrypted balance' : (repairMode ? 'repair encrypted balance' : (compactMode ? 'refresh encrypted balance' : (upgradeMode ? 'upgrade encrypted balance' : 'switch encryption key')));
      btn.style.display = '';
    } else if (st.mode === 'legacy_blocked' || st.mode === 'key_mismatch' || st.mode === 'blocked' || st.mode === 'fee_blocked') {
      btn.textContent = st.mode === 'fee_blocked' ? 'public fee required for upgrade' : 'encryption upgrade unavailable';
      btn.disabled = false;
      btn.style.display = '';
    } else {
      btn.style.display = 'none';
    }
    return st;
  } catch (e) {
    const btn = $('btn-key-switch');
    if (btn && (_encPresent || _encryptedBalanceRaw > 0)) {
      btn.textContent = 'check encryption upgrade';
      btn.style.display = '';
    }
    return null;
  }
}

async function doKeySwitch() {
  if (_pvacUpgradeInFlight) return;
  hideAllModalPanels();
  $('modal-sub').textContent = 'encryption key switching';
  const st = _pvacUpgradeStatus || await refreshPvacUpgradeStatus();
  if (!st) {
    $('modal-result').innerHTML = '<div class="result-msg result-error" style="margin:20px 0">cannot read encryption upgrade status</div>';
    $('modal-overlay').style.display = 'flex';
    return;
  }
  const resetMode = st.mode === 'legacy_zero_reset';
  const upgradeMode = st.mode === 'key_bound_migration' || st.mode === 'legacy_public_migration' || st.mode === 'legacy_commitment_migration';
  const repairMode = st.repair_required === true;
  const compactMode = st.compact_refresh === true;
  const title = resetMode ? 'encrypted balance reset' : (repairMode ? 'encrypted balance repair' : (compactMode ? 'encrypted balance refresh' : (upgradeMode ? 'encrypted balance upgrade' : 'encryption key switch')));
  const detailRow = (label, value, mono) => {
    const safeValue = escapeHtml(value);
    const renderedValue = mono ? '<span class="mono">' + safeValue + '</span>' : safeValue;
    return '<div class="modal-detail-row"><b>' + escapeHtml(label) + ':</b> ' + renderedValue + '</div>';
  };
  let h = '<div class="modal-detail">';
  h += '<div class="modal-detail-title"><b>' + escapeHtml(title) + '</b></div>';
  if (st.mode === 'upgrade_recent') {
    h += detailRow('status', 'transaction submitted to network', false);
    if (st.tx_hash) h += '<div class="modal-detail-row upgrade-tx"><b>tx:</b><span>' + escapeHtml(st.tx_hash) + '</span></div>';
    h += '<div class="modal-detail-note">Submitted. Refresh after confirmation.</div>';
    h += '</div>';
    h += '<div class="action-row"><button class="action-btn" id="ks-cancel">close</button></div>';
    $('modal-result').innerHTML = h;
    $('modal-overlay').style.display = 'flex';
    $('ks-cancel').onclick = function() {
      $('modal-result').innerHTML = '';
      $('modal-overlay').style.display = 'none';
      fetchBalance();
    };
    return;
  }
  h += detailRow('status', networkText(st.reason || st.mode || ''), false);
  const balanceText = st.encrypted_balance_known
    ? fmtOct(st.encrypted_balance_raw || '0')
    : (st.cipher_present ? 'legacy ciphertext | upgrade required' : '0 oct');
  h += detailRow('encrypted balance', balanceText, true);
  if (st.required_public_fee_raw) {
    h += detailRow('required public fee', fmtOct(st.required_public_fee_raw), true);
  }
  if (st.public_balance_raw) {
    h += detailRow('public balance', fmtOct(st.public_balance_raw), true);
  }
  if (st.can_submit) {
    if (resetMode) {
      h += '<div class="modal-detail-note modal-detail-note-danger">Replaces the legacy ciphertext with verified zero. Any hidden balance will be lost.</div>';
    } else if (repairMode) {
      h += '<div class="modal-detail-note">Rebuilds the same balance after a local proof failure.</div>';
    } else if (compactMode) {
      h += '<div class="modal-detail-note">Rebuilds the same balance as a compact ciphertext.</div>';
    } else if (st.mode === 'legacy_commitment_migration') {
      h += '<div class="modal-detail-note">Rebuilds the balance from verified history commitments. Keep this wallet open.</div>';
    } else if (st.mode === 'legacy_public_migration') {
      h += '<div class="modal-detail-note">Rebuilds the balance from verified public history.</div>';
    } else {
      h += '<div class="modal-detail-note">Builds local ciphertext proofs. Keep this wallet open.</div>';
    }
  } else {
    h += '<div class="modal-detail-note">No local upgrade is available. Funds are unchanged.</div>';
  }
  h += '</div>';
  h += '<div class="action-row">';
  if (st.can_submit) h += '<button class="action-btn" id="ks-confirm">' + (resetMode ? 'reset to zero' : (repairMode ? 'repair' : (compactMode ? 'refresh' : (upgradeMode ? 'upgrade' : 'switch')))) + '</button>';
  else h += '<button class="action-btn action-btn-muted" disabled>not available</button>';
  h += '<button class="action-btn" style="background:#8C9DB6" id="ks-cancel">cancel</button>';
  h += '</div>';
  $('modal-result').innerHTML = h;
  $('modal-overlay').style.display = 'flex';
  $('ks-cancel').onclick = function() {
    $('modal-result').innerHTML = '';
    $('modal-overlay').style.display = 'none';
  };
  if (!st.can_submit) return;
  $('ks-confirm').onclick = async function() {
    const resetPhrase = 'RESET ENCRYPTED BALANCE';
    const resetConfirm = resetMode
      ? await modalPrompt(
          'confirm encrypted balance reset',
          'type ' + resetPhrase,
          { placeholder: resetPhrase })
      : '';
    if (resetMode && resetConfirm !== resetPhrase) {
      hideAllModalPanels();
      $('modal-sub').textContent = 'encryption key switching';
      $('modal-result').innerHTML = '<div class="result-msg result-error">reset confirmation did not match</div>';
      $('modal-overlay').style.display = 'flex';
      return;
    }
    const promptTitle = resetMode ? 'confirm encrypted balance reset' : (repairMode ? 'confirm encryption repair' : (compactMode ? 'confirm encrypted balance refresh' : 'confirm encryption upgrade'));
    const promptText = resetMode ? 'enter PIN to authorize the zero reset' : (repairMode ? 'enter PIN to repair the encrypted balance' : (compactMode ? 'enter PIN to refresh the encrypted balance' : 'enter PIN to authorize the upgrade'));
    const promptButton = resetMode ? 'reset to zero' : (repairMode ? 'repair' : (compactMode ? 'refresh' : (upgradeMode ? 'upgrade' : 'switch')));
    const pin = await modalPrompt(promptTitle, promptText, { pin: true, btnText: promptButton });
    if (!pin) return;
    _pvacUpgradeInFlight = true;
    let currentUpgradeStage = 'checking_fee';
    let pollUpgradeStatus = null;
    const btn = $('btn-key-switch');
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'upgrade in progress...';
    }
    const upgradeSteps = [
      { key: 'unlock', label: 'local wallet unlocked' },
      { key: 'checking_fee', label: 'checking key_switch fee and public balance' },
      {
        key: 'building_proof',
        label: resetMode
          ? 'building verified zero replacement proof'
          : (repairMode
            ? 'building encrypted balance repair proof'
            : (compactMode
              ? 'building encrypted balance refresh proof'
              : 'building encrypted balance migration proof'))
      },
      { key: 'submitting', label: 'submitting key_switch transaction' },
      { key: 'submitted', label: 'transaction submitted to network' },
      { key: 'confirmed', label: 'transaction confirmed by chain' }
    ];
    const upgradeStageIndex = function(stage) {
      return upgradeSteps.findIndex(function(step) { return step.key === stage; });
    };
    const renderUpgradeLog = function(stage, detail, txHash, failed, finished) {
      const safeStage = stage || currentUpgradeStage || 'checking_fee';
      if (safeStage !== 'error') currentUpgradeStage = safeStage;
      const terminal = finished || safeStage === 'confirmed';
      const displayStage = failed ? currentUpgradeStage : safeStage;
      const activeIndexRaw = upgradeStageIndex(displayStage);
      const activeIndex = activeIndexRaw >= 0 ? activeIndexRaw : 1;
      const activeLabel = upgradeSteps[activeIndex] ? upgradeSteps[activeIndex].label : '';
      const detailText = networkText(detail);
      const detailLower = detailText.toLowerCase();
      const detailRedundant = detailLower === activeLabel.toLowerCase() ||
        (displayStage === 'submitted' && detailLower.indexOf('transaction submitted') === 0);
      $('modal-sub').textContent = 'encryption upgrade in progress';
      $('modal-overlay').style.display = 'flex';
      let out = '<div class="modal-detail' + (failed ? ' result-error' : '') + '">';
      out += '<div class="modal-detail-title">' + escapeHtml(title) + '</div>';
      out += '<div id="upgrade-log">';
      upgradeSteps.forEach(function(step, idx) {
        let state = 'pending';
        if (failed && idx === activeIndex) {
          state = 'error';
        } else if ((!failed && terminal) || idx < activeIndex) {
          state = 'done';
        } else if (idx === activeIndex) {
          state = 'active';
        }
        out += renderLogRow(state === 'pending' ? 'wait' : state, escapeHtml(step.label));
      });
      if (txHash) out += renderLogRow('done', 'tx <span class="upgrade-tx">' + escapeHtml(txHash) + '</span>');
      out += '</div>';
      if (detailText && !detailRedundant) {
        out += '<div class="note-box' + (failed ? ' note-error' : '') + '"><b>detail:</b> ' + escapeHtml(detailText) + '</div>';
      }
      if (!failed && !terminal) {
        out += '<div class="upgrade-wait">building proof (keep wallet open)</div>';
      }
      out += '</div>';
      if (terminal && txHash) {
        out += '<div style="margin:12px 0;font-size:13px">tx: ' + txLinkExt(txHash) + '</div>';
      }
      if (failed || terminal) {
        out += '<div class="action-row"><button class="action-btn" id="ks-close">close</button></div>';
      }
      $('modal-result').innerHTML = out;
      const close = $('ks-close');
      if (close) close.onclick = function() {
        $('modal-overlay').style.display = 'none';
        fetchBalance();
      };
    };
    const pollUpgrade = async function() {
      try {
        if (currentUpgradeStage === 'confirmed') return;
        const progress = await api('GET', '/pvac/upgrade_status');
        const stage = progress.stage || (progress.upgrade_inflight ? 'building_proof' : currentUpgradeStage);
        if (currentUpgradeStage === 'confirmed' && stage !== 'error') return;
        const detail = progress.detail || progress.reason || '';
        const txHash = progress.tx_hash || '';
        if (progress.upgrade_inflight || stage === 'submitted') {
          renderUpgradeLog(stage, detail, txHash, false, false);
        }
      } catch (e) {}
    };
    const waitUpgradeTx = async function(txHash) {
      if (!txHash) return { ok: false, detail: 'missing transaction hash' };
      for (let i = 0; i < 30; i++) {
        try {
          const tx = await api('GET', '/tx?hash=' + encodeURIComponent(txHash));
          const st = tx.status || '';
          if (st === 'confirmed' || st === 'accepted') return { ok: true, detail: 'confirmed' };
          if (st === 'rejected') {
            const reason = tx.reject_reason || tx.reject_type || tx.error || 'rejected';
            return { ok: false, detail: String(reason) };
          }
        } catch (e) {}
        await new Promise(function(resolve) { setTimeout(resolve, 4000); });
      }
      return { ok: false, detail: 'confirmation timeout' };
    };
    renderUpgradeLog('checking_fee', 'checking key_switch fee and public balance', '', false, false);
    pollUpgradeStatus = setInterval(pollUpgrade, 1500);
    try {
      const upgradeBody = { pin: pin };
      if (resetMode) upgradeBody.reset_confirm = resetConfirm;
      const res = await api('POST', '/pvac/upgrade', upgradeBody);
      const txHash = res.hash || res.tx_hash || '';
      invalidateCurrentAddressState();
      _pvacUpgradeStatus = null;
      renderUpgradeLog('submitted', 'transaction submitted (waiting for final status)', txHash, false, false);
      const finalStatus = await waitUpgradeTx(txHash);
      if (!finalStatus.ok) {
        try {
          await api('POST', '/pvac/upgrade_reject', {
            tx_hash: txHash,
            detail: finalStatus.detail,
            pin: pin
          });
        } catch(e) {}
        renderUpgradeLog('submitted', finalStatus.detail, txHash, true, true);
      } else {
        renderUpgradeLog('confirmed', 'transaction confirmed (refreshing wallet state)', txHash, false, true);
        try { await api('POST', '/pvac/upgrade_ack', { tx_hash: txHash }); } catch(e) {}
        try { await fetchBalance(); } catch(e) {}
        try { await loadHistory(); } catch(e) {}
      }
    } catch (e) {
      const msg = e.message || 'upgrade failed';
      renderUpgradeLog('error', msg, '', true, true);
    } finally {
      if (pollUpgradeStatus) clearInterval(pollUpgradeStatus);
      _pvacUpgradeInFlight = false;
      const btn2 = $('btn-key-switch');
      if (btn2) btn2.disabled = false;
      refreshPvacUpgradeStatus();
    }
  };
}

async function doEncrypt() {
  clearResult('enc-result');
  clearEncryptLog();
  var amount = $('enc-amount').value.trim();
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logEncrypt('error: invalid amount', 'log-err'); return; }
  if (!validateFee('enc-fee', 'encrypt')) { logEncrypt('error: invalid fee - must be integer >= ' + ((_fees.encrypt && _fees.encrypt.minimum) || '?'), 'log-err'); return; }
  var btn = document.querySelector('button[data-action="doEncrypt"]');
  try {
    logEncrypt('initiating encrypt', 'log-info');
    logEncrypt('amount: ' + amount + ' oct', 'log-info');
    logEncrypt('waiting for PIN', 'log-info');
    var pin = await modalPrompt('confirm encrypt', 'enter PIN to encrypt ' + amount + ' oct', { pin: true, btnText: 'encrypt' });
    if (!pin) { logEncrypt('encrypt cancelled', 'log-err'); return; }
    if (btn) {
      btn.disabled = true;
      btn.textContent = 'encrypting...';
    }
    setPrivateOpBusy(true);
    logEncrypt('pin accepted locally', 'log-ok');
    await ensurePrivateSpendCompact(pin, logEncrypt);
    logEncrypt('building ciphertext and bound proof (keep wallet open)', 'log-info');
    var encBody = { amount: amount, pin: pin };
    var encFee = $('enc-fee') ? $('enc-fee').value.trim() : '';
    if (encFee) encBody.ou = encFee;
    var res = await api('POST', '/encrypt', encBody);
    var txHash = res.hash || res.tx_hash || '';
    invalidateCurrentAddressState();
    logEncrypt('encrypt transaction accepted by network', 'log-ok');
    if (txHash) logEncrypt('tx: ' + txLink(txHash), 'log-ok');
    showResult('enc-result', true, 'encrypted ' + amount + ' oct');
    $('enc-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    var msg = e && e.message ? e.message : 'request failed';
    if (msg === 'Failed to fetch') msg = 'local wallet request failed (check history before retrying)';
    logEncrypt('error: ' + msg, 'log-err');
    showResult('enc-result', false, msg);
  } finally {
    setPrivateOpBusy(false);
    if (btn) {
      btn.disabled = false;
      btn.textContent = 'encrypt';
    }
  }
}

async function waitPrivateTx(txHash, logFn) {
  if (!txHash) return { ok: false, detail: 'missing transaction hash' };
  for (var i = 0; i < 45; i++) {
    try {
      var tx = await api('GET', '/tx?hash=' + encodeURIComponent(txHash));
      var st = tx.status || '';
      if (st === 'confirmed' || st === 'accepted') return { ok: true, detail: 'confirmed' };
      if (st === 'rejected') {
        var reason = tx.reject_reason || tx.reject_type || tx.error || 'rejected';
        return { ok: false, detail: String(reason) };
      }
    } catch (e) {}
    if (logFn && (i === 0 || i % 5 === 0)) logFn('waiting for compact refresh confirmation', 'log-info');
    await new Promise(function(resolve) { setTimeout(resolve, 4000); });
  }
  return { ok: false, detail: 'confirmation timeout' };
}

function statusNeedsPrivateSpendRefresh(st) {
  if (!st || st.mode !== 'key_bound_migration' || !st.can_submit) return false;
  var reason = String(st.reason || '');
  if (reason.indexOf('compact refresh') >= 0) return true;
  if (reason.indexOf('repair required') >= 0) return true;
  var baseLayers = Number(st.base_layers || 0);
  var maxLayers = Number(st.private_spend_max_base_layers || 0);
  return maxLayers > 0 && baseLayers > maxLayers;
}

async function ensurePrivateSpendCompact(pin, logFn) {
  var st = await api('GET', '/pvac/upgrade_status');
  if (!statusNeedsPrivateSpendRefresh(st)) return false;
  var baseLayers = st.base_layers ? (' (' + st.base_layers + ' base layers)') : '';
  logFn('encrypted balance needs compact refresh before private spend' + baseLayers, 'log-info');
  logFn('submitting compact refresh key_switch', 'log-info');
  var refresh = await api('POST', '/key_switch', { pin: pin, refresh: true, force_refresh: true });
  var txHash = refresh.hash || refresh.tx_hash || '';
  if (txHash) logFn('compact refresh tx: ' + txLink(txHash), 'log-info');
  var finalStatus = await waitPrivateTx(txHash, logFn);
  if (!finalStatus.ok) throw new Error('compact refresh failed: ' + finalStatus.detail);
  try { await api('POST', '/pvac/upgrade_ack', { tx_hash: txHash }); } catch(e) {}
  logFn('compact refresh confirmed (continuing private spend)', 'log-ok');
  invalidateCurrentAddressState();
  try { await fetchBalance(true); } catch(e) {}
  try { await refreshPvacUpgradeStatus(); } catch(e) {}
  return true;
}

async function doDecrypt() {
  clearResult('dec-result');
  clearDecryptLog();
  var amount = $('dec-amount').value.trim();
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logDecrypt('error: invalid amount', 'log-err'); return; }
  var needRaw = Math.round(parseFloat(amount) * 1000000);
  if (_encPresent && !_encKnown) { logDecrypt('error: encrypted balance upgrade required before decrypt', 'log-err'); return; }
  if (_encryptedBalanceRaw <= 0) { logDecrypt('error: no encrypted balance to decrypt', 'log-err'); return; }
  if (needRaw > _encryptedBalanceRaw) { logDecrypt('error: insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct', 'log-err'); return; }
  if (!validateFee('dec-fee', 'decrypt')) { logDecrypt('error: invalid fee - must be integer >= ' + ((_fees.decrypt && _fees.decrypt.minimum) || '?'), 'log-err'); return; }
  logDecrypt('initiating decrypt', 'log-info');
  logDecrypt('amount: ' + amount + ' oct', 'log-info');
  logDecrypt('waiting for PIN', 'log-info');
  try {
    var pin = await modalPrompt('confirm decrypt', 'enter PIN to decrypt ' + amount + ' oct', { pin: true, btnText: 'decrypt' });
    if (!pin) { logDecrypt('decrypt cancelled', 'log-err'); return; }
    setPrivateOpBusy(true);
    logDecrypt('pin accepted locally', 'log-ok');
    await ensurePrivateSpendCompact(pin, logDecrypt);
    var decBody = { amount: amount, pin: pin };
    var decFee = $('dec-fee') ? $('dec-fee').value.trim() : '';
    if (decFee) decBody.ou = decFee;
    logDecrypt('building ciphertext and bound proofs (keep wallet open)', 'log-info');
    var res = await api('POST', '/decrypt', decBody);
    invalidateCurrentAddressState();
    if (res.steps) {
      for (var i = 0; i < res.steps.length; i++) logDecrypt(escapeHtml(networkText(res.steps[i])), 'log-info');
    }
    logDecrypt('', '');
    logDecrypt('decrypt complete', 'log-ok');
    if (res.hash || res.tx_hash) logDecrypt('tx: ' + txLink(res.hash || res.tx_hash), 'log-ok');
    $('dec-amount').value = '';
    loadDashboard();
    refreshEncryptBalances();
  } catch (e) {
    logDecrypt('error: ' + e.message, 'log-err');
  } finally {
    setPrivateOpBusy(false);
  }
}

async function doStealthSend() {
  clearStealthLog();
  var to = $('stealth-to').value.trim();
  var amount = $('stealth-amount').value.trim();
  if (!validAddr(to)) { logStealth('error: invalid recipient address', 'log-err'); return; }
  if (!amount || !/^\d+(\.\d{1,6})?$/.test(amount) || parseFloat(amount) <= 0) { logStealth('error: invalid amount', 'log-err'); return; }
  var needRaw = Math.round(parseFloat(amount) * 1000000);
  if (_encPresent && !_encKnown) { logStealth('error: encrypted balance upgrade required before send', 'log-err'); return; }
  if (_encryptedBalanceRaw <= 0) { logStealth('error: no encrypted balance - encrypt funds first', 'log-err'); return; }
  if (needRaw > _encryptedBalanceRaw) { logStealth('error: insufficient encrypted balance: have ' + fmtOct(_encryptedBalanceRaw) + ', need ' + amount + ' oct', 'log-err'); return; }
  if (!validateFee('stealth-fee', 'stealth')) { logStealth('error: invalid fee - must be integer >= ' + ((_fees.stealth && _fees.stealth.minimum) || '?'), 'log-err'); return; }
  logStealth('initiating stealth send', 'log-info');

  
  logStealth('to: ' + to, 'log-info');
  logStealth('amount: ' + amount + ' oct', 'log-info');
  logStealth('waiting for PIN', 'log-info');
  try {
    var pin = await modalPrompt('confirm stealth send', 'enter PIN to send ' + amount + ' oct to ' + to, { pin: true, btnText: 'send' });
    if (!pin) { logStealth('stealth send cancelled', 'log-err'); return; }
    setPrivateOpBusy(true);
    logStealth('pin accepted locally', 'log-ok');
    await ensurePrivateSpendCompact(pin, logStealth);
    var stBody = { to: to, amount: amount, pin: pin };
    var stFee = $('stealth-fee') ? $('stealth-fee').value.trim() : '';
    if (stFee) stBody.ou = stFee;
    logStealth('building stealth ciphertext and bound proofs (keep wallet open)', 'log-info');
    var res = await api('POST', '/stealth/send', stBody);
    invalidateCurrentAddressState();
    if (res.steps) {
      for (var i = 0; i < res.steps.length; i++) logStealth(escapeHtml(networkText(res.steps[i])), 'log-info');
    }
    logStealth('', '');
    logStealth('stealth send complete', 'log-ok');
    if (res.tx_hash || res.hash) logStealth('tx: ' + txLink(res.tx_hash || res.hash), 'log-ok');
    $('stealth-to').value = '';
    $('stealth-amount').value = '';
    loadDashboard();
    refreshStealthBalance();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  } finally {
    setPrivateOpBusy(false);
  }
}

async function doStealthScan() {
  $('stealth-outputs').innerHTML = '<div class="loading">scanning...</div>';
  try {
    var res = await api('GET', '/stealth/scan');
    var outputs = res.outputs || [];
    if (outputs.length === 0) {
      $('stealth-outputs').innerHTML = '<div class="staging-empty">no stealth outputs found</div>';
      return;
    }
    var h = '<table class="desktop-table stealth-table"><tr><th></th><th>id</th><th>amount</th><th>status</th></tr>';
    var cards = '<div class="card-list">';
    for (var i = 0; i < outputs.length; i++) {
      var o = outputs[i];
      var amt = o.amount_raw ? fmtOctCompact(o.amount_raw) : '?';
      var isPending = !o.claimed && _pendingClaimIds[String(o.id)];
      var claimable = o.claimable !== false;
      var st = o.claimed
        ? '<span class="gray">claimed</span>'
        : (isPending
          ? '<span class="gray">claiming\u2026</span>'
          : (claimable ? '<span class="green">unclaimed</span>' : '<span class="gray">' + escapeHtml(stealthClaimStatusLabel(o.claim_status)) + '</span>'));
      var chk = (o.claimed || isPending || !claimable) ? '' : '<input type="checkbox" class="stealth-chk" data-id="' + o.id + '">';
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
      if (outputs[i].claimable === false) continue;
      if (!_pendingClaimIds[String(outputs[i].id)]) unclaimed++;
    }
    updateStealthBadge(unclaimed);
    if (unclaimed > 0) {
      h += '<div class="claim-row"><button class="action-btn" data-action="claimSelected">claim selected</button></div>';
    }
    $('stealth-outputs').innerHTML = h;
  } catch (e) {
    $('stealth-outputs').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
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
  logStealth('claiming ' + ids.length + ' output(s)', 'log-info');
  logStealth('waiting for PIN', 'log-info');
  try {
    var pin = await modalPrompt('confirm stealth claim', 'enter PIN to claim ' + ids.length + ' stealth output(s)', { pin: true, btnText: 'claim' });
    if (!pin) { logStealth('stealth claim cancelled', 'log-err'); return; }
    setPrivateOpBusy(true);
    logStealth('pin accepted locally', 'log-ok');
    logStealth('building stealth claim transaction (keep wallet open)', 'log-info');
    var res = await api('POST', '/stealth/claim', { ids: ids, pin: pin });
    invalidateCurrentAddressState();
    logStealth('claim transaction submitted (waiting for confirmation)', 'log-info');
    if (res.results) {
      for (var i = 0; i < res.results.length; i++) {
        var r = res.results[i];
        if (r.ok) {
          _pendingClaimIds[String(r.id)] = true;
          if (r.tx_hash) _pendingClaimTxs[String(r.id)] = r.tx_hash;
          logStealth(escapeHtml(r.id) + ': submitted ' + escapeHtml(r.tx_hash || ''), 'log-info');
        } else {
          logStealth(escapeHtml(r.id) + ': failed - ' + escapeHtml(r.error || ''), 'log-err');
        }
      }
    }
    doStealthScan();
    loadDashboard();
    pollPendingClaims();
  } catch (e) {
    logStealth('error: ' + e.message, 'log-err');
  } finally {
    setPrivateOpBusy(false);
  }
}

function pollPendingClaims() {
  if (Object.keys(_pendingClaimIds).length === 0) return;
  var attempts = 0;
  var poll = setInterval(async function() {
    attempts++;
    if (attempts > 6 || Object.keys(_pendingClaimIds).length === 0) { clearInterval(poll); return; }
    var txIds = Object.keys(_pendingClaimTxs);
    for (var i = 0; i < txIds.length; i++) {
      var id = txIds[i];
      var hash = _pendingClaimTxs[id];
      if (!hash) continue;
      try {
        var tx = await api('GET', '/tx?hash=' + encodeURIComponent(hash));
        var st = tx.status || 'pending';
        if (st === 'rejected') {
          var reason = tx.reject_reason || tx.reject_type || 'rejected';
          logStealth(id + ': rejected - ' + escapeHtml(reason), 'log-err');
          delete _pendingClaimIds[id];
          delete _pendingClaimTxs[id];
        } else if (st === 'confirmed' || st === 'accepted') {
          logStealth(id + ': confirmed', 'log-ok');
          delete _pendingClaimIds[id];
          delete _pendingClaimTxs[id];
        }
      } catch (e) {}
    }
    await doStealthScan();
    await loadDashboard();
  }, 12000);
}

async function refreshContractBalance() {
  await fetchBalance();
}

var _editorErrorLine = -1;

function escapeHtmlCode(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

var _amlRe = /(\/\*[\s\S]*?\*\/)|(\/\/[^\n]*)|("(?:[^"\\]|\\.)*")|(\b(?:Program|program|Contract|contract|state|constructor|fn|view|let|if|else|while|for|in|return|assert|require|match|const|struct|enum|true|false|payable|nonreentrant|public|private|internal|event|error|import|interface|implements|indexed)\b)|(\b(?:string|int|u64|u128|u256|bool|address|bytes|cipher|pubkey|map|list|void)\b)|(\b(?:self_addr|transfer|call|to_int|checkpoint|rollback|commit|origin|caller|balance|emit|log|value|epoch|min|max|abs|concat|to_string|len|split|join|replace|pow|sha256|keccak256|is_address|assert_address|starts_with|substr|index_of|bit_and|bit_or|bit_xor|parse_ints|mget|mset|blob_store|blob_load|some|none|is_some_opt|unwrap|fhe_load_pk|fhe_add|fhe_sub|fhe_mul|fhe_scale|fhe_add_const|fhe_sub_const|fhe_verify_zero|fhe_verify_range|fhe_verify_bound|fhe_commit|fhe_pedersen|fhe_ser|fhe_deser)\b)|(\bself\b)|(\b[0-9]+\b)|([+\-*\/]=|[=!<>]=|&&|\|\||->|\?|[+\-*\/%<>=!])/g;

function highlightAml(src) {
  _amlRe.lastIndex = 0;
  var out = '';
  var last = 0;
  var m;
  while ((m = _amlRe.exec(src)) !== null) {
    if (m.index > last) out += escapeHtmlCode(src.slice(last, m.index));
    var tok = escapeHtmlCode(m[0]);
    if (m[1]) out += '<span class="aml-comment">' + tok + '</span>';
    else if (m[2]) out += '<span class="aml-comment">' + tok + '</span>';
    else if (m[3]) out += '<span class="aml-str">' + tok + '</span>';
    else if (m[4]) out += '<span class="aml-kw">' + tok + '</span>';
    else if (m[5]) out += '<span class="aml-type">' + tok + '</span>';
    else if (m[6]) out += '<span class="aml-builtin">' + tok + '</span>';
    else if (m[7]) out += '<span class="aml-self">' + tok + '</span>';
    else if (m[8]) out += '<span class="aml-num">' + tok + '</span>';
    else if (m[9]) out += '<span class="aml-op">' + tok + '</span>';
    last = m.index + m[0].length;
  }
  if (last < src.length) out += escapeHtmlCode(src.slice(last));
  return out + '\n';
}

var _asmRe = /(;[^\n]*)|("(?:[^"\\]|\\.)*")|(\br[0-9]{1,2}\b)|(\b[A-Z_]{2,}\b)|(\b[0-9]+\b)/g;

function highlightAsm(src) {
  _asmRe.lastIndex = 0;
  var out = '';
  var last = 0;
  var m;
  while ((m = _asmRe.exec(src)) !== null) {
    if (m.index > last) out += escapeHtmlCode(src.slice(last, m.index));
    var tok = escapeHtmlCode(m[0]);
    if (m[1]) out += '<span class="asm-comment">' + tok + '</span>';
    else if (m[2]) out += '<span class="asm-str">' + tok + '</span>';
    else if (m[3]) out += '<span class="asm-reg">' + tok + '</span>';
    else if (m[4]) out += '<span class="asm-instr">' + tok + '</span>';
    else if (m[5]) out += '<span class="asm-num">' + tok + '</span>';
    last = m.index + m[0].length;
  }
  if (last < src.length) out += escapeHtmlCode(src.slice(last));
  return out + '\n';
}

function updateGutter(src) {
  var g = $('ct-gutter');
  if (!g) return;
  var n = (src.match(/\n/g) || []).length + 1;
  var lines = [];
  for (var i = 1; i <= n; i++) {
    if (i === _editorErrorLine) lines.push('<span class="gutter-error">' + i + '</span>');
    else lines.push('' + i);
  }
  g.innerHTML = lines.join('\n');
}

function editorUpdate() {
  var ta = $('ct-source');
  var hl = $('ct-highlight');
  if (!ta || !hl) return;
  var src = ta.value;
  var lang = $('ct-lang').value;
  hl.innerHTML = lang === 'aml' ? highlightAml(src) : highlightAsm(src);
  updateGutter(src);
  editorSync();
  if (_ideProject && _ideActiveFile) {
    _ideFiles[_ideActiveFile] = src;
    if (_ideSaveTimer) clearTimeout(_ideSaveTimer);
    _ideSaveTimer = setTimeout(function() {
      ProjectStore.saveFile(_ideProject.id, _ideActiveFile, src).catch(function() {});
    }, 2000);
  }
}

function editorSync() {
  var ta = $('ct-source');
  var hl = $('ct-highlight');
  var g = $('ct-gutter');
  if (!ta || !hl) return;
  hl.style.transform = 'translate(' + (-ta.scrollLeft) + 'px,' + (-ta.scrollTop) + 'px)';
  if (g) g.scrollTop = ta.scrollTop;
}

function editorMarkError(lineNum) {
  _editorErrorLine = lineNum;
  var ta = $('ct-source');
  if (ta) updateGutter(ta.value);
}

function editorClearError() {
  _editorErrorLine = -1;
  var ta = $('ct-source');
  if (ta) updateGutter(ta.value);
}

function initEditor() {
  var ta = $('ct-source');
  if (!ta) return;
  ta.addEventListener('keydown', function(e) {
    if (e.key === 'Tab') {
      e.preventDefault();
      var start = ta.selectionStart;
      var end = ta.selectionEnd;
      var val = ta.value;
      ta.value = val.substring(0, start) + '  ' + val.substring(end);
      ta.selectionStart = ta.selectionEnd = start + 2;
      editorUpdate();
    }
  });
  editorUpdate();
}

function onLangChange() {
  var lang = $('ct-lang').value;
  var ta = $('ct-source');
  if (lang === 'aml') {
    $('ct-source-label').textContent = 'AppliedML source (.aml)';
    ta.placeholder = 'Program Token {\n  state { name: string }\n  constructor(n: string) {\n    self.name = n\n  }\n}';
  } else {
    $('ct-source-label').textContent = 'assembly source (.oasm)';
    ta.placeholder = '; constructor\nCALLER r0\nSSTORE "owner", r0\nSTOP\n; dispatcher\nJDEST 100\n...';
  }
  ta.value = '';
  editorUpdate();
}

async function doCompile() {
  if (_ideProject) { doCompileProject(); return; }
  clearResult('ct-compile-result');
  editorClearError();
  _compiledAbi = null;
  _compiledVerification = null;
  _compiledCertificate = null;
  renderVerificationReport(null);
  var source = $('ct-source').value;
  var lang = $('ct-lang').value;
  if (!source.trim()) { showResult('ct-compile-result', false, 'source required'); return; }
  try {
    var endpoint = lang === 'aml' ? '/contract/compile-aml' : '/contract/compile';
    var res = await api('POST', endpoint, { source: source });
    var b64 = res.bytecode || '';
    $('ct-bytecode').value = b64;
    var ver = res.version ? ('AppliedML ' + res.version + ' - ') : '';
    var msg = ver + 'compiled: ' + res.instructions + ' instructions, ' + res.size + ' bytes';
    showResult('ct-compile-result', true, msg);
    if (res.abi) {
      _compiledAbi = res.abi;
      var abiEl = $('ct-abi-json');
      if (abiEl) abiEl.textContent = JSON.stringify(res.abi, null, 2);
    }
    if (res.disasm) {
      var disEl = $('ct-disasm-code');
      if (disEl) disEl.innerHTML = highlightDisasm(res.disasm);
    }
    if (res.verification) {
      _compiledVerification = res.verification;
      _compiledCertificate = res.certificate || null;
      renderVerificationReport(res.verification, _compiledCertificate);
      msg += ' | ' + verificationLabel(res.verification);
      showResult('ct-compile-result', verificationLevel(res.verification) !== 'error', msg + (verificationLevel(res.verification) === 'error' ? ' (deploy not blocked yet)' : ''));
      logVerificationTrace(res.verification);
    }
    showBottomPanels();
    consoleLog('info', msg);
  } catch (e) {
    var errMsg = e.message || '';
    var lineMatch = errMsg.match(/line\s+(\d+)/i);
    if (lineMatch) editorMarkError(parseInt(lineMatch[1], 10));
    showResult('ct-compile-result', false, errMsg);
    consoleLog('error', 'compile error: ' + errMsg);
  }
}

function switchBottomTab(panel) {
  var tabs = document.querySelectorAll('.ide-bottom-tab');
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.toggle('active', tabs[i].getAttribute('data-panel') === panel);
  }
  var panels = document.querySelectorAll('.ide-bottom-panel');
  for (var i = 0; i < panels.length; i++) {
    var id = panels[i].id.replace('ct-','').replace('-display','');
    panels[i].style.display = id === panel ? 'block' : 'none';
    panels[i].classList.toggle('active', id === panel);
  }
}

function showBottomPanels() {
  var panels = document.querySelectorAll('.ide-bottom-panel');
  var activePanel = null;
  var tabs = document.querySelectorAll('.ide-bottom-tab');
  for (var i = 0; i < tabs.length; i++) {
    if (tabs[i].classList.contains('active')) { activePanel = tabs[i].getAttribute('data-panel'); break; }
  }
  if (!activePanel) activePanel = 'abi';
  switchBottomTab(activePanel);
}

var _consoleLogs = [];
function consoleLog(level, msg) {
  var ts = new Date().toLocaleTimeString();
  _consoleLogs.push({ level: level, msg: msg, ts: ts });
  if (_consoleLogs.length > 200) _consoleLogs.shift();
  renderConsole();
}

function consoleClear() {
  _consoleLogs = [];
  renderConsole();
}

function verificationLevel(v) {
  if (!v) return 'unknown';
  if (v.safety) return String(v.safety);
  if (v.verified === false || (v.errors || 0) > 0) return 'error';
  if ((v.warnings || 0) > 0) return 'warning';
  return 'safe';
}

function verificationLabel(v) {
  var level = verificationLevel(v);
  if (level === 'safe') return 'formal verification = safe';
  if (level === 'warning') return 'formal verification = warning';
  if (level === 'error') return 'formal verification = error';
  return 'formal verification = unavailable';
}

function verificationResultHtml(v) {
  if (!v) return '';
  var level = verificationLevel(v);
  var ok = level !== 'error';
  return '<span class="' + (ok ? 'ok' : 'bad') + '">' + escapeHtml(verificationLabel(v)) +
    '</span> <span class="mono">errors = ' + escapeHtml(String(v.errors || 0)) +
    ' warnings = ' + escapeHtml(String(v.warnings || 0)) + '</span>';
}

function renderVerificationReport(v, cert) {
  var el = $('ct-verify-output');
  if (!el) return;
  if (!v) {
    el.innerHTML = '<div class="panel-empty">compile AppliedML to view formal verification trace</div>';
    return;
  }
  var h = '';
  h += '<div class="console-line info">schema = ' + escapeHtml(v.schema || '-') + '</div>';
  h += '<div class="console-line info">engine = ' + escapeHtml(v.engine || '-') + '</div>';
  h += '<div class="console-line info">proof_model = ' + escapeHtml(v.proof_model || '-') + '</div>';
  if (cert) {
    h += '<div class="console-line info">certificate = ' + escapeHtml(cert.schema || '-') + '</div>';
    h += '<div class="console-line info">source_hash = ' + escapeHtml(cert.source_hash || '-') + '</div>';
    h += '<div class="console-line info">bytecode_hash = ' + escapeHtml(cert.bytecode_hash || '-') + '</div>';
    h += '<div class="console-line info">verification_hash = ' + escapeHtml(cert.verification_hash || '-') + '</div>';
  }
  h += '<div class="console-line ' + (verificationLevel(v) === 'error' ? 'error' : 'info') + '">safety = ' + escapeHtml(verificationLevel(v)) + ' | errors = ' + escapeHtml(String(v.errors || 0)) + ' | warnings = ' + escapeHtml(String(v.warnings || 0)) + '</div>';
  var trace = Array.isArray(v.trace) ? v.trace : [];
  for (var i = 0; i < trace.length; i++) {
    var t = trace[i] || {};
    var level = t.status === 'error' ? 'error' : (t.status === 'warning' ? 'warn' : 'info');
    h += '<div class="console-line ' + level + '">trace = ' + escapeHtml(t.code || '-') + ' | status = ' + escapeHtml(t.status || '-') + ' | findings = ' + escapeHtml(String(t.findings || 0)) + '</div>';
  }
  var invariants = Array.isArray(v.invariants) ? v.invariants : [];
  for (var k = 0; k < invariants.length; k++) {
    var inv = invariants[k] || {};
    var invLevel = inv.status === 'warning' ? 'warn' : (inv.status === 'error' ? 'error' : 'info');
    h += '<div class="console-line ' + invLevel + '">invariant = ' + escapeHtml(inv.code || '-') + ' | status = ' + escapeHtml(inv.status || '-') + ' | fields = ' + escapeHtml((inv.fields || []).join(',')) + ' | functions = ' + escapeHtml((inv.functions || []).join(',')) + '</div>';
  }
  var summaries = Array.isArray(v.function_summaries) ? v.function_summaries : [];
  for (var s = 0; s < summaries.length; s++) {
    var sm = summaries[s] || {};
    h += '<div class="console-line info">summary = ' + escapeHtml(sm.name || '-') + ' | visibility = ' + escapeHtml(sm.visibility || '-') + ' | writes = ' + escapeHtml((sm.direct_writes || []).join(',')) + ' | transitive_writes = ' + escapeHtml((sm.transitive_writes || []).join(',')) + '</div>';
  }
  var findings = Array.isArray(v.findings) ? v.findings : [];
  for (var j = 0; j < findings.length; j++) {
    var f = findings[j] || {};
    var sev = f.severity === 'error' ? 'error' : 'warn';
    h += '<div class="console-line ' + sev + '">finding = ' + escapeHtml(f.code || '-') + ' | fn = ' + escapeHtml(f.function_name || '-') + ' | field = ' + escapeHtml(f.state_field || '-') + ' | param = ' + escapeHtml(f.parameter || '-') + ' | message = ' + escapeHtml(f.message || '-') + '</div>';
  }
  el.innerHTML = h;
}

function logVerificationTrace(v) {
  if (!v) return;
  consoleLog(verificationLevel(v) === 'error' ? 'error' : 'info',
    verificationLabel(v) + ' | errors = ' + (v.errors || 0) + ' | warnings = ' + (v.warnings || 0));
  var trace = Array.isArray(v.trace) ? v.trace : [];
  for (var i = 0; i < trace.length; i++) {
    var t = trace[i] || {};
    consoleLog(t.status === 'error' ? 'error' : (t.status === 'warning' ? 'warn' : 'info'),
      'trace = ' + (t.code || '-') + ' | status = ' + (t.status || '-') + ' | findings = ' + (t.findings || 0));
  }
}

function renderConsole() {
  var el = $('ct-console-output');
  if (!el) return;
  var html = '';
  for (var i = 0; i < _consoleLogs.length; i++) {
    var l = _consoleLogs[i];
    html += '<div class="console-line ' + l.level + '">' +
      '<span class="timestamp">' + escapeHtml(l.ts) + '</span>' +
      '<span class="label">[' + l.level.toUpperCase() + ']</span> ' +
      escapeHtml(l.msg) + '</div>';
  }
  el.innerHTML = html || '<div class="console-line info" style="color:#666">no output yet</div>';
  el.scrollTop = el.scrollHeight;
}

function highlightDisasm(src) {
  var lines = src.split('\n');
  var html = '';
  for (var i = 0; i < lines.length; i++) {
    var line = escapeHtml(lines[i]);
    line = line.replace(/(;.*)$/, '<span class="cmt">$1</span>');
    line = line.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="str">$1</span>');
    line = line.replace(/\b(r[0-9]{1,2})\b/g, '<span class="reg">$1</span>');
    line = line.replace(/\b(\-?[0-9]+)\b/g, '<span class="num">$1</span>');
    line = line.replace(/^(\s*)(JDEST)/, '$1<span class="lbl">$2</span>');
    line = line.replace(/^(\s*)([A-Z_]{2,})/, '$1<span class="op">$2</span>');
    html += line + '\n';
  }
  return html;
}

async function loadTemplate() {
  var sel = $('ct-template');
  if (!sel) return;
  var key = sel.value;
  if (!key) return;
  try {
    var r = await fetch('templates/' + key + '/main.aml');
    if (!r.ok) return;
    var source = await r.text();
    var ta = $('ct-source');
    if (ta) { ta.value = source; editorUpdate(); }
  } catch (e) {}
  sel.value = '';
}

document.addEventListener('keydown', function(e) {
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    var devView = $('view-dev');
    if (devView && devView.classList.contains('active')) {
      e.preventDefault();
      doCompile();
    }
  }
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    var devView = $('view-dev');
    if (devView && devView.classList.contains('active')) {
      e.preventDefault();
      doDeploy();
    }
  }
});

var _liveCompileTimer = null;
var _liveCompileEnabled = true;
function editorUpdateWithLiveCompile() {
  editorUpdate();
  if (!_liveCompileEnabled) return;
  if (_liveCompileTimer) clearTimeout(_liveCompileTimer);
  _liveCompileTimer = setTimeout(function() {
    var source = $('ct-source').value;
    if (source.trim().length > 10) doCompile();
  }, 1500);
}

function updateStorageView(storage) {
  var el = $('ct-storage-output');
  if (!el || !storage) return;
  var keys = Object.keys(storage).sort();
  if (keys.length === 0) {
    el.innerHTML = '<div style="color:#666">no storage entries</div>';
    return;
  }
  var html = '';
  for (var i = 0; i < keys.length; i++) {
    var k = keys[i];
    var v = storage[k];
    if (typeof v === 'string' && v.length > 80) v = v.slice(0, 80) + '...';
    html += '<div class="storage-row"><span class="storage-key">' +
      escapeHtml(k) + '</span><span class="storage-val">' +
      escapeHtml(String(v)) + '</span></div>';
  }
  el.innerHTML = html;
}

async function doPreviewDeploy() {
  clearResult('ct-deploy-result');
  var bytecode = $('ct-bytecode').value.trim();
  if (!bytecode) { showResult('ct-deploy-result', false, 'bytecode required (compile first)'); return; }
  try {
    var res = await api('POST', '/contract/address', { bytecode: bytecode });
    showResult('ct-deploy-result', true,
      'predicted address: <span class="mono">' + escapeHtml(res.address) + '</span> (nonce ' + res.nonce + ')');
  } catch (e) {
    showResult('ct-deploy-result', false, e.message);
  }
}

function verifySourceRetry(addr, source, depFiles, attempts) {
  if (attempts <= 0) return;
  setTimeout(async function() {
    try {
      var payload = { address: addr, source: source };
      if (depFiles && depFiles.length > 0) payload.files = depFiles;
      var res = await api('POST', '/contract/verify', payload);
      var safety = res.verification ? ' - ' + verificationResultHtml(res.verification) : '';
      showResult('ct-deploy-result', true,
        'deployed to <span class="mono">' + escapeHtml(addr) + '</span> - <strong>source verified</strong>' + safety);
    } catch (e) {
      verifySourceRetry(addr, source, depFiles, attempts - 1);
    }
  }, 12000);
}

async function doDeploy() {
  clearResult('ct-deploy-result');
  var bytecode = $('ct-bytecode').value.trim();
  if (!bytecode) { showResult('ct-deploy-result', false, 'bytecode required (compile first)'); return; }
  var params = $('ct-deploy-params').value.trim();
  if (params && params !== '[]') {
    try { JSON.parse(params); } catch (e) {
      showResult('ct-deploy-result', false, 'invalid json params');
      return;
    }
  }
  if (!validateFee('ct-deploy-fee', 'deploy')) { feeError('ct-deploy-result', 'ct-deploy-fee', 'deploy'); return; }
  try {
    var body = { bytecode: bytecode };
    if (params) body.params = params;
    var deployFee = $('ct-deploy-fee') ? $('ct-deploy-fee').value.trim() : '';
    if (deployFee) body.ou = deployFee;
    var res = await api('POST', '/contract/deploy', body);
    var addr = res.contract_address || '';
    var hash = res.tx_hash || '';
    invalidateCurrentAddressState();
    showResult('ct-deploy-result', true,
      'deployed to <span class="mono">' + escapeHtml(addr) + '</span> - tx: ' + txLink(hash) + ' (verifying source...)');
    $('ct-call-addr').value = addr;
    $('ct-info-addr').value = addr;
    var source = _ideProject ? (_ideFiles['main.aml'] || '') : ($('ct-source').value || '');
    var depFiles = [];
    if (_ideProject) {
      for (var path in _ideFiles) {
        if (path !== 'main.aml') depFiles.push({ path: path, source: _ideFiles[path] });
      }
    }
    if (source.trim()) verifySourceRetry(addr, source, depFiles, 5);
    loadDashboard();
  } catch (e) {
    showResult('ct-deploy-result', false, e.message);
  }
}

async function doContractCall() {
  clearResult('ct-call-result');
  var addr = $('ct-call-addr').value.trim();
  var method = $('ct-call-method').value.trim();
  if (!addr) { showResult('ct-call-result', false, 'program address required'); return; }
  if (!method) { showResult('ct-call-result', false, 'method name required'); return; }
  var params_str = $('ct-call-params').value.trim() || '[]';
  var params;
  try { params = JSON.parse(params_str); } catch (e) {
    showResult('ct-call-result', false, 'invalid json params');
    return;
  }
  var amount = $('ct-call-amount').value.trim() || '0';
  var amount_raw = '0';
  if (amount !== '0' && amount !== '') {
    var f = parseFloat(amount);
    if (isNaN(f) || f < 0) { showResult('ct-call-result', false, 'invalid amount'); return; }
    amount_raw = String(Math.round(f * 1000000));
  }
  if (!validateFee('ct-call-fee', 'call')) { feeError('ct-call-result', 'ct-call-fee', 'call'); return; }
  try {
    var callBody = { address: addr, method: method, params: params, amount: amount_raw };
    var callFee = $('ct-call-fee') ? $('ct-call-fee').value.trim() : '';
    if (callFee) callBody.ou = callFee;
    var res = await api('POST', '/contract/call', callBody);
    var hash = res.tx_hash || '';
    invalidateCurrentAddressState();
    showResult('ct-call-result', true, 'program call submitted - tx: ' + txLink(hash));
    consoleLog('event', 'call ' + method + '() -> tx ' + (hash ? hash.slice(0,16) + '...' : ''));
    loadDashboard();
  } catch (e) {
    showResult('ct-call-result', false, e.message);
    consoleLog('error', 'call ' + method + '() failed: ' + e.message);
  }
}

async function expandEncParams(params_str) {
  var re = /enc\((-?\d+)\)/g;
  var match;
  var replacements = [];
  while ((match = re.exec(params_str)) !== null) {
    replacements.push({start: match.index, end: match.index + match[0].length, value: parseInt(match[1])});
  }
  if (replacements.length === 0) return params_str;
  for (var i = replacements.length - 1; i >= 0; i--) {
    var r = replacements[i];
    var res = await api('POST', '/fhe/encrypt', {value: r.value});
    params_str = params_str.substring(0, r.start) + '"' + res.ciphertext + '"' + params_str.substring(r.end);
  }
  return params_str;
}

async function tryFheDecrypt(val) {
  if (typeof val !== 'string' || val.length < 100) return null;
  var pin = await modalPrompt(
    'decrypt program output',
    'enter PIN to decrypt this ciphertext',
    { pin: true, btnText: 'decrypt' });
  if (!pin) return null;
  try {
    var res = await api('POST', '/fhe/decrypt', {ciphertext: val, pin: pin});
    return res.value;
  } catch (e) {
    return null;
  }
}

async function doContractView() {
  clearResult('ct-call-result');
  var addr = $('ct-call-addr').value.trim();
  var method = $('ct-call-method').value.trim();
  if (!addr) { showResult('ct-call-result', false, 'program address required'); return; }
  if (!method) { showResult('ct-call-result', false, 'method name required'); return; }
  var params_str = $('ct-call-params').value.trim() || '[]';
  try {
    showResult('ct-call-result', true, '<span class="mono">processing...</span>');
    params_str = await expandEncParams(params_str);
    try { JSON.parse(params_str); } catch (e) {
      showResult('ct-call-result', false, 'invalid json params');
      return;
    }
    var url = '/contract/view?address=' + encodeURIComponent(addr) +
      '&method=' + encodeURIComponent(method) +
      '&params=' + encodeURIComponent(params_str);
    var res = await api('GET', url);
    var val = res.result;
    if (val === null || val === undefined) val = 'null';
    var decrypted = await tryFheDecrypt(val);
    if (decrypted !== null) {
      showResult('ct-call-result', true,
        'result (encrypted): <span class="mono">' + escapeHtml(String(val)).substring(0, 40) + '...</span>' +
        '<br>decrypted: <span class="mono" style="color:#0f0;font-size:1.1em">' + decrypted + '</span>');
      consoleLog('log', 'view ' + method + '() -> ' + decrypted + ' (decrypted)');
    } else {
      showResult('ct-call-result', true, 'result: <span class="mono">' + escapeHtml(String(val)) + '</span>');
      consoleLog('log', 'view ' + method + '() -> ' + String(val));
    }
    if (res.storage) updateStorageView(res.storage);
    if (res.events && res.events.length > 0) {
      for (var i = 0; i < res.events.length; i++) {
        consoleLog('event', 'emit ' + res.events[i].name + '(' + (res.events[i].args || []).join(', ') + ')');
      }
    }
  } catch (e) {
    showResult('ct-call-result', false, e.message);
    consoleLog('error', 'view ' + method + '() failed: ' + e.message);
  }
}

async function doFheEncrypt() {
  clearResult('fhe-result');
  var val = $('fhe-enc-value').value.trim();
  if (val === '') { showResult('fhe-result', false, 'enter an integer value'); return; }
  var num = parseInt(val);
  if (isNaN(num)) { showResult('fhe-result', false, 'invalid integer'); return; }
  try {
    var res = await api('POST', '/fhe/encrypt', {value: num});
    $('fhe-enc-output').value = res.ciphertext;
    $('fhe-enc-result-row').style.display = '';
    showResult('fhe-result', true, 'encrypted ' + num + ' (' + res.ciphertext.length + ' chars)');
  } catch (e) {
    showResult('fhe-result', false, e.message);
  }
}

async function doFheDecrypt() {
  clearResult('fhe-result');
  var ct = $('fhe-dec-input').value.trim();
  if (!ct) { showResult('fhe-result', false, 'paste a ciphertext'); return; }
  var pin = await modalPrompt(
    'decrypt ciphertext',
    'enter PIN to decrypt this ciphertext',
    { pin: true, btnText: 'decrypt' });
  if (!pin) return;
  try {
    var res = await api('POST', '/fhe/decrypt', {ciphertext: ct, pin: pin});
    showResult('fhe-result', true, 'decrypted value: <span class="mono">' + escapeHtml(String(res.value)) + '</span>');
  } catch (e) {
    showResult('fhe-result', false, e.message);
  }
}

async function doContractInfo() {
  clearResult('ct-info-result');
  var addr = $('ct-info-addr').value.trim();
  if (!addr) { showResult('ct-info-result', false, 'address required'); return; }
  try {
    var res = await api('GET', '/contract/info?address=' + encodeURIComponent(addr));
    var h = '<table class="detail-table">';
    h += '<tr><td>address</td><td class="mono">' + escapeHtml(res.address || addr) + '</td></tr>';
    h += '<tr><td>owner</td><td class="mono">' + escapeHtml(res.owner || '') + '</td></tr>';
    h += '<tr><td>version</td><td>' + escapeHtml(res.version || '') + '</td></tr>';
    h += '<tr><td>code hash</td><td class="mono">' + escapeHtml(res.code_hash || '') + '</td></tr>';
    h += '<tr><td>balance</td><td class="mono">' + fmtOct(res.balance || '0') + '</td></tr>';
    h += '</table>';
    $('ct-info-result').innerHTML = h;
  } catch (e) {
    showResult('ct-info-result', false, e.message);
  }
}

async function doContractReceipt() {
  clearResult('ct-info-result');
  var addr = $('ct-info-addr').value.trim();
  if (!addr) { showResult('ct-info-result', false, 'enter a tx hash to lookup receipt'); return; }
  try {
    var res = await api('GET', '/contract/receipt?hash=' + encodeURIComponent(addr));
    var h = '<table class="detail-table">';
    var keys = Object.keys(res);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = res[k];
      if (typeof v === 'object') v = JSON.stringify(v);
      h += '<tr><td>' + escapeHtml(k) + '</td><td class="mono">' + escapeHtml(String(v)) + '</td></tr>';
    }
    h += '</table>';
    $('ct-info-result').innerHTML = h;
  } catch (e) {
    showResult('ct-info-result', false, e.message);
  }
}

async function doVerifyContract() {
  if (_ideProject) { doVerifyProject(); return; }
  clearResult('ct-verify-result');
  var addr = $('ct-verify-addr').value.trim();
  var source = $('ct-verify-source').value;
  if (!addr) { showResult('ct-verify-result', false, 'program address required'); return; }
  if (!source.trim()) { showResult('ct-verify-result', false, 'source required'); return; }
  try {
    var res = await api('POST', '/contract/verify', { address: addr, source: source });
    var safety = res.verification ? '<br>' + verificationResultHtml(res.verification) : '';
    showResult('ct-verify-result', true,
      'source verified - code_hash: <span class="mono">' + escapeHtml(res.code_hash || '') + '</span>' + safety);
  } catch (e) {
    showResult('ct-verify-result', false, e.message);
  }
}

async function loadTokenSymbols() {
  var cached = restoreAddressTokens(_walletAddr);
  var state = ensureAddressRuntime(_walletAddr);
  if (cached && state && (Date.now() - state.tokensTs) <= TOKEN_STALE_REFRESH_MS) return;
  try {
    _tokens = await fetchAddressTokens(false);
    _tokensLoaded = true;
    hydrateTokenMaps(_tokens);
  } catch(e) {}
}

async function fetchMissingSymbols(txs) {
  var need = {};
  for (var i = 0; i < txs.length; i++) {
    var transfer = tokenTransfer(txs[i]);
    if (transfer && !_tokenSymbols[transfer.token]) need[transfer.token] = true;
  }
  var unknowns = Object.keys(need);
  if (unknowns.length === 0) return;
  await Promise.all(unknowns.map(function(ca) {
    if (_tokenMetaInflight[ca]) return _tokenMetaInflight[ca];
    _tokenMetaInflight[ca] = Promise.all([
      api('GET', '/contract-storage?address=' + encodeURIComponent(ca) + '&key=symbol').then(function(r) {
        if (r && r.value) _tokenSymbols[ca] = String(r.value).slice(0, 32);
      }).catch(function() {}),
      api('GET', '/contract-storage?address=' + encodeURIComponent(ca) + '&key=decimals').then(function(r) {
        if (r && r.value) _tokenDecimals[ca] = String(r.value);
      }).catch(function() {})
    ]).finally(function() {
      delete _tokenMetaInflight[ca];
    });
    return _tokenMetaInflight[ca];
  }));
}

async function loadTokens() {
  $('tok-list').innerHTML = '<div class="loading">loading tokens...</div>';
  var restored = restoreAddressTokens(_walletAddr);
  var state = ensureAddressRuntime(_walletAddr);
  if (restored) {
    renderTokenList();
    if (state && (Date.now() - state.tokensTs) <= TOKEN_STALE_REFRESH_MS) {
      loadTokenTxs();
      return;
    }
  }
  try {
    _tokens = await fetchAddressTokens(false);
    _tokensLoaded = true;
    hydrateTokenMaps(_tokens);
  } catch (e) {
    if (!restored) $('tok-list').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
    loadTokenTxs();
    return;
  }
  renderTokenList();
  loadTokenTxs();
}

async function loadTokenTxs() {
  var el = $('tok-txs');
  if (!el) return;
  var gen = ++_tokTxGen;
  try {
    var hist = await fetchTokenHistory(false);
    if ((!hist.total || hist.total === 0) && _tokens && _tokens.length > 0) {
      hist = await fetchTokenHistory(true);
    }
    if (gen !== _tokTxGen) return;
    var filtered = hist.transactions || [];
    $('tok-tx-count').textContent = String(filtered.length);
    $('tok-tx-total').textContent = String(hist.total || filtered.length);
    $('tok-tx-in').textContent = String(hist.incoming || 0);
    $('tok-tx-out').textContent = String(hist.outgoing || 0);
    if (filtered.length === 0) {
      el.innerHTML = '<div class="staging-empty">no token transactions yet</div>';
      return;
    }
    await fetchMissingSymbols(filtered);
    var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
    var cards = '<div class="card-list">';
    for (var j = 0; j < filtered.length; j++) {
      h += txRow(filtered[j]);
      cards += txCardHtml(filtered[j]);
    }
    h += '</table>';
    cards += '</div>';
    el.innerHTML = h + cards;
  } catch(e) {
    $('tok-tx-count').textContent = '0';
    $('tok-tx-total').textContent = '0';
    $('tok-tx-in').textContent = '0';
    $('tok-tx-out').textContent = '0';
    el.innerHTML = '<div class="staging-empty">no token transactions yet</div>';
  }
}

function renderTokenList() {
  if (_tokens.length === 0) {
    $('tok-list').innerHTML = '<div class="staging-empty">no tokens found on this network</div>';
    $('tok-count').textContent = '0';
    return;
  }
  $('tok-count').textContent = _tokens.length;
  var h = '';
  for (var i = 0; i < _tokens.length; i++) {
    var t = _tokens[i];
    var bal = t.balance || '0';
    var balCls = (bal === '0') ? 'token-zero' : 'token-balance';
    h += '<div class="token-card">';
    h += '<div class="token-header">';
    h += '<div><span class="token-symbol">' + escapeHtml(t.symbol) + '</span>';
    h += '<span class="token-name">' + escapeHtml(t.name) + '</span></div>';
    h += '<div class="' + balCls + '">' + fmtTokenCompact(bal, t.decimals) + ' ' + escapeHtml(t.symbol) + '</div>';
    h += '</div>';
    h += '<div class="token-row">';
    h += '<span class="mono gray">' + short(t.address) + '</span>';
    h += '</div>';
    h += '<div class="token-actions">';
    h += '<button class="token-btn" data-action="openTokenTransfer" data-arg="' + i + '">transfer</button>';
    h += '</div>';
    h += '</div>';
  }
  $('tok-list').innerHTML = h;
}

function openTokenTransfer(idx) {
  _selectedToken = _tokens[idx];
  $('tok-transfer-sym').textContent = _selectedToken.symbol;
  $('tok-to').value = '';
  $('tok-amount').value = '';
  clearResult('tok-transfer-result');
  $('tok-transfer').style.display = '';
  $('tok-to').focus();
}

function closeTokenTransfer() {
  $('tok-transfer').style.display = 'none';
  _selectedToken = null;
}

function parseUnits(humanStr, decimals) {
  var dec = parseInt(decimals) || 0;
  var s = String(humanStr).trim();
  if (!s || s === '0') return '';
  var neg = false;
  if (s[0] === '-') { neg = true; s = s.slice(1); }
  var parts = s.split('.');
  var intPart = parts[0].replace(/[^0-9]/g, '') || '0';
  var fracPart = parts.length > 1 ? parts[1].replace(/[^0-9]/g, '') : '';
  if (fracPart.length > dec) fracPart = fracPart.slice(0, dec);
  while (fracPart.length < dec) fracPart += '0';
  var raw = (intPart + fracPart).replace(/^0+/, '') || '0';
  if (raw === '0') return '';
  return neg ? '-' + raw : raw;
}

async function doTokenTransfer() {
  clearResult('tok-transfer-result');
  if (!_selectedToken) { showResult('tok-transfer-result', false, 'no token selected'); return; }
  var to = $('tok-to').value.trim();
  var humanAmt = $('tok-amount').value.trim();
  if (!validAddr(to)) { showResult('tok-transfer-result', false, 'invalid recipient address'); return; }
  if (!humanAmt || isNaN(parseFloat(humanAmt)) || parseFloat(humanAmt) <= 0) {
    showResult('tok-transfer-result', false, 'invalid amount'); return;
  }
  var rawAmount = parseUnits(humanAmt, _selectedToken.decimals);
  if (!rawAmount) { showResult('tok-transfer-result', false, 'invalid amount'); return; }
  if (!validateFee('tok-fee', 'call')) { feeError('tok-transfer-result', 'tok-fee', 'call'); return; }
  try {
    var pin = await modalPrompt('confirm token transfer', 'enter PIN to transfer ' + humanAmt + ' to ' + to, { pin: true, btnText: 'transfer' });
    if (!pin) { showResult('tok-transfer-result', false, 'transfer cancelled'); return; }
    var tokBody = { token: _selectedToken.address, to: to, amount: rawAmount, pin: pin };
    var tokFee = $('tok-fee') ? $('tok-fee').value.trim() : '';
    if (tokFee) tokBody.ou = tokFee;
    var res = await api('POST', '/token/transfer', tokBody);
    var txHash = res.hash || res.tx_hash || '';
    invalidateCurrentAddressState();
    showResult('tok-transfer-result', true,
      'sent ' + escapeHtml(humanAmt) + ' ' + escapeHtml(_selectedToken.symbol) + ' - tx: ' + txLink(txHash));
    $('tok-to').value = '';
    $('tok-amount').value = '';
    setTimeout(function() { loadTokens(); }, 2000);
  } catch (e) {
    showResult('tok-transfer-result', false, e.message);
  }
}

function renderHistoryTxs(txs) {
  $('hist-count').textContent = String(_historyOffset + txs.length);
  var h = '<table class="desktop-table"><tr><th>hash</th><th>from</th><th>to</th><th class="col-amount">amount</th><th class="col-status">status</th><th class="col-time">time</th></tr>';
  var cards = '<div class="card-list">';
  for (var i = 0; i < txs.length; i++) {
    h += txRow(txs[i]);
    cards += txCardHtml(txs[i]);
  }
  h += '</table>';
  cards += '</div>';
  $('history-list').innerHTML = h + cards;
}

async function loadHistory() {
  var cached = peekHistoryPage(_walletAddr, _historyLimit, _historyOffset);
  if (!cached) $('history-list').innerHTML = '<div class="loading">loading...</div>';
  $('history-more').innerHTML = '';
  var rendered = false;
  try {
    if (cached) {
      rendered = true;
      var cachedTxs = cached.response.transactions || [];
      $('hist-total').textContent = String(cached.response.total || cachedTxs.length);
      if (cachedTxs.length === 0 && _historyOffset === 0) {
        $('hist-count').textContent = '0';
        $('history-list').innerHTML = '<div class="staging-empty">no transactions yet</div>';
      } else {
        renderHistoryTxs(cachedTxs);
        if (cached.response.has_more) {
          $('history-more').innerHTML = '<button class="load-more" data-action="loadMoreHistory">load more</button>';
        }
        fetchMissingSymbols(cachedTxs).then(function() { renderHistoryTxs(cachedTxs); });
      }
      if ((Date.now() - cached.ts) <= HISTORY_STALE_REFRESH_MS) return;
    }
    var res = await fetchHistoryPage(_historyLimit, _historyOffset, false);
    var txs = res.transactions || [];
    $('hist-total').textContent = String(res.total || txs.length);
    if (txs.length === 0 && _historyOffset === 0) {
      $('hist-count').textContent = '0';
      $('history-list').innerHTML = '<div class="staging-empty">no transactions yet</div>';
      return;
    }
    renderHistoryTxs(txs);
    if (res.has_more) {
      $('history-more').innerHTML = '<button class="load-more" data-action="loadMoreHistory">load more</button>';
    }
    fetchMissingSymbols(txs).then(function() { renderHistoryTxs(txs); });
  } catch (e) {
    if (!rendered) {
      $('hist-count').textContent = '0';
      $('history-list').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
    }
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
    var res = await fetchHistoryPage(_historyLimit, _historyOffset, false);
    var txs = res.transactions || [];
    $('hist-total').textContent = String(res.total || txs.length);
    if (txs.length === 0) {
      $('history-more').innerHTML = '<div class="staging-empty">no more transactions</div>';
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
    fetchMissingSymbols(txs).then(function() {
      if (tbl) {
        for (var j = 0; j < txs.length; j++) {
          var rowIndex = tbl.rows.length - txs.length + j;
          if (rowIndex > 0 && tbl.rows[rowIndex]) tbl.rows[rowIndex].innerHTML = txRow(txs[j]).replace(/<\/?tr>/g, '');
        }
      }
      if (cardList) {
        var all = $('history-list').querySelector('.card-list');
        if (all) {
          var cards = all.querySelectorAll('.tx-card');
          for (var k = 0; k < txs.length; k++) {
            var cardIndex = cards.length - txs.length + k;
            if (cardIndex >= 0 && cards[cardIndex]) cards[cardIndex].outerHTML = txCardHtml(txs[k]);
          }
        }
      }
    });
    $('hist-count').textContent = String(_historyOffset + txs.length);
    if (res.has_more) {
      $('history-more').innerHTML = '<button class="load-more" data-action="loadMoreHistory">load more</button>';
    } else {
      $('history-more').innerHTML = '';
    }
  } catch (e) {
    $('history-more').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
  }
}

async function showKeys() {
  $('keys-table').innerHTML = '<div class="loading">loading...</div>';
  try {
    var res = await api('GET', '/keys');
    var h = '<table class="detail-table">';
    h += '<tr><td>address</td><td class="mono">' + (res.address || '') + '</td></tr>';
    h += '<tr><td>public key</td><td class="mono">' + escapeHtml(res.public_key || '') + '</td></tr>';
    h += '<tr><td>view pubkey</td><td class="mono">' + (res.view_pubkey || '-') + '</td></tr>';
    h += '<tr><td>private key</td><td id="privkey-cell" style="color:#8C9DB6;cursor:pointer" data-action="revealPrivateKeys">****** (click to reveal)</td></tr>';
    h += '<tr><td>seed phrase</td><td id="seed-cell" style="color:#8C9DB6' + (res.has_master_seed ? ';cursor:pointer" data-action="revealPrivateKeys' : '') + '">' + (res.has_master_seed ? '****** (click to reveal)' : 'not set - imported via private key only') + '</td></tr>';
    h += '</table>';
    $('keys-table').innerHTML = h;
  } catch (e) {
    $('keys-table').innerHTML = '<div class="error-box">' + escapeHtml(e.message) + '</div>';
  }
}

async function revealPrivateKeys() {
  var pin = await modalPrompt('reveal private keys', 'enter PIN', { pin: true, btnText: 'reveal' });
  if (!pin) return;
  try {
    var res = await api('POST', '/keys/private', {
      pin: pin,
      confirm: 'I_UNDERSTAND_KEY_EXPORT_RISK'
    });
    var pkCell = $('privkey-cell');
    if (pkCell) {
      pkCell.className = 'mono';
      pkCell.style.color = '';
      pkCell.style.cursor = '';
      pkCell.onclick = null;
      pkCell.textContent = res.private_key || '';
    }
    var seedCell = $('seed-cell');
    if (seedCell && res.mnemonic) {
      seedCell.className = 'mono';
      seedCell.style.color = '';
      seedCell.textContent = res.mnemonic;
    } else if (seedCell) {
      seedCell.textContent = 'not set - imported via private key only';
    }
  } catch (e) {
    showResult('keys-table', false, e.message);
  }
}

async function loadSettings() {
  try {
    var w = await api('GET', '/wallet');
    $('settings-rpc').value = w.rpc_url || 'https://octra.network/rpc';
    $('settings-explorer').value = w.explorer_url || 'https://octrascan.io';
    $('settings-bridge-signer').value = w.bridge_signer_url || 'https://relayer-002838819188.octra.network';
  } catch (e) {}
  loadAccountList();
}

async function loadAccountList() {
  var el = $('wallet-list');
  if (!el) return;
  try {
    var resp = await api('GET', '/wallet/accounts');
    var accounts = resp.accounts || [];
    if (accounts.length === 0) {
      el.innerHTML = '<div class="staging-empty">no accounts</div>';
      return;
    }
    var btnStyle = 'display:inline-block;width:96px;padding:8px;margin:0;border:none;border-top:1px solid #D0D7E2;border-bottom:1px solid #D0D7E2;margin-right:4px;color:#3B567F;font-family:Tahoma,arial,sans-serif;font-size:11px;font-weight:bold;letter-spacing:1px;cursor:pointer;text-align:center;text-transform:lowercase';
    var html = '<table class="tx-table" style="width:100%;table-layout:fixed"><colgroup>';
    html += '<col style="width:22%">';
    html += '<col style="width:auto">';
    html += '<col style="width:220px">';
    html += '</colgroup><tbody>';
    for (var i = 0; i < accounts.length; i++) {
      var a = accounts[i];
      var badge = a.active ? '<span style="color:#4CAF50;margin-right:4px">●</span>' : '';
      var hdLabel = '';
      if (a.hd) {
        if (a.parent_addr) {
          var short_parent = a.parent_addr.substring(0, 8) + '...' + a.parent_addr.slice(-4);
          hdLabel = ' <span style="color:#8C9DB6;font-size:11px">[HD #' + a.hd_index + ' from ' + short_parent + ']</span>';
        } else {
          hdLabel = ' <span style="color:#8C9DB6;font-size:11px">[HD]</span>';
        }
      }
      var name = a.name || 'unnamed';
      html += '<tr>';
      html += '<td style="padding:6px 8px;vertical-align:middle;overflow:hidden;text-overflow:ellipsis">' + badge + '<b>' + escapeHtml(name) + '</b>' + hdLabel + '</td>';
      html += '<td class="mono" style="padding:6px 8px;font-size:11px;vertical-align:middle;word-break:break-all">' + escapeHtml(a.addr) + '</td>';
      html += '<td style="padding:6px 4px;text-align:right;white-space:nowrap;vertical-align:middle">';
      if (!a.active) {
        html += '<button class="acct-btn" style="' + btnStyle + '" data-action="doSwitchAccount" data-arg="' + escapeAttr(a.addr) + '">switch</button>';
      } else {
        html += '<button class="acct-btn" style="' + btnStyle + '" data-action="doChangePinForWallet" data-arg="' + escapeAttr(a.addr) + '">change PIN</button>';
      }
      html += '<button class="acct-btn" style="' + btnStyle + '" data-action="renameAccount" data-arg="' + escapeAttr(a.addr) + '" data-name="' + escapeAttr(name) + '">rename</button>';
      html += '</td></tr>';
    }
    html += '</tbody></table>';
    el.innerHTML = html;
    var actEl = $('wallet-actions');
    if (actEl) {
      var ah = '<div class="action-row" style="gap:6px;flex-wrap:wrap;align-items:center">';
      if (resp.has_master_seed) {
        var idx = resp.next_hd_index || 0;
        ah += '<button class="action-btn" data-action="doDeriveAccount">derive #' + idx + '</button>';
        ah += '<span style="color:#8C9DB6;font-size:11px;margin:0 4px">or</span>';
      }
      ah += '<button class="action-btn" data-action="showImportAnother">import another wallet</button>';
      ah += '</div>';
      actEl.innerHTML = ah;
    }
  } catch (e) {
    el.innerHTML = '<div class="staging-empty">could not load accounts</div>';
  }
}

var _modalPromptResolve = null;
var _modalPromptBtnText = '';

function modalPrompt(title, label, opts) {
  opts = opts || {};
  return new Promise(function(resolve) {
    _modalPromptResolve = resolve;
    _modalPromptBtnText = opts.btnText || 'ok';
    hideAllModalPanels();
    $('modal-sub').textContent = title;
    $('modal-result').innerHTML = '';
    if (opts.pin) {
      $('modal-pin').style.display = 'block';
      var lbl = $('modal-pin-label');
      if (lbl) lbl.textContent = label;
      $('modal-pin-input').value = '';
      $('pin-back-btn').style.display = '';
      var unlockBtn = $('modal-pin').querySelector('.action-btn');
      if (unlockBtn) unlockBtn.textContent = _modalPromptBtnText;
      $('modal-pin-input').focus();
      $('modal-overlay').style.display = 'flex';
    } else {
      var h = '<div class="form-row"><label>' + escapeHtml(label) + '</label>';
      h += '<input type="text" id="modal-prompt-input"';
      if (opts.placeholder) h += ' placeholder="' + escapeAttr(opts.placeholder) + '"';
      h += ' autocomplete="off"></div>';
      h += '<div class="action-row">';
      h += '<button class="action-btn" id="modal-prompt-ok">ok</button>';
      h += '<button class="action-btn" style="background:#8C9DB6" id="modal-prompt-cancel">cancel</button>';
      h += '</div>';
      $('modal-result').innerHTML = h;
      $('modal-overlay').style.display = 'flex';
      $('modal-prompt-input').focus();
      $('modal-prompt-ok').onclick = function() {
        var val = $('modal-prompt-input').value;
        _modalPromptResolve = null;
        $('modal-result').innerHTML = '';
        $('modal-overlay').style.display = 'none';
        resolve(val);
      };
      $('modal-prompt-cancel').onclick = function() {
        _modalPromptResolve = null;
        $('modal-result').innerHTML = '';
        $('modal-overlay').style.display = 'none';
        resolve(null);
      };
      $('modal-prompt-input').onkeydown = function(e) {
        if (e.key === 'Enter') $('modal-prompt-ok').click();
        if (e.key === 'Escape') $('modal-prompt-cancel').click();
      };
    }
  });
}

async function doSwitchAccount(addr) {
  var pin = await modalPrompt('switch account', 'enter PIN', { pin: true, btnText: 'switch' });
  if (!pin) return;
  clearResult('wallet-mgmt-result');
  _walletSwitching = true;
  try {
    await api('POST', '/wallet/switch', { addr: addr, pin: pin });
    showResult('wallet-mgmt-result', true, 'switched account');
    ['send-result','enc-result','dec-result','fhe-result','ct-compile-result','ct-deploy-result','ct-call-result','ct-info-result','ct-verify-result','tok-transfer-result','settings-result'].forEach(function(id) { clearResult(id); });
    var sl = $('stealth-log'); if (sl) sl.remove();
    var so = $('stealth-outputs'); if (so) so.innerHTML = '';
    _pendingClaimIds = {};
    _pendingClaimTxs = {};
    _cachedBal = null;
    _encryptedBalanceRaw = 0;
    _encPresent = false;
    _encKnown = false;
    _unclaimedCount = 0;
    _historyOffset = 0;
    _tokens = [];
    _tokensLoaded = false;
    _fees = {};
    resetDashboardView();
    await loadWalletInfo();
    _walletSwitching = false;
    loadAccountList();
    fetchBalance();
    fetchFees();
    switchView('dashboard');
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  } finally {
    _walletSwitching = false;
  }
}

async function doChangePinForWallet(addr) {
  var cur = await modalPrompt('change PIN (step 1 of 3)', 'enter current PIN', { pin: true, btnText: 'next' });
  if (!cur) return;
  var np = await modalPrompt('change PIN (step 2 of 3)', 'enter new PIN (min 8, 15+ recommended)', { pin: true, btnText: 'next' });
  if (!np) return;
  var newErr = validatePin(np);
  if (newErr) { showResult('wallet-mgmt-result', false, 'new PIN: ' + newErr); return; }
  var nc = await modalPrompt('change PIN (step 3 of 3)', 'confirm new PIN', { pin: true, btnText: 'change' });
  if (!nc) return;
  if (np !== nc) { showResult('wallet-mgmt-result', false, 'PINs do not match'); return; }
  if (cur === np) { showResult('wallet-mgmt-result', false, 'new PIN must be different from current'); return; }
  clearResult('wallet-mgmt-result');
  try {
    await api('POST', '/wallet/change-pin', { current_pin: cur, new_pin: np });
    showResult('wallet-mgmt-result', true, 'PIN changed successfully');
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

async function doRenameAccount(addr, currentName) {
  var name = await modalPrompt('rename account', 'new name', { placeholder: currentName || 'my wallet' });
  if (!name || !name.trim()) return;
  clearResult('wallet-mgmt-result');
  try {
    await api('POST', '/wallet/rename', { addr: addr, name: name.trim() });
    showResult('wallet-mgmt-result', true, 'renamed');
    loadAccountList();
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

async function doDeriveAccount() {
  if (!_hasMasterSeed) return;
  var pin = await modalPrompt('derive new address', 'enter PIN', { pin: true });
  if (!pin) return;
  var name = await modalPrompt('derive new address', 'name for new account (optional)', { placeholder: 'trading' });
  if (name === null) return;
  clearResult('wallet-mgmt-result');
  try {
    var resp = await api('POST', '/wallet/derive', { pin: pin, name: (name || '').trim() });
    showResult('wallet-mgmt-result', true, 'derived: ' + (resp.address || '').substring(0, 16) + '...');
    loadAccountList();
  } catch (e) {
    showResult('wallet-mgmt-result', false, e.message);
  }
}

var _importFromSettings = false;

function showImportAnother() {
  _pendingAction = null;
  _pendingPriv = '';
  _pendingMnemonic = '';
  _importFromSettings = true;
  hideAllModalPanels();
  $('modal-sub').textContent = 'import additional wallet';
  $('modal-import').style.display = 'block';
  switchImportTab('seed');
  $('modal-overlay').style.display = 'flex';
}

async function doSaveSettings() {
  clearResult('settings-result');
  var rpc = $('settings-rpc').value.trim();
  var explorer = $('settings-explorer').value.trim();
  var bridgeSigner = $('settings-bridge-signer').value.trim();
  if (!rpc) { showResult('settings-result', false, 'rpc url required'); return; }
  try {
    var pin = await modalPrompt('confirm settings change', 'enter PIN to change network endpoints', { pin: true, btnText: 'save' });
    if (!pin) { showResult('settings-result', false, 'settings change cancelled'); return; }
    var resp = await api('POST', '/settings', { rpc_url: rpc, explorer_url: explorer, bridge_signer_url: bridgeSigner, pin: pin });
    if (explorer) _explorerUrl = explorer.replace(/\/+$/, '');
    try { _rpcHost = new URL(rpc).hostname; } catch(e) { _rpcHost = rpc; }
    if (resp && resp.cache_cleared) {
      clearAllAddressRuntime();
      dropAllPersistedRuntime();
      _cachedBal = null;
      _historyOffset = 0;
      _tokens = [];
      _tokensLoaded = false;
      _fees = {};
      _encryptedBalanceRaw = 0;
      _encPresent = false;
      _encKnown = false;
      _unclaimedCount = 0;
      _tokenSymbols = {};
      _tokenDecimals = {};
      fetchBalance();
      if (document.querySelector('.nav-tabs a.active[data-view="dashboard"]'))
        loadDashboard();
      showResult('settings-result', true, 'saved | cache cleared');
    } else {
      showResult('settings-result', true, 'saved');
    }
  } catch (e) {
    showResult('settings-result', false, e.message);
  }
}

async function doChangePin() {
  clearResult('pin-change-result');
  var cur = $('pin-current').value;
  var np = $('pin-new').value;
  var nc = $('pin-confirm-new').value;
  if (!cur || cur.length === 0) { showResult('pin-change-result', false, 'current PIN required'); return; }
  var newErr = validatePin(np);
  if (newErr) { showResult('pin-change-result', false, 'new PIN: ' + newErr); return; }
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
var _pendingMnemonic = '';
var _importMode = 'seed';

function hideAllModalPanels() {
  $('modal-btns').style.display = 'none';
  $('modal-import').style.display = 'none';
  $('modal-pin').style.display = 'none';
  $('modal-pin-setup').style.display = 'none';
  $('modal-mnemonic-show').style.display = 'none';
  $('modal-result').innerHTML = '';
  var lbl = $('modal-pin-label');
  if (lbl) lbl.textContent = 'enter PIN to unlock';
}

function showPinEntry(showBack) {
  hideAllModalPanels();
  $('modal-pin').style.display = 'block';
  $('modal-pin-input').value = '';
  var backBtn = $('pin-back-btn');
  if (backBtn) backBtn.style.display = showBack ? '' : 'none';
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
  switchImportTab('seed');
}

function switchImportTab(mode) {
  _importMode = mode;
  var tabs = document.querySelectorAll('.import-tab');
  tabs.forEach(function(t) { t.classList.remove('active'); });
  if (mode === 'seed') {
    tabs[0].classList.add('active');
    $('import-seed').style.display = 'block';
    $('import-key').style.display = 'none';
  } else {
    tabs[1].classList.add('active');
    $('import-seed').style.display = 'none';
    $('import-key').style.display = 'block';
  }
}

function modalBack() {
  _selectedUnlockAddr = '';
  _selectedUnlockFile = '';
  hideAllModalPanels();
  if (_importFromSettings) {
    _importFromSettings = false;
    $('modal-overlay').style.display = 'none';
    return;
  }
  init();
}

function modalBackFromPin() {
  if (_modalPromptResolve) {
    var cb = _modalPromptResolve;
    _modalPromptResolve = null;
    var unlockBtn = $('modal-pin').querySelector('.action-btn');
    if (unlockBtn) unlockBtn.textContent = 'unlock';
    hideAllModalPanels();
    $('modal-overlay').style.display = 'none';
    cb(null);
    return;
  }
  _pendingAction = null;
  _pendingPriv = '';
  _pendingMnemonic = '';
  _selectedUnlockAddr = '';
  _selectedUnlockFile = '';
  hideAllModalPanels();
  init();
}

function modalCreate() {
  showPinSetup('create');
  $('modal-sub').textContent = 'set a PIN for your new wallet';
}

function modalDoImport() {
  if (_importMode === 'seed') {
    var mn = $('modal-mnemonic').value.trim().toLowerCase();
    if (!mn) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">seed phrase required</div>';
      return;
    }
    var words = mn.split(/\s+/);
    if (words.length !== 12 && words.length !== 24) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">seed phrase must be 12 or 24 words</div>';
      return;
    }
    _pendingMnemonic = words.join(' ');
    _pendingPriv = '';
    $('modal-mnemonic').value = '';
  } else {
    var priv = $('modal-privkey').value.trim();
    if (!priv) {
      $('modal-result').innerHTML = '<div class="result-msg result-error">private key required</div>';
      return;
    }
    _pendingPriv = priv;
    _pendingMnemonic = '';
    $('modal-privkey').value = '';
  }
  showPinSetup('import');
  $('modal-sub').textContent = 'set a PIN for your wallet';
}

function showMnemonicWords(mnemonic) {
  var words = mnemonic.split(' ');
  var html = '';
  for (var i = 0; i < words.length; i++) {
    html += '<div class="mnemonic-word"><span class="mw-num">' + (i+1) + '</span>' + words[i] + '</div>';
  }
  $('mnemonic-words').innerHTML = html;
  $('mnemonic-confirm-check').checked = false;
  $('mnemonic-continue-btn').disabled = true;
  $('mnemonic-confirm-check').onchange = function() {
    $('mnemonic-continue-btn').disabled = !this.checked;
  };
}

function modalMnemonicDone() {
  $('mnemonic-words').innerHTML = '';
  $('modal-overlay').style.display = 'none';
  loadWalletInfo();
  startRefreshTimer();
}

async function modalUnlock() {
  var pin = $('modal-pin-input').value;
  if (!pin || pin.length === 0) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">PIN required</div>';
    return;
  }
  if (_modalPromptResolve) {
    var cb = _modalPromptResolve;
    _modalPromptResolve = null;
    var unlockBtn = $('modal-pin').querySelector('.action-btn');
    if (unlockBtn) unlockBtn.textContent = 'unlock';
    hideAllModalPanels();
    $('modal-overlay').style.display = 'none';
    cb(pin);
    return;
  }
  $('modal-result').innerHTML = '<div class="loading">unlocking...</div>';
  try {
    var unlockBody = { pin: pin };
    if (_selectedUnlockAddr) unlockBody.addr = _selectedUnlockAddr;
    if (_selectedUnlockFile) unlockBody.file = _selectedUnlockFile;
    await api('POST', '/wallet/unlock', unlockBody);
    _selectedUnlockAddr = '';
    _selectedUnlockFile = '';
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + escapeHtml(e.message) + '</div>';
    $('modal-pin-input').value = '';
    $('modal-pin-input').focus();
  }
}

async function modalFinishSetup() {
  var pin = $('modal-pin-new').value;
  var confirm = $('modal-pin-confirm').value;
  var pinErr = validatePin(pin);
  if (pinErr) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + pinErr + '</div>';
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
      var resp = await api('POST', '/wallet/create', { pin: pin });
      if (resp.mnemonic) {
        hideAllModalPanels();
        $('modal-sub').textContent = 'your seed phrase';
        $('modal-mnemonic-show').style.display = 'block';
        showMnemonicWords(resp.mnemonic);
        return;
      }
    } else if (_pendingAction === 'import') {
      var importBody = { pin: pin };
      if (_pendingMnemonic) {
        importBody.mnemonic = _pendingMnemonic;
        _pendingMnemonic = '';
      } else {
        importBody.priv = _pendingPriv;
        _pendingPriv = '';
      }
      var resp = await api('POST', '/wallet/import', importBody);
      if (resp.switched === false) {
        $('modal-overlay').style.display = 'none';
        showResult('wallet-mgmt-result', true, 'imported: ' + (resp.address || '').substring(0, 16) + '...');
        loadAccountList();
        return;
      }
    } else if (_pendingAction === 'migrate') {
      await api('POST', '/wallet/unlock', { pin: pin });
    }
    $('modal-overlay').style.display = 'none';
    await loadWalletInfo();
    startRefreshTimer();
  } catch (e) {
    $('modal-result').innerHTML = '<div class="result-msg result-error">' + escapeHtml(e.message) + '</div>';
  }
}

async function loadWalletInfo() {
  try {
    var w = await api('GET', '/wallet');
    var prevAddr = _walletAddr;
    _walletAddr = w.address || w.addr || '';
    ensureAddressRuntime(_walletAddr);
    if (prevAddr !== _walletAddr) {
      _historyOffset = 0;
      _tokens = [];
      _tokensLoaded = false;
      resetDashboardView();
      restoreAddressTokens(_walletAddr);
    }
    if (w.explorer_url) _explorerUrl = w.explorer_url.replace(/\/+$/, '');
    if (w.rpc_url) try { _rpcHost = new URL(w.rpc_url).hostname; } catch(e) { _rpcHost = w.rpc_url; }
    _hasMasterSeed = !!w.has_master_seed;
    $('hdr-addr').innerHTML = '<span class="mono">' + _walletAddr + '</span>';
    $('hdr-logout').style.display = '';
    $('hdr-dev').style.display = '';
    $('hdr-circles').style.display = '';
    $('hdr-apps').style.display = '';
    fetchFees();
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
  clearAllAddressRuntime();
  _walletAddr = '';
  _cachedBal = null;
  _encryptedBalanceRaw = 0;
  _encPresent = false;
  _encKnown = false;
  _hasMasterSeed = false;
  _tokens = [];
  _tokensLoaded = false;
  _tokenSymbols = {};
  _tokenDecimals = {};
  $('hdr-logout').style.display = 'none';
  $('hdr-dev').style.display = 'none';
  $('hdr-circles').style.display = 'none';
  $('hdr-apps').style.display = 'none';
  $('hdr-addr').textContent = 'locked';
  $('hdr-status').textContent = 'locked';
  $('hdr-status').className = 'right';
  switchView('dashboard');
  init();
}

function startRefreshTimer() {
  if (_refreshTimer) return;
  bgStealthScan();
  _refreshTimer = setInterval(function() {
    if (_walletSwitching) return;
    if (_privateOpInFlight) return;
    fetchBalance(true);
    bgStealthScan();
    fetchFees();
    var dash = $('view-dashboard');
    var tok = $('view-tokens');
    var hist = $('view-history');
    if (dash && dash.classList.contains('active')) loadDashboard();
    if (tok && tok.classList.contains('active')) loadTokens();
    if (hist && hist.classList.contains('active') && _historyOffset === 0) loadHistory();
  }, 15000);
}

var _selectedUnlockAddr = '';
var _selectedUnlockFile = '';

function showAccountPicker(wallets) {
  hideAllModalPanels();
  $('modal-sub').textContent = 'select account';
  var html = '<div style="margin:10px 0;max-height:300px;overflow-y:auto">';
  for (var i = 0; i < wallets.length; i++) {
    var a = wallets[i];
    var hasAddr = a.addr && a.addr.length > 0;
    var name = a.name || (hasAddr ? 'wallet' : a.file.replace('data/', ''));
    var sub = hasAddr
      ? a.addr.substring(0, 12) + '...' + a.addr.substring(a.addr.length - 6)
      : a.file;
    var hdTag = a.hd ? ' | hd' : '';
    var dataAttr = hasAddr
      ? 'data-addr="' + escapeAttr(a.addr) + '"'
      : 'data-file="' + escapeAttr(a.file) + '"';
    html += '<div class="account-card" ' + dataAttr + ' data-action="pickWallet" style="cursor:pointer;padding:10px 12px;margin:6px 0;border:1px solid #3B567F;transition:background 0.15s,color 0.15s">';
    html += '<div style="font-weight:600">' + escapeHtml(name) + '<span style="color:#8C9DB6;font-size:11px">' + hdTag + '</span></div>';
    html += '<div class="mono" style="font-size:12px;color:#8C9DB6;margin-top:2px">' + sub + '</div>';
    html += '</div>';
  }
  html += '</div>';
  html += '<div style="margin-top:8px;text-align:center">';
  html += '<a href="#" style="color:#8C9DB6;font-size:12px" data-action="showImportOptions" data-prevent="1">+ import or create new wallet</a>';
  html += '</div>';
  $('modal-result').innerHTML = html;
  $('modal-overlay').style.display = 'flex';
}

function pickWallet(el) {
  _selectedUnlockAddr = el.getAttribute('data-addr') || '';
  _selectedUnlockFile = el.getAttribute('data-file') || '';
  $('modal-sub').textContent = 'enter PIN to unlock';
  $('modal-result').innerHTML = '';
  showPinEntry(true);
}

function showImportOptions() {
  hideAllModalPanels();
  $('modal-sub').textContent = 'add wallet';
  $('modal-btns').style.display = 'flex';
  $('modal-result').innerHTML = '';
}

async function init() {
  try {
    var st = await api('GET', '/wallet/status');
    if (st.loaded) {
      await loadWalletInfo();
      startRefreshTimer();
      return;
    }
    if (st.has_legacy) {
      $('modal-sub').textContent = 'migrating wallet - set a PIN';
      showPinSetup('migrate');
      $('modal-overlay').style.display = 'flex';
      return;
    }
    var wallets = st.wallets || [];
    if (wallets.length === 0) {
      $('modal-sub').textContent = 'no wallet found';
      $('modal-btns').style.display = 'flex';
      $('modal-overlay').style.display = 'flex';
      return;
    }
    if (wallets.length === 1 && wallets[0].addr) {
      _selectedUnlockAddr = wallets[0].addr;
      _selectedUnlockFile = '';
      $('modal-sub').textContent = 'enter PIN to unlock';
      showPinEntry();
      $('modal-overlay').style.display = 'flex';
      return;
    }
    showAccountPicker(wallets);
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

function wireDelegation() {
  var actions = {
    modalShowImport, modalCreate, modalDoImport, modalBack, modalMnemonicDone,
    modalUnlock, modalBackFromPin, modalFinishSetup, doLogout, doKeySwitch,
    doSend, doEncrypt, doDecrypt, doStealthSend, doStealthScan, doTokenTransfer,
    closeTokenTransfer, onLangChange, editorUpdateWithLiveCompile, doCompile,
    loadTemplate, doPreviewDeploy, doDeploy, doContractCall, doContractView,
    doFheEncrypt, doFheDecrypt, doContractInfo, doContractReceipt, doVerifyContract,
    doSaveSettings, doChangePin, goBack, switchView, switchImportTab, switchBottomTab,
    ideCloseProject, ideExportZip, ideNewFile, ideOpenFile, ideCloseTab, ideNewProject,
    ideLoadProject, ideDeleteProject, showTx, claimSelected, openTokenTransfer,
    loadMoreHistory, revealPrivateKeys, doSwitchAccount, doChangePinForWallet,
    doDeriveAccount, showImportAnother, showImportOptions,
    navTo: function(a) { window.location.href = a; },
    openTab: function(a) { window.open(a, '_blank'); },
    selectSelf: function(a, el) { el.select(); },
    importFiles: function(a, el) { ideImportFiles(el.files); },
    fileMenu: function(a, el, e) { ideFileMenu(e, a); },
    renameAccount: function(a, el) { doRenameAccount(el.getAttribute('data-arg'), el.getAttribute('data-name')); },
    pickWallet: function(a, el) { pickWallet(el); }
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
  document.addEventListener('change', function(e) { run(e, 'data-change'); });
  document.addEventListener('input', function(e) { run(e, 'data-input'); });
  document.addEventListener('contextmenu', function(e) { run(e, 'data-context'); });
  document.addEventListener('submit', function(e) { if (e.target.closest('[data-nosubmit]')) e.preventDefault(); });
  var ed = $('ct-source');
  if (ed) ed.addEventListener('scroll', editorSync);
}

wireDelegation();
initEditor();

init();