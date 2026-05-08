(function () {
  var FIELD_NAMES = [
    'age',
    'income_k',
    'debt_k',
    'savings_k',
    'history_score',
    'employment_years',
    'defaults_count',
    'open_accounts'
  ];
  var CONTRACT_KEY = 'octra_private_credit_contract';
  var compiledBytecode = '';
  var contractSource = '';
  var walletAddress = '';
  var latestCiphertext = '';
  var publicBalanceRaw = 0;
  var fees = {};

  function el(id) {
    return document.getElementById(id);
  }

  function setPill(id, text, cls) {
    var node = el(id);
    node.textContent = text;
    node.className = 'pill ' + (cls || 'muted');
  }

  function setLog(id, text, cls) {
    var node = el(id);
    node.textContent = text || '';
    node.className = 'log-box' + (cls ? ' ' + cls : '');
  }

  function progress(items) {
    el('progress-list').innerHTML = items.map(function (item) {
      var cls = item.cls ? ' ' + item.cls : '';
      return '<div class="progress-item' + cls + '">' + escapeHtml(item.text) + '</div>';
    }).join('');
  }

  function escapeHtml(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function api(method, path, body) {
    var opts = { method: method, headers: {} };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    var res = await fetch('/api' + path, opts);
    var text = await res.text();
    var json = {};
    if (text) {
      try {
        json = JSON.parse(text);
      } catch (e) {
        throw new Error('bad response');
      }
    }
    if (!res.ok) {
      throw new Error(json.error || json.message || 'request failed');
    }
    return json;
  }

  async function loadSource() {
    if (contractSource) return contractSource;
    var res = await fetch('templates/private_credit/main.aml?v=1');
    contractSource = await res.text();
    return contractSource;
  }

  async function refreshWallet() {
    try {
      var status = await api('GET', '/wallet/status');
      if (!status.loaded) {
        walletAddress = '';
        publicBalanceRaw = 0;
        el('wallet-state').textContent = 'wallet locked';
        el('wallet-address').textContent = '';
        el('wallet-balance').textContent = '';
        setPill('run-state', 'locked', 'warn');
        return;
      }
      var wallet = await api('GET', '/wallet');
      walletAddress = wallet.address || '';
      el('wallet-state').textContent = 'wallet ready';
      el('wallet-address').textContent = walletAddress;
      await Promise.all([refreshBalance(), refreshFees()]);
      setPill('run-state', 'idle', 'muted');
    } catch (err) {
      walletAddress = '';
      publicBalanceRaw = 0;
      el('wallet-state').textContent = 'wallet unavailable';
      el('wallet-address').textContent = '';
      el('wallet-balance').textContent = '';
      setPill('run-state', 'offline', 'err');
    }
  }

  async function refreshBalance() {
    var balance = await api('GET', '/balance');
    publicBalanceRaw = Number(balance.public_balance || 0);
    el('wallet-balance').textContent = 'balance ' + formatOct(publicBalanceRaw) + ' OCT';
  }

  async function refreshFees() {
    fees = await api('GET', '/fee');
  }

  function feeFor(op, fallback) {
    var fee = fees[op] || {};
    return String(fee.recommended || fee.base_fee || fallback);
  }

  function formatOct(raw) {
    var value = Number(raw || 0) / 1000000;
    return value.toLocaleString(undefined, { maximumFractionDigits: 6 });
  }

  function assertBalanceFor(rawFee) {
    var fee = Number(rawFee || 0);
    if (Number.isFinite(fee) && publicBalanceRaw < fee) {
      throw new Error('insufficient balance: need ' + formatOct(fee) + ' OCT fee, current balance is ' + formatOct(publicBalanceRaw) + ' OCT. Use the faucet first.');
    }
  }

  function loadStoredContract() {
    var stored = localStorage.getItem(CONTRACT_KEY) || '';
    el('contract-address').value = stored;
    updateContractState();
  }

  function updateContractState() {
    var address = getContractAddress();
    if (address) {
      setPill('contract-state', 'ready', 'ok');
    } else {
      setPill('contract-state', 'not set', 'muted');
    }
  }

  function saveContractAddress() {
    var address = getContractAddress();
    localStorage.setItem(CONTRACT_KEY, address);
    updateContractState();
    setLog('contract-output', address ? 'saved ' + address : 'cleared');
  }

  function getContractAddress() {
    return el('contract-address').value.trim();
  }

  async function compileContract() {
    setPill('contract-state', 'compiling', 'warn');
    setLog('contract-output', 'compiling...');
    var source = await loadSource();
    var result = await api('POST', '/contract/compile-aml', { source: source });
    compiledBytecode = result.bytecode || '';
    setPill('contract-state', 'compiled', 'ok');
    setLog('contract-output', 'compiled: ' + result.instructions + ' instructions, ' + result.size + ' bytes');
    return result;
  }

  async function deployContract() {
    if (!walletAddress) await refreshWallet();
    if (!walletAddress) throw new Error('wallet locked');
    await Promise.all([refreshBalance(), refreshFees()]);
    var deployFee = feeFor('deploy', '200000');
    assertBalanceFor(deployFee);
    if (!compiledBytecode) await compileContract();

    setPill('contract-state', 'deploying', 'warn');
    setLog('contract-output', 'deploying with fee ' + formatOct(deployFee) + ' OCT...');
    var source = await loadSource();
    var result = await api('POST', '/contract/deploy', {
      bytecode: compiledBytecode,
      params: '[]',
      source: source,
      ou: deployFee
    });
    if (!result.contract_address) throw new Error(result.error || 'deploy failed');
    el('contract-address').value = result.contract_address;
    localStorage.setItem(CONTRACT_KEY, result.contract_address);
    setPill('contract-state', 'deployed', 'ok');
    setLog('contract-output', 'deployed ' + result.contract_address + (result.tx_hash ? ' / ' + result.tx_hash : ''));
  }

  function readInputs() {
    var values = {};
    FIELD_NAMES.forEach(function (name) {
      var input = el(name);
      var value = Number(input.value);
      if (!Number.isFinite(value)) {
        throw new Error(name + ' invalid');
      }
      var min = input.min === '' ? -Infinity : Number(input.min);
      var max = input.max === '' ? Infinity : Number(input.max);
      if (value < min || value > max) {
        throw new Error(name + ' out of range');
      }
      values[name] = Math.trunc(value);
    });
    return values;
  }

  function plainScore(values) {
    return 520
      - values.age
      + values.income_k
      - values.debt_k * 2
      + values.savings_k * 2
      + values.history_score * 2
      + values.employment_years * 8
      - values.defaults_count * 140
      - values.open_accounts * 3;
  }

  function tierFor(score) {
    if (score >= 720) return 'excellent';
    if (score >= 660) return 'good';
    if (score >= 600) return 'fair';
    return 'high risk';
  }

  async function encryptValues(values) {
    var out = [];
    for (var i = 0; i < FIELD_NAMES.length; i++) {
      var name = FIELD_NAMES[i];
      progress([{ text: 'encrypting ' + name + ' (' + (i + 1) + '/' + FIELD_NAMES.length + ')', cls: '' }]);
      var encrypted = await api('POST', '/fhe/encrypt', { value: values[name] });
      if (!encrypted.ciphertext) throw new Error('encrypt failed: ' + name);
      out.push(encrypted.ciphertext);
    }
    return out;
  }

  async function runPrivateScore() {
    var contract = getContractAddress();
    if (!contract) throw new Error('contract address required');
    if (!walletAddress) await refreshWallet();
    if (!walletAddress) throw new Error('wallet locked');
    await ensureContractExists(contract);

    var values = readInputs();
    var localScore = plainScore(values);
    setPill('run-state', 'encrypting', 'warn');
    progress([{ text: 'local estimate: ' + localScore, cls: '' }]);

    var ciphertexts = await encryptValues(values);
    setPill('run-state', 'calling', 'warn');
    progress([{ text: 'calling private_score', cls: '' }]);

    var params = [walletAddress].concat(ciphertexts);
    var view = await api('POST', '/contract/view', {
      address: contract,
      method: 'private_score',
      params: params
    });
    var ctScore = view.result || view.value || '';
    if (!ctScore) throw new Error('empty contract result');
    latestCiphertext = ctScore;
    el('cipher-output').value = ctScore;

    setPill('run-state', 'decrypting', 'warn');
    progress([{ text: 'decrypting result', cls: '' }]);
    var decrypted = await api('POST', '/fhe/decrypt', { ciphertext: ctScore });
    var score = Number(decrypted.value);
    if (!Number.isFinite(score)) throw new Error('decrypt failed');

    el('score-value').textContent = String(score);
    el('risk-tier').textContent = tierFor(score);
    el('store-score').disabled = false;
    setPill('run-state', 'complete', 'ok');
    progress([
      { text: 'encrypted inputs submitted to view call', cls: 'ok' },
      { text: 'score decrypted locally: ' + score, cls: 'ok' },
      { text: 'tier: ' + tierFor(score), cls: 'ok' }
    ]);
  }

  async function storeScore() {
    var contract = getContractAddress();
    if (!contract) throw new Error('contract address required');
    if (!latestCiphertext) throw new Error('run score first');
    await Promise.all([refreshBalance(), refreshFees()]);
    var callFee = feeFor('call', '1000');
    assertBalanceFor(callFee);
    setPill('run-state', 'storing', 'warn');
    var result = await api('POST', '/contract/call', {
      address: contract,
      method: 'store_score',
      params: [latestCiphertext],
      ou: callFee
    });
    setPill('run-state', 'stored', 'ok');
    progress([{ text: 'store_score tx: ' + (result.tx_hash || 'submitted'), cls: 'ok' }]);
  }

  async function loadLatest() {
    var contract = getContractAddress();
    if (!contract) throw new Error('contract address required');
    if (!walletAddress) await refreshWallet();
    if (!walletAddress) throw new Error('wallet locked');
    await ensureContractExists(contract);
    setPill('run-state', 'loading', 'warn');
    var view = await api('POST', '/contract/view', {
      address: contract,
      method: 'latest_score',
      params: [walletAddress]
    });
    var ctScore = view.result || view.value || '';
    if (!ctScore || ctScore === '0') throw new Error('no stored score');
    latestCiphertext = ctScore;
    el('cipher-output').value = ctScore;
    var decrypted = await api('POST', '/fhe/decrypt', { ciphertext: ctScore });
    var score = Number(decrypted.value);
    el('score-value').textContent = String(score);
    el('risk-tier').textContent = tierFor(score);
    el('store-score').disabled = false;
    setPill('run-state', 'loaded', 'ok');
    progress([{ text: 'latest encrypted score loaded', cls: 'ok' }]);
  }

  function loadSample() {
    var sample = {
      age: 34,
      income_k: 115,
      debt_k: 42,
      savings_k: 38,
      history_score: 82,
      employment_years: 7,
      defaults_count: 0,
      open_accounts: 5
    };
    FIELD_NAMES.forEach(function (name) {
      el(name).value = sample[name];
    });
  }

  async function ensureContractExists(contract) {
    try {
      await api('GET', '/contract/info?address=' + encodeURIComponent(contract));
    } catch (err) {
      throw new Error('contract not deployed or wrong address. Deploy it first, then use the deployed contract address.');
    }
  }

  function wire(id, fn) {
    el(id).addEventListener('click', function () {
      Promise.resolve()
        .then(fn)
        .catch(function (err) {
          var contractAction = id.indexOf('contract') >= 0 || id === 'deploy-contract' || id === 'save-contract';
          setPill(contractAction ? 'contract-state' : 'run-state', 'error', 'err');
          if (contractAction) {
            setLog('contract-output', err.message || String(err));
          } else {
            progress([{ text: err.message || String(err), cls: 'err' }]);
          }
        });
    });
  }

  function init() {
    loadStoredContract();
    refreshWallet();
    loadSource().catch(function () {
      setLog('contract-output', 'contract source unavailable');
    });
    wire('refresh-wallet', refreshWallet);
    wire('save-contract', saveContractAddress);
    wire('compile-contract', compileContract);
    wire('deploy-contract', deployContract);
    wire('score-private', runPrivateScore);
    wire('store-score', storeScore);
    wire('load-latest', loadLatest);
    wire('load-sample', loadSample);
    el('contract-address').addEventListener('input', updateContractState);
  }

  init();
})();
