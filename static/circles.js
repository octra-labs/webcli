const $ = (id) => document.getElementById(id)
const bindIfPresent = (id, eventName, handler) => {
  const element = $(id)
  if (element) {
    element.addEventListener(eventName, handler)
  }
}
const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder()
const runtimeBase = window.location.protocol === 'file:' ? 'http://127.0.0.1:8420' : ''
const sealedMagic = utf8Encoder.encode('OCRS1')
const keyCache = new Map()
const decryptedCache = new Map()
const bridgeGrantState = new Map()
const bridgeCreatedCircleIds = new Map()
const maxFrameScripts = 64
const maxFrameScriptBytes = 4 * 1024 * 1024
let activeBridgeWindow = null
let activeBridgeContext = null
let expandedPreviewOpen = false
let publicPreludeSourcePromise = null
let uploadPathGuess = ''
let uploadContentTypeGuess = ''
let uploadFeeGuess = ''

const bytesToBase64 = (bytes) => {
  let text = ''
  const chunk = 0x8000
  for (let index = 0; index < bytes.length; index += chunk) {
    text += String.fromCharCode(...bytes.subarray(index, index + chunk))
  }
  return btoa(text)
}

const base64ToBytes = (b64) => Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0))

const utf8Bytes = (text) => utf8Encoder.encode(text)

const bytesToText = (bytes) => utf8Decoder.decode(bytes)

const mergeBytes = (...parts) => {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  parts.forEach((part) => {
    out.set(part, offset)
    offset += part.length
  })
  return out
}

const u32be = (value) => {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value, false)
  return out
}

const readU32be = (bytes) => new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, false)

const randomBytes = (size) => {
  const out = new Uint8Array(size)
  crypto.getRandomValues(out)
  return out
}

const hexOfBytes = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')

const sha256Hex = async (bytes) => hexOfBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))

const sha256Raw = async (bytes) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))

const h256Raw = async (tag, parts) => {
  const prefix = mergeBytes(utf8Bytes(tag), new Uint8Array([0]))
  const framed = parts.reduce(
    (acc, part) => mergeBytes(acc, u32be(part.length), part),
    prefix
  )
  return sha256Raw(framed)
}

const h256Hex = async (tag, parts) => hexOfBytes(await h256Raw(tag, parts))

const resourceKeyOfPath = (circleId, canonicalPath) => h256Hex('octra:circle_resource_key:v1', [utf8Bytes(circleId), utf8Bytes(canonicalPath)])
const resourceKeyOfSlotRef = (circleId, slotRef) => h256Hex('octra:circle_resource_key:slot:v1', [utf8Bytes(circleId), utf8Bytes(slotRef)])

const base58Encode = (bytes) => {
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
  let value = 0n
  bytes.forEach((byte) => {
    value = (value << 8n) + BigInt(byte)
  })
  let encoded = ''
  while (value > 0n) {
    const digit = Number(value % 58n)
    encoded = alphabet[digit] + encoded
    value /= 58n
  }
  let leadingZeros = 0
  while (leadingZeros < bytes.length && bytes[leadingZeros] === 0) {
    encoded = `1${encoded}`
    leadingZeros += 1
  }
  return encoded
}

const deployProfileOf = (mode) => mode === 'public' ? 'public' : 'sealed'

const deployConfigOf = (mode) => CircleBridgePolicy.deployPayload(deployProfileOf(mode))

const selectedDeployMode = () => $('deploy-mode') && $('deploy-mode').value === 'public' ? 'public' : 'sealed'

const buildCircleDeployPayload = (mode = selectedDeployMode()) => deployConfigOf(mode)

const circleIdOfDeploy = async (deployer, nonce, payload) => {
  const payloadHash = await h256Hex('octra:circle_deploy_payload:v1', [utf8Bytes(JSON.stringify(payload))])
  const seed = await h256Raw('octra:circle_deploy_id:v1', [utf8Bytes(deployer), u64be(nonce), utf8Bytes(payloadHash)])
  const base58 = base58Encode(seed)
  const base58Part = base58.length >= 44
    ? base58.slice(0, 44)
    : base58.length === 0
      ? '1'.repeat(44)
      : (base58 + base58.repeat(Math.ceil((44 - base58.length) / base58.length))).slice(0, 44)
  return `oct${base58Part}`
}

const isTextContent = (contentType) => (
  contentType.startsWith('text/')
  || contentType.includes('json')
  || contentType.includes('javascript')
  || contentType.includes('xml')
  || contentType.includes('svg')
)

const mediaTypeOf = (contentType) => (contentType || '').split(';')[0].trim().toLowerCase()

const isStylesheetContentType = (contentType) => mediaTypeOf(contentType) === 'text/css'

const isScriptContentType = (contentType) => [
  'application/javascript',
  'text/javascript',
  'application/ecmascript',
  'text/ecmascript',
  'application/x-javascript',
  'module'
].includes(mediaTypeOf(contentType))

const isBlockedRemoteSpec = (spec) => /^(https?:)?\/\//i.test(spec) || /^javascript:/i.test(spec) || /^mailto:/i.test(spec)

const isDataSpec = (spec) => /^data:/i.test(spec) || /^blob:/i.test(spec)

const normalizeAssetPath = (rawPath) => {
  const path = (rawPath || '').trim()
  if (!path) return '/index.html'
  return path.startsWith('/') ? path : `/${path}`
}

const circleUriOf = (circleId, path) => `oct://${circleId}${normalizeAssetPath(path)}`

const parseCircleUri = (uri) => {
  const parsed = CircleBridgePolicy.parseUri(uri)
  if (!parsed) return null
  return {
    circleId: parsed.circle_id,
    path: parsed.path,
    uri: parsed.uri
  }
}

const parseCircleTarget = (rawCircle, rawPath) => {
  const parsedUri = parseCircleUri(rawCircle)
  if (parsedUri) {
    return parsedUri
  }
  const circleId = (rawCircle || '').trim()
  const path = normalizeAssetPath(rawPath)
  return {
    circleId,
    path,
    uri: circleId ? circleUriOf(circleId, path) : ''
  }
}

const currentCircleTarget = () => parseCircleTarget($('circle-id').value.trim(), '/index.html')

const circleResourceUrl = (circleId, path) => {
  const resourcePath = CircleBridgePolicy.publicResourcePath(circleId, path)
  return resourcePath ? `${runtimeBase}${resourcePath}` : ''
}

const setStatus = (nodeId, text, bad) => {
  const element = $(nodeId)
  if (!element) {
    return
  }
  element.textContent = text
  element.style.color = bad ? '#3B567F' : '#516E9A'
}

const validTxHash = (hash) => /^[a-f0-9]{64}$/i.test(hash || '')

const explorerTxUrl = (hash, explorerUrl) => {
  if (!validTxHash(hash) || !explorerUrl) {
    return ''
  }
  return `${explorerUrl.replace(/\/+$/, '')}/tx.html?hash=${encodeURIComponent(hash)}`
}

const appendStatusLine = (element, text) => {
  const line = document.createElement('div')
  line.className = 'circle-status-line'
  line.textContent = text
  element.appendChild(line)
  return line
}

const setSubmittedStatus = (nodeId, txHash, lines, explorerUrl) => {
  const element = $(nodeId)
  if (!element) {
    return
  }
  element.textContent = ''
  element.style.color = '#516E9A'
  const firstLine = appendStatusLine(element, 'submitted ')
  const url = explorerTxUrl(txHash, explorerUrl)
  if (url) {
    const link = document.createElement('a')
    link.className = 'mono circle-status-link'
    link.href = url
    link.target = '_blank'
    link.rel = 'noopener noreferrer'
    link.textContent = txHash
    firstLine.appendChild(link)
  } else {
    firstLine.append(txHash || 'tx')
  }
  lines.forEach((line) => appendStatusLine(element, line))
}

const normalizeFee = (nodeId, fallback) => {
  const element = $(nodeId)
  const raw = element ? element.value.trim() : ''
  if (/^[1-9][0-9]*$/.test(raw)) {
    return raw
  }
  if (element) {
    element.value = fallback
  }
  return fallback
}

const lockedMessageOf = (err) => {
  const message = err && err.message ? err.message : ''
  return message === 'no wallet loaded' || message === 'wallet not loaded'
    ? 'unlock wallet first'
    : (message || 'request failed')
}

const ensureWalletUnlocked = async (statusNodeId) => {
  try {
    const status = await fetchJson('/api/wallet/status')
    if (!status.loaded) {
      setStatus(statusNodeId, 'unlock wallet first', true)
      return false
    }
    return true
  } catch (err) {
    setStatus(statusNodeId, lockedMessageOf(err), true)
    return false
  }
}

const formatFileSize = (size) => `${Number(size || 0).toLocaleString()} bytes`

const switchCircleView = (name) => {
  document.querySelectorAll('.nav-tabs a[data-circle-view]').forEach((tab) => {
    tab.classList.toggle('active', tab.getAttribute('data-circle-view') === name)
  })
  document.querySelectorAll('.circle-view').forEach((view) => {
    view.classList.toggle('active', view.id === `view-${name}`)
  })
}

const previewInlineHost = () => $('preview-inline-host')

const previewOverlayHost = () => $('preview-overlay-host')

const syncActiveBridgeWindow = () => {
  const frame = $('preview-body').querySelector('iframe')
  if (!frame) {
    activeBridgeWindow = null
    return
  }
  if (activeBridgeContext) {
    activeBridgeWindow = frame.contentWindow
  }
}

const movePreviewHost = (target) => {
  if (!target) {
    return
  }
  target.appendChild($('preview-head'))
  target.appendChild($('preview-body'))
  syncActiveBridgeWindow()
}

const syncOverlayControlsFromMain = () => {
  $('overlay-circle-id').value = $('circle-id').value
  $('overlay-sealed-passphrase').value = $('sealed-passphrase').value
}

const syncMainControlsFromOverlay = () => {
  $('circle-id').value = $('overlay-circle-id').value
  $('sealed-passphrase').value = $('overlay-sealed-passphrase').value
}

const closeExpandedPreview = () => {
  expandedPreviewOpen = false
  $('preview-overlay').classList.remove('is-open')
  document.body.classList.remove('circle-overlay-open')
  movePreviewHost(previewInlineHost())
}

const setPreviewExpandAvailable = (available) => {
  $('preview-expand-btn').hidden = !available
  if (!available && expandedPreviewOpen) {
    closeExpandedPreview()
  }
}

const openExpandedPreview = () => {
  if ($('preview-expand-btn').hidden) {
    return
  }
  syncOverlayControlsFromMain()
  expandedPreviewOpen = true
  $('preview-overlay').classList.add('is-open')
  document.body.classList.add('circle-overlay-open')
  movePreviewHost(previewOverlayHost())
}

const toggleExpandedPreview = () => {
  if (expandedPreviewOpen) {
    closeExpandedPreview()
    return
  }
  openExpandedPreview()
}

const circleConfirm = (title, message, confirmLabel = 'confirm') => new Promise((resolve) => {
  const overlay = document.createElement('div')
  const box = document.createElement('div')
  const titleNode = document.createElement('div')
  const messageNode = document.createElement('div')
  const buttons = document.createElement('div')
  const cancelButton = document.createElement('button')
  const confirmButton = document.createElement('button')

  overlay.className = 'modal-overlay'
  box.className = 'modal-box circle-confirm-box'
  titleNode.className = 'modal-title'
  messageNode.className = 'modal-message'
  buttons.className = 'modal-buttons'
  cancelButton.className = 'modal-btn'
  confirmButton.className = 'modal-btn modal-btn-primary'

  titleNode.textContent = title
  messageNode.textContent = message
  cancelButton.textContent = 'cancel'
  confirmButton.textContent = confirmLabel

  const close = (accepted) => {
    overlay.remove()
    resolve(accepted)
  }

  cancelButton.addEventListener('click', () => close(false))
  confirmButton.addEventListener('click', () => close(true))
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) {
      close(false)
    }
  })

  buttons.append(cancelButton, confirmButton)
  box.append(titleNode, messageNode, buttons)
  overlay.append(box)
  document.body.append(overlay)
  cancelButton.focus()
})

const circlePin = (title, message) => new Promise((resolve) => {
  const overlay = document.createElement('div')
  const box = document.createElement('div')
  const titleNode = document.createElement('div')
  const messageNode = document.createElement('div')
  const input = document.createElement('input')
  const buttons = document.createElement('div')
  const cancelButton = document.createElement('button')
  const confirmButton = document.createElement('button')

  overlay.className = 'modal-overlay'
  box.className = 'modal-box'
  titleNode.className = 'modal-title'
  messageNode.className = 'modal-message'
  buttons.className = 'modal-buttons'
  cancelButton.className = 'modal-btn'
  confirmButton.className = 'modal-btn modal-btn-primary'
  input.type = 'password'
  input.autocomplete = 'current-password'
  input.className = 'input-field'

  titleNode.textContent = title
  messageNode.textContent = message
  cancelButton.textContent = 'cancel'
  confirmButton.textContent = 'sign'

  const close = (value) => {
    overlay.remove()
    resolve(value)
  }

  cancelButton.addEventListener('click', () => close(''))
  confirmButton.addEventListener('click', () => close(input.value))
  input.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      close(input.value)
    }
  })
  overlay.addEventListener('click', (event) => {
    if (event.target === overlay) {
      close('')
    }
  })

  buttons.append(cancelButton, confirmButton)
  box.append(titleNode, messageNode, input, buttons)
  overlay.append(box)
  document.body.append(overlay)
  input.focus()
})

const renderMeta = (info) => {
  $('meta-summary-note').textContent = 'identity | mode | roots | ownership'
  const rows = [
    ['circle id', info.circle_id],
    ['runtime', info.runtime],
    ['privacy class', info.privacy_class],
    ['browser mode', info.browser_mode],
    ['resource mode', info.resource_mode],
    ['owner', info.owner],
    ['version', info.version],
    ['code hash', info.code_hash],
    ['stable root', info.stable_root],
    ['assets root', info.assets_root]
  ]
  const meta = $('meta')
  meta.textContent = ''
  rows.forEach(([key, value]) => {
    const row = document.createElement('div')
    row.className = 'circle-meta-row'
    const keyCell = document.createElement('div')
    keyCell.className = 'circle-meta-key'
    keyCell.textContent = key
    const valueCell = document.createElement('div')
    valueCell.className = 'circle-meta-value'
    valueCell.textContent = value ?? ''
    row.append(keyCell, valueCell)
    meta.append(row)
  })
}

const resetMeta = () => {
  $('meta-summary-note').textContent = 'no information yet'
  $('meta').innerHTML = ''
}

const fetchJson = async (url, options = {}) => {
  const response = await fetch(`${runtimeBase}${url}`, options)
  const text = await response.text()
  const json = text ? JSON.parse(text) : {}
  if (!response.ok) {
    throw new Error(json.error || 'request failed')
  }
  return json
}

const postJson = (url, payload) => fetchJson(url, {
  method: 'POST',
  headers: {'Content-Type': 'text/plain;charset=utf-8'},
  body: JSON.stringify(payload)
})

const clearBridgeContext = () => {
  activeBridgeWindow = null
  activeBridgeContext = null
}

const createdCircleIdsForBridge = () => {
  const sourceCircleId = activeBridgeContext.circle_id
  if (!bridgeCreatedCircleIds.has(sourceCircleId)) {
    bridgeCreatedCircleIds.set(sourceCircleId, new Set())
  }
  return bridgeCreatedCircleIds.get(sourceCircleId)
}

const postBridgeReply = (target, token, id, ok, result, error) => {
  if (!target || !token || !id) {
    return
  }
  target.postMessage({
    type: 'octra.circle.bridge.reply',
    token,
    id,
    ok,
    result: ok ? result : undefined,
    error: ok ? undefined : error
  }, '*')
}

const bridgeMethodsForInfo = (info) => [
  'circle.context',
  'circle.asset',
  'circle.deploy',
  'circle.asset_plain',
  'compute.request',
  'program.info',
  'program.view',
  'program.call',
  'program.storage',
  'sealed_slot.read',
  'sealed_slot.put',
  'sealed_state.read',
  'sealed_state.put',
  'slot_policy.read',
  'slot_policy.put',
  'state_policy.read',
  'state_policy.put',
  'state_descriptor.read',
  'state_descriptor.put',
  'balance_cell.read',
  'balance_cell.put',
  'balance_binding.read',
  'balance_workflow.read',
  'object.refs.read',
  'object.list.read',
  'object.detail.read',
  'object.member.read',
  'object.summary.read',
  'object.members.read',
  'object.policy.define',
  'object.bind',
  'object.member.attach',
  'object.member.detach',
  'object.transition.apply',
  'register_cell.read',
  'register_cell.put',
  'register_binding.read',
  'register_workflow.read',
  'transport_policy.read',
  'transport_policy.put',
  'hfhe_policy.read',
  'hfhe_policy.put',
  'key_policy.read',
  'key_policy.put',
  'key.grant',
  'key.extend',
  'key.revoke',
  'key.erase',
  'outbox.open',
  'outbox.intent',
  'outbox.claim',
  'outbox.status',
  'relay.claim',
  'relay.cancel',
  'ingress.commit',
  'ingress.packet',
  'wallet.info',
  'wallet.balance',
  'wallet.keys',
  'wallet.send',
  'fhe.load_pk',
  'fhe.encrypt',
  'fhe.decrypt',
  'fhe.commit',
  'fhe.pedersen',
  'fhe.serialize_cipher',
  'fhe.deserialize_cipher',
  'fhe.verify_zero',
  'fhe.verify_bound',
  'relay.request',
  'relay.status',
  'relay.response',
  'relay.receipt',
  'relay.ingress',
  'relay.health'
]

const bridgeGrantTextOf = (context, method) => {
  if (method === 'circle.deploy') {
    return `allow this circle to create new circles through the active wallet for this session?\n\n${context.uri}`
  }
  if (method === 'circle.asset_plain') {
    return `allow this circle to upload public assets to its current or newly created circles for this session?\n\n${context.uri}`
  }
  if (method === 'circle.asset') {
    return `allow this public circle to read its own bounded assets for this session?\n\n${context.uri}`
  }
  if (method === 'compute.request') {
    return `allow this public circle to use bounded compute through the configured RPC origin for this session?\n\n${context.uri}`
  }
  if (method === 'program.info' || method === 'program.view' || method === 'program.storage' || method === 'program.abi') {
    return `allow this circle to read onchain program state for this session?\n\n${context.uri}`
  }
  if (method === 'program.call') {
    return `allow this circle to submit onchain program calls for this session?\n\n${context.uri}`
  }
  if (method === 'sealed_slot.put' || method === 'sealed_state.put' || method === 'slot_policy.put' || method === 'state_policy.put' || method === 'state_descriptor.put' || method === 'balance_cell.put' || method === 'register_cell.put' || method === 'outbox.open' || method === 'ingress.commit') {
    return `allow this circle to submit low-level circle runtime transactions for this session?\n\n${context.uri}`
  }
  if (method === 'object.policy.define' || method === 'object.bind' || method === 'object.member.attach' || method === 'object.member.detach' || method === 'object.transition.apply') {
    return `allow this circle to submit private object runtime writes for this session?\n\n${context.uri}`
  }
  if (method === 'sealed_slot.read' || method === 'sealed_state.read' || method === 'slot_policy.read' || method === 'state_policy.read' || method === 'state_descriptor.read' || method === 'balance_cell.read' || method === 'balance_binding.read' || method === 'balance_workflow.read' || method === 'object.refs.read' || method === 'object.list.read' || method === 'object.detail.read' || method === 'object.member.read' || method === 'object.summary.read' || method === 'object.members.read' || method === 'register_cell.read' || method === 'register_binding.read' || method === 'register_workflow.read' || method === 'outbox.intent' || method === 'outbox.status' || method === 'ingress.packet') {
    return `allow this circle to read low-level circle runtime state for this session?\n\n${context.uri}`
  }
  if (method === 'transport_policy.put' || method === 'hfhe_policy.put' || method === 'key_policy.put' || method === 'key.grant' || method === 'key.extend' || method === 'key.revoke' || method === 'key.erase' || method === 'relay.claim' || method === 'relay.cancel') {
    return `allow this circle to modify low-level circle policy or relay transport state for this session?\n\n${context.uri}`
  }
  if (method === 'transport_policy.read' || method === 'hfhe_policy.read' || method === 'key_policy.read' || method === 'outbox.claim') {
    return `allow this circle to read low-level circle policy or relay state for this session?\n\n${context.uri}`
  }
  if (method === 'wallet.info') {
    return `allow this circle to read the active wallet address for this session?\n\n${context.uri}`
  }
  if (method === 'wallet.balance') {
    return `allow this circle to read wallet balances for this session?\n\n${context.uri}`
  }
  if (method === 'wallet.keys') {
    return `allow this circle to read the wallet view public key for this session?\n\n${context.uri}`
  }
  if (method === 'wallet.send') {
    return `allow this circle to send OCT through the active wallet for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.encrypt') {
    return `allow this circle to request FHE encryption for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.load_pk') {
    return `allow this circle to request PVAC public keys for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.decrypt') {
    return `allow this circle to request FHE decryption for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.commit') {
    return `allow this circle to request FHE ciphertext commitments for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.pedersen') {
    return `allow this circle to request FHE amount commitments for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.serialize_cipher') {
    return `allow this circle to request canonical FHE cipher serialization for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.deserialize_cipher') {
    return `allow this circle to request canonical FHE cipher decoding for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.verify_zero') {
    return `allow this circle to request FHE zero-proof verification for this session?\n\n${context.uri}`
  }
  if (method === 'fhe.verify_bound') {
    return `allow this circle to request FHE bound-proof verification for this session?\n\n${context.uri}`
  }
  if (method.startsWith('relay.')) {
    return `allow this circle to use the local relay membrane for this session?\n\n${context.uri}`
  }
  return `allow this circle to use runtime access method ${method} for this session?\n\n${context.uri}`
}

const bridgeGrantScopeOf = (method) => {
  if (method === 'circle.context') return 'circle.context'
  if (method === 'circle.asset') return 'circle.asset.read'
  if (method === 'circle.deploy') return 'circle.deploy'
  if (method === 'circle.asset_plain') return 'circle.asset.write'
  if (method === 'compute.request') return 'compute.read'
  if (method === 'program.call') return 'program.call'
  if (method === 'program.info' || method === 'program.view' || method === 'program.storage' || method === 'program.abi') return 'program.read'
  if (method === 'sealed_slot.put' || method === 'sealed_state.put' || method === 'slot_policy.put' || method === 'state_policy.put' || method === 'state_descriptor.put' || method === 'balance_cell.put' || method === 'register_cell.put' || method === 'outbox.open' || method === 'ingress.commit') return 'circle.write'
  if (method === 'object.policy.define' || method === 'object.bind' || method === 'object.member.attach' || method === 'object.member.detach' || method === 'object.transition.apply') return 'circle.object.write'
  if (method === 'sealed_slot.read' || method === 'sealed_state.read' || method === 'slot_policy.read' || method === 'state_policy.read' || method === 'state_descriptor.read' || method === 'balance_cell.read' || method === 'balance_binding.read' || method === 'balance_workflow.read' || method === 'object.refs.read' || method === 'object.list.read' || method === 'object.detail.read' || method === 'object.member.read' || method === 'object.summary.read' || method === 'object.members.read' || method === 'register_cell.read' || method === 'register_binding.read' || method === 'register_workflow.read' || method === 'outbox.intent' || method === 'outbox.status' || method === 'ingress.packet') return 'circle.read'
  if (method === 'transport_policy.put' || method === 'hfhe_policy.put' || method === 'key_policy.put' || method === 'key.grant' || method === 'key.extend' || method === 'key.revoke' || method === 'key.erase' || method === 'relay.claim' || method === 'relay.cancel') return 'circle.policy.write'
  if (method === 'transport_policy.read' || method === 'hfhe_policy.read' || method === 'key_policy.read' || method === 'outbox.claim') return 'circle.policy.read'
  if (method === 'wallet.send') return 'wallet.send'
  if (method === 'wallet.info') return 'wallet.info'
  if (method === 'wallet.balance') return 'wallet.balance'
  if (method === 'wallet.keys') return 'wallet.keys'
  if (method === 'fhe.load_pk') return 'fhe.load_pk'
  if (method === 'fhe.encrypt') return 'fhe.encrypt'
  if (method === 'fhe.decrypt') return 'fhe.decrypt'
  if (method === 'fhe.commit') return 'fhe.commit'
  if (method === 'fhe.pedersen') return 'fhe.pedersen'
  if (method === 'fhe.serialize_cipher') return 'fhe.serialize_cipher'
  if (method === 'fhe.deserialize_cipher') return 'fhe.deserialize_cipher'
  if (method === 'fhe.verify_zero') return 'fhe.verify_zero'
  if (method === 'fhe.verify_bound') return 'fhe.verify_bound'
  if (method.startsWith('relay.')) return 'relay.access'
  return method
}

const ensureBridgeGrant = async (method) => {
  if (!activeBridgeContext) {
    throw new Error('sealed bridge inactive')
  }
  if (method === 'circle.context') {
    return
  }
  if (method === 'circle.asset') {
    return
  }
  const grantKey = `${activeBridgeContext.circle_id}:${bridgeGrantScopeOf(method)}`
  if (bridgeGrantState.get(grantKey)) {
    return
  }
  const allowed = await circleConfirm('runtime access', bridgeGrantTextOf(activeBridgeContext, method), 'allow')
  if (!allowed) {
    throw new Error(`runtime access denied: ${method}`)
  }
  bridgeGrantState.set(grantKey, true)
}

const bridgeResultOf = async (method, payload = {}) => {
  if (!activeBridgeContext) {
    throw new Error('sealed bridge inactive')
  }
  if (!activeBridgeContext.bridge_methods.includes(method)) {
    throw new Error(`bridge method not allowed: ${method}`)
  }
  await ensureBridgeGrant(method)
  if (method === 'circle.context') {
    return activeBridgeContext
  }
  const bridgeCircleId = activeBridgeContext.circle_id || ''
  const requireBridgeCircleId = () => {
    if (!bridgeCircleId) {
      throw new Error('sealed bridge has no active circle target')
    }
    if (payload.address) {
      throw new Error('bridge target override denied')
    }
    if (payload.circle_id && payload.circle_id !== bridgeCircleId) {
      throw new Error('bridge target override denied')
    }
    return bridgeCircleId
  }
  const postWrite = async (path, circleId) => {
    const fee = String(payload.ou || payload.fee || 'wallet default')
    const pin = await circlePin(
      'confirm circle write',
      `method: ${method}\ncircle: ${circleId}\nfee: ${fee} ou`)
    if (!pin) {
      throw new Error(`${method} cancelled`)
    }
    return postJson(path, { ...payload, circle_id: circleId, pin })
  }
  if (method === 'circle.asset') {
    if (activeBridgeContext.privacy_class !== 'public') {
      throw new Error('plain asset access requires a public circle')
    }
    if (
      !payload
      || typeof payload !== 'object'
      || Array.isArray(payload)
      || Object.keys(payload).join(',') !== 'path'
    ) {
      throw new Error('circle asset request fields differ')
    }
    const path = CircleBridgePolicy.canonicalAssetPath(payload.path)
    if (!path || path === '/') {
      throw new Error('circle asset path refused')
    }
    const asset = await fetchJson(
      `/api/circle/asset?circle_id=${encodeURIComponent(bridgeCircleId)}&path=${encodeURIComponent(path)}`)
    const contentType = CircleBridgePolicy.canonicalContentType(asset?.content_type)
    if (
      !asset
      || asset.circle_id !== bridgeCircleId
      || asset.canonical_path !== path
      || !contentType
      || typeof asset.body_b64 !== 'string'
      || asset.body_b64.length > 4 * Math.ceil((1024 * 1024) / 3)
    ) {
      throw new Error('circle asset response invalid')
    }
    let bytes
    try {
      bytes = base64ToBytes(asset.body_b64)
    } catch (_) {
      throw new Error('circle asset body invalid')
    }
    if (bytes.length > 1024 * 1024) {
      throw new Error('circle asset response exceeds limit')
    }
    if (bytesToBase64(bytes) !== asset.body_b64) {
      throw new Error('circle asset body invalid')
    }
    return {
      body_b64: bytesToBase64(bytes),
      body_sha256: await sha256Hex(bytes),
      content_type: contentType,
      path,
      size_bytes: bytes.length
    }
  }
  if (method === 'circle.deploy') {
    const profile = payload.profile || 'public'
    const deployPayload = CircleBridgePolicy.deployPayload(profile)
    const pin = await circlePin('confirm circle deploy', `enter PIN to create a new ${profile} circle`)
    if (!pin) {
      throw new Error('circle deploy cancelled')
    }
    const result = await postJson('/api/circle/deploy', {
      ...deployPayload,
      ou: '200000',
      pin
    })
    if (!result || !CircleBridgePolicy.validCircleId(result.circle_id)) {
      throw new Error('circle deploy returned invalid id')
    }
    createdCircleIdsForBridge().add(result.circle_id)
    return { ...result, profile }
  }
  if (method === 'circle.asset_plain') {
    const prepared = CircleBridgePolicy.preparePlainAsset(
      bridgeCircleId,
      createdCircleIdsForBridge(),
      payload,
      circleAssetMaxB64Bytes)
    const plan = await CircleAssetChunks.plan(prepared, {
      decode: base64ToBytes,
      encode: bytesToBase64,
      utf8: utf8Bytes,
      sha256: sha256Hex
    })
    const pin = await circlePin(
      'confirm circle asset',
      `enter PIN to upload ${prepared.path} | ${plan.raw_bytes} bytes | ${prepared.circle_id}`)
    if (!pin) {
      throw new Error('circle asset upload cancelled')
    }
    if (plan.direct) {
      return postJson('/api/circle/asset_plain', { ...plan.asset, pin })
    }
    const uploaded = []
    for (const chunk of plan.chunks) {
      const result = await postJson('/api/circle/asset_plain', {
        circle_id: prepared.circle_id,
        path: chunk.path,
        content_type: chunk.content_type,
        body_b64: bytesToBase64(plan.raw.subarray(chunk.offset, chunk.offset + chunk.size_bytes)),
        encoding: chunk.encoding,
        pin
      })
      uploaded.push(result.tx_hash)
    }
    const result = await postJson('/api/circle/asset_plain', { ...plan.asset, pin })
    return {
      ...result,
      chunked: true,
      chunks: plan.chunks.length,
      chunk_tx_hashes: uploaded
    }
  }
  if (method === 'compute.request') {
    if (activeBridgeContext.privacy_class !== 'public') {
      throw new Error('compute access requires a public circle')
    }
    const wallet = await fetchJson('/api/wallet')
    const prepared = CircleBridgePolicy.prepareComputeRequest(
      wallet.rpc_url,
      payload,
      64 * 1024)
    const localRequest = {
      method: prepared.method,
      path: new URL(prepared.url).pathname
    }
    if (prepared.body !== null) {
      localRequest.body = prepared.body
    }
    return postJson('/api/circle/compute', localRequest)
  }
  if (method === 'program.info') {
    const effectiveCircleId = requireBridgeCircleId()
    if (authBridgeRoot) {
      return fetchJson(`${authBridgeRoot}/api/program/info`)
    }
    return fetchJson(`/api/program/info?circle_id=${encodeURIComponent(effectiveCircleId)}`)
  }
  if (method === 'program.view') {
    const effectiveCircleId = requireBridgeCircleId()
    const nextPayload = { ...payload, circle_id: effectiveCircleId }
    if (authBridgeRoot) {
      return postJson(`${authBridgeRoot}/api/program/view`, nextPayload)
    }
    return postJson('/api/program/view', nextPayload)
  }
  if (method === 'program.call') {
    const effectiveCircleId = requireBridgeCircleId()
    const pin = await circlePin('confirm program call', 'enter PIN to sign this circle program call')
    if (!pin) {
      throw new Error('program call cancelled')
    }
    const nextPayload = { ...payload, circle_id: effectiveCircleId, pin }
    return postJson('/api/program/call', nextPayload)
  }
  if (method === 'program.storage') {
    if (!payload.key) {
      throw new Error('program.storage requires key')
    }
    const effectiveCircleId = requireBridgeCircleId()
    return fetchJson(`/api/program/storage?circle_id=${encodeURIComponent(effectiveCircleId)}&key=${encodeURIComponent(payload.key)}`)
  }
  if (method === 'program.abi') {
    throw new Error('program.abi disabled in native sealed mode')
  }
  if (method === 'sealed_slot.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.slot_ref) {
      throw new Error('sealed_slot.read requires slot_ref')
    }
    return fetchJson(`/api/circle/asset_ciphertext_by_slot?circle_id=${encodeURIComponent(effectiveCircleId)}&slot_ref=${encodeURIComponent(payload.slot_ref)}`)
  }
  if (method === 'sealed_slot.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/sealed_slot_put', effectiveCircleId)
  }
  if (method === 'sealed_state.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.state_ref) {
      throw new Error('sealed_state.read requires state_ref')
    }
    return fetchJson(`/api/circle/asset_ciphertext_by_state?circle_id=${encodeURIComponent(effectiveCircleId)}&state_ref=${encodeURIComponent(payload.state_ref)}`)
  }
  if (method === 'sealed_state.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/sealed_slot_put', effectiveCircleId)
  }
  if (method === 'slot_policy.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.slot_ref) {
      throw new Error('slot_policy.read requires circle_id and slot_ref')
    }
    return fetchJson(`/api/circle/slot_policy?circle_id=${encodeURIComponent(effectiveCircleId)}&slot_ref=${encodeURIComponent(payload.slot_ref)}`)
  }
  if (method === 'slot_policy.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/slot_policy_put', effectiveCircleId)
  }
  if (method === 'state_policy.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.state_ref) {
      throw new Error('state_policy.read requires state_ref')
    }
    return fetchJson(`/api/circle/state_policy?circle_id=${encodeURIComponent(effectiveCircleId)}&state_ref=${encodeURIComponent(payload.state_ref)}`)
  }
  if (method === 'state_policy.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/slot_policy_put', effectiveCircleId)
  }
  if (method === 'state_descriptor.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.state_ref) {
      throw new Error('state_descriptor.read requires state_ref')
    }
    return fetchJson(`/api/circle/state_descriptor?circle_id=${encodeURIComponent(effectiveCircleId)}&state_ref=${encodeURIComponent(payload.state_ref)}`)
  }
  if (method === 'state_descriptor.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/state_descriptor_put', effectiveCircleId)
  }
  if (method === 'balance_cell.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.state_ref) {
      throw new Error('balance_cell.read requires state_ref')
    }
    return fetchJson(`/api/circle/balance_cell?circle_id=${encodeURIComponent(effectiveCircleId)}&state_ref=${encodeURIComponent(payload.state_ref)}`)
  }
  if (method === 'balance_binding.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.subject_addr) {
      throw new Error('balance_binding.read requires subject_addr')
    }
    return fetchJson(`/api/circle/balance_binding?circle_id=${encodeURIComponent(effectiveCircleId)}&subject_addr=${encodeURIComponent(payload.subject_addr)}`)
  }
  if (method === 'balance_workflow.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.workflow_ref) {
      throw new Error('balance_workflow.read requires workflow_ref')
    }
    return fetchJson(`/api/circle/balance_workflow?circle_id=${encodeURIComponent(effectiveCircleId)}&workflow_ref=${encodeURIComponent(payload.workflow_ref)}`)
  }
  if (method === 'object.refs.read') {
    const effectiveCircleId = requireBridgeCircleId()
    return fetchJson(`/api/circle/object_refs?circle_id=${encodeURIComponent(effectiveCircleId)}`)
  }
  if (method === 'object.list.read') {
    const effectiveCircleId = requireBridgeCircleId()
    return fetchJson(`/api/circle/object_list?circle_id=${encodeURIComponent(effectiveCircleId)}`)
  }
  if (method === 'object.detail.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.object_ref) {
      throw new Error('object.detail.read requires object_ref')
    }
    return fetchJson(`/api/circle/object_detail?circle_id=${encodeURIComponent(effectiveCircleId)}&object_ref=${encodeURIComponent(payload.object_ref)}`)
  }
  if (method === 'object.member.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.object_ref || !payload.member_ref) {
      throw new Error('object.member.read requires object_ref and member_ref')
    }
    return fetchJson(`/api/circle/object_member?circle_id=${encodeURIComponent(effectiveCircleId)}&object_ref=${encodeURIComponent(payload.object_ref)}&member_ref=${encodeURIComponent(payload.member_ref)}`)
  }
  if (method === 'object.summary.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.object_ref) {
      throw new Error('object.summary.read requires object_ref')
    }
    return fetchJson(`/api/circle/object_summary?circle_id=${encodeURIComponent(effectiveCircleId)}&object_ref=${encodeURIComponent(payload.object_ref)}`)
  }
  if (method === 'object.members.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.object_ref) {
      throw new Error('object.members.read requires object_ref')
    }
    return fetchJson(`/api/circle/object_members?circle_id=${encodeURIComponent(effectiveCircleId)}&object_ref=${encodeURIComponent(payload.object_ref)}`)
  }
  if (method === 'object.policy.define') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/object_policy_define', effectiveCircleId)
  }
  if (method === 'object.bind') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/object_bind', effectiveCircleId)
  }
  if (method === 'object.member.attach') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/object_member_attach', effectiveCircleId)
  }
  if (method === 'object.member.detach') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/object_member_detach', effectiveCircleId)
  }
  if (method === 'object.transition.apply') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/object_transition_apply', effectiveCircleId)
  }
  if (method === 'balance_cell.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/balance_cell_put', effectiveCircleId)
  }
  if (method === 'register_cell.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.state_ref) {
      throw new Error('register_cell.read requires state_ref')
    }
    return fetchJson(`/api/circle/register_cell?circle_id=${encodeURIComponent(effectiveCircleId)}&state_ref=${encodeURIComponent(payload.state_ref)}`)
  }
  if (method === 'register_binding.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.register_ref) {
      throw new Error('register_binding.read requires register_ref')
    }
    return fetchJson(`/api/circle/register_binding?circle_id=${encodeURIComponent(effectiveCircleId)}&register_ref=${encodeURIComponent(payload.register_ref)}`)
  }
  if (method === 'register_workflow.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.workflow_ref) {
      throw new Error('register_workflow.read requires workflow_ref')
    }
    return fetchJson(`/api/circle/register_workflow?circle_id=${encodeURIComponent(effectiveCircleId)}&workflow_ref=${encodeURIComponent(payload.workflow_ref)}`)
  }
  if (method === 'register_cell.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/register_cell_put', effectiveCircleId)
  }
  if (method === 'transport_policy.read') {
    const effectiveCircleId = requireBridgeCircleId()
    return fetchJson(`/api/circle/transport_policy?circle_id=${encodeURIComponent(effectiveCircleId)}`)
  }
  if (method === 'transport_policy.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/transport_policy_put', effectiveCircleId)
  }
  if (method === 'hfhe_policy.read') {
    const effectiveCircleId = requireBridgeCircleId()
    return fetchJson(`/api/circle/hfhe_policy?circle_id=${encodeURIComponent(effectiveCircleId)}`)
  }
  if (method === 'hfhe_policy.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/hfhe_policy_put', effectiveCircleId)
  }
  if (method === 'key_policy.read') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.key_id) {
      throw new Error('key_policy.read requires key_id')
    }
    return fetchJson(`/api/circle/key_policy?circle_id=${encodeURIComponent(effectiveCircleId)}&key_id=${encodeURIComponent(payload.key_id)}`)
  }
  if (method === 'key_policy.put') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/key_policy_put', effectiveCircleId)
  }
  if (method === 'key.grant') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/key_grant', effectiveCircleId)
  }
  if (method === 'key.extend') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/key_extend', effectiveCircleId)
  }
  if (method === 'key.revoke') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/key_revoke', effectiveCircleId)
  }
  if (method === 'key.erase') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/key_erase', effectiveCircleId)
  }
  if (method === 'outbox.open') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/outbox_open', effectiveCircleId)
  }
  if (method === 'outbox.intent') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.intent_id) {
      throw new Error('outbox.intent requires circle_id and intent_id')
    }
    return fetchJson(`/api/circle/outbox_intent?circle_id=${encodeURIComponent(effectiveCircleId)}&intent_id=${encodeURIComponent(payload.intent_id)}`)
  }
  if (method === 'outbox.claim') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.intent_id) {
      throw new Error('outbox.claim requires circle_id and intent_id')
    }
    return fetchJson(`/api/circle/outbox_claim?circle_id=${encodeURIComponent(effectiveCircleId)}&intent_id=${encodeURIComponent(payload.intent_id)}`)
  }
  if (method === 'outbox.status') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.intent_id) {
      throw new Error('outbox.status requires circle_id and intent_id')
    }
    return fetchJson(`/api/circle/outbox_status?circle_id=${encodeURIComponent(effectiveCircleId)}&intent_id=${encodeURIComponent(payload.intent_id)}`)
  }
  if (method === 'relay.claim') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/relay_claim', effectiveCircleId)
  }
  if (method === 'relay.cancel') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/relay_cancel', effectiveCircleId)
  }
  if (method === 'ingress.commit') {
    const effectiveCircleId = requireBridgeCircleId()
    return postWrite('/api/circle/ingress_commit', effectiveCircleId)
  }
  if (method === 'ingress.packet') {
    const effectiveCircleId = requireBridgeCircleId()
    if (!payload.intent_id) {
      throw new Error('ingress.packet requires circle_id and intent_id')
    }
    return fetchJson(`/api/circle/ingress_packet?circle_id=${encodeURIComponent(effectiveCircleId)}&intent_id=${encodeURIComponent(payload.intent_id)}`)
  }
  if (method === 'wallet.info') {
    return fetchJson('/api/wallet')
  }
  if (method === 'wallet.balance') {
    return fetchJson('/api/balance')
  }
  if (method === 'wallet.keys') {
    return fetchJson('/api/keys')
  }
  if (method === 'wallet.send') {
    const to = String(payload.to || '')
    const amount = String(payload.amount || '')
    const fee = String(payload.ou || payload.fee || 'wallet default')
    const pin = await circlePin(
      'confirm wallet transfer',
      `to: ${to}\namount: ${amount} oct\nfee: ${fee} ou`)
    if (!pin) {
      throw new Error('wallet.send cancelled')
    }
    return postJson('/api/send', { ...payload, pin })
  }
  if (method === 'fhe.load_pk') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/load_pk', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.encrypt') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/encrypt', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.decrypt') {
    const effectiveCircleId = requireBridgeCircleId()
    const pin = await circlePin('confirm FHE decrypt', 'enter PIN to decrypt this circle ciphertext')
    if (!pin) {
      throw new Error('FHE decrypt cancelled')
    }
    return postJson('/api/circle/fhe/decrypt', { ...payload, circle_id: effectiveCircleId, pin })
  }
  if (method === 'fhe.commit') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/commit', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.pedersen') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/pedersen', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.serialize_cipher') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/serialize_cipher', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.deserialize_cipher') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/deserialize_cipher', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.verify_zero') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/verify_zero', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'fhe.verify_bound') {
    const effectiveCircleId = requireBridgeCircleId()
    return postJson('/api/circle/fhe/verify_bound', { ...payload, circle_id: effectiveCircleId })
  }
  if (method === 'relay.request') {
    return postJson('/api/relay/request', payload)
  }
  if (method === 'relay.status') {
    const suffix = payload.request_id ? `?request_id=${encodeURIComponent(payload.request_id)}` : ''
    return fetchJson(`/api/relay/status${suffix}`)
  }
  if (method === 'relay.response') {
    if (!payload.request_id) {
      throw new Error('relay.response requires request_id')
    }
    return fetchJson(`/api/relay/response?request_id=${encodeURIComponent(payload.request_id)}`)
  }
  if (method === 'relay.receipt') {
    if (!payload.request_id) {
      throw new Error('relay.receipt requires request_id')
    }
    return fetchJson(`/api/relay/receipt?request_id=${encodeURIComponent(payload.request_id)}`)
  }
  if (method === 'relay.ingress') {
    if (!payload.request_id) {
      throw new Error('relay.ingress requires request_id')
    }
    return fetchJson(`/api/relay/ingress?request_id=${encodeURIComponent(payload.request_id)}`)
  }
  if (method === 'relay.health') {
    return fetchJson('/api/relay/health')
  }
  throw new Error(`unsupported bridge method: ${method}`)
}

window.addEventListener('message', async (event) => {
  if (!activeBridgeWindow || event.source !== activeBridgeWindow) {
    return
  }
  const data = event.data
  if (!data || typeof data !== 'object') {
    return
  }
  if (!activeBridgeContext || data.token !== activeBridgeContext.bridge_token) {
    return
  }
  if (data.type === 'octra.circle.navigate') {
    const target = parseCircleTarget(data.uri || '', '/index.html')
    if (!target.circleId) {
      return
    }
    $('circle-id').value = target.uri
    await loadCircle()
    return
  }
  if (data.type !== 'octra.circle.bridge.request' || !data.id || !data.method) {
    return
  }
  try {
    const result = await bridgeResultOf(data.method, data.payload || {})
    postBridgeReply(event.source, data.token, data.id, true, result, '')
  } catch (err) {
    postBridgeReply(event.source, data.token, data.id, false, null, err.message || 'bridge request failed')
  }
})

const padTargetBytes = (paddingClass) => {
  if (paddingClass === '4k') return 4096
  if (paddingClass === '16k') return 16384
  if (paddingClass === '32k') return 32768
  if (paddingClass === '128k') return 131072
  return 0
}

const circleAssetMaxRawBytes = 33554432
const circleAssetMaxB64Bytes = Math.ceil(circleAssetMaxRawBytes / 3) * 4
const base64EncodedLength = byteLength => Math.ceil(byteLength / 3) * 4

const paddedFrame = (plaintextBytes, paddingClass) => {
  const bare = mergeBytes(u32be(plaintextBytes.length), plaintextBytes)
  const target = padTargetBytes(paddingClass)
  if (!target) return bare
  const aligned = Math.ceil(bare.length / target) * target
  if (aligned <= bare.length) return bare
  return mergeBytes(bare, randomBytes(aligned - bare.length))
}

const circleAssetDecodedSizeUpperBound = wireLen => Math.ceil(wireLen / 4) * 3

const circleAssetFeeOfB64Length = wireLen => {
  const rawUpperBound = circleAssetDecodedSizeUpperBound(wireLen)
  if (rawUpperBound <= 4096) return 5000
  if (rawUpperBound <= 16384) return 10000
  if (rawUpperBound <= 32768) return 20000
  if (rawUpperBound <= 131072) return 40000
  if (rawUpperBound <= 524288) return 80000
  if (rawUpperBound <= 2097152) return 160000
  if (rawUpperBound <= 8388608) return 320000
  return 640000
}

const circleAssetFeeOfCiphertextB64 = ciphertextB64 => circleAssetFeeOfB64Length(ciphertextB64.length)

const deriveReadKey = async (circleId, keyId, passphrase) => {
  const cacheKey = `${circleId}:${keyId}:${passphrase}`
  if (!keyCache.has(cacheKey)) {
    keyCache.set(cacheKey, (async () => {
      const material = await crypto.subtle.importKey('raw', utf8Bytes(passphrase), 'PBKDF2', false, ['deriveKey'])
      const salt = utf8Bytes(`octra:circle:sealed_read:v1:${circleId}:${keyId}`)
      return crypto.subtle.deriveKey(
        {name: 'PBKDF2', salt, iterations: 120000, hash: 'SHA-256'},
        material,
        {name: 'AES-GCM', length: 256},
        false,
        ['encrypt', 'decrypt']
      )
    })())
  }
  return keyCache.get(cacheKey)
}

const encryptSealedBytes = async (circleId, keyId, passphrase, plaintextBytes, paddingClass) => {
  const key = await deriveReadKey(circleId, keyId, passphrase)
  const nonce = randomBytes(12)
  const frame = paddedFrame(plaintextBytes, paddingClass)
  const cipherBuffer = await crypto.subtle.encrypt({name: 'AES-GCM', iv: nonce}, key, frame)
  const envelope = mergeBytes(sealedMagic, nonce, new Uint8Array(cipherBuffer))
  return {
    ciphertext_b64: bytesToBase64(envelope),
    plaintext_hash: await sha256Hex(plaintextBytes)
  }
}

const decryptSealedBytes = async (circleId, asset, passphrase) => {
  if (!asset.key_id || !asset.plaintext_hash) {
    throw new Error('sealed asset metadata incomplete')
  }
  const envelope = base64ToBytes(asset.ciphertext_b64)
  const magicText = bytesToText(envelope.subarray(0, sealedMagic.length))
  if (magicText !== 'OCRS1') {
    throw new Error('invalid sealed envelope')
  }
  const nonce = envelope.subarray(sealedMagic.length, sealedMagic.length + 12)
  const cipher = envelope.subarray(sealedMagic.length + 12)
  const key = await deriveReadKey(circleId, asset.key_id, passphrase)
  const plainFrame = new Uint8Array(await crypto.subtle.decrypt({name: 'AES-GCM', iv: nonce}, key, cipher))
  if (plainFrame.length < 4) {
    throw new Error('invalid sealed payload')
  }
  const plainSize = readU32be(plainFrame.subarray(0, 4))
  if (plainSize > plainFrame.length - 4) {
    throw new Error('invalid sealed payload length')
  }
  const plaintext = plainFrame.subarray(4, 4 + plainSize)
  const actualHash = await sha256Hex(plaintext)
  if (actualHash !== asset.plaintext_hash) {
    throw new Error('plaintext hash mismatch')
  }
  return plaintext
}

const resolveCirclePath = (basePath, spec) => {
  if (!spec || spec.startsWith('#') || isDataSpec(spec) || isBlockedRemoteSpec(spec)) return spec
  const base = `https://circle.local${normalizeAssetPath(basePath)}`
  return new URL(spec, base).pathname
}

const makeDataUrl = (contentType, bytes) => `data:${contentType};base64,${bytesToBase64(bytes)}`

const loadPlainAsset = async (circleId, path) => fetchJson(`/api/circle/asset?circle_id=${encodeURIComponent(circleId)}&path=${encodeURIComponent(normalizeAssetPath(path))}`)

const loadPublicMaterializedAsset = async (circleId, path) => {
  const normalizedPath = normalizeAssetPath(path)
  const asset = await loadPlainAsset(circleId, normalizedPath)
  const contentType = CircleBridgePolicy.canonicalContentType(asset?.content_type)
  const maxBytes = 1024 * 1024
  if (
    !asset
    || asset.circle_id !== circleId
    || asset.canonical_path !== normalizedPath
    || !contentType
    || typeof asset.body_b64 !== 'string'
    || asset.body_b64.length > 4 * Math.ceil(maxBytes / 3)
  ) {
    throw new Error(`circle subresource response invalid: ${normalizedPath}`)
  }
  let bytes
  try {
    bytes = base64ToBytes(asset.body_b64)
  } catch (_) {
    throw new Error(`circle subresource body invalid: ${normalizedPath}`)
  }
  if (bytes.length > maxBytes || bytesToBase64(bytes) !== asset.body_b64) {
    throw new Error(`circle subresource body invalid: ${normalizedPath}`)
  }
  return {
    ...asset,
    content_type: contentType,
    bytes,
    text: isTextContent(contentType) ? bytesToText(bytes) : ''
  }
}

const loadSealedAsset = async (circleId, path, passphrase, versionToken = '') => {
  const normalizedPath = normalizeAssetPath(path)
  const cacheKey = `${circleId}:${versionToken}:${normalizedPath}:${passphrase}`
  if (!decryptedCache.has(cacheKey)) {
    decryptedCache.set(cacheKey, (async () => {
      const resourceKey = await resourceKeyOfPath(circleId, normalizedPath)
      const asset = await fetchJson(`/api/circle/asset_ciphertext_by_key?circle_id=${encodeURIComponent(circleId)}&resource_key=${encodeURIComponent(resourceKey)}`)
      const bytes = await decryptSealedBytes(circleId, asset, passphrase)
      return {
        ...asset,
        canonical_path: asset.canonical_path || normalizedPath,
        bytes,
        text: isTextContent(asset.content_type) ? bytesToText(bytes) : ''
      }
    })())
  }
  return decryptedCache.get(cacheKey)
}

const ensureDocumentHead = (doc) => {
  if (doc.head) return doc.head
  const head = doc.createElement('head')
  doc.documentElement.insertBefore(head, doc.body || null)
  return head
}

const prependHeadMeta = (doc, name, value, attrName) => {
  const head = ensureDocumentHead(doc)
  const meta = doc.createElement('meta')
  meta.setAttribute(attrName, name)
  meta.setAttribute('content', value)
  head.prepend(meta)
}

const materializeCssWithLoader = async (circleId, cssPath, cssText, loadAsset, seen = new Set()) => {
  const cssKey = `${circleId}:${cssPath}`
  if (seen.has(cssKey)) return ''
  const nextSeen = new Set(seen)
  nextSeen.add(cssKey)
  let result = cssText
  const importRegex = /@import\s+(?:url\(\s*)?["']?([^"')\s]+)["']?\s*\)?\s*;/gi
  let importMatch
  while ((importMatch = importRegex.exec(result)) !== null) {
    const source = importMatch[1].trim()
    const replacement = isDataSpec(source) || isBlockedRemoteSpec(source)
      ? ''
      : await (async () => {
          const resolved = resolveCirclePath(cssPath, source)
          if (!resolved || isDataSpec(resolved) || isBlockedRemoteSpec(resolved)) return ''
          const imported = await loadAsset(resolved)
          if (!isStylesheetContentType(imported.content_type)) {
            throw new Error(`circle stylesheet content type refused: ${resolved}`)
          }
          return await materializeCssWithLoader(circleId, resolved, imported.text, loadAsset, nextSeen)
        })()
    result = `${result.slice(0, importMatch.index)}${replacement}${result.slice(importMatch.index + importMatch[0].length)}`
    importRegex.lastIndex = 0
  }
  const urlRegex = /url\(\s*(['"]?)([^"')]+)\1\s*\)/gi
  let urlMatch
  while ((urlMatch = urlRegex.exec(result)) !== null) {
    const source = urlMatch[2].trim()
    let replacement = urlMatch[0]
    if (isBlockedRemoteSpec(source)) {
      replacement = 'url("data:,")'
    } else if (!isDataSpec(source)) {
      const resolved = resolveCirclePath(cssPath, source)
      if (!resolved || isBlockedRemoteSpec(resolved)) {
        replacement = 'url("data:,")'
      } else {
        const asset = await loadAsset(resolved)
        replacement = `url("${makeDataUrl(asset.content_type, asset.bytes)}")`
      }
    }
    result = `${result.slice(0, urlMatch.index)}${replacement}${result.slice(urlMatch.index + urlMatch[0].length)}`
    urlRegex.lastIndex = urlMatch.index + replacement.length
  }
  return result
}

const materializeCss = async (circleId, cssPath, cssText, passphrase, versionToken = '', seen = new Set()) => (
  materializeCssWithLoader(
    circleId,
    cssPath,
    cssText,
    (path) => loadSealedAsset(circleId, path, passphrase, versionToken),
    seen)
)

const removeDocumentCsp = (doc) => {
  doc.querySelectorAll('meta[http-equiv]').forEach((node) => {
    const directive = (node.getAttribute('http-equiv') || '').trim().toLowerCase()
    if (directive === 'content-security-policy') {
      node.remove()
    }
  })
}

const injectSealedPolicy = (doc) => {
  removeDocumentCsp(doc)
  doc.querySelectorAll('base').forEach((node) => node.remove())
  prependHeadMeta(
    doc,
    'Content-Security-Policy',
    "default-src 'none'; script-src data:; style-src 'unsafe-inline'; img-src data:; font-src data:; media-src data:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; manifest-src 'none'",
    'http-equiv'
  )
  prependHeadMeta(doc, 'referrer', 'no-referrer', 'name')
}

const injectPublicPolicy = (doc) => {
  removeDocumentCsp(doc)
  doc.querySelectorAll('base').forEach((node) => node.remove())
  prependHeadMeta(
    doc,
    'Content-Security-Policy',
    "default-src 'none'; script-src data:; style-src 'unsafe-inline'; img-src data:; font-src data:; media-src data:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; manifest-src 'none'",
    'http-equiv'
  )
  prependHeadMeta(doc, 'referrer', 'no-referrer', 'name')
}

const sealedPreludeSource = (circleId, htmlPath, bridgeToken) => {
  const contextJson = JSON.stringify({
    circle_id: circleId,
    path: normalizeAssetPath(htmlPath),
    uri: circleUriOf(circleId, htmlPath)
  })
  const tokenJson = JSON.stringify(bridgeToken)
  return `(function () {
  const context = ${contextJson};
  const bridgeToken = ${tokenJson};
  const waiters = new Map();
  let nextRequestId = 0;
  const safe = function (fn) {
    try {
      return fn();
    } catch (_) {
      return undefined;
    }
  };
  const deny = function (name) {
    throw new Error(name + ' disabled in native sealed mode');
  };
  const blockedStorage = function (name) {
    return Object.freeze({
      getItem: function () { deny(name); },
      setItem: function () { deny(name); },
      removeItem: function () { deny(name); },
      clear: function () { deny(name); },
      key: function () { return null; },
      get length() { return 0; }
    });
  };
  const allowSpec = function (value) {
    const spec = String(value || '').trim().toLowerCase();
    return spec === '' || spec[0] === '#' || spec.startsWith('data:') || spec.startsWith('blob:') || spec.startsWith('about:blank') || spec.startsWith('oct://');
  };
  const guardSpec = function (name, value) {
    if (!allowSpec(value)) {
      throw new Error(name + ' blocked in native sealed mode');
    }
    return value;
  };
  const redefine = function (target, key, getter) {
    try {
      Object.defineProperty(target, key, {
        configurable: true,
        get: getter
      });
    } catch (_) {}
  };
  const blockProperty = function (target, key) {
    redefine(target, key, function () {
      deny(key);
    });
  };
  window.OctraCircle = Object.freeze({
    context: Object.freeze(context),
    request: function (method, payload) {
      return new Promise(function (resolve, reject) {
        const id = 'req_' + String(++nextRequestId);
        waiters.set(id, { resolve: resolve, reject: reject });
        parent.postMessage({
          type: 'octra.circle.bridge.request',
          token: bridgeToken,
          id: id,
          method: method,
          payload: payload || {}
        }, '*');
      });
    },
    navigate: function (uri) {
      parent.postMessage({
        type: 'octra.circle.navigate',
        token: bridgeToken,
        uri: uri
      }, '*');
    }
  });
  window.addEventListener('message', function (event) {
    const data = event.data;
    if (!data || data.token !== bridgeToken || data.type !== 'octra.circle.bridge.reply' || !data.id || !waiters.has(data.id)) {
      return;
    }
    const waiter = waiters.get(data.id);
    waiters.delete(data.id);
    if (data.ok) {
      waiter.resolve(data.result);
      return;
    }
    waiter.reject(new Error(data.error || 'bridge request failed'));
  });
  const wrapUrlProperty = function (target, key) {
    if (!target) {
      return;
    }
    try {
      const desc = Object.getOwnPropertyDescriptor(target, key);
      if (!desc || !desc.configurable || !desc.set) {
        return;
      }
      Object.defineProperty(target, key, {
        configurable: true,
        enumerable: desc.enumerable,
        get: desc.get ? function () { return desc.get.call(this); } : function () { return ''; },
        set: function (value) {
          desc.set.call(this, guardSpec(key, value));
        }
      });
    } catch (_) {}
  };
  safe(function () {
    const rawSetAttribute = Element.prototype.setAttribute;
    Element.prototype.setAttribute = function (name, value) {
      const lower = String(name || '').toLowerCase();
      if (lower === 'src' || lower === 'href' || lower === 'poster' || lower === 'action') {
        guardSpec(lower, value);
      }
      return rawSetAttribute.call(this, name, value);
    };
  });
  safe(function () { redefine(navigator, 'userAgent', function () { return 'OctraCircle/1'; }); });
  safe(function () { redefine(navigator, 'platform', function () { return 'Octra'; }); });
  safe(function () { redefine(navigator, 'language', function () { return 'en-US'; }); });
  safe(function () { redefine(navigator, 'languages', function () { return Object.freeze(['en-US']); }); });
  safe(function () { redefine(navigator, 'hardwareConcurrency', function () { return 4; }); });
  safe(function () { redefine(navigator, 'deviceMemory', function () { return 4; }); });
  safe(function () { redefine(window, 'devicePixelRatio', function () { return 1; }); });
  safe(function () {
    navigator.sendBeacon = function () { return false; };
  });
  safe(function () {
    if (window.Intl && window.Intl.DateTimeFormat && window.Intl.DateTimeFormat.prototype) {
      const rawResolvedOptions = window.Intl.DateTimeFormat.prototype.resolvedOptions;
      window.Intl.DateTimeFormat.prototype.resolvedOptions = function () {
        const out = rawResolvedOptions ? rawResolvedOptions.call(this) : {};
        out.locale = 'en-US';
        out.timeZone = 'UTC';
        return out;
      };
    }
  });
  safe(function () {
    if (window.Date && window.Date.prototype) {
      window.Date.prototype.getTimezoneOffset = function () {
        return 0;
      };
    }
  });
  window.fetch = function () { deny('fetch'); };
  window.XMLHttpRequest = function () { deny('XMLHttpRequest'); };
  window.WebSocket = function () { deny('WebSocket'); };
  window.EventSource = function () { deny('EventSource'); };
  window.Worker = function () { deny('Worker'); };
  window.SharedWorker = function () { deny('SharedWorker'); };
  window.BroadcastChannel = function () { deny('BroadcastChannel'); };
  window.open = function () { return null; };
  blockProperty(window, 'localStorage');
  blockProperty(window, 'sessionStorage');
  blockProperty(window, 'indexedDB');
  blockProperty(window, 'caches');
  safe(function () {
    if (navigator.serviceWorker) {
      blockProperty(navigator, 'serviceWorker');
    }
  });
  safe(function () {
    if (window.Document && window.Document.prototype) {
      Object.defineProperty(window.Document.prototype, 'cookie', {
        configurable: true,
        get: function () { return ''; },
        set: function () { return ''; }
      });
    }
  });
  safe(function () { if (window.HTMLImageElement) wrapUrlProperty(window.HTMLImageElement.prototype, 'src'); });
  safe(function () { if (window.HTMLScriptElement) wrapUrlProperty(window.HTMLScriptElement.prototype, 'src'); });
  safe(function () { if (window.HTMLLinkElement) wrapUrlProperty(window.HTMLLinkElement.prototype, 'href'); });
  safe(function () { if (window.HTMLIFrameElement) wrapUrlProperty(window.HTMLIFrameElement.prototype, 'src'); });
  safe(function () { if (window.HTMLSourceElement) wrapUrlProperty(window.HTMLSourceElement.prototype, 'src'); });
  safe(function () {
    if (window.HTMLMediaElement) {
      wrapUrlProperty(window.HTMLMediaElement.prototype, 'src');
      wrapUrlProperty(window.HTMLMediaElement.prototype, 'poster');
    }
  });
  safe(function () { if (window.HTMLAnchorElement) wrapUrlProperty(window.HTMLAnchorElement.prototype, 'href'); });
  safe(function () { if (window.HTMLFormElement) wrapUrlProperty(window.HTMLFormElement.prototype, 'action'); });
  safe(function () {
    if (window.HTMLCanvasElement && window.HTMLCanvasElement.prototype) {
      if (window.HTMLCanvasElement.prototype.toDataURL) {
        window.HTMLCanvasElement.prototype.toDataURL = function () { deny('canvas.toDataURL'); };
      }
      if (window.HTMLCanvasElement.prototype.toBlob) {
        window.HTMLCanvasElement.prototype.toBlob = function () { deny('canvas.toBlob'); };
      }
    }
  });
  safe(function () {
    if (window.CanvasRenderingContext2D && window.CanvasRenderingContext2D.prototype && window.CanvasRenderingContext2D.prototype.getImageData) {
      window.CanvasRenderingContext2D.prototype.getImageData = function () { deny('canvas.getImageData'); };
    }
  });
  document.addEventListener('click', function (event) {
    const anchor = event.target && event.target.closest ? event.target.closest('a[href]') : null;
    if (!anchor) {
      return;
    }
    const href = anchor.getAttribute('href') || '';
    if (href.startsWith('oct://')) {
      event.preventDefault();
      window.OctraCircle.navigate(href);
      return;
    }
    if (!allowSpec(href)) {
      event.preventDefault();
    }
  }, true);
  window.addEventListener('submit', function (event) {
    event.preventDefault();
  }, true);
})();`
}

const installSealedPrelude = (doc, circleId, htmlPath, bridgeToken) => {
  const head = ensureDocumentHead(doc)
  const script = doc.createElement('script')
  script.textContent = sealedPreludeSource(circleId, htmlPath, bridgeToken)
  head.prepend(script)
}

const loadPublicPreludeSource = async () => {
  if (!publicPreludeSourcePromise) {
    publicPreludeSourcePromise = (async () => {
      const response = await fetch(`${runtimeBase}/circle_public_prelude.js?v=1`, {
        cache: 'no-store',
        credentials: 'same-origin',
        redirect: 'error'
      })
      const contentType = (response.headers.get('content-type') || '').split(';')[0].trim().toLowerCase()
      if (!response.ok || ![
        'application/javascript',
        'text/javascript',
        'application/ecmascript',
        'text/ecmascript'
      ].includes(contentType)) {
        throw new Error('circle prelude response invalid')
      }
      const source = await response.text()
      if (!source || source.length > 128 * 1024) {
        throw new Error('circle prelude response invalid')
      }
      return source
    })()
  }
  try {
    return await publicPreludeSourcePromise
  } catch (error) {
    publicPreludeSourcePromise = null
    throw error
  }
}

const installPublicPrelude = async (doc, circleId, htmlPath, bridgeToken) => {
  const head = ensureDocumentHead(doc)
  doc.querySelectorAll('#octra-circle-public-prelude').forEach((node) => node.remove())
  const script = doc.createElement('script')
  script.id = 'octra-circle-public-prelude'
  script.textContent = await loadPublicPreludeSource()
  script.dataset.octraContext = JSON.stringify({
    circle_id: circleId,
    path: normalizeAssetPath(htmlPath),
    uri: circleUriOf(circleId, htmlPath)
  })
  script.dataset.octraBridgeToken = bridgeToken
  script.referrerPolicy = 'no-referrer'
  head.prepend(script)
}

const executableFrameScript = (node) => {
  const type = (node.getAttribute('type') || '').trim().toLowerCase()
  return [
    '',
    'module',
    'application/javascript',
    'text/javascript',
    'application/ecmascript',
    'text/ecmascript',
    'application/x-javascript'
  ].includes(type)
}

const encodeFrameScripts = (doc) => {
  let totalBytes = 0
  const scripts = Array.from(doc.querySelectorAll('script'))
    .filter(executableFrameScript)
  if (scripts.length > maxFrameScripts) {
    throw new Error('circle script count exceeds limit')
  }
  scripts.forEach((node) => {
    if (node.hasAttribute('src')) {
      throw new Error('circle script source was not materialized')
    }
    const sourceBytes = utf8Bytes(node.textContent || '')
    totalBytes += sourceBytes.length
    if (totalBytes > maxFrameScriptBytes) {
      throw new Error('circle script bytes exceed limit')
    }
    node.textContent = ''
    node.removeAttribute('integrity')
    node.removeAttribute('crossorigin')
    node.setAttribute('src', `data:application/javascript;base64,${bytesToBase64(sourceBytes)}`)
  })
}

const rewriteInternalAnchor = (circleId, basePath, href) => {
  if (!href || href.startsWith('#') || isDataSpec(href)) return href
  if (isBlockedRemoteSpec(href)) return '#'
  const parsed = parseCircleUri(href)
  if (parsed) return parsed.uri
  const resolved = resolveCirclePath(basePath, href)
  if (!resolved || isBlockedRemoteSpec(resolved)) return '#'
  return circleUriOf(circleId, resolved)
}

const materializeSealedHtml = async (circleId, htmlPath, htmlText, passphrase, bridgeToken, versionToken = '') => {
  const doc = new DOMParser().parseFromString(htmlText, 'text/html')
  injectSealedPolicy(doc)
  installSealedPrelude(doc, circleId, htmlPath, bridgeToken)
  const inlineStyles = Array.from(doc.querySelectorAll('style'))
  for (const node of inlineStyles) {
    node.textContent = await materializeCss(circleId, htmlPath, node.textContent || '', passphrase, versionToken)
  }
  const styleLinks = Array.from(doc.querySelectorAll('link[href]'))
  for (const node of styleLinks) {
    const rel = (node.getAttribute('rel') || '').toLowerCase()
    const href = node.getAttribute('href') || ''
    if (rel.includes('stylesheet')) {
      if (isBlockedRemoteSpec(href)) {
        node.remove()
      } else {
        const resolved = resolveCirclePath(htmlPath, href)
        if (!resolved || isBlockedRemoteSpec(resolved)) {
          node.remove()
        } else {
          const asset = await loadSealedAsset(circleId, resolved, passphrase, versionToken)
          const style = doc.createElement('style')
          style.textContent = await materializeCss(circleId, resolved, asset.text, passphrase, versionToken)
          node.replaceWith(style)
        }
      }
    } else if (isBlockedRemoteSpec(href)) {
      node.removeAttribute('href')
    } else if (!isDataSpec(href)) {
      const resolved = resolveCirclePath(htmlPath, href)
      if (resolved) {
        const asset = await loadSealedAsset(circleId, resolved, passphrase, versionToken)
        node.setAttribute('href', makeDataUrl(asset.content_type, asset.bytes))
      }
    }
  }
  const scripts = Array.from(doc.querySelectorAll('script[src]'))
  for (const node of scripts) {
    const src = node.getAttribute('src') || ''
    if (isBlockedRemoteSpec(src)) {
      node.remove()
    } else {
        const resolved = resolveCirclePath(htmlPath, src)
        if (!resolved || isBlockedRemoteSpec(resolved)) {
          node.remove()
        } else {
          const asset = await loadSealedAsset(circleId, resolved, passphrase, versionToken)
          const inline = doc.createElement('script')
          inline.textContent = asset.text
          node.replaceWith(inline)
      }
    }
  }
  const sourcedNodes = Array.from(doc.querySelectorAll('[src]'))
  for (const node of sourcedNodes) {
    if (node.tagName.toLowerCase() === 'script') {
      continue
    }
    const src = node.getAttribute('src') || ''
    if (isBlockedRemoteSpec(src)) {
      node.removeAttribute('src')
    } else if (!isDataSpec(src)) {
      const resolved = resolveCirclePath(htmlPath, src)
      if (resolved && !isBlockedRemoteSpec(resolved)) {
        const asset = await loadSealedAsset(circleId, resolved, passphrase, versionToken)
        node.setAttribute('src', makeDataUrl(asset.content_type, asset.bytes))
      }
    }
  }
  const posterNodes = Array.from(doc.querySelectorAll('[poster]'))
  for (const node of posterNodes) {
    const poster = node.getAttribute('poster') || ''
    if (isBlockedRemoteSpec(poster)) {
      node.removeAttribute('poster')
    } else if (!isDataSpec(poster)) {
      const resolved = resolveCirclePath(htmlPath, poster)
      if (resolved && !isBlockedRemoteSpec(resolved)) {
        const asset = await loadSealedAsset(circleId, resolved, passphrase, versionToken)
        node.setAttribute('poster', makeDataUrl(asset.content_type, asset.bytes))
      }
    }
  }
  const anchors = Array.from(doc.querySelectorAll('a[href]'))
  anchors.forEach((node) => {
    node.setAttribute('href', rewriteInternalAnchor(circleId, htmlPath, node.getAttribute('href') || ''))
  })
  const forms = Array.from(doc.querySelectorAll('form[action]'))
  forms.forEach((node) => {
    node.setAttribute('action', '#')
  })
  encodeFrameScripts(doc)
  return {
    html: `<!DOCTYPE html>\n${doc.documentElement.outerHTML}`
  }
}

const rewritePublicAssetRefs = async (doc, circleId, htmlPath) => {
  const loadAsset = (path) => loadPublicMaterializedAsset(circleId, path)
  const inlineStyles = Array.from(doc.querySelectorAll('style'))
  for (const node of inlineStyles) {
    node.textContent = await materializeCssWithLoader(
      circleId,
      htmlPath,
      node.textContent || '',
      loadAsset)
  }
  const styleLinks = Array.from(doc.querySelectorAll('link[href]'))
  for (const node of styleLinks) {
    const rel = (node.getAttribute('rel') || '').toLowerCase()
    const href = node.getAttribute('href') || ''
    if (isBlockedRemoteSpec(href)) {
      node.remove()
      continue
    }
    if (isDataSpec(href)) continue
    const resolved = resolveCirclePath(htmlPath, href)
    if (!resolved || isBlockedRemoteSpec(resolved)) {
      node.remove()
      continue
    }
    const asset = await loadAsset(resolved)
    if (rel.includes('stylesheet')) {
      if (!isStylesheetContentType(asset.content_type)) {
        throw new Error(`circle stylesheet content type refused: ${resolved}`)
      }
      const style = doc.createElement('style')
      style.textContent = await materializeCssWithLoader(
        circleId,
        resolved,
        asset.text,
        loadAsset)
      node.replaceWith(style)
    } else {
      node.setAttribute('href', makeDataUrl(asset.content_type, asset.bytes))
    }
  }
  const scripts = Array.from(doc.querySelectorAll('script[src]'))
  for (const node of scripts) {
    const src = node.getAttribute('src') || ''
    if (isBlockedRemoteSpec(src)) {
      node.remove()
      continue
    }
    const resolved = resolveCirclePath(htmlPath, src)
    if (!resolved || isBlockedRemoteSpec(resolved)) {
      node.remove()
      continue
    }
    const asset = await loadAsset(resolved)
    if (!isScriptContentType(asset.content_type)) {
      throw new Error(`circle script content type refused: ${resolved}`)
    }
    const inline = doc.createElement('script')
    const type = node.getAttribute('type')
    if (type) inline.setAttribute('type', type)
    inline.textContent = asset.text
    node.replaceWith(inline)
  }
  const sourcedNodes = Array.from(doc.querySelectorAll('[src]'))
  for (const node of sourcedNodes) {
    if (node.tagName.toLowerCase() === 'script') continue
    const src = node.getAttribute('src') || ''
    if (isBlockedRemoteSpec(src)) {
      node.removeAttribute('src')
      continue
    }
    if (isDataSpec(src)) continue
    const resolved = resolveCirclePath(htmlPath, src)
    if (resolved && !isBlockedRemoteSpec(resolved)) {
      const asset = await loadAsset(resolved)
      node.setAttribute('src', makeDataUrl(asset.content_type, asset.bytes))
    }
  }
  const posterNodes = Array.from(doc.querySelectorAll('[poster]'))
  for (const node of posterNodes) {
    const poster = node.getAttribute('poster') || ''
    if (isBlockedRemoteSpec(poster)) {
      node.removeAttribute('poster')
      continue
    }
    if (isDataSpec(poster)) continue
    const resolved = resolveCirclePath(htmlPath, poster)
    if (resolved && !isBlockedRemoteSpec(resolved)) {
      const asset = await loadAsset(resolved)
      node.setAttribute('poster', makeDataUrl(asset.content_type, asset.bytes))
    }
  }
  Array.from(doc.querySelectorAll('a[href]')).forEach((node) => {
    node.setAttribute('href', rewriteInternalAnchor(circleId, htmlPath, node.getAttribute('href') || ''))
  })
  Array.from(doc.querySelectorAll('form[action]')).forEach((node) => {
    node.setAttribute('action', '#')
  })
}

const materializePublicHtml = async (circleId, htmlPath, htmlText, bridgeToken) => {
  const doc = new DOMParser().parseFromString(htmlText, 'text/html')
  injectPublicPolicy(doc)
  await rewritePublicAssetRefs(doc, circleId, htmlPath)
  await installPublicPrelude(doc, circleId, htmlPath, bridgeToken)
  encodeFrameScripts(doc)
  return {
    html: `<!DOCTYPE html>\n${doc.documentElement.outerHTML}`
  }
}

const renderPublicAsset = async (asset, info) => {
  clearBridgeContext()
  setPreviewExpandAvailable(true)
  $('preview-head').textContent = `oct://${asset.circle_id}${asset.canonical_path} | ${asset.content_type} | ${asset.size_bytes} bytes`
  const body = $('preview-body')
  body.innerHTML = ''
  if (asset.content_type.startsWith('text/html')) {
    const bridgeToken = hexOfBytes(randomBytes(16))
    const frame = document.createElement('iframe')
    frame.className = 'circle-preview-frame'
    frame.setAttribute('sandbox', 'allow-scripts allow-forms')
    frame.addEventListener('load', () => {
      if (activeBridgeContext && activeBridgeContext.bridge_token === bridgeToken) {
        activeBridgeWindow = frame.contentWindow
      }
    })
    const materialized = await materializePublicHtml(
      asset.circle_id,
      asset.canonical_path,
      bytesToText(base64ToBytes(asset.body_b64)),
      bridgeToken)
    frame.srcdoc = materialized.html
    activeBridgeContext = {
      circle_id: asset.circle_id,
      path: asset.canonical_path,
      uri: circleUriOf(asset.circle_id, asset.canonical_path),
      privacy_class: info.privacy_class,
      browser_mode: info.browser_mode,
      resource_mode: info.resource_mode,
      bridge_token: bridgeToken,
      bridge_methods: bridgeMethodsForInfo(info)
    }
    body.appendChild(frame)
    activeBridgeWindow = frame.contentWindow
    return
  }
  if (CircleBridgePolicy.isPdfContentType(asset.content_type)) {
    const frame = document.createElement('iframe')
    frame.className = 'circle-preview-frame'
    frame.referrerPolicy = 'no-referrer'
    frame.title = asset.canonical_path
    frame.src = circleResourceUrl(asset.circle_id, asset.canonical_path)
    body.appendChild(frame)
    return
  }
  if (asset.content_type.startsWith('image/')) {
    const img = document.createElement('img')
    img.className = 'circle-preview-image'
    img.src = circleResourceUrl(asset.circle_id, asset.canonical_path)
    body.appendChild(img)
    return
  }
  const pre = document.createElement('pre')
  pre.className = 'circle-preview-text'
  pre.textContent = bytesToText(base64ToBytes(asset.body_b64))
  body.appendChild(pre)
}

const renderSealedAsset = async (circleId, path, info, passphrase) => {
  clearBridgeContext()
  const versionToken = info.assets_root || info.stable_root || ''
  const asset = await loadSealedAsset(circleId, path, passphrase, versionToken)
  setPreviewExpandAvailable(true)
  $('preview-head').textContent = `oct://${circleId}${asset.canonical_path} | sealed_read | ${asset.content_type} | key_id=${asset.key_id || 'none'}`
  const body = $('preview-body')
  body.innerHTML = ''
  if (asset.content_type.startsWith('text/html')) {
    const bridgeToken = hexOfBytes(randomBytes(16))
    const frame = document.createElement('iframe')
    frame.className = 'circle-preview-frame'
    frame.setAttribute('sandbox', 'allow-scripts')
    frame.referrerPolicy = 'no-referrer'
    frame.addEventListener('load', () => {
      if (activeBridgeContext && activeBridgeContext.bridge_token === bridgeToken) {
        activeBridgeWindow = frame.contentWindow
      }
    })
    const materialized = await materializeSealedHtml(circleId, asset.canonical_path, asset.text, passphrase, bridgeToken, versionToken)
    frame.srcdoc = materialized.html
    activeBridgeContext = {
      circle_id: circleId,
      path: asset.canonical_path,
      uri: circleUriOf(circleId, asset.canonical_path),
      privacy_class: info.privacy_class,
      browser_mode: info.browser_mode,
      resource_mode: info.resource_mode,
      bridge_token: bridgeToken,
      bridge_methods: bridgeMethodsForInfo(info)
    }
    body.appendChild(frame)
    activeBridgeWindow = frame.contentWindow
    return
  }
  clearBridgeContext()
  if (asset.content_type.startsWith('image/')) {
    const img = document.createElement('img')
    img.className = 'circle-preview-image'
    img.src = makeDataUrl(asset.content_type, asset.bytes)
    body.appendChild(img)
    return
  }
  const pre = document.createElement('pre')
  pre.className = 'circle-preview-text'
  pre.textContent = isTextContent(asset.content_type)
    ? asset.text
    : `sealed asset loaded\ncontent_type: ${asset.content_type}\nbytes: ${asset.bytes.length}`
  body.appendChild(pre)
}

const loadCircle = async () => {
  const target = currentCircleTarget()
  const circleId = target.circleId
  const path = target.path
  if (!circleId) {
    resetMeta()
    setStatus('status', 'circle id required', true)
    return
  }
  setStatus('status', 'loading...', false)
  try {
    const info = await fetchJson(`/api/circle/info?circle_id=${encodeURIComponent(circleId)}`)
    renderMeta(info)
    if ($('upload-circle-id')) {
      $('upload-circle-id').value = circleId
    }
    syncUploadModeForResourceMode(info.resource_mode)
    if (info.resource_mode === 'sealed_read') {
      const passphrase = $('sealed-passphrase').value
      if (!passphrase) {
        clearBridgeContext()
        setPreviewExpandAvailable(false)
        $('preview-head').textContent = `oct://${circleId}${path} | sealed_read`
        $('preview-body').innerHTML = '<pre class="circle-preview-text">sealed read key required</pre>'
        setStatus('status', `sealed circle loaded at oct://${circleId}${path}`, false)
      } else {
        await renderSealedAsset(circleId, path, info, passphrase)
        setStatus('status', `sealed asset loaded from oct://${circleId}${path}`, false)
      }
    } else {
      const asset = await loadPlainAsset(circleId, path)
      await renderPublicAsset(asset, info)
      setStatus('status', `loaded oct://${circleId}${asset.canonical_path}`, false)
    }
    const next = new URL(window.location.href)
    next.searchParams.set('uri', circleUriOf(circleId, path))
    next.searchParams.delete('circle')
    next.searchParams.delete('path')
    window.history.replaceState({}, '', next)
  } catch (err) {
    clearBridgeContext()
    setPreviewExpandAvailable(false)
    resetMeta()
    $('preview-head').textContent = 'load failed'
    $('preview-body').innerHTML = ''
    setStatus('status', err.message || 'load failed', true)
  }
}

const syncDeployMode = () => {
  const config = deployConfigOf(selectedDeployMode())
  const pairs = [
    ['deploy-runtime', config.runtime],
    ['deploy-privacy-class', config.privacy_class],
    ['deploy-browser-mode', config.browser_mode],
    ['deploy-resource-mode', config.resource_mode]
  ]
  pairs.forEach(([id, value]) => {
    if ($(id)) {
      $(id).textContent = value
    }
  })
}

const deployCircle = async () => {
  setStatus('deploy-status', 'preparing deploy...', false)
  try {
    if (!(await ensureWalletUnlocked('deploy-status'))) {
      return
    }
    const wallet = await fetchJson('/api/wallet')
    const balance = await fetchJson('/api/balance')
    const mode = selectedDeployMode()
    const config = deployConfigOf(mode)
    const payload = buildCircleDeployPayload(mode)
    const fee = normalizeFee('deploy-fee', '200000')
    const nonce = Number(balance.nonce || 0) + 1
    const circleId = await circleIdOfDeploy(wallet.address, nonce, payload)
    const confirmed = await circleConfirm(
      'circle deployer',
      [
        `circle id: ${circleId}`,
        `runtime: ${config.runtime}`,
        `privacy class: ${config.privacy_class}`,
        `browser mode: ${config.browser_mode}`,
        `resource mode: ${config.resource_mode}`,
        `fee ou: ${fee}`
      ].join('\n'),
      'sign'
    )
    if (!confirmed) {
      setStatus('deploy-status', 'cancelled', false)
      return
    }
    const pin = await circlePin('confirm circle deploy', `enter PIN to create a new ${deployProfileOf(mode)} circle`)
    if (!pin) {
      throw new Error('circle deploy cancelled')
    }
    setStatus('deploy-status', 'checking nonce...', false)
    const latestBalance = await fetchJson('/api/balance')
    const latestNonce = Number(latestBalance.nonce || 0) + 1
    const latestCircleId = await circleIdOfDeploy(wallet.address, latestNonce, payload)
    if (latestCircleId !== circleId) {
      setStatus('deploy-status', 'circle id changed, retry deploy', true)
      return
    }
    setStatus('deploy-status', 'submitting tx...', false)
    const result = await postJson('/api/circle/deploy', {
      ...payload,
      ou: fee,
      pin
    })
    const submittedCircleId = result.circle_id || circleId
    const uri = circleUriOf(submittedCircleId, '/index.html')
    $('circle-id').value = uri
    if ($('upload-circle-id')) {
      $('upload-circle-id').value = submittedCircleId
    }
    setUploadMode(config.resource_mode === 'public_resources' ? 'plain' : 'sealed')
    setSubmittedStatus('deploy-status', result.tx_hash, [`default browse uri: ${uri}`], wallet.explorer_url)
    setStatus('status', `deployed circle ${submittedCircleId}`, false)
  } catch (err) {
    setStatus('deploy-status', lockedMessageOf(err), true)
  }
}

const selectedUploadMode = () => $('upload-mode') && $('upload-mode').value === 'plain' ? 'plain' : 'sealed'

const setUploadMode = (mode) => {
  if ($('upload-mode')) {
    $('upload-mode').value = mode === 'plain' ? 'plain' : 'sealed'
  }
  syncUploadMode()
}

const uploadModeOfResourceMode = (resourceMode) => {
  if (resourceMode === 'public_resources') return 'plain'
  if (resourceMode === 'sealed_read') return 'sealed'
  return null
}

const syncUploadModeForResourceMode = (resourceMode) => {
  const mode = uploadModeOfResourceMode(resourceMode)
  if (mode) {
    setUploadMode(mode)
  }
}

const syncUploadMode = () => {
  const sealedFields = $('upload-sealed-fields')
  if (sealedFields) {
    sealedFields.style.display = selectedUploadMode() === 'plain' ? 'none' : ''
  }
  syncUploadFeeEstimate()
}

const selectedUploadPassphrase = () => ($('upload-passphrase') ? $('upload-passphrase').value : '') || $('sealed-passphrase').value

const selectedUploadCircleRaw = () => ($('upload-circle-id') && $('upload-circle-id').value.trim()) || $('circle-id').value.trim()

const selectedUploadCircleId = () => {
  const raw = selectedUploadCircleRaw()
  const parsed = parseCircleUri(raw)
  return parsed ? parsed.circleId : raw
}

const selectedUploadFile = () => ($('upload-file') && $('upload-file').files[0]) || null

const estimatedUploadB64Length = (file) => {
  if (selectedUploadMode() === 'plain') {
    return base64EncodedLength(file.size)
  }
  const bareSize = 4 + file.size
  const target = padTargetBytes($('upload-padding').value)
  const frameSize = target ? Math.ceil(bareSize / target) * target : bareSize
  return base64EncodedLength(sealedMagic.length + 12 + frameSize + 16)
}

const syncUploadFeeEstimate = () => {
  const element = $('upload-fee')
  const file = selectedUploadFile()
  if (!element) {
    return
  }
  if (!file) {
    if (element.value.trim() === uploadFeeGuess) {
      element.value = ''
    }
    uploadFeeGuess = ''
    return
  }
  const nextFee = String(circleAssetFeeOfB64Length(estimatedUploadB64Length(file)))
  if (!element.value.trim() || element.value.trim() === uploadFeeGuess) {
    element.value = nextFee
  }
  uploadFeeGuess = nextFee
}

const selectedUploadFee = (fallback) => {
  const element = $('upload-fee')
  if (!element) {
    return fallback
  }
  const raw = element.value.trim()
  if (/^[1-9][0-9]*$/.test(raw) && raw !== uploadFeeGuess) {
    return raw
  }
  element.value = fallback
  uploadFeeGuess = fallback
  return fallback
}

const updateUploadFileState = (file) => {
  const state = $('upload-file-state')
  if (!state) {
    return
  }
  state.textContent = file ? `${file.name} | ${formatFileSize(file.size)}` : 'no asset selected'
}

const updateUploadSelection = (file) => {
  if (file) {
    const nextPath = `/${file.name}`
    const nextContentType = file.type || guessContentType(file.name)
    if ($('upload-path') && (!$('upload-path').value.trim() || $('upload-path').value.trim() === uploadPathGuess)) {
      $('upload-path').value = nextPath
    }
    if ($('upload-content-type') && (!$('upload-content-type').value.trim() || $('upload-content-type').value.trim() === uploadContentTypeGuess)) {
      $('upload-content-type').value = nextContentType
    }
    if ($('upload-fee') && $('upload-fee').value.trim() === uploadFeeGuess) {
      $('upload-fee').value = ''
    }
    uploadPathGuess = nextPath
    uploadContentTypeGuess = nextContentType
    uploadFeeGuess = ''
  }
  updateUploadFileState(file)
  syncUploadFeeEstimate()
}

const uploadCircleAsset = async () => {
  const file = selectedUploadFile()
  const rawPath = $('upload-path').value.trim() || (file ? `/${file.name}` : '')
  const circleId = selectedUploadCircleId()
  const path = normalizeAssetPath(rawPath)
  const contentType = $('upload-content-type').value.trim()
  if (!circleId || !path || !contentType || !file) {
    setStatus('upload-status', 'circle id, path, content type, and file required', true)
    return
  }
  try {
    if (!(await ensureWalletUnlocked('upload-status'))) {
      return
    }
    const info = await fetchJson(`/api/circle/info?circle_id=${encodeURIComponent(circleId)}`)
    const requiredMode = uploadModeOfResourceMode(info.resource_mode)
    const mode = selectedUploadMode()
    if (!requiredMode) {
      setStatus('upload-status', `unsupported circle resource mode ${info.resource_mode || 'unknown'}`, true)
      return
    }
    if (mode !== requiredMode) {
      setUploadMode(requiredMode)
      setStatus('upload-status', `${info.resource_mode} circles require ${requiredMode === 'plain' ? 'plain' : 'sealed_read'} asset mode`, true)
      return
    }
    const keyId = $('upload-key-id').value.trim()
    const passphrase = selectedUploadPassphrase()
    const paddingClass = $('upload-padding').value
    if (mode === 'sealed' && (!keyId || !passphrase)) {
      setStatus('upload-status', 'key id and sealed read passphrase required', true)
      return
    }
    const plaintext = new Uint8Array(await file.arrayBuffer())
    const body = {
      circle_id: circleId,
      path,
      content_type: contentType,
      encoding: 'identity'
    }
    let endpoint = '/api/circle/asset_plain'
    let statusText = 'submitting asset...'
    if (mode === 'sealed') {
      setStatus('upload-status', 'encrypting...', false)
      const sealed = await encryptSealedBytes(circleId, keyId, passphrase, plaintext, paddingClass)
      if (sealed.ciphertext_b64.length > circleAssetMaxB64Bytes) {
        throw new Error('sealed asset exceeds 32mb circle limit')
      }
      endpoint = '/api/circle/asset_encrypted'
      statusText = 'submitting encrypted asset...'
      body.key_id = keyId
      body.plaintext_hash = sealed.plaintext_hash
      body.padding_class = paddingClass
      body.ciphertext_b64 = sealed.ciphertext_b64
      body.ou = selectedUploadFee(String(circleAssetFeeOfCiphertextB64(sealed.ciphertext_b64)))
    } else {
      const bodyB64 = bytesToBase64(plaintext)
      if (bodyB64.length > circleAssetMaxB64Bytes) {
        throw new Error('asset exceeds 32mb circle limit')
      }
      body.body_b64 = bodyB64
      body.ou = selectedUploadFee(String(circleAssetFeeOfB64Length(bodyB64.length)))
    }
    const wallet = await fetchJson('/api/wallet')
    const confirmed = await circleConfirm(
      'circle asset upload',
      [
        `circle id: ${circleId}`,
        `asset mode: ${mode === 'plain' ? 'plain' : 'sealed_read'}`,
        `path: ${path}`,
        `content type: ${contentType}`,
        `file size: ${formatFileSize(file.size)}`,
        `fee ou: ${body.ou}`
      ].join('\n'),
      'sign'
    )
    if (!confirmed) {
      setStatus('upload-status', 'cancelled', false)
      return
    }
    const pin = await circlePin('confirm circle asset', `enter PIN to upload ${path} | ${circleId}`)
    if (!pin) {
      throw new Error('circle asset upload cancelled')
    }
    setStatus('upload-status', statusText, false)
    const result = await postJson(endpoint, { ...body, pin })
    decryptedCache.clear()
    setSubmittedStatus('upload-status', result.tx_hash, [circleUriOf(circleId, path)], wallet.explorer_url)
    const target = currentCircleTarget()
    if (target.circleId === circleId && target.path === path) {
      await loadCircle()
    }
  } catch (err) {
    setStatus('upload-status', lockedMessageOf(err), true)
  }
}

const guessContentType = (name) => {
  const lower = name.toLowerCase()
  if (lower.endsWith('.html')) return 'text/html; charset=utf-8'
  if (lower.endsWith('.css')) return 'text/css; charset=utf-8'
  if (lower.endsWith('.js')) return 'application/javascript; charset=utf-8'
  if (lower.endsWith('.json')) return 'application/json; charset=utf-8'
  if (lower.endsWith('.svg')) return 'image/svg+xml'
  if (lower.endsWith('.png')) return 'image/png'
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg'
  if (lower.endsWith('.gif')) return 'image/gif'
  if (lower.endsWith('.webp')) return 'image/webp'
  return 'application/octet-stream'
}

bindIfPresent('load-btn', 'click', loadCircle)
bindIfPresent('wallet-btn', 'click', () => { window.location.href = 'index.html' })
bindIfPresent('preview-expand-btn', 'click', toggleExpandedPreview)
bindIfPresent('preview-overlay-close', 'click', closeExpandedPreview)
bindIfPresent('overlay-open-btn', 'click', async () => {
  syncMainControlsFromOverlay()
  await loadCircle()
})
bindIfPresent('deploy-btn', 'click', deployCircle)
bindIfPresent('deploy-mode', 'change', syncDeployMode)
bindIfPresent('upload-btn', 'click', uploadCircleAsset)
bindIfPresent('upload-file', 'change', (event) => {
  const file = event.target.files[0]
  updateUploadSelection(file)
})
bindIfPresent('upload-mode', 'change', syncUploadMode)
bindIfPresent('upload-padding', 'change', syncUploadFeeEstimate)
document.querySelectorAll('.nav-tabs a[data-circle-view]').forEach((tab) => {
  tab.addEventListener('click', (event) => {
    event.preventDefault()
    switchCircleView(tab.getAttribute('data-circle-view'))
  })
})
bindIfPresent('circle-id', 'keydown', (event) => {
  if (event.key === 'Enter') {
    loadCircle()
  }
})
bindIfPresent('sealed-passphrase', 'keydown', (event) => {
  if (event.key === 'Enter') {
    loadCircle()
  }
})
bindIfPresent('overlay-circle-id', 'keydown', (event) => {
  if (event.key === 'Enter') {
    syncMainControlsFromOverlay()
    loadCircle()
  }
})
bindIfPresent('overlay-sealed-passphrase', 'keydown', (event) => {
  if (event.key === 'Enter') {
    syncMainControlsFromOverlay()
    loadCircle()
  }
})
window.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && expandedPreviewOpen) {
    closeExpandedPreview()
  }
})

const params = new URLSearchParams(window.location.search)
const startUri = params.get('uri')
const startCircle = params.get('circle')
const startPath = params.get('path')
const startPassphrase = params.get('passphrase')
if (startPassphrase) {
  $('sealed-passphrase').value = startPassphrase
  $('overlay-sealed-passphrase').value = startPassphrase
}
if (startUri) {
  const target = parseCircleUri(startUri)
  if (target) {
    $('circle-id').value = startUri
    if ($('upload-path')) {
      $('upload-path').value = target.path
      uploadPathGuess = target.path
    }
    loadCircle()
  }
} else if (startCircle) {
  const target = parseCircleTarget(startCircle, startPath || '/index.html')
  $('circle-id').value = target.uri || startCircle
  if ($('upload-path')) {
    $('upload-path').value = target.path
    uploadPathGuess = target.path
  }
  loadCircle()
}
syncDeployMode()
syncUploadMode()
updateUploadFileState(selectedUploadFile())
