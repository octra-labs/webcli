// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>

const CircleBridgePolicy = (() => {
  const units = typeof AmountUnits !== 'undefined' ? AmountUnits : require('./amount_units.js')
  const circleIdPattern = /^oct[1-9A-HJ-NP-Za-km-z]{44}$/

  const deployLimits = () => ({
    max_stable_bytes: '33554432',
    max_assets_bytes: '33554432',
    max_inline_value: '65536',
    max_wasm_bytes: '33554432'
  })

  const deployPayload = (profile = 'public') => {
    if (profile !== 'public' && profile !== 'sealed') {
      throw new Error('circle.deploy profile must be public or sealed')
    }
    const sealed = profile === 'sealed'
    return {
      runtime: 'octb',
      privacy_class: sealed ? 'sealed' : 'public',
      browser_mode: 'native_sealed',
      resource_mode: sealed ? 'sealed_read' : 'public_resources',
      code_b64: null,
      policy_hash: null,
      members_root: null,
      export_policy: null,
      limits: deployLimits()
    }
  }

  const validCircleId = (circleId) => (
    typeof circleId === 'string' && circleIdPattern.test(circleId)
  )

  const callAmount = (text) => {
    if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,12})(\.[0-9]{1,6})?$/.test(text)) {
      throw new Error('amount requires OCT with up to six decimal places')
    }
    const [whole, fraction = ''] = text.split('.')
    const raw = BigInt(whole) * 1000000n + BigInt(fraction.padEnd(6, '0'))
    if (raw > 9223372036854775807n) throw new Error('amount exceeds range')
    return raw.toString()
  }

  const paymentTerms = (fee, amount = '0', count = 1, reference = '1000') => {
    if (typeof fee !== 'string' || !/^[1-9][0-9]*$/.test(fee) || BigInt(fee) > 10000000n
      || !Number.isSafeInteger(count) || count < 1 || count > 64
      || typeof reference !== 'string' || !/^[1-9][0-9]*$/.test(reference))
      throw new Error('invalid transaction fee')
    const oct = raw => {
      const digits = BigInt(raw).toString().padStart(7, '0')
      return (digits.slice(0, -6) + '.' + digits.slice(-6)).replace(/\.?0+$/, '')
    }
    const total = BigInt(callAmount(amount)) + BigInt(fee) * BigInt(count)
    const warning = BigInt(fee) > 5n * BigInt(reference)
      ? `\nWARNING: fee exceeds 5 x local reference (${oct(reference)} OCT). Check the fee before approving.` : ''
    return `fee: ${fee} ou (${oct(fee)} OCT)\ntotal OCT debit: ${oct(total)}${warning}`
  }

  const callTerms = (circleId, payload, amount, fixedMethod = '') => {
    if (!validCircleId(circleId) || payload.address
      || (payload.circle_id && payload.circle_id !== circleId)) {
      throw new Error('bridge target override denied')
    }
    const method = fixedMethod || payload.method
    if (typeof method !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(method)) {
      throw new Error('invalid program method')
    }
    if (fixedMethod && payload.method && payload.method !== fixedMethod) {
      throw new Error('bridge method override denied')
    }
    if (fixedMethod && payload.amount !== undefined && payload.amount !== '0') {
      throw new Error('management call amount must be zero')
    }
    const fee = payload.ou || payload.fee || '1000'
    if (typeof fee !== 'string' || !/^[1-9][0-9]{0,18}$/.test(fee)
      || BigInt(fee) > 10000000n) {
      throw new Error('invalid program fee')
    }
    const text = (name) => {
      const value = payload[name] ?? ''
      if (typeof value !== 'string') throw new Error(`invalid program field: ${name}`)
      return value
    }
    const integer = (name) => {
      const value = payload[name] ?? 0
      if (!Number.isInteger(value) || value < 0 || value > 2147483647) {
        throw new Error(`invalid program field: ${name}`)
      }
      return value
    }
    const boolean = (name) => {
      if (typeof payload[name] !== 'boolean') throw new Error(`invalid program field: ${name}`)
      return payload[name]
    }
    const nativeParams = {
      define_object_policy_native: () => [text('object_ref'), text('delivery_key_id'),
        integer('activate_after_epoch'), integer('expire_after_epoch'), text('transition_mode'),
        text('required_proof_kind'), integer('member_quorum'), boolean('allow_detach'),
        boolean('allow_root_state_rotation')],
      bind_object_native: () => ['object_ref', 'state_ref', 'transition_ref', 'status'].map(text),
      attach_object_member_native: () => ['object_ref', 'member_ref', 'state_ref', 'member_kind',
        'state_class', 'codec', 'status'].map(text),
      detach_object_member_native: () => ['object_ref', 'member_ref'].map(text),
      apply_object_transition_native: () => ['transition_ref', 'object_ref', 'previous_state_ref',
        'next_state_ref', 'member_bundle', 'touched_members_hash', 'proof_kind',
        'proof_receipt_hash', 'status', 'intent_id'].map(text)
    }
    const raw = payload.params_raw !== undefined
    if (raw && (fixedMethod || payload.params !== undefined))
      throw new Error('params_raw cannot be combined with params or management calls')
    const params = raw ? units.paramShape(payload.params_raw)
      : fixedMethod ? nativeParams[fixedMethod]() : (payload.params ?? [])
    if (!Array.isArray(params)) throw new Error('program parameters must be an array')
    const exact = (value, depth = 0) => {
      if (depth > 32) throw new Error('program parameters too deep')
      if (typeof value === 'number' && !Number.isSafeInteger(value))
        throw new Error('program numbers must be safe integers; use params_raw for larger values')
      if (value && typeof value === 'object') Object.values(value).forEach(item => exact(item, depth + 1))
    }
    exact(params)
    const parameterFields = raw ? {params_raw: payload.params_raw} : {params, approved_params: params}
    const body = {...payload, circle_id: circleId, method, amount: callAmount(amount), ou: fee,
      ...parameterFields}
    delete body.fee
    delete body.pin
    const displayParams = (raw ? payload.params_raw : JSON.stringify(params)).replace(/[^\x20-\x7e]/g, (value) =>
      `\\u${value.charCodeAt(0).toString(16).padStart(4, '0')}`)
    if (displayParams.length > 65536) throw new Error('program parameters exceed display limit')
    return Object.freeze({body: Object.freeze(body), text:
      `method: ${method}\ncircle: ${circleId}\namount: ${amount} OCT\n${paymentTerms(fee, amount)}\nparams: ${displayParams}`})
  }

  const assetTarget = (activeCircleId, createdCircleIds, requestedCircleId = '') => {
    const target = requestedCircleId || activeCircleId
    if (!validCircleId(target)) return ''
    if (target === activeCircleId) return target
    return createdCircleIds.has(target) ? target : ''
  }

  const assetPath = (rawPath) => {
    if (typeof rawPath !== 'string') return ''
    let decoded
    try {
      decoded = decodeURIComponent(rawPath.trim())
    } catch (_) {
      return ''
    }
    const path = decoded.startsWith('/') ? decoded : `/${decoded}`
    const segments = path.split('/').filter((segment) => segment && segment !== '.')
    if (segments.includes('..')) return ''
    const normalized = segments.length ? `/${segments.join('/')}` : '/'
    return normalized.length <= 1024 ? normalized : ''
  }

  const parseUri = (rawUri) => {
    if (typeof rawUri !== 'string') return null
    let decoded
    try {
      decoded = decodeURIComponent(rawUri.trim())
    } catch (_) {
      return null
    }
    if (!decoded.toLowerCase().startsWith('oct://')) return null
    const rest = decoded.slice(6).split(/[?#]/, 1)[0]
    const slash = rest.indexOf('/')
    const circleId = slash < 0 ? rest : rest.slice(0, slash)
    if (!validCircleId(circleId)) return null
    const path = assetPath(slash < 0 ? '/index.html' : rest.slice(slash))
    if (!path) return null
    return {
      circle_id: circleId,
      path,
      uri: `oct://${circleId}${path}`
    }
  }

  const publicResourcePath = (circleId, rawPath) => {
    if (!validCircleId(circleId)) return ''
    const path = assetPath(rawPath)
    if (!path) return ''
    const parts = path.split('/').filter(Boolean).map(encodeURIComponent)
    return parts.length
      ? `/oct/${encodeURIComponent(circleId)}/${parts.join('/')}`
      : `/oct/${encodeURIComponent(circleId)}/`
  }

  const isPdfContentType = (rawContentType) => (
    typeof rawContentType === 'string'
    && rawContentType.split(';', 1)[0].trim().toLowerCase() === 'application/pdf'
  )

  const assetMime = (rawContentType) => {
    if (typeof rawContentType !== 'string') return ''
    const contentType = rawContentType.trim()
    if (!contentType || contentType.length > 256) return ''
    if (!/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+(;[ ]*[A-Za-z0-9_-]+=([A-Za-z0-9_.+-]+|"[A-Za-z0-9_. +-]+"))*$/.test(contentType)) return ''
    for (let index = 0; index < contentType.length; index += 1) {
      const code = contentType.charCodeAt(index)
      if (code < 0x20 || code > 0x7e) return ''
    }
    return contentType
  }

  const base64Valid = (body, maxLength) => {
    if (typeof body !== 'string' || !body || body.length > maxLength || body.length % 4 !== 0) {
      return false
    }
    const padding = body.endsWith('==') ? 2 : body.endsWith('=') ? 1 : 0
    const dataLength = body.length - padding
    for (let index = 0; index < dataLength; index += 1) {
      const code = body.charCodeAt(index)
      const alpha = code >= 0x41 && code <= 0x5a
      const lower = code >= 0x61 && code <= 0x7a
      const digit = code >= 0x30 && code <= 0x39
      if (!alpha && !lower && !digit && code !== 0x2b && code !== 0x2f) return false
    }
    for (let index = dataLength; index < body.length; index += 1) {
      if (body[index] !== '=') return false
    }
    const valueOf = (code) => {
      if (code >= 0x41 && code <= 0x5a) return code - 0x41
      if (code >= 0x61 && code <= 0x7a) return code - 0x61 + 26
      if (code >= 0x30 && code <= 0x39) return code - 0x30 + 52
      return code === 0x2b ? 62 : 63
    }
    if (padding === 2 && (valueOf(body.charCodeAt(dataLength - 1)) & 0x0f) !== 0) return false
    if (padding === 1 && (valueOf(body.charCodeAt(dataLength - 1)) & 0x03) !== 0) return false
    return true
  }

  const preparePlainAsset = (activeCircleId, createdCircleIds, payload, maxBodyLength) => {
    if (!payload || typeof payload !== 'object' || Object.hasOwn(payload, 'address')) {
      throw new Error('circle.asset_plain payload rejected')
    }
    const circleId = assetTarget(activeCircleId, createdCircleIds, payload.circle_id || '')
    if (!circleId) throw new Error('circle.asset_plain target denied')
    const path = assetPath(payload.path)
    if (!path || path === '/') throw new Error('circle.asset_plain path invalid')
    if (path.startsWith('/.octra/')) throw new Error('circle.asset_plain path reserved')
    const contentType = assetMime(payload.content_type)
    if (!contentType) throw new Error('circle.asset_plain content type invalid')
    if (payload.encoding && payload.encoding !== 'identity') {
      throw new Error('circle.asset_plain encoding must be identity')
    }
    if (!base64Valid(payload.body_b64, maxBodyLength)) {
      throw new Error('circle.asset_plain body invalid')
    }
    return {
      circle_id: circleId,
      path,
      content_type: contentType,
      body_b64: payload.body_b64,
      encoding: 'identity'
    }
  }

  const computeJsonShape = (value, depth, budget) => {
    if (depth > 16 || budget.nodes <= 0) {
      throw new Error('compute request JSON exceeds shape limit')
    }
    budget.nodes -= 1
    if (value === null || typeof value === 'boolean' || typeof value === 'string') {
      return value
    }
    if (typeof value === 'number') {
      if (!Number.isSafeInteger(value)) {
        throw new Error('compute request number refused')
      }
      return value
    }
    if (Array.isArray(value)) {
      return value.map((entry) => computeJsonShape(entry, depth + 1, budget))
    }
    if (typeof value === 'object') {
      const keys = Object.keys(value).sort()
      if (keys.length > 256 || keys.some((key) => !key || key.length > 128)) {
        throw new Error('compute request object refused')
      }
      return Object.fromEntries(
        keys.map((key) => [key, computeJsonShape(value[key], depth + 1, budget)]))
    }
    throw new Error('compute request JSON refused')
  }

  const decimalString = (value, name) => {
    const text = typeof value === 'number' && Number.isSafeInteger(value)
      ? String(value)
      : value
    if (typeof text !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(text)) {
      throw new Error(`compute request ${name} refused`)
    }
    return text
  }

  const prepareComputeRequest = (payload, maxBodyBytes) => {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      throw new Error('compute request rejected')
    }
    const allowedKeys = [
      'unit_price',
      'fee_cap',
      'executor_root',
      'graph_root',
      'max_output_bytes',
      'method_name',
      'model_root',
      'params',
      'program_root',
      'sequence',
      'session_id'
    ]
    if (Object.keys(payload).sort().join(',') !== allowedKeys.sort().join(',')) {
      throw new Error('compute request fields differ')
    }
    const hashes = [
      'executor_root',
      'graph_root',
      'model_root',
      'program_root',
      'session_id'
    ]
    if (hashes.some((field) => typeof payload[field] !== 'string' || !/^[0-9a-f]{64}$/.test(payload[field]))) {
      throw new Error('compute request hash refused')
    }
    if (typeof payload.method_name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(payload.method_name)) {
      throw new Error('compute request method refused')
    }
    if (!Array.isArray(payload.params)) {
      throw new Error('compute request params refused')
    }
    if (!Number.isInteger(payload.max_output_bytes)
      || payload.max_output_bytes <= 0
      || payload.max_output_bytes > 262144) {
      throw new Error('compute request output limit refused')
    }
    const params = computeJsonShape(payload.params, 0, { nodes: 4096 })
    for (const key of ['unit_price', 'fee_cap']) {
      if (typeof payload[key] !== 'string' || !/^[1-9][0-9]{0,18}$/.test(payload[key])
        || BigInt(payload[key]) > 9223372036854775807n) {
        throw new Error('compute fee terms refused')
      }
    }
    const prepared = {
      unit_price: payload.unit_price,
      fee_cap: payload.fee_cap,
      executor_root: payload.executor_root,
      graph_root: payload.graph_root,
      max_output_bytes: payload.max_output_bytes,
      method_name: payload.method_name,
      model_root: payload.model_root,
      params,
      program_root: payload.program_root,
      sequence: decimalString(payload.sequence, 'sequence'),
      session_id: payload.session_id
    }
    if (new TextEncoder().encode(JSON.stringify(prepared)).length > maxBodyBytes) {
      throw new Error('compute request body exceeds limit')
    }
    return prepared
  }

  return Object.freeze({
    deployPayload,
    validCircleId,
    callAmount,
    callTerms,
    paymentTerms,
    parseUri,
    publicResourcePath,
    isPdfContentType,
    assetTarget,
    assetPath,
    assetMime,
    base64Valid,
    preparePlainAsset,
    prepareComputeRequest
  })
})()

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CircleBridgePolicy
}