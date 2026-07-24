const CircleBridgePolicy = (() => {
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

  const assetTarget = (activeCircleId, createdCircleIds, requestedCircleId = '') => {
    const target = requestedCircleId || activeCircleId
    if (!validCircleId(target)) return ''
    if (target === activeCircleId) return target
    return createdCircleIds.has(target) ? target : ''
  }

  const canonicalAssetPath = (rawPath) => {
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
    const canonical = segments.length ? `/${segments.join('/')}` : '/'
    return canonical.length <= 1024 ? canonical : ''
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
    const path = canonicalAssetPath(slash < 0 ? '/index.html' : rest.slice(slash))
    if (!path) return null
    return {
      circle_id: circleId,
      path,
      uri: `oct://${circleId}${path}`
    }
  }

  const publicResourcePath = (circleId, rawPath) => {
    if (!validCircleId(circleId)) return ''
    const path = canonicalAssetPath(rawPath)
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

  const canonicalContentType = (rawContentType) => {
    if (typeof rawContentType !== 'string') return ''
    const contentType = rawContentType.trim()
    if (!contentType || contentType.length > 256) return ''
    for (let index = 0; index < contentType.length; index += 1) {
      const code = contentType.charCodeAt(index)
      if (code < 0x20 || code > 0x7e) return ''
    }
    return contentType
  }

  const canonicalBase64 = (body, maxLength) => {
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
    const path = canonicalAssetPath(payload.path)
    if (!path || path === '/') throw new Error('circle.asset_plain path invalid')
    if (path.startsWith('/.octra/')) throw new Error('circle.asset_plain path reserved')
    const contentType = canonicalContentType(payload.content_type)
    if (!contentType) throw new Error('circle.asset_plain content type invalid')
    if (payload.encoding && payload.encoding !== 'identity') {
      throw new Error('circle.asset_plain encoding must be identity')
    }
    if (!canonicalBase64(payload.body_b64, maxBodyLength)) {
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

  return Object.freeze({
    deployPayload,
    validCircleId,
    parseUri,
    publicResourcePath,
    isPdfContentType,
    assetTarget,
    canonicalAssetPath,
    canonicalContentType,
    canonicalBase64,
    preparePlainAsset
  })
})()

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CircleBridgePolicy
}