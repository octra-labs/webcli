// cmix (Circle IN) Fri 7 Aug 2026 need to check 
// brunch (lambda0xe)


(() => {
  'use strict'

  const source = document.currentScript
  if (!source || source.id !== 'octra-circle-public-prelude') return

  let context
  try {
    context = JSON.parse(source.dataset.octraContext || '')
  } catch (_) {
    return
  }
  const bridgeToken = source.dataset.octraBridgeToken || ''
  const circlePattern = /^oct[1-9A-HJ-NP-Za-km-z]{44}$/
  const path = context?.path
  if (
    !context
    || !circlePattern.test(context.circle_id || '')
    || typeof path !== 'string'
    || !path.startsWith('/')
    || path.length > 1024
    || context.uri !== `oct://${context.circle_id}${path}`
    || !/^[0-9a-f]{32}$/.test(bridgeToken)
  ) return

  const waiters = new Map()
  const maxPending = 16
  const requestTimeoutMs = 95_000
  let nextRequestId = 0

  const bridge = Object.freeze({
    context: Object.freeze({ ...context }),
    request(method, payload = {}) {
      if (typeof method !== 'string' || !method || method.length > 128) {
        return Promise.reject(new Error('bridge method invalid'))
      }
      if (waiters.size >= maxPending) {
        return Promise.reject(new Error('bridge request capacity reached'))
      }
      return new Promise((resolve, reject) => {
        const id = `req_${String(++nextRequestId)}`
        const timeout = setTimeout(() => {
          if (!waiters.delete(id)) return
          reject(new Error('bridge request timed out'))
        }, requestTimeoutMs)
        waiters.set(id, { reject, resolve, timeout })
        parent.postMessage({
          type: 'octra.circle.bridge.request',
          token: bridgeToken,
          id,
          method,
          payload
        }, '*')
      })
    },
    navigate(uri) {
      if (typeof uri !== 'string' || !uri.startsWith('oct://') || uri.length > 2048) return
      parent.postMessage({
        type: 'octra.circle.navigate',
        token: bridgeToken,
        uri
      }, '*')
    }
  })

  window.OctraCircle = bridge
  window.addEventListener('message', (event) => {
    const data = event.data
    if (
      event.source !== parent
      || !data
      || data.token !== bridgeToken
      || data.type !== 'octra.circle.bridge.reply'
      || !data.id
      || !waiters.has(data.id)
    ) return
    const waiter = waiters.get(data.id)
    waiters.delete(data.id)
    clearTimeout(waiter.timeout)
    if (data.ok) {
      waiter.resolve(data.result)
      return
    }
    waiter.reject(new Error(data.error || 'bridge request failed'))
  })

  document.addEventListener('click', (event) => {
    const anchor = event.target?.closest?.('a[href]')
    if (!anchor) return
    const href = anchor.getAttribute('href') || ''
    if (!href.startsWith('oct://')) return
    event.preventDefault()
    bridge.navigate(href)
  }, true)
})()