// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// NikBel0x ヽ(*・ω・)ﾉ
// Julia L.
// Review: Vadim S.

(() => {
  'use strict'
  const key = 'octra-browser-access'
  const send = window.fetch.bind(window)
  let memory = ''
  let memoryOnly = false
  const read = () => {
    if (memoryOnly) return memory
    try { return localStorage.getItem(key) || memory } catch (_) { return memory }
  }
  const save = token => {
    memory = token
    try { localStorage.setItem(key, token); memoryOnly = false } catch (_) { memoryOnly = true }
  }
  const entry = /^#webcli=([0-9a-f]{64})$/.exec(location.hash || '')
  if ((location.hash || '').startsWith('#webcli='))
    history.replaceState(history.state, '', location.pathname + (location.search || ''))
  const ready = entry ? new Promise(resolve => {
    const controller = new AbortController()
    let pending = true
    const timer = setTimeout(() => {
      pending = false
      controller.abort()
      resolve()
    }, 5000)
    send(new Request(new URL('/api/wallet/status', location.origin), {
      headers: {Authorization: `Bearer ${entry[1]}`}, cache: 'no-store',
      credentials: 'omit', signal: controller.signal
    })).then(response => {
      if (pending && response.ok) save(entry[1])
    }).catch(() => {}).finally(() => {
      clearTimeout(timer)
      pending = false
      resolve()
    })
  }) : Promise.resolve()
  const waitReady = signal => new Promise((resolve, reject) => {
    const abort = () => reject(new DOMException('Request aborted', 'AbortError'))
    if (signal.aborted) return abort()
    signal.addEventListener('abort', abort, {once: true})
    ready.then(() => {
      signal.removeEventListener('abort', abort)
      if (signal.aborted) abort()
      else resolve()
    })
  })
  window.fetch = async (input, options) => {
    const request = new Request(input, options)
    const url = new URL(request.url)
    if (url.origin !== location.origin || !url.pathname.startsWith('/api/')) return send(request)
    await waitReady(request.signal)
    const token = read()
    const headers = new Headers(request.headers)
    const explicit = headers.has('Authorization')
    const attach = token && !headers.has('Authorization')
    if (attach) headers.set('Authorization', `Bearer ${token}`)
    const status = request.method === 'GET' && url.pathname === '/api/wallet/status'
    const login = request.method === 'POST' && url.pathname === '/api/wallet/unlock'
    const direct = !token && !explicit && (status || login)
    const destination = direct ? new URL(status ? '/api/browser/status' : '/api/browser/login', url) : url
    const outgoing = direct ? new Request(destination, {
      method: request.method, headers, signal: request.signal, credentials: 'omit', cache: 'no-store',
      body: login ? await request.arrayBuffer() : undefined
    }) : new Request(request, {headers})
    const response = await send(outgoing)
    const rotation = response.headers.get('X-Webcli-Session')
    const controls = ['/api/wallet/switch', '/api/settings', '/api/wallet/change-pin', '/api/wallet/lock']
    if (!explicit && response.ok && read() === token
      && ((direct && login) || (request.method === 'POST' && controls.includes(url.pathname)))) {
      if (/^[0-9a-f]{64}$/.test(rotation || '')) save(rotation)
      else if (rotation === 'signed-out') save('')
    }
    if (response.status === 401
      && response.headers.get('WWW-Authenticate') === 'Bearer realm="webcli-launch"') {
      if (!explicit && read() === token) {
        save('')
        if (status && !direct)
          return send(new Request(new URL('/api/browser/status', url), {
            signal: request.signal, cache: 'no-store', credentials: 'omit'
          }))
        if (!direct) location.replace('/')
      }
    }
    return response
  }
})()