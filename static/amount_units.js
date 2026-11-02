// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
// NikBel0x ヽ(*・ω・)ﾉ
// Julia L.
// Review: Vadim S.

const AmountUnits = (() => {
  const places = (value) => {
    const text = String(value)
    if (!/^(0|[1-9][0-9]{0,2})$/.test(text) || Number(text) > 255) throw new Error('invalid amount decimals')
    return Number(text)
  }
  const parse = (value, decimals) => {
    const count = places(decimals)
    const text = String(value).trim()
    if (text.length > 512 || !/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(text)) throw new Error('invalid amount')
    const [whole, fraction = ''] = text.split('.')
    if (fraction.length > count) throw new Error('amount precision exceeds decimals')
    return (whole + fraction.padEnd(count, '0')).replace(/^0+(?=[0-9])/, '')
  }
  const format = (value, decimals) => {
    try {
      const count = places(decimals)
      const text = String(value)
      if (text.length > 512 || !/^[0-9]+$/.test(text)) return 'unavailable'
      const raw = text.replace(/^0+(?=[0-9])/, '')
      if (!count) return raw
      const padded = raw.padStart(count + 1, '0')
      const fraction = padded.slice(-count).replace(/0+$/, '')
      const whole = padded.slice(0, -count)
      return fraction ? `${whole}.${fraction}` : whole
    } catch (_) {
      return 'unavailable'
    }
  }
  const paramShape = text => {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > 1048576)
      throw new Error('program params exceed size limit')
    const parts = []
    let start = 0
    let index = 0
    while (index < text.length) {
      if (text[index] === '"') {
        index++
        let closed = false
        while (index < text.length) {
          const char = text[index++]
          if (char === '\\') index++
          else if (char === '"') { closed = true; break }
        }
        if (!closed) throw new Error('invalid program params JSON')
      } else if (text[index] === '-' || /[0-9]/.test(text[index])) {
        const number = index++
        while (index < text.length && /[0-9eE+.\-]/.test(text[index])) index++
        const token = text.slice(number, index)
        if (token.length - (token[0] === '-' ? 1 : 0) > 4096 || !/^-?(0|[1-9][0-9]*)$/.test(token))
          throw new Error('program numbers must be integers of at most 4096 digits')
        parts.push(text.slice(start, number), '0')
        start = index
      } else index++
    }
    parts.push(text.slice(start))
    const shape = parts.join('')
    let value
    try { value = JSON.parse(shape) } catch (_) { throw new Error('invalid program params JSON') }
    if (!Array.isArray(value)) throw new Error('program params must be a JSON array')
    return value
  }
  const paramText = text => { paramShape(text); return text }
  const params = text => {
    paramShape(text)
    const value = JSON.parse(text, (key, item) => {
      if (typeof item === 'number' && !Number.isSafeInteger(item))
        throw new Error('use params_raw for large program integers')
      return item
    })
    return value
  }
  return Object.freeze({parse, format, places, params, paramText, paramShape})
})()

if (typeof module !== 'undefined' && module.exports) module.exports = AmountUnits