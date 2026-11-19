// SPDX-License-Identifier: BSD-3-Clause
// Run: node --test tests/circle_prompt.test.cjs
const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const vm = require('node:vm')

// Exercise the production dialog functions without a wallet backend or DOM dependency.
const source = fs.readFileSync(path.join(__dirname, '../static/circles.js'), 'utf8')
const start = source.indexOf('let circlePromptOpen = false')
const end = source.indexOf('\nconst renderMeta = ', start)
assert.ok(start >= 0 && end > start, 'dialog source boundaries exist')

class Element {
  constructor(tag) {
    this.tag = tag
    this.children = []
    this.listeners = new Map()
    this.attributes = {}
    this.value = ''
    this.disabled = false
  }
  append(...children) {
    for (const child of children) { child.parent = this; this.children.push(child) }
  }
  remove() { this.parent.children = this.parent.children.filter(child => child !== this) }
  focus() { this.focused = true }
  setAttribute(name, value) { this.attributes[name] = value }
  addEventListener(name, callback) {
    this.listeners.set(name, [...(this.listeners.get(name) || []), callback])
  }
  emit(name, properties = {}) {
    const event = { target: this, preventDefault() { this.prevented = true },
      stopPropagation() { this.stopped = true }, ...properties }
    for (const callback of this.listeners.get(name) || []) callback(event)
    return event
  }
  enter(value) { this.value = value; this.emit('input') }
  find(tag) { return this.children.find(child => child.tag === tag) }
}
function harness() {
  const body = new Element('body')
  const context = vm.createContext({ document: { body, createElement: tag => new Element(tag) },
    setTimeout, clearTimeout, activeBridgeContext: {} })
  vm.runInContext(source.slice(start, end) + '\nglobalThis.prompt = circlePin;', context)
  const dialog = () => {
    const overlay = body.children[0], box = overlay.children[0]
    const buttons = box.children.find(child => child.className === 'modal-buttons')
    return { overlay, input: box.find('input'), label: box.find('label'), help: box.find('p'),
      cancel: buttons.children[0], confirm: buttons.children[1] }
  }
  return { context, body, dialog, prompt: secret => context.prompt('test action', 'review terms', secret) }
}
const tick = () => new Promise(resolve => setImmediate(resolve))

test('amount is explicitly entered; its label and help do not depend on a placeholder', async () => {
  const h = harness(), result = h.prompt(false), d = h.dialog()
  assert.equal(d.input.value, '')
  assert.equal(d.input.placeholder, 'Enter amount, e.g. 0')
  assert.equal(d.input.inputMode, 'decimal')
  assert.equal(d.label.textContent, 'Amount to attach (OCT)')
  assert.equal(d.label.htmlFor, d.input.id)
  assert.equal(d.input.attributes['aria-describedby'], d.help.id)
  assert.match(d.help.textContent, /Type 0.*fee is separate/)
  assert.equal(d.confirm.disabled, true)
  const event = d.input.emit('keydown', { key: 'Enter', repeat: false })
  assert.ok(event.prevented && event.stopped)
  assert.equal(h.body.children.length, 1)
  d.input.enter('   ')
  d.confirm.emit('click')
  assert.equal(h.body.children.length, 1)
  d.input.enter('0')
  assert.equal(d.confirm.disabled, false)
  d.input.emit('keydown', { key: 'Enter', repeat: false })
  assert.equal(await result, '0')
  assert.equal(h.body.children.length, 0)
})

test('amount click path trims whitespace and preserves nonzero amounts', async () => {
  const h = harness(), result = h.prompt(false), d = h.dialog()
  d.input.enter(' 1.25 ')
  d.confirm.emit('click')
  assert.equal(await result, '1.25')
})

test('PIN is labeled, masked and passed through without trimming', async () => {
  const h = harness(), result = h.prompt(true), d = h.dialog()
  assert.equal(d.label.textContent, 'Wallet PIN')
  assert.equal(d.input.type, 'password')
  assert.equal(d.input.autocomplete, 'current-password')
  assert.equal(d.input.placeholder, '••••••••••••')
  assert.equal(d.input.maxLength, 64)
  assert.equal(d.input.value, '')
  assert.match(d.input.className, /circle-pin-input/)
  assert.match(d.help.textContent, /wallet PIN/)
  assert.equal(d.confirm.disabled, true)
  d.input.emit('keydown', { key: 'Enter', repeat: false })
  assert.equal(h.body.children.length, 1)
  d.input.enter(' synthetic PIN ')
  d.confirm.emit('click')
  assert.equal(await result, ' synthetic PIN ')
  assert.equal(d.input.value, '')
})

test('clearing input disables confirmation again; repeat Enter does not submit', async () => {
  const h = harness(), result = h.prompt(true), d = h.dialog()
  d.input.enter('synthetic PIN')
  d.input.emit('keydown', { key: 'Enter', repeat: true })
  assert.equal(h.body.children.length, 1)
  d.input.enter('')
  assert.equal(d.confirm.disabled, true)
  d.confirm.emit('click')
  assert.equal(h.body.children.length, 1)
  d.cancel.emit('click')
  assert.equal(await result, '')
})

test('confirmation preserves the full call details and literal parameter content', async () => {
  const h = harness()
  const terms = 'from: octExampleSender\nmethod: send\ncircle: octExampleCircle\namount: 0 OCT\nfee: 1000 ou (0.001 OCT)\ntotal OCT debit: 0.001'
  const params = 'params: ["Hello <b>world</b>","Guest",0,"request-id"]'
  const result = h.context.prompt('confirm program call', terms + '\n' + params, true)
  const box = h.body.children[0].children[0]
  assert.equal(box.children.find(child => child.className === 'modal-message').textContent, terms)
  assert.equal(box.children.find(child => child.className === 'modal-params').textContent, params)
  h.dialog().cancel.emit('click')
  assert.equal(await result, '')
})

test('amount and PIN dialogs remain sequential and support cancellation', async () => {
  const h = harness(), first = h.prompt(false), second = h.prompt(true)
  assert.equal(h.body.children.length, 1)
  h.dialog().input.enter('0')
  h.dialog().confirm.emit('click')
  assert.equal(await first, '0')
  await tick()
  assert.equal(h.body.children.length, 1)
  assert.equal(h.dialog().label.textContent, 'Wallet PIN')
  h.dialog().overlay.emit('click')
  assert.equal(await second, '')
  await tick()
  assert.equal(h.body.children.length, 0)
})

test('a queued dialog cannot continue after the active Circle context changes', async () => {
  const h = harness(), first = h.prompt(false), second = h.prompt(true)
  h.context.activeBridgeContext = {}
  h.dialog().cancel.emit('click')
  assert.equal(await first, '')
  assert.equal(await second, '')
  assert.equal(h.body.children.length, 0)
})
