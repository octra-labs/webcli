'use strict'

const $ = id => document.getElementById(id)
const svgNs = 'http://www.w3.org/2000/svg'
const graphLayerCap = 96
const layerListCap = 256
const indexCap = 96

const graph = {
  data: null,
  visible: [],
  positions: new Map(),
  selectedId: null,
  bounds: null,
  view: {x: 0, y: 0, scale: 1},
  drag: null
}

const svgEl = (name, attrs = {}) => {
  const element = document.createElementNS(svgNs, name)
  Object.entries(attrs).forEach(([key, value]) => element.setAttribute(key, String(value)))
  return element
}

const textEl = (x, y, value, className) => {
  const element = svgEl('text', {x, y, class: className})
  element.textContent = value
  return element
}

const safeInt = (value, min, max) => {
  const number = Number(value)
  if (!Number.isSafeInteger(number) || number < min || number > max) {
    throw new Error('ciphertext structure contains an invalid integer')
  }
  return number
}

const safeRatio = value => {
  const number = Number(value)
  if (!Number.isFinite(number) || number < 0 || number > 1) {
    throw new Error('ciphertext structure contains an invalid ratio')
  }
  return number
}

const safeText = (value, max) => {
  if (typeof value !== 'string' || value.length > max) {
    throw new Error('ciphertext structure contains an invalid string')
  }
  return value
}

const normalizeLayer = (raw, id) => {
  if (!raw || typeof raw !== 'object') {
    throw new Error('ciphertext layer is invalid')
  }
  const actualId = safeInt(raw.id, 0, 4095)
  if (actualId !== id || (raw.rule !== 'base' && raw.rule !== 'prod')) {
    throw new Error('ciphertext layer ordering is invalid')
  }
  const layer = {
    id,
    rule: raw.rule,
    depth: safeInt(raw.depth, 0, 4095),
    edgeCount: safeInt(raw.edge_count, 0, 1200000),
    rPcCount: safeInt(raw.r_pc_count, 0, 65536),
    pcCount: safeInt(raw.pc_count, 0, 65536),
    hasRCom: raw.has_r_com === true,
    sigmaDensity: safeRatio(raw.sigma_density),
    sigmaSamples: safeInt(raw.sigma_sampled_edges, 0, 4096),
    sigmaExact: raw.sigma_exact === true,
    parentA: null,
    parentB: null
  }
  if (layer.rule === 'prod') {
    layer.parentA = safeInt(raw.parent_a, 0, id - 1)
    layer.parentB = safeInt(raw.parent_b, 0, id - 1)
  }
  return Object.freeze(layer)
}

const normalizeEdge = (raw, layerCount) => {
  if (!raw || typeof raw !== 'object') {
    throw new Error('ciphertext edge sample is invalid')
  }
  if (raw.sign !== '+' && raw.sign !== '-') {
    throw new Error('ciphertext edge sign is invalid')
  }
  return Object.freeze({
    layerId: safeInt(raw.layer_id, 0, layerCount - 1),
    idx: safeInt(raw.idx, 0, 65535),
    sign: raw.sign,
    weightSlots: safeInt(raw.weight_slots, 0, 65536),
    sigmaDensity: safeRatio(raw.sigma_density)
  })
}

const normalizeData = raw => {
  if (!raw || typeof raw !== 'object' || !Array.isArray(raw.layers) ||
      !Array.isArray(raw.edge_samples)) {
    throw new Error('ciphertext structure response is invalid')
  }
  if (raw.layers.length > 4096 || raw.edge_samples.length > 192) {
    throw new Error('ciphertext structure response exceeds display limits')
  }
  const layers = raw.layers.map(normalizeLayer)
  const edges = layers.length === 0
    ? []
    : raw.edge_samples.map(edge => normalizeEdge(edge, layers.length))
  const baseLayers = layers.filter(layer => layer.rule === 'base').length
  const prodLayers = layers.length - baseLayers
  const wireHash = safeText(raw.wire_hash, 128)
  if (!/^[0-9a-f]{64}$/.test(wireHash)) {
    throw new Error('ciphertext wire hash is invalid')
  }
  return Object.freeze({
    address: safeText(raw.address, 96),
    wireHash,
    wireBytes: safeInt(raw.wire_bytes, 1, 48 * 1024 * 1024),
    slots: safeInt(raw.slots, 1, 65536),
    c0Count: safeInt(raw.c0_count, 0, 65536),
    edgeCount: safeInt(raw.edge_count, 0, 1200000),
    baseLayers,
    prodLayers,
    sigmaDensity: safeRatio(raw.sigma_density),
    sigmaSamples: safeInt(raw.sigma_sampled_edges, 0, 4096),
    sigmaExact: raw.sigma_exact === true,
    spendLimit: safeInt(raw.private_spend_max_base_layers, 1, 64),
    layers: Object.freeze(layers),
    edges: Object.freeze(edges)
  })
}

const fmtInt = value => new Intl.NumberFormat('en-US').format(value)
const fmtPct = value => `${(value * 100).toFixed(2)}%`

const fmtBytes = value => {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`
  return `${(value / (1024 * 1024)).toFixed(2)} MiB`
}

const setStatus = (message, failed = false) => {
  $('load-state').textContent = message
  $('load-state').parentElement.classList.toggle('error', failed)
}

const setDataVisibility = visible => {
  document.querySelector('.metrics').hidden = !visible
  document.querySelector('.map-section').hidden = !visible
  $('empty-state').hidden = visible
}

const showEmpty = (title, detail) => {
  graph.data = null
  graph.visible = []
  graph.positions.clear()
  $('empty-title').textContent = title
  $('empty-detail').textContent = detail
  setDataVisibility(false)
}

const renderMetrics = data => {
  $('address').textContent = data.address
  $('wire-hash').textContent = data.wireHash
  $('metric-layers').textContent = fmtInt(data.layers.length)
  $('metric-layer-mix').textContent = `base ${fmtInt(data.baseLayers)} | prod ${fmtInt(data.prodLayers)}`
  $('metric-edges').textContent = fmtInt(data.edgeCount)
  $('metric-edge-sample').textContent = `visual sample ${fmtInt(data.edges.length)}`
  $('metric-sigma').textContent = fmtPct(data.sigmaDensity)
  $('metric-sigma-mode').textContent = data.sigmaExact
    ? `exact | ${fmtInt(data.sigmaSamples)} edges`
    : `estimate | ${fmtInt(data.sigmaSamples)} edges`
  $('metric-pressure').textContent = `${data.baseLayers} / ${data.spendLimit}`
  $('metric-pressure-detail').textContent = 'base layers'
  $('metric-wire').textContent = fmtBytes(data.wireBytes)
  $('metric-slots').textContent = `slots ${data.slots} | c0 ${data.c0Count}`
}

const buildPositions = layers => {
  const center = {x: 560, y: 330}
  const groups = layers.reduce((result, layer) => {
    const group = result.get(layer.depth) || []
    group.push(layer)
    result.set(layer.depth, group)
    return result
  }, new Map())
  const positions = new Map()
  const maxDepth = layers.reduce((depth, layer) => Math.max(depth, layer.depth), 0)
  groups.forEach((group, depth) => {
    const baseRadius = Math.min(175, 74 + group.length * 16)
    const radius = depth === 0
      ? baseRadius
      : 170 + (maxDepth === 1 ? 70 : (depth - 1) * 120 / (maxDepth - 1))
    const phase = -Math.PI / 2 + depth * 0.47
    group.forEach((layer, index) => {
      const angle = phase + index * Math.PI * 2 / group.length
      positions.set(layer.id, {
        x: center.x + Math.cos(angle) * radius,
        y: center.y + Math.sin(angle) * radius * 0.72
      })
    })
  })
  return {
    positions,
    center,
    groups,
    maxDepth,
    bounds: {minX: 18, minY: 18, maxX: 1102, maxY: 642}
  }
}

const buildIndexPositions = edges => {
  const indices = [...new Set(edges.map(edge => edge.idx))].slice(0, indexCap)
  const positions = new Map()
  indices.forEach((idx, index) => {
    const angle = -Math.PI / 2 + index * Math.PI * 2 / indices.length
    positions.set(idx, {
      x: 560 + Math.cos(angle) * 510,
      y: 330 + Math.sin(angle) * 292
    })
  })
  return positions
}

const incidencePath = (from, to, offset) => {
  const dx = to.x - from.x
  const dy = to.y - from.y
  const length = Math.max(1, Math.hypot(dx, dy))
  const bend = ((offset % 9) - 4) * 4
  const cx = (from.x + to.x) / 2 - dy / length * bend
  const cy = (from.y + to.y) / 2 + dx / length * bend
  return `M ${from.x} ${from.y} Q ${cx} ${cy}, ${to.x} ${to.y}`
}

const productPath = (a, b, child, center) => {
  return [
    `M ${a.x} ${a.y}`,
    `Q ${center.x} ${center.y}, ${child.x} ${child.y}`,
    `Q ${center.x} ${center.y}, ${b.x} ${b.y}`,
    `Q ${center.x} ${center.y}, ${a.x} ${a.y}`,
    'Z'
  ].join(' ')
}

const titleEl = value => {
  const title = svgEl('title')
  title.textContent = value
  return title
}

const setTransform = view => {
  graph.view = view
  $('map-viewport').setAttribute(
    'transform',
    `translate(${view.x} ${view.y}) scale(${view.scale})`)
}

const resetView = () => {
  if (!graph.bounds) return
  const width = Math.max(1, graph.bounds.maxX - graph.bounds.minX)
  const height = Math.max(1, graph.bounds.maxY - graph.bounds.minY)
  const scale = Math.min(1.15, 1080 / width, 550 / height)
  setTransform({
    x: (1200 - width * scale) / 2 - graph.bounds.minX * scale,
    y: (660 - height * scale) / 2 - graph.bounds.minY * scale,
    scale
  })
}

const detailRow = (label, value) => {
  const row = document.createElement('div')
  row.className = 'detail-row'
  const key = document.createElement('span')
  const result = document.createElement('strong')
  key.textContent = label
  result.textContent = value
  row.append(key, result)
  return row
}

const renderSelected = () => {
  if (!graph.data || graph.selectedId === null) return
  const layer = graph.data.layers[graph.selectedId]
  if (!layer) return
  $('selected-title').textContent = `${layer.rule.toUpperCase()} layer ${layer.id}`
  const relation = layer.rule === 'prod'
    ? `${layer.parentA} x ${layer.parentB}`
    : 'independent base'
  const sigmaMode = layer.sigmaExact ? 'exact' : 'estimate'
  $('selected-detail').replaceChildren(
    detailRow('rule', layer.rule),
    detailRow('depth', String(layer.depth)),
    detailRow('parents', relation),
    detailRow('edges', fmtInt(layer.edgeCount)),
    detailRow('sigma density', `${fmtPct(layer.sigmaDensity)} ${sigmaMode}`),
    detailRow('sigma sample', fmtInt(layer.sigmaSamples)),
    detailRow('R commitment', layer.hasRCom ? 'present' : 'absent'),
    detailRow('slot bindings', `${layer.rPcCount} R_PC | ${layer.pcCount} PC`)
  )
  document.querySelectorAll('.layer-node').forEach(node => {
    node.classList.toggle('selected', Number(node.dataset.layerId) === layer.id)
  })
  const activeIndices = new Set(graph.data.edges
    .filter(edge => edge.layerId === layer.id)
    .map(edge => edge.idx))
  document.querySelectorAll('.incidence').forEach(edge => {
    edge.classList.toggle('active', Number(edge.dataset.layerId) === layer.id)
  })
  document.querySelectorAll('.index-node').forEach(node => {
    node.classList.toggle('active', activeIndices.has(Number(node.dataset.idx)))
  })
  document.querySelectorAll('.prod-hyperedge').forEach(edge => {
    const members = [
      Number(edge.dataset.parentA),
      Number(edge.dataset.parentB),
      Number(edge.dataset.child)
    ]
    edge.classList.toggle('active', members.includes(layer.id))
  })
  document.querySelectorAll('.layer-row').forEach(row => {
    row.classList.toggle('active', Number(row.dataset.layerId) === layer.id)
  })
}

const focusLayer = layerId => {
  const point = graph.positions.get(layerId)
  if (!point) return
  const scale = Math.max(0.85, Math.min(1.35, graph.view.scale))
  setTransform({
    x: 600 - point.x * scale,
    y: 330 - point.y * scale,
    scale
  })
}

const selectLayer = (layerId, focus = false) => {
  if (!graph.data || !graph.data.layers[layerId]) return
  graph.selectedId = layerId
  renderSelected()
  if (focus) focusLayer(layerId)
}

const renderLayerList = data => {
  const rows = data.layers.slice(0, layerListCap).map(layer => {
    const row = document.createElement('button')
    row.type = 'button'
    row.className = `layer-row ${layer.rule}`
    row.dataset.layerId = String(layer.id)
    const id = document.createElement('span')
    const rule = document.createElement('span')
    const edges = document.createElement('span')
    id.textContent = `L${layer.id}`
    rule.textContent = layer.rule
    edges.textContent = `${fmtInt(layer.edgeCount)} e`
    row.append(id, rule, edges)
    row.addEventListener('click', () => selectLayer(layer.id, true))
    return row
  })
  $('layer-list').replaceChildren(...rows)
  $('layer-list-count').textContent = data.layers.length > rows.length
    ? `${rows.length} / ${data.layers.length}`
    : String(data.layers.length)
}

const renderGraph = data => {
  graph.data = data
  graph.visible = data.layers.slice(0, graphLayerCap)
  const layout = buildPositions(graph.visible)
  graph.positions = layout.positions
  graph.bounds = layout.bounds
  const indexPositions = buildIndexPositions(data.edges)
  const links = []
  const nodes = []

  links.push(svgEl('ellipse', {
    cx: layout.center.x,
    cy: layout.center.y,
    rx: 510,
    ry: 292,
    class: 'index-orbit'
  }))
  layout.groups.forEach((group, depth) => {
    const points = group.map(layer => graph.positions.get(layer.id))
    const radiusX = points.length === 0
      ? 0
      : Math.max(...points.map(point => Math.abs(point.x - layout.center.x)))
    const radiusY = points.length === 0
      ? 0
      : Math.max(...points.map(point => Math.abs(point.y - layout.center.y)))
    links.push(svgEl('ellipse', {
      cx: layout.center.x,
      cy: layout.center.y,
      rx: Math.max(58, radiusX),
      ry: Math.max(42, radiusY),
      class: 'depth-orbit',
      'data-depth': depth
    }))
  })

  graph.visible.filter(layer => layer.rule === 'prod').forEach(layer => {
    const point = graph.positions.get(layer.id)
    const a = graph.positions.get(layer.parentA)
    const b = graph.positions.get(layer.parentB)
    if (!point || !a || !b) return
    const center = {
      x: (a.x + b.x + point.x) / 3,
      y: (a.y + b.y + point.y) / 3
    }
    const hyperedge = svgEl('g', {
      class: 'prod-hyperedge',
      'data-parent-a': layer.parentA,
      'data-parent-b': layer.parentB,
      'data-child': layer.id
    })
    hyperedge.append(
      svgEl('path', {
        d: productPath(a, b, point, center),
        class: 'prod-surface'
      }),
      svgEl('circle', {
        cx: center.x,
        cy: center.y,
        r: 8,
        class: 'prod-junction'
      }),
      textEl(center.x, center.y + 3, 'x', 'prod-mark'),
      titleEl(`PROD hyperedge: L${layer.parentA} x L${layer.parentB} -> L${layer.id}`)
    )
    links.push(hyperedge)
  })

  data.edges.forEach((edge, index) => {
    const layer = graph.positions.get(edge.layerId)
    const idx = indexPositions.get(edge.idx)
    if (!layer || !idx) return
    const line = svgEl('path', {
      d: incidencePath(layer, idx, index),
      class: `incidence ${edge.sign === '+' ? 'plus' : 'minus'}`,
      'data-layer-id': edge.layerId,
      'data-idx': edge.idx
    })
    line.style.setProperty('--edge-alpha', String(0.12 + edge.sigmaDensity * 0.34))
    line.append(titleEl(
      `edge: L${edge.layerId} | idx ${edge.idx} | sign ${edge.sign} | sigma ${fmtPct(edge.sigmaDensity)}`))
    links.push(line)
  })

  const idxFrequency = data.edges.reduce((counts, edge) => {
    counts.set(edge.idx, (counts.get(edge.idx) || 0) + 1)
    return counts
  }, new Map())
  const labelStep = Math.max(1, Math.ceil(indexPositions.size / 24))
  const indexEntries = [...indexPositions.entries()]
  indexEntries.forEach(([idx, point], index) => {
    const frequency = idxFrequency.get(idx) || 1
    const node = svgEl('g', {
      class: 'index-node',
      transform: `translate(${point.x} ${point.y})`,
      'data-idx': idx
    })
    node.dataset.idx = String(idx)
    node.append(
      svgEl('circle', {
        r: Math.min(7, 2.8 + frequency * 0.55),
        class: 'index-core'
      }),
      titleEl(`public index ${idx} | ${frequency} sampled incidence${frequency === 1 ? '' : 's'}`)
    )
    if (index % labelStep === 0) {
      const dx = point.x >= layout.center.x ? 9 : -9
      const anchor = point.x >= layout.center.x ? 'start' : 'end'
      node.append(svgEl('text', {
        x: dx,
        y: 3,
        class: 'index-label',
        'text-anchor': anchor
      }))
      node.lastChild.textContent = `i${idx}`
    }
    nodes.push(node)
  })

  graph.visible.forEach(layer => {
    const point = graph.positions.get(layer.id)
    const node = svgEl('g', {
      class: `layer-node ${layer.rule}`,
      transform: `translate(${point.x} ${point.y})`,
      tabindex: '0',
      role: 'button',
      'aria-label': `${layer.rule} layer ${layer.id}`
    })
    node.dataset.layerId = String(layer.id)
    const circumference = 194.8
    node.append(
      svgEl('circle', {r: 38, class: 'node-halo'}),
      svgEl('circle', {r: 29, class: 'node-core'}),
      svgEl('circle', {
        r: 31,
        class: 'node-density',
        'stroke-dasharray': `${layer.sigmaDensity * circumference} ${circumference}`,
        transform: 'rotate(-90)'
      }),
      textEl(0, 5, `L${layer.id}`, 'node-title'),
      textEl(0, 51, `${layer.rule} | d${layer.depth}`, 'node-meta'),
      titleEl(
        `${layer.rule.toUpperCase()} layer ${layer.id} | ${fmtInt(layer.edgeCount)} edges | sigma ${fmtPct(layer.sigmaDensity)}`)
    )
    node.addEventListener('click', () => selectLayer(layer.id))
    node.addEventListener('keydown', event => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        selectLayer(layer.id)
      }
    })
    nodes.push(node)
  })

  $('map-links').replaceChildren(...links)
  $('map-nodes').replaceChildren(...nodes)
  renderLayerList(data)
  graph.selectedId = graph.visible.length === 0 ? null : graph.visible[0].id
  resetView()
  renderSelected()
}

const svgPoint = event => {
  const bounds = $('cipher-map').getBoundingClientRect()
  return {
    x: (event.clientX - bounds.left) * 1200 / bounds.width,
    y: (event.clientY - bounds.top) * 660 / bounds.height
  }
}

const wireMapControls = () => {
  const svg = $('cipher-map')
  svg.addEventListener('wheel', event => {
    event.preventDefault()
    const point = svgPoint(event)
    const nextScale = Math.max(
      0.18,
      Math.min(2.8, graph.view.scale * (event.deltaY < 0 ? 1.12 : 0.89)))
    const ratio = nextScale / graph.view.scale
    setTransform({
      x: point.x - (point.x - graph.view.x) * ratio,
      y: point.y - (point.y - graph.view.y) * ratio,
      scale: nextScale
    })
  }, {passive: false})

  svg.addEventListener('pointerdown', event => {
    if (event.target.closest('.layer-node')) return
    const point = svgPoint(event)
    graph.drag = {
      pointerId: event.pointerId,
      point,
      x: graph.view.x,
      y: graph.view.y
    }
    svg.setPointerCapture(event.pointerId)
    svg.classList.add('dragging')
  })

  svg.addEventListener('pointermove', event => {
    if (!graph.drag || graph.drag.pointerId !== event.pointerId) return
    const point = svgPoint(event)
    setTransform({
      x: graph.drag.x + point.x - graph.drag.point.x,
      y: graph.drag.y + point.y - graph.drag.point.y,
      scale: graph.view.scale
    })
  })

  const stopDrag = event => {
    if (!graph.drag || graph.drag.pointerId !== event.pointerId) return
    graph.drag = null
    svg.classList.remove('dragging')
  }
  svg.addEventListener('pointerup', stopDrag)
  svg.addEventListener('pointercancel', stopDrag)

  $('reset-btn').addEventListener('click', resetView)
  $('deepest-btn').addEventListener('click', () => {
    if (!graph.visible.length) return
    const deepest = graph.visible.reduce((selected, layer) =>
      layer.depth >= selected.depth ? layer : selected)
    selectLayer(deepest.id, true)
  })
}

const load = async () => {
  setStatus('loading')
  try {
    const response = await fetch('/api/pvac/cipher_structure', {
      method: 'GET',
      headers: {Accept: 'application/json'},
      cache: 'no-store',
      credentials: 'same-origin'
    })
    const raw = await response.json()
    if (!response.ok) {
      throw new Error(typeof raw.error === 'string' ? raw.error : 'ciphertext lookup failed')
    }
    $('address').textContent = typeof raw.address === 'string' ? raw.address : '-'
    $('wire-hash').textContent = '-'
    if (raw.present !== true) {
      showEmpty(
        'No encrypted ciphertext',
        'The active wallet has no public ciphertext structure to inspect.')
      setStatus('not loaded')
      return
    }
    if (raw.supported !== true) {
      showEmpty(
        'Legacy structure unavailable',
        typeof raw.reason === 'string'
          ? raw.reason
          : 'This ciphertext format has no public structure view.')
      setStatus('not loaded', true)
      return
    }
    const data = normalizeData(raw)
    setDataVisibility(true)
    renderMetrics(data)
    renderGraph(data)
    setStatus('loaded')
  } catch (error) {
    showEmpty(
      'Ciphertext map unavailable',
      error instanceof Error ? error.message : 'Unable to load ciphertext structure.')
    setStatus('not loaded', true)
  }
}

wireMapControls()
$('reload-btn').addEventListener('click', load)

load()