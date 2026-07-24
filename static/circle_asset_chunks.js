const CircleAssetChunks = (() => {
  const format = 'octra.circle.asset.chunks.v1'
  const manifestType = 'application/vnd.octra.circle.chunks+json'
  const chunkType = 'application/octet-stream'
  const maxRawBytes = 33554432
  const directRawBytes = 2097152
  const chunkRawBytes = 2097152

  const plan = async (asset, tools) => {
    const raw = tools.decode(asset.body_b64)
    if (raw.length > maxRawBytes) {
      throw new Error('circle asset exceeds 32 MiB')
    }
    if (raw.length <= directRawBytes) {
      return Object.freeze({ direct: true, raw_bytes: raw.length, asset })
    }
    const digest = await tools.sha256(raw)
    const chunks = []
    for (let offset = 0, index = 0; offset < raw.length; offset += chunkRawBytes, index += 1) {
      const body = raw.subarray(offset, Math.min(offset + chunkRawBytes, raw.length))
      const hash = await tools.sha256(body)
      chunks.push(Object.freeze({
        path: `/.octra/chunks/${digest}/${index.toString().padStart(4, '0')}`,
        content_type: chunkType,
        encoding: 'identity',
        offset,
        size_bytes: body.length,
        sha256: hash
      }))
    }
    const manifest = {
      format,
      content_type: asset.content_type,
      encoding: asset.encoding,
      size_bytes: String(raw.length),
      sha256: digest,
      chunks: chunks.map((chunk) => ({
        path: chunk.path,
        size_bytes: String(chunk.size_bytes),
        sha256: chunk.sha256
      }))
    }
    return Object.freeze({
      direct: false,
      raw_bytes: raw.length,
      raw,
      chunks: Object.freeze(chunks),
      asset: Object.freeze({
        ...asset,
        content_type: manifestType,
        body_b64: tools.encode(tools.utf8(JSON.stringify(manifest)))
      })
    })
  }

  return Object.freeze({
    format,
    manifestType,
    chunkType,
    maxRawBytes,
    directRawBytes,
    chunkRawBytes,
    plan
  })
})()

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CircleAssetChunks
}