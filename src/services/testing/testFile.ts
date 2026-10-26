/**
 * TEST-ONLY: a File-like Blob whose bytes can be read back in jsdom (jsdom's Blob
 * has no arrayBuffer()). Used for synthetic test media only.
 */
export function testFile(name: string, bytes: Uint8Array, lastModified = 0): Blob & { name: string; lastModified: number } {
  const wrap = (data: Uint8Array): Blob => {
    const blob = new Blob([data as BlobPart])
    return Object.assign(blob, {
      arrayBuffer: async () => data.slice().buffer,
      slice: (start?: number, end?: number) => wrap(data.slice(start, end)),
    })
  }
  return Object.assign(wrap(bytes), { name, lastModified })
}
