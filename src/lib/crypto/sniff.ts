/**
 * Content-type detection from magic bytes. File names, extensions and
 * File.type are never trusted. Only the types listed in INLINE_TYPES are ever
 * rendered in the page; everything else (including SVG and HTML, which could
 * run script in a same-origin blob: URL) is offered only as a download of
 * application/octet-stream.
 */

export type SniffedType =
  | 'image/jpeg'
  | 'image/png'
  | 'image/gif'
  | 'image/webp'
  | 'image/avif'
  | 'image/heic'
  | 'video/mp4'
  | 'video/quicktime'
  | 'video/webm'
  | 'application/pdf'
  | 'application/octet-stream'

export const INLINE_TYPES: ReadonlySet<SniffedType> = new Set<SniffedType>([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/avif',
  'video/mp4',
  'video/quicktime',
  'video/webm',
])

function startsWith(bytes: Uint8Array, signature: number[], offset = 0): boolean {
  if (bytes.length < offset + signature.length) return false
  return signature.every((value, i) => bytes[offset + i] === value)
}

function ascii(bytes: Uint8Array, start: number, length: number): string {
  if (bytes.length < start + length) return ''
  return String.fromCharCode(...bytes.subarray(start, start + length))
}

export function sniffType(bytes: Uint8Array): SniffedType {
  if (startsWith(bytes, [0xff, 0xd8, 0xff])) return 'image/jpeg'
  if (startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return 'image/png'
  if (ascii(bytes, 0, 6) === 'GIF87a' || ascii(bytes, 0, 6) === 'GIF89a') return 'image/gif'
  if (ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') return 'image/webp'
  if (startsWith(bytes, [0x1a, 0x45, 0xdf, 0xa3])) return 'video/webm'
  if (ascii(bytes, 0, 5) === '%PDF-') return 'application/pdf'
  if (ascii(bytes, 4, 4) === 'ftyp') {
    const brand = ascii(bytes, 8, 4)
    if (brand === 'avif' || brand === 'avis') return 'image/avif'
    if (['heic', 'heix', 'heim', 'heis', 'mif1', 'msf1', 'hevc', 'hevx'].includes(brand)) return 'image/heic'
    if (brand === 'qt  ') return 'video/quicktime'
    if (['isom', 'iso2', 'iso4', 'iso5', 'iso6', 'mp41', 'mp42', 'avc1', 'M4V ', 'dash', 'MSNV', '3gp4', '3gp5'].includes(brand)) {
      return 'video/mp4'
    }
  }
  return 'application/octet-stream'
}
