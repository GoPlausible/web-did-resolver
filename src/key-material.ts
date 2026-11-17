/**
 * Verification-material validation shared by the DID document validators
 * (ThisDID). A verification method's material must be usable: a JWK carries
 * the members its key type requires, with base64url values of the right size
 * and, for curve keys, a point on the curve; a Multikey of a known multicodec
 * decodes to a valid key. Private members are refused. RSA moduli are checked
 * for encoding and size only (primality is out of reach here).
 */
import { ed25519 } from '@noble/curves/ed25519.js'
import { p256, p384, p521 } from '@noble/curves/nist.js'
import { secp256k1 } from '@noble/curves/secp256k1.js'

type PointDecoder = { fromBytes(bytes: Uint8Array): unknown }

const EC_CURVES: Record<string, { point: PointDecoder; size: number }> = {
  'P-256': { point: p256.Point, size: 32 },
  'P-384': { point: p384.Point, size: 48 },
  'P-521': { point: p521.Point, size: 66 },
  secp256k1: { point: secp256k1.Point, size: 32 },
}

/** Multicodec → key length and, where this validator can, a point decoder. */
const MULTICODECS: Record<number, { name: string; length: number; point?: PointDecoder }> = {
  0xed: { name: 'ed25519', length: 32, point: ed25519.Point },
  0xec: { name: 'x25519', length: 32 },
  0xe7: { name: 'secp256k1', length: 33, point: secp256k1.Point },
  0x1200: { name: 'p256', length: 33, point: p256.Point },
  0x1201: { name: 'p384', length: 49, point: p384.Point },
  0x1202: { name: 'p521', length: 67, point: p521.Point },
  0xeb: { name: 'bls12_381-g2', length: 96 },
}

const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value)

/** Strict base64url (no padding, no other characters); null when malformed. */
export function base64urlDecode(text: unknown): Uint8Array | null {
  if (typeof text !== 'string' || text.length === 0 || !/^[A-Za-z0-9_-]+$/.test(text) || text.length % 4 === 1) {
    return null
  }
  const out: number[] = []
  let buffer = 0
  let bits = 0
  for (const ch of text) {
    buffer = (buffer << 6) | BASE64URL.indexOf(ch)
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >> bits) & 0xff)
    }
  }
  // leftover bits must be zero padding
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null
  return Uint8Array.from(out)
}

export function base58Decode(text: string): Uint8Array | null {
  if (!BASE58_PATTERN.test(text)) return null
  const bytes: number[] = [0]
  for (const ch of text) {
    let carry = BASE58.indexOf(ch)
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58
      bytes[i] = carry & 0xff
      carry >>= 8
    }
    while (carry > 0) {
      bytes.push(carry & 0xff)
      carry >>= 8
    }
  }
  for (const ch of text) {
    if (ch !== '1') break
    bytes.push(0)
  }
  return Uint8Array.from(bytes.reverse())
}

function onCurve(point: PointDecoder | undefined, bytes: Uint8Array): boolean {
  if (!point) return true
  try {
    point.fromBytes(bytes)
    return true
  } catch {
    return false
  }
}

/** Why `jwk` is not a usable public JWK, or null. */
export function jwkProblem(jwk: unknown): string | null {
  if (!isPlainObject(jwk)) return 'publicKeyJwk must be a JWK object'
  if (jwk.d !== undefined) return 'publicKeyJwk must not carry a private key (d)'
  switch (jwk.kty) {
    case 'EC': {
      const crv = typeof jwk.crv === 'string' ? jwk.crv : ''
      const spec = EC_CURVES[crv]
      if (!spec) return `publicKeyJwk.crv '${crv}' is not a supported EC curve`
      const x = base64urlDecode(jwk.x)
      const y = base64urlDecode(jwk.y)
      if (!x || !y || x.length !== spec.size || y.length !== spec.size) {
        return `publicKeyJwk x and y must be base64url of ${spec.size} bytes for ${crv}`
      }
      const uncompressed = new Uint8Array(1 + 2 * spec.size)
      uncompressed[0] = 0x04
      uncompressed.set(x, 1)
      uncompressed.set(y, 1 + spec.size)
      return onCurve(spec.point, uncompressed) ? null : `publicKeyJwk is not a point on ${crv}`
    }
    case 'OKP': {
      const crv = typeof jwk.crv === 'string' ? jwk.crv : ''
      if (crv !== 'Ed25519' && crv !== 'X25519') return `publicKeyJwk.crv '${crv}' is not a supported OKP curve`
      const x = base64urlDecode(jwk.x)
      if (!x || x.length !== 32) return `publicKeyJwk.x must be base64url of 32 bytes for ${crv}`
      if (crv === 'Ed25519' && !onCurve(ed25519.Point, x)) return 'publicKeyJwk is not a point on Ed25519'
      return null
    }
    case 'RSA': {
      const n = base64urlDecode(jwk.n)
      const e = base64urlDecode(jwk.e)
      if (!n || !e) return 'publicKeyJwk n and e must be base64url integers'
      if (n.length < 256) return 'publicKeyJwk n must be at least 2048 bits'
      // RFC 7518 §6.3.1: minimal big-endian octets, so the first octet carries
      // the top bit of the modulus size; a modulus is a product of odd primes.
      if ((n[0] & 0x80) === 0 || (n[n.length - 1] & 1) === 0) {
        return 'publicKeyJwk n must be a minimal big-endian odd modulus with its top bit set'
      }
      if (e.length > 8 || e[0] === 0 || (e[e.length - 1] & 1) === 0 || (e.length === 1 && e[0] < 3)) {
        return 'publicKeyJwk e must be a minimal odd exponent of at least 3'
      }
      return null
    }
    default:
      return `publicKeyJwk.kty '${String(jwk.kty)}' is not a public key type this validator accepts`
  }
}

/**
 * Why `value` is not a usable Multikey, or null. Known multicodecs must carry
 * a key of the right length and, for the curves this validator decodes, a
 * point on the curve; unknown multicodecs pass on syntax alone.
 */
export function multikeyProblem(value: unknown): string | null {
  if (typeof value !== 'string' || value[0] !== 'z') return 'must be base58btc multibase (z…)'
  const decoded = base58Decode(value.slice(1))
  if (!decoded || decoded.length === 0) return 'must be base58btc multibase (z…)'
  // unsigned-varint multicodec: at most five 7-bit groups, terminated by a
  // byte without the continuation bit, minimal (no trailing zero group) and
  // followed by at least one key byte — one key, one encoding.
  let codec = 0
  let length = 0
  let terminated = false
  for (; length < decoded.length && length < 5; length += 1) {
    codec += (decoded[length] & 0x7f) * 2 ** (7 * length)
    if ((decoded[length] & 0x80) === 0) {
      terminated = true
      length += 1
      break
    }
  }
  if (!terminated) return 'multicodec varint does not terminate'
  if (length > 1 && decoded[length - 1] === 0) return 'multicodec varint is not minimal'
  const key = decoded.subarray(length)
  if (key.length === 0) return 'carries no key bytes after the multicodec'
  const spec = MULTICODECS[codec]
  if (!spec) return null
  if (key.length !== spec.length) {
    return `multicodec 0x${codec.toString(16)} needs ${spec.length} key bytes, got ${key.length}`
  }
  return onCurve(spec.point, key) ? null : `is not a valid ${spec.name} public key`
}
