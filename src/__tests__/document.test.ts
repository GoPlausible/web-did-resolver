// ThisDID fork: the retrieved JSON must be a DID document, not just an id match.
import { describe, expect, it, vi, afterEach } from 'vitest'
import { Resolver } from 'did-resolver'
import { getResolver } from '../resolver.js'
import { assertValidDidDocument, InvalidDidDocument } from '../document.js'

const DID = 'did:web:example.com'
const ED25519_KEY = 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V'
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const multibase = (bytes: number[]) => {
  const digits = [0]
  for (const byte of bytes) {
    let carry = byte
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] << 8
      digits[i] = carry % 58
      carry = (carry / 58) | 0
    }
    while (carry > 0) {
      digits.push(carry % 58)
      carry = (carry / 58) | 0
    }
  }
  return (
    'z' +
    digits
      .reverse()
      .map((d) => BASE58[d])
      .join('')
  )
}
const VALID = {
  '@context': 'https://www.w3.org/ns/did/v1',
  id: DID,
  verificationMethod: [
    { id: `${DID}#key-1`, type: 'Ed25519VerificationKey2020', controller: DID, publicKeyMultibase: ED25519_KEY },
  ],
  authentication: [`${DID}#key-1`],
  service: [{ id: `${DID}#hub`, type: 'LinkedDomains', serviceEndpoint: 'https://example.com/hub' }],
}

const serve = (document: unknown) =>
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(document), { status: 200 }))
  )

afterEach(() => vi.unstubAllGlobals())

describe('DID document validation (ThisDID fork)', () => {
  const rejects = (document: unknown, fragment: string) => {
    expect(() => assertValidDidDocument(document, DID), fragment).toThrow(InvalidDidDocument)
    try {
      assertValidDidDocument(document, DID)
    } catch (error) {
      expect((error as Error).message, fragment).toContain(fragment)
    }
  }

  it('leaves the id comparison to the resolver (a mismatch is notFound, not malformed)', () => {
    expect(() => assertValidDidDocument({ ...VALID, id: 'did:web:other.example' }, DID)).not.toThrow()
  })

  it('accepts a well-formed document', () => {
    expect(() => assertValidDidDocument(VALID, DID)).not.toThrow()
  })

  it('accepts relative DID URLs, which DID Core allows and real documents use', () => {
    const relative = {
      ...VALID,
      verificationMethod: [{ id: '#key-1', type: 'Multikey', controller: DID, publicKeyMultibase: ED25519_KEY }],
      authentication: ['#key-1'],
      service: [{ id: '#hub', type: 'LinkedDomains', serviceEndpoint: 'https://example.com/hub' }],
    }
    expect(() => assertValidDidDocument(relative, DID)).not.toThrow()
  })

  it('resolves relative ids before checking uniqueness', () => {
    const clashing = {
      ...VALID,
      verificationMethod: [{ id: DID + '#dup', type: 'Multikey', controller: DID, publicKeyMultibase: ED25519_KEY }],
      authentication: [],
      service: [{ id: '#dup', type: 'X', serviceEndpoint: 'https://x.test' }],
    }
    rejects(clashing, "duplicate id 'did:web:example.com#dup'")
  })

  it('refuses documents whose structure violates the data model', () => {
    rejects({ ...VALID, verificationMethod: 'a string' }, 'verificationMethod must be an array')
    rejects({ ...VALID, verificationMethod: ['not an object'] }, 'must be a verification method object')
    rejects({ ...VALID, verificationMethod: [{ id: 'key-1', type: 'X', controller: DID }] }, 'id must be a DID URL')
    rejects({ ...VALID, verificationMethod: [{ id: `${DID}#k`, type: 42, controller: DID }] }, 'type must be a string')
    rejects(
      { ...VALID, verificationMethod: [{ id: `${DID}#k`, type: 'X', controller: 'nope' }] },
      'controller must be a DID'
    )
    rejects({ ...VALID, authentication: [42] }, 'authentication[0] must be a verification method object')
    rejects({ ...VALID, authentication: ['key-1'] }, 'authentication[0] must be a DID URL')
    rejects({ ...VALID, keyAgreement: 'x' }, 'keyAgreement must be an array')
    rejects(
      { ...VALID, service: [{ id: `${DID}#s`, type: '', serviceEndpoint: 'https://x.test' }] },
      'type must be a string'
    )
    rejects({ ...VALID, service: [{ id: `${DID}#s`, type: 'X' }] }, 'serviceEndpoint must be a URI')
    rejects(
      { ...VALID, service: [{ id: `${DID}#s`, type: 'X', serviceEndpoint: 42 }] },
      'serviceEndpoint must be a URI'
    )
    rejects(
      { ...VALID, service: [{ id: `${DID}#s`, type: 'X', serviceEndpoint: 'not a uri' }] },
      'serviceEndpoint must be a URI'
    )
    rejects('a string', 'document must be a JSON object')
  })

  it('requires exactly one well-formed verification material property', () => {
    const vm = (extra: Record<string, unknown>) => ({
      ...VALID,
      verificationMethod: [{ id: `${DID}#k`, type: 'Multikey', controller: DID, ...extra }],
      authentication: [`${DID}#k`],
    })
    rejects(vm({}), 'has no verification material')
    rejects(
      vm({ publicKeyJwk: { kty: 'OKP' }, publicKeyMultibase: ED25519_KEY }),
      'more than one verification material'
    )
    rejects(vm({ publicKeyJwk: 'not an object' }), 'publicKeyJwk must be a JWK object')
    rejects(vm({ publicKeyJwk: {} }), 'not a public key type')
    rejects(vm({ publicKeyMultibase: 'abc' }), 'must be base58btc multibase')
    rejects(vm({ publicKeyMultibase: 'z0OIl' }), 'must be base58btc multibase')
    rejects(
      vm({ publicKeyMultibase: multibase([0xed, 0x01, ...new Array(31).fill(7)]) }),
      'multicodec 0xed needs 32 key bytes, got 31'
    )
    rejects(
      vm({ publicKeyMultibase: multibase([0xe7, 0x01, 0x02, 0x03]) }),
      'multicodec 0xe7 needs 33 key bytes, got 2'
    )
    rejects(vm({ publicKeyBase58: 'not base58 0OIl' }), 'publicKeyBase58 must be base58btc')
    rejects(vm({ publicKeyHex: 'xyz' }), 'publicKeyHex must be hex bytes')
    rejects(vm({ blockchainAccountId: 'garbage' }), 'blockchainAccountId must be a CAIP-10 account id')
    for (const ok of [
      { publicKeyMultibase: 'z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V' },
      { publicKeyMultibase: 'zQ3shbgnTGcgBpXPdBjDur3ATMDWhS7aPs6FRFkWR19Lb9Zwz' },
      { publicKeyMultibase: multibase([0x55, ...new Array(10).fill(1)]) }, // unknown multicodec (0x55 raw): syntax only
      { publicKeyBase58: 'H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV' },
      { blockchainAccountId: 'eip155:1:0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb' },
    ]) {
      expect(() => assertValidDidDocument(vm(ok), DID), JSON.stringify(ok)).not.toThrow()
    }
  })

  it('requires a JSON-LD @context to start with the DID Core context', () => {
    rejects({ ...VALID, '@context': [] }, '@context must be https://www.w3.org/ns/did/v1')
    rejects({ ...VALID, '@context': [42, { unexpected: true }] }, '@context[0] must be')
    rejects({ ...VALID, '@context': 'https://w3id.org/did/v1' }, '@context must be https://www.w3.org/ns/did/v1')
    rejects({ ...VALID, '@context': ['https://www.w3.org/ns/did/v1', 42] }, '@context[1] must be a context URI')
    rejects(
      { ...VALID, '@context': ['https://www.w3.org/ns/did/v1', 'not a uri'] },
      '@context[1] must be a context URI'
    )
    for (const ok of [
      undefined,
      'https://www.w3.org/ns/did/v1',
      ['https://www.w3.org/ns/did/v1'],
      ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1', { '@base': DID }],
    ]) {
      const doc = { ...VALID }
      if (ok === undefined) delete (doc as { '@context'?: unknown })['@context']
      else (doc as { '@context'?: unknown })['@context'] = ok
      expect(() => assertValidDidDocument(doc, DID), JSON.stringify(ok)).not.toThrow()
    }
  })

  it('refuses duplicate ids across verification methods and services', () => {
    rejects(
      { ...VALID, service: [{ id: `${DID}#key-1`, type: 'X', serviceEndpoint: 'https://x.test' }] },
      "duplicate id 'did:web:example.com#key-1'"
    )
  })

  it('reports a malformed document as invalidDidDocument, not as a successful resolution', async () => {
    serve({ ...VALID, verificationMethod: 'a string', authentication: [42] })
    const result = await new Resolver(getResolver()).resolve(DID)
    expect(result.didDocument).toBeNull()
    expect(result.didResolutionMetadata.error).toBe('invalidDidDocument')
  })

  it('still resolves a well-formed document', async () => {
    serve(VALID)
    const result = await new Resolver(getResolver()).resolve(DID)
    expect(result.didResolutionMetadata.error).toBeUndefined()
    expect(result.didDocument?.id).toBe(DID)
  })
})

// ThisDID fork: verification material must be usable, not merely present.
describe('key material validation', () => {
  const b64u = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
  const vm = (extra: Record<string, unknown>) => ({
    ...VALID,
    verificationMethod: [{ id: `${DID}#k`, type: 'JsonWebKey2020', controller: DID, ...extra }],
    authentication: [],
  })
  const bad = (extra: Record<string, unknown>, fragment: string) => rejects(vm(extra), fragment)
  const ok = (extra: Record<string, unknown>) =>
    expect(() => assertValidDidDocument(vm(extra), DID), JSON.stringify(extra)).not.toThrow()
  const rejects = (document: unknown, fragment: string) => {
    let message = ''
    try {
      assertValidDidDocument(document, DID)
    } catch (error) {
      message = (error as Error).message
    }
    expect(message, fragment).toContain(fragment)
  }

  it('accepts real EC, OKP and RSA public JWKs and Multikeys', async () => {
    const { p256 } = await import('@noble/curves/p256')
    const { ed25519 } = await import('@noble/curves/ed25519')
    const ec = p256.getPublicKey(p256.utils.randomPrivateKey(), false)
    ok({ publicKeyJwk: { kty: 'EC', crv: 'P-256', x: b64u(ec.slice(1, 33)), y: b64u(ec.slice(33)) } })
    ok({
      publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(ed25519.getPublicKey(ed25519.utils.randomPrivateKey())) },
    })
    const n = new Uint8Array(256).fill(0x9b)
    ok({ publicKeyJwk: { kty: 'RSA', n: b64u(n), e: 'AQAB' } })
    ok({ publicKeyMultibase: ED25519_KEY })
    ok({ publicKeyMultibase: 'zQ3shbgnTGcgBpXPdBjDur3ATMDWhS7aPs6FRFkWR19Lb9Zwz' })
  })

  it('refuses JWKs that are not usable public keys', () => {
    bad({ publicKeyJwk: { kty: 'EC' } }, 'not a supported EC curve')
    bad({ publicKeyJwk: { kty: 'RSA' } }, 'n and e must be base64url')
    bad({ publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'not-base64url!' } }, 'x must be base64url of 32 bytes')
    bad(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32).fill(0xff)) } },
      'not a point on Ed25519'
    )
    bad(
      {
        publicKeyJwk: {
          kty: 'EC',
          crv: 'P-256',
          x: b64u(new Uint8Array(32).fill(1)),
          y: b64u(new Uint8Array(32).fill(1)),
        },
      },
      'not a point on P-256'
    )
    bad({ publicKeyJwk: { kty: 'EC', crv: 'P-256', x: 'AQ', y: 'AQ' } }, 'x and y must be base64url of 32 bytes')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(128).fill(0x9b)), e: 'AQAB' } }, 'at least 2048 bits')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9b)), e: 'AQAC' } }, 'odd exponent')
    bad({ publicKeyJwk: { kty: 'oct', k: 'AQAB' } }, 'not a public key type')
    bad(
      { publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: b64u(new Uint8Array(32)), d: 'AQAB' } },
      'must not carry a private key'
    )
  })

  it('resolves references in any property order and refuses dangling ones (DID Core §5.3, R9.3)', () => {
    const embedded = { id: `${DID}#k2`, type: 'Multikey', controller: DID, publicKeyMultibase: ED25519_KEY }
    // authentication references a method embedded later, under assertionMethod
    expect(() =>
      assertValidDidDocument({ ...VALID, authentication: [`${DID}#k2`], assertionMethod: [embedded] }, DID)
    ).not.toThrow()
    rejects({ ...VALID, authentication: [`${DID}#missing`] }, 'references undefined verification method')
    // an embedded method is validated like any other
    rejects(
      { ...VALID, assertionMethod: [{ id: `${DID}#k3`, type: 'Multikey', controller: DID }] },
      'has no verification material'
    )
  })

  it('refuses RSA moduli and exponents that cannot be keys (R8.2)', () => {
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256)), e: 'AQ' } }, 'odd modulus with its top bit set')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256)), e: 'AQAB' } }, 'odd modulus with its top bit set')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x7f)), e: 'AQAB' } }, 'top bit set')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0xfe)), e: 'AQAB' } }, 'odd modulus')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9b)), e: 'AQ' } }, 'at least 3')
    bad({ publicKeyJwk: { kty: 'RSA', n: b64u(new Uint8Array(256).fill(0x9b)), e: 'AAEAAQ' } }, 'minimal odd exponent')
  })

  it('refuses Multikeys whose multicodec varint is unterminated, non-minimal or bare (R8.2)', async () => {
    const { ed25519 } = await import('@noble/curves/ed25519')
    const key = Array.from(ed25519.getPublicKey(ed25519.utils.randomPrivateKey()))
    ok({ publicKeyMultibase: multibase([0xed, 0x01, ...key]) })
    bad({ publicKeyMultibase: multibase([0xed, 0x81, 0x80, 0x80, 0x80, ...key]) }, 'varint does not terminate')
    bad({ publicKeyMultibase: multibase([0x80, 0x80, 0x80, 0x80, 0x80]) }, 'varint does not terminate')
    bad({ publicKeyMultibase: multibase([0xed, 0x81, 0x00, ...key]) }, 'varint is not minimal')
    bad({ publicKeyMultibase: multibase([0x80, 0x26]) }, 'no key bytes')
    ok({ publicKeyMultibase: multibase([0x80, 0x26, 0x01]) }) // unknown codec 0x1300 with key bytes: syntax only
  })

  it('refuses Multikeys of known codecs that are off the curve', () => {
    bad(
      { publicKeyMultibase: multibase([0xe7, 0x01, 0x02, ...new Array(32).fill(0xff)]) },
      'not a valid secp256k1 public key'
    )
    bad({ publicKeyMultibase: multibase([0xed, 0x01, ...new Array(32).fill(0xff)]) }, 'not a valid ed25519 public key')
  })
})

describe('unsuccessful resolutions carry no document (ThisDID fork)', () => {
  it('drops the retrieved document when its id does not match the requested DID', async () => {
    serve({ ...VALID, id: 'did:web:other.example' })
    const result = await new Resolver(getResolver()).resolve(DID)
    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect(result.didDocument).toBeNull()
  })
})
