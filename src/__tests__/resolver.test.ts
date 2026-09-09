// Ported from the upstream jest suite (which mocked cross-fetch) to vitest
// against the global fetch, plus the ThisDID fetch-boundary cases.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { Resolver, type DIDDocument, type Resolvable } from 'did-resolver'
import { getResolver, isPrivateHost } from '../resolver.js'

const json = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' }, ...init })

describe('web did resolver', () => {
  const did: string = 'did:web:example.com'
  const didLong: string = 'did:web:example.com:user:alice'
  const didWithPort: string = 'did:web:localhost%3A8443'
  const didWithEncodedPath: string = 'did:web:example.com:path:some%2Bsubpath'
  const identity: string = '0x2Cc31912B2b0f3075A87b3640923D45A26cef3Ee'
  const validResponse: DIDDocument = {
    '@context': 'https://www.w3.org/ns/did/v1',
    id: did,
    publicKey: [
      {
        id: `${did}#owner`,
        type: 'EcdsaSecp256k1RecoveryMethod2020',
        controller: did,
        ethereumAddress: identity,
      },
    ],
    authentication: [`${did}#owner`],
  }
  const noContextResponse: DIDDocument = { id: did, verificationMethod: [] }

  let didResolver: Resolvable
  const fetchMock = vi.fn<typeof fetch>()

  beforeAll(() => {
    vi.stubGlobal('fetch', fetchMock)
    didResolver = new Resolver(getResolver())
  })

  afterEach(() => {
    fetchMock.mockReset()
  })

  it('resolves document', async () => {
    fetchMock.mockResolvedValueOnce(json(validResponse))
    const result = await didResolver.resolve(did)
    expect(fetchMock.mock.calls[0][0]).toBe('https://example.com/.well-known/did.json')
    expect(result.didDocument).toEqual(validResponse)
    expect(result.didResolutionMetadata.contentType).toBe('application/did+ld+json')
  })

  it('resolves document with long did (path form)', async () => {
    fetchMock.mockResolvedValueOnce(json({ ...validResponse, id: didLong }))
    const result = await didResolver.resolve(didLong)
    expect(fetchMock.mock.calls[0][0]).toBe('https://example.com/user/alice/did.json')
    expect(result.didDocument?.id).toBe(didLong)
  })

  it('resolves document with port (private host explicitly allowed)', async () => {
    fetchMock.mockResolvedValueOnce(json({ ...validResponse, id: didWithPort }))
    const local = new Resolver(getResolver({ allowPrivateHosts: true }))
    const result = await local.resolve(didWithPort)
    expect(fetchMock.mock.calls[0][0]).toBe('https://localhost:8443/.well-known/did.json')
    expect(result.didDocument?.id).toBe(didWithPort)
  })

  it('resolves document with encoded path', async () => {
    fetchMock.mockResolvedValueOnce(json({ ...validResponse, id: didWithEncodedPath }))
    const result = await didResolver.resolve(didWithEncodedPath)
    expect(fetchMock.mock.calls[0][0]).toBe('https://example.com/path/some+subpath/did.json')
    expect(result.didDocument?.id).toBe(didWithEncodedPath)
  })

  it('reports application/did+json when the document has no @context', async () => {
    fetchMock.mockResolvedValueOnce(json(noContextResponse))
    const result = await didResolver.resolve(did)
    expect(result.didResolutionMetadata.contentType).toBe('application/did+json')
  })

  it('fails with notFound when the server answers 404', async () => {
    fetchMock.mockResolvedValueOnce(new Response('nope', { status: 404, statusText: 'Not Found' }))
    const result = await didResolver.resolve(did)
    expect(result.didDocument).toBeNull()
    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect(result.didResolutionMetadata.message).toContain('Bad response Not Found')
  })

  it('fails with notFound when the body is not JSON', async () => {
    fetchMock.mockResolvedValueOnce(new Response('<html>', { status: 200 }))
    const result = await didResolver.resolve(did)
    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect(result.didResolutionMetadata.message).toContain('not a JSON document')
  })

  it('fails with notFound when the document id does not match the did', async () => {
    fetchMock.mockResolvedValueOnce(json({ ...validResponse, id: 'did:web:other.example' }))
    const result = await didResolver.resolve(did)
    expect(result.didResolutionMetadata.error).toBe('notFound')
    expect(result.didResolutionMetadata.message).toContain('does not match')
  })

  describe('fetch boundaries (ThisDID fork)', () => {
    it('rejects loopback, private and link-local hosts by default', async () => {
      // (an IPv6 literal cannot be expressed in did:web — its colons are path separators — so it is
      // covered by the isPrivateHost unit test below)
      for (const target of ['did:web:localhost', 'did:web:127.0.0.1', 'did:web:10.0.0.5', 'did:web:169.254.169.254']) {
        const result = await didResolver.resolve(target)
        expect(result.didDocument).toBeNull()
        expect(result.didResolutionMetadata.error).toBe('notFound')
        expect(result.didResolutionMetadata.message).toContain('blocked by fetch policy')
      }
      expect(fetchMock).not.toHaveBeenCalled()
    })

    it('classifies private hosts including IPv4-mapped IPv6', () => {
      expect(isPrivateHost('localhost')).toBe(true)
      expect(isPrivateHost('app.localhost')).toBe(true)
      expect(isPrivateHost('192.168.1.1')).toBe(true)
      expect(isPrivateHost('172.31.0.1')).toBe(true)
      expect(isPrivateHost('[::ffff:127.0.0.1]')).toBe(true)
      expect(isPrivateHost('::ffff:7f00:1')).toBe(true)
      expect(isPrivateHost('fe80::1')).toBe(true)
      expect(isPrivateHost('example.com')).toBe(false)
      expect(isPrivateHost('172.32.0.1')).toBe(false)
    })

    it('follows https redirects up to the limit and re-validates each hop', async () => {
      fetchMock
        .mockResolvedValueOnce(new Response(null, { status: 301, headers: { location: 'https://www.example.com/.well-known/did.json' } }))
        .mockResolvedValueOnce(json(validResponse))
      const result = await didResolver.resolve(did)
      expect(result.didDocument).toEqual(validResponse)
      expect(fetchMock.mock.calls[1][0]).toBe('https://www.example.com/.well-known/did.json')
      expect(fetchMock.mock.calls[0][1]).toMatchObject({ redirect: 'manual' })
    })

    it('refuses a redirect to a non-https or private destination', async () => {
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: 'http://example.com/did.json' } }))
      let result = await didResolver.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('notFound')
      expect(result.didResolutionMetadata.message).toContain('not https')

      fetchMock.mockResolvedValueOnce(new Response(null, { status: 302, headers: { location: 'https://127.0.0.1/did.json' } }))
      result = await didResolver.resolve(did)
      expect(result.didResolutionMetadata.message).toContain('not a globally routable unicast')
    })

    it('stops after maxRedirects hops', async () => {
      const bounce = () => new Response(null, { status: 302, headers: { location: 'https://example.com/.well-known/did.json' } })
      fetchMock.mockResolvedValue(bounce())
      const strict = new Resolver(getResolver({ maxRedirects: 1 }))
      const result = await strict.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('notFound')
      expect(result.didResolutionMetadata.message).toContain('more than 1 redirects')
      expect(fetchMock).toHaveBeenCalledTimes(2)
    })

    it('bounds the response body (streamed and content-length)', async () => {
      const big = 'x'.repeat(2048)
      fetchMock.mockResolvedValueOnce(new Response(big, { status: 200 }))
      const bounded = new Resolver(getResolver({ maxResponseBytes: 1024 }))
      let result = await bounded.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('internalError')
      expect(result.didResolutionMetadata.message).toContain('exceeds 1024 bytes')

      fetchMock.mockResolvedValueOnce(new Response('{}', { status: 200, headers: { 'content-length': '999999' } }))
      result = await bounded.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('internalError')
    })

    it('times out and reports a transport-class error', async () => {
      fetchMock.mockImplementationOnce(
        (_url, init) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
          }),
      )
      const quick = new Resolver(getResolver({ timeoutMs: 20 }))
      const result = await quick.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('timeout')
    })

    it('reports network failures as networkError, not notFound', async () => {
      fetchMock.mockRejectedValueOnce(new Error('getaddrinfo ENOTFOUND example.com'))
      const result = await didResolver.resolve(did)
      expect(result.didResolutionMetadata.error).toBe('networkError')
      expect(result.didResolutionMetadata.message).toContain('ENOTFOUND')
    })

    it('uses an injected fetch implementation', async () => {
      const custom = vi.fn<typeof fetch>().mockResolvedValueOnce(json(validResponse))
      const injected = new Resolver(getResolver({ fetch: custom }))
      const result = await injected.resolve(did)
      expect(custom).toHaveBeenCalledTimes(1)
      expect(fetchMock).not.toHaveBeenCalled()
      expect(result.didDocument).toEqual(validResponse)
    })
  })
})
