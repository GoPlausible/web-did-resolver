import type { DIDDocument, DIDResolutionResult, DIDResolver, ParsedDID } from 'did-resolver'
import { isPrivateHost } from './address-policy.js'

const DOC_PATH = '/.well-known/did.json'

/**
 * Fetch boundaries added in the ThisDID fork. Upstream fetches the document
 * URL with implicit redirect following, no timeout, no destination policy and
 * an unbounded body read. Every default below fails closed and is overridable
 * by the host (the ThisDID CLI exposes them as WEB_* variables).
 *
 * The destination policy here is the first of two layers: it checks the
 * literal hostname of the document URL and of every redirect target before
 * that hop is fetched. What a name resolves to — including a public name that
 * resolves to a loopback, private, link-local or cloud-metadata address, or
 * changes its answer between check and connection (DNS rebinding) — can only
 * be decided at the connection, so the second layer belongs to the host: pass
 * a `fetch` that resolves each hostname once, refuses private answers and
 * connects only to the validated addresses (the ThisDID wrapper's `./node`
 * guard does exactly that and is its default on Node), or run on a platform
 * that cannot reach private destinations at all (Cloudflare Workers). Every
 * redirect hop goes through both layers.
 */
export interface WebResolverOptions {
  /** Wall-clock bound for the whole retrieval, redirects included. Default 6000 ms. */
  timeoutMs?: number
  /** Largest DID document body accepted. Default 1 MiB. */
  maxResponseBytes?: number
  /** Redirect hops followed, each re-validated against the policy. Default 3; 0 disables. */
  maxRedirects?: number
  /** Permit loopback, private and link-local hosts (local development only). Default false. */
  allowPrivateHosts?: boolean
  /** Fetch implementation. Defaults to the global fetch (Node ≥ 18, Workers, browsers). */
  fetch?: typeof fetch
}

const DEFAULT_TIMEOUT_MS = 6000
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024
const DEFAULT_MAX_REDIRECTS = 3
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308])

type Settled = Required<Omit<WebResolverOptions, 'fetch'>> & { fetch: typeof fetch }

/** A failure whose DIF error code is already decided. */
class ResolutionFailure extends Error {
  constructor(
    readonly code: 'notFound' | 'networkError' | 'timeout' | 'internalError',
    message: string,
  ) {
    super(message)
  }
}

export { isGlobalUnicastAddress, isPrivateHost, parseIpAddress } from './address-policy.js'
export type { ParsedAddress } from './address-policy.js'

function checkDestination(url: URL, allowPrivateHosts: boolean): void {
  if (url.protocol !== 'https:') {
    throw new ResolutionFailure('notFound', `blocked by fetch policy: ${url.protocol} is not https:`)
  }
  if (!allowPrivateHosts && isPrivateHost(url.hostname)) {
    throw new ResolutionFailure('notFound', `blocked by fetch policy: ${url.hostname} is not a globally routable unicast host`)
  }
}

/** Error text; undici wraps connect-time failures as "fetch failed" with the reason in `cause`. */
function describe(error: unknown): string {
  if (!(error instanceof Error)) return String(error)
  const cause = (error as { cause?: unknown }).cause
  if (error.message === 'fetch failed' && cause !== undefined) return describe(cause)
  return error.message
}

async function readBounded(res: Response, maxBytes: number): Promise<string> {
  const tooLarge = () => new ResolutionFailure('internalError', `response exceeds ${maxBytes} bytes`)
  const declared = Number(res.headers.get('content-length'))
  if (Number.isFinite(declared) && declared > maxBytes) throw tooLarge()
  if (!res.body) {
    const bytes = new Uint8Array(await res.arrayBuffer())
    if (bytes.byteLength > maxBytes) throw tooLarge()
    return new TextDecoder().decode(bytes)
  }
  const reader = res.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined)
      throw tooLarge()
    }
    chunks.push(value)
  }
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder().decode(out)
}

/** Retrieve and parse the document at `url` within the configured boundaries. */
async function get(url: string, options: Settled): Promise<unknown> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), options.timeoutMs)
  try {
    let current: URL
    try {
      current = new URL(url)
    } catch {
      throw new ResolutionFailure('notFound', `not a valid URL: ${url}`)
    }
    for (let hop = 0; ; hop += 1) {
      checkDestination(current, options.allowPrivateHosts)
      let res: Response
      try {
        res = await options.fetch(current.toString(), { redirect: 'manual', signal: controller.signal })
      } catch (error) {
        if (controller.signal.aborted) {
          throw new ResolutionFailure('timeout', `fetch timed out after ${options.timeoutMs} ms`)
        }
        throw new ResolutionFailure('networkError', `fetch failed: ${describe(error)}`)
      }
      if (REDIRECT_STATUSES.has(res.status)) {
        const location = res.headers.get('location')
        if (!location) throw new ResolutionFailure('notFound', `Bad response ${res.status} without a Location header`)
        if (hop >= options.maxRedirects) {
          throw new ResolutionFailure('notFound', `blocked by fetch policy: more than ${options.maxRedirects} redirects`)
        }
        current = new URL(location, current)
        continue
      }
      if (res.status >= 400) {
        // Upstream wording, kept for consumers that match on it.
        throw new ResolutionFailure('notFound', `Bad response ${res.statusText}`)
      }
      const text = await readBounded(res, options.maxResponseBytes)
      try {
        return JSON.parse(text)
      } catch {
        throw new ResolutionFailure('notFound', 'response is not a JSON document')
      }
    }
  } finally {
    clearTimeout(timer)
  }
}

export function getResolver(options: WebResolverOptions = {}): Record<string, DIDResolver> {
  const settled: Settled = {
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    maxResponseBytes: options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES,
    maxRedirects: options.maxRedirects ?? DEFAULT_MAX_REDIRECTS,
    allowPrivateHosts: options.allowPrivateHosts ?? false,
    fetch: options.fetch ?? fetch,
  }

  async function resolve(did: string, parsed: ParsedDID): Promise<DIDResolutionResult> {
    let err = null
    let path = decodeURIComponent(parsed.id) + DOC_PATH
    const id = parsed.id.split(':')
    if (id.length > 1) {
      path = id.map(decodeURIComponent).join('/') + '/did.json'
    }

    const url = `https://${path}`

    const didDocumentMetadata = {}
    let didDocument: DIDDocument | null = null

    do {
      try {
        didDocument = (await get(url, settled)) as DIDDocument
      } catch (error) {
        // Transport-class failures keep their own DIF code so a hosting
        // resolver can fail over instead of treating them as a verdict.
        if (error instanceof ResolutionFailure && error.code !== 'notFound') {
          return {
            didDocument: null,
            didDocumentMetadata,
            didResolutionMetadata: { error: error.code, message: error.message },
          }
        }
        err = `resolver_error: DID must resolve to a valid https URL containing a JSON document: ${error}`
        break
      }

      // TODO: this excludes the use of query params
      const docIdMatchesDid = didDocument?.id === did
      if (!docIdMatchesDid) {
        err = 'resolver_error: DID document id does not match requested did'
        // break // uncomment this when adding more checks
      }
      // eslint-disable-next-line no-constant-condition
    } while (false)

    const contentType =
      typeof didDocument?.['@context'] !== 'undefined' ? 'application/did+ld+json' : 'application/did+json'

    if (err) {
      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: {
          error: 'notFound',
          message: err,
        },
      }
    } else {
      return {
        didDocument,
        didDocumentMetadata,
        didResolutionMetadata: { contentType },
      }
    }
  }

  return { web: resolve }
}
