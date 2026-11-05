/**
 * ThisDID fork: DID document data-model validation.
 *
 * Upstream compared only `document.id` with the requested DID and returned
 * whatever else the host had served, so arbitrary JSON crossed the resolver's
 * trust boundary as a successful resolution (a string where a set of
 * verification methods belongs, numbers inside `authentication`, services
 * without a usable id). Consumers then type-confuse on it.
 *
 * The checks below are the structural requirements of DID Core §5: required
 * properties, their types, DID / DID URL / URI syntax, and unique `id` values
 * across the document. They are deliberately structural — nothing here judges
 * key material or the semantics of a service, and a syntactically valid URI is
 * accepted whatever its scheme, so consumers must still apply their own policy
 * before dereferencing a service endpoint.
 */

const DID_PATTERN = /^did:[a-z0-9]+:[A-Za-z0-9._%:-]*[A-Za-z0-9._%-]$/
const DID_URL_PATTERN = /^did:[a-z0-9]+:[^\s]+$/
// DID Core §3.2.1: ids inside a document may be relative DID URLs, resolved
// against the DID subject. Documents in the wild (did:web, did:plc) use them.
const RELATIVE_REF = /^[#?/][^\s]*$/
import { jwkProblem, multikeyProblem } from './key-material.js'
const DID_CORE_CONTEXT = 'https://www.w3.org/ns/did/v1'
const BASE58_PATTERN = /^[1-9A-HJ-NP-Za-km-z]+$/
// CAIP-10 account id: namespace:reference:address
const CAIP10_PATTERN = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/
const MATERIAL_PROPERTIES = [
  'publicKeyJwk',
  'publicKeyMultibase',
  'publicKeyBase58',
  'publicKeyHex',
  'publicKeyPem',
  'blockchainAccountId',
] as const

/** DID Core §5.2.1: exactly one verification material property, well-formed for its kind. */
function materialProblem(vm: Record<string, unknown>): string | null {
  const present = MATERIAL_PROPERTIES.filter((name) => vm[name] !== undefined)
  if (present.length === 0) return 'has no verification material'
  if (present.length > 1) return `has more than one verification material property (${present.join(', ')})`
  const name = present[0]
  const value = vm[name]
  switch (name) {
    case 'publicKeyJwk':
      return jwkProblem(value)
    case 'publicKeyMultibase': {
      const problem = multikeyProblem(value)
      return problem === null ? null : `publicKeyMultibase ${problem}`
    }
    case 'publicKeyBase58':
      return typeof value === 'string' && BASE58_PATTERN.test(value) ? null : 'publicKeyBase58 must be base58btc'
    case 'publicKeyHex':
      return typeof value === 'string' && /^(0x)?([0-9a-fA-F]{2})+$/.test(value)
        ? null
        : 'publicKeyHex must be hex bytes'
    case 'publicKeyPem':
      return typeof value === 'string' && value.includes('-----BEGIN') ? null : 'publicKeyPem must be PEM text'
    case 'blockchainAccountId':
      return typeof value === 'string' && CAIP10_PATTERN.test(value)
        ? null
        : 'blockchainAccountId must be a CAIP-10 account id'
  }
  return null
}

/**
 * DID Core §6.3.1: a JSON-LD document's @context is the DID Core context, or
 * a non-empty array whose first item is that context and whose remaining
 * items are context URIs or embedded context objects. Absent means plain JSON.
 */
function contextProblem(context: unknown): string | null {
  if (context === undefined) return null
  if (typeof context === 'string') return context === DID_CORE_CONTEXT ? null : `@context must be ${DID_CORE_CONTEXT}`
  if (!Array.isArray(context) || context.length === 0)
    return `@context must be ${DID_CORE_CONTEXT} or a non-empty array starting with it`
  if (context[0] !== DID_CORE_CONTEXT) return `@context[0] must be ${DID_CORE_CONTEXT}`
  for (let i = 1; i < context.length; i += 1) {
    const item = context[i]
    if (typeof item === 'string' ? !isUri(item) : !isPlainObject(item))
      return `@context[${i}] must be a context URI or a context object`
  }
  return null
}

export class InvalidDidDocument extends Error {}

function fail(detail: string): never {
  throw new InvalidDidDocument(detail)
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isUri(value: string): boolean {
  if (value.length === 0) return false
  try {
    new URL(value)
    return true
  } catch {
    return false
  }
}

/** An id in a document: an absolute URI, or a relative DID URL resolved against `did`. */
function absoluteId(value: unknown, did: string): string | null {
  if (typeof value !== 'string' || value.length === 0) return null
  if (RELATIVE_REF.test(value)) return did + value
  return isUri(value) ? value : null
}

/** `id` values must be unique across verification methods and services (DID Core §4). */
function claimId(seen: Set<string>, id: string, where: string): void {
  if (seen.has(id)) fail(`duplicate id '${id}' (${where})`)
  seen.add(id)
}

function checkVerificationMethod(vm: unknown, index: number, where: string, seen: Set<string>, did: string): string {
  if (!isPlainObject(vm)) fail(`${where}[${index}] must be a verification method object`)
  const { type, controller } = vm
  const id = absoluteId(vm.id, did)
  if (id === null || !DID_URL_PATTERN.test(id)) fail(`${where}[${index}].id must be a DID URL`)
  if (typeof type !== 'string' || type.length === 0) fail(`${where}[${index}].type must be a string`)
  if (typeof controller !== 'string' || !DID_PATTERN.test(controller))
    fail(`${where}[${index}].controller must be a DID`)
  const material = materialProblem(vm)
  if (material !== null) fail(`${where}[${index}] ${material}`)
  claimId(seen, id, where)
  return id
}

const RELATIONSHIPS = [
  'authentication',
  'assertionMethod',
  'keyAgreement',
  'capabilityInvocation',
  'capabilityDelegation',
] as const

/**
 * Validate a retrieved document against the DID Core data model. Throws
 * `InvalidDidDocument` with the first violation found.
 */
export function assertValidDidDocument(document: unknown, did: string): void {
  if (!isPlainObject(document)) fail('document must be a JSON object')

  const context = contextProblem(document['@context'])
  if (context !== null) fail(context)

  const seen = new Set<string>()
  const methodIds = new Set<string>()
  const verificationMethod = document.verificationMethod
  if (verificationMethod !== undefined) {
    if (!Array.isArray(verificationMethod)) fail('verificationMethod must be an array')
    verificationMethod.forEach((vm, i) =>
      methodIds.add(checkVerificationMethod(vm, i, 'verificationMethod', seen, did))
    )
  }

  // DID Core §5.3: a relationship entry is a method embedded there or a reference to a method defined
  // anywhere in the document — including one embedded under another relationship — so every method is
  // collected first and references are checked in a second pass, whatever the order of the properties.
  const references: Array<{ place: string; id: string }> = []
  for (const relationship of RELATIONSHIPS) {
    const value = document[relationship]
    if (value === undefined) continue
    if (!Array.isArray(value)) fail(`${relationship} must be an array`)
    value.forEach((entry, i) => {
      if (typeof entry === 'string') {
        const absolute = absoluteId(entry, did)
        if (absolute === null || !DID_URL_PATTERN.test(absolute)) fail(`${relationship}[${i}] must be a DID URL`)
        references.push({ place: `${relationship}[${i}]`, id: absolute })
        return
      }
      methodIds.add(checkVerificationMethod(entry, i, relationship, seen, did))
    })
  }
  for (const { place, id } of references) {
    if (id.startsWith(did + '#') && !methodIds.has(id))
      fail(`${place} references undefined verification method '${id}'`)
  }

  const service = document.service
  if (service !== undefined) {
    if (!Array.isArray(service)) fail('service must be an array')
    service.forEach((entry, i) => {
      if (!isPlainObject(entry)) fail(`service[${i}] must be a service object`)
      const { type, serviceEndpoint } = entry
      const id = absoluteId(entry.id, did)
      if (id === null) fail(`service[${i}].id must be a URI or a relative DID URL`)
      claimId(seen, id, 'service')
      const typeOk =
        (typeof type === 'string' && type.length > 0) ||
        (Array.isArray(type) && type.length > 0 && type.every((t) => typeof t === 'string' && t.length > 0))
      if (!typeOk) fail(`service[${i}].type must be a string or a non-empty array of strings`)
      const endpointOk = (value: unknown): boolean =>
        (typeof value === 'string' && isUri(value)) || isPlainObject(value)
      const endpoints = Array.isArray(serviceEndpoint) ? serviceEndpoint : [serviceEndpoint]
      if (serviceEndpoint === undefined || endpoints.length === 0 || !endpoints.every(endpointOk)) {
        fail(`service[${i}].serviceEndpoint must be a URI, a map, or a non-empty set of them`)
      }
    })
  }

  // Legacy DID Core 0.11 property some documents still carry.
  const publicKey = document.publicKey
  if (publicKey !== undefined) {
    if (!Array.isArray(publicKey)) fail('publicKey must be an array')
    publicKey.forEach((vm, i) => {
      if (!isPlainObject(vm)) fail(`publicKey[${i}] must be an object`)
      const absolute = absoluteId(vm.id, did)
      if (absolute === null || !DID_URL_PATTERN.test(absolute)) fail(`publicKey[${i}].id must be a DID URL`)
    })
  }
}
