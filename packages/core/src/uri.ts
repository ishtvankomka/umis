import { utf8Decode, utf8Encode } from './bytes.js';
import { UmisError } from './reasons.js';

const HEX_UPPER = '0123456789ABCDEF';
const WELL_KNOWN_NAMES = ['jwt-vc-issuer', 'openid-credential-issuer', 'oauth-authorization-server'] as const;
/** RFC 3986 appendix B, with `.` allowed to match line breaks so that nothing is silently left out. */
const URI_PATTERN = /^(?:([^:/?#]+):)?(?:\/\/([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#([\s\S]*))?$/;

const invalid = (message: string): UmisError => new UmisError('INVALID_ARGUMENT', message);
const malformed = (message: string, cause?: unknown): UmisError => new UmisError('MALFORMED', message, { cause });

// ---------------------------------------------------------------------------------------------------------------
// application/x-www-form-urlencoded
// ---------------------------------------------------------------------------------------------------------------

function isFormSafe(byte: number): boolean {
  return (
    (byte >= 0x30 && byte <= 0x39) ||
    (byte >= 0x41 && byte <= 0x5a) ||
    (byte >= 0x61 && byte <= 0x7a) ||
    byte === 0x2a ||
    byte === 0x2d ||
    byte === 0x2e ||
    byte === 0x5f
  );
}

function formEscape(value: string): string {
  let out = '';
  for (const byte of utf8Encode(value)) {
    if (isFormSafe(byte)) out += String.fromCharCode(byte);
    else if (byte === 0x20) out += '+';
    else out += `%${HEX_UPPER.charAt(byte >> 4)}${HEX_UPPER.charAt(byte & 15)}`;
  }
  return out;
}

/**
 * Encodes fields as `application/x-www-form-urlencoded`: UTF-8 bytes, letters, digits and `*-._` as they are, a space as
 * `+`, everything else as `%XX`; fields in the order given.
 */
export function formEncode(fields: Readonly<Record<string, string>>): string {
  if (typeof fields !== 'object' || fields === null || Array.isArray(fields)) throw invalid('fields must be an object');
  return Object.entries(fields)
    .map(([name, value]) => {
      if (typeof value !== 'string') throw invalid(`the value of "${name}" must be a string`);
      return `${formEscape(name)}=${formEscape(value)}`;
    })
    .join('&');
}

function hexDigit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  return -1;
}

function formUnescape(value: string): string {
  const bytes: number[] = [];
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    if (code === 0x25) {
      const high = hexDigit(value.charCodeAt(index + 1));
      const low = hexDigit(value.charCodeAt(index + 2));
      if (high < 0 || low < 0) throw malformed('a percent escape needs two hexadecimal digits');
      bytes.push((high << 4) | low);
      index += 2;
    } else if (code === 0x2b) {
      bytes.push(0x20);
    } else if (code < 0x80) {
      bytes.push(code);
    } else {
      const point = value.codePointAt(index) ?? code;
      if (point > 0xffff) index += 1;
      bytes.push(...utf8Encode(String.fromCodePoint(point)));
    }
  }
  return utf8Decode(Uint8Array.from(bytes));
}

/**
 * Reads a query string (a leading `?` is allowed): fields separated by `&`, name and value by the first `=`, `+` as a
 * space, `%XX` as bytes that must form UTF-8. The first value of a repeated name wins; empty fields are skipped. A
 * broken escape or invalid UTF-8 is MALFORMED.
 */
export function parseQuery(query: string): Record<string, string> {
  if (typeof query !== 'string') throw malformed('a query is a string');
  const fields: Record<string, string> = {};
  for (const pair of (query.startsWith('?') ? query.slice(1) : query).split('&')) {
    if (pair === '') continue;
    const separator = pair.indexOf('=');
    const name = formUnescape(separator === -1 ? pair : pair.slice(0, separator));
    const value = separator === -1 ? '' : formUnescape(pair.slice(separator + 1));
    if (!Object.hasOwn(fields, name)) {
      // defineProperty keeps a field named "__proto__" an ordinary entry
      Object.defineProperty(fields, name, { value, enumerable: true, writable: true, configurable: true });
    }
  }
  return fields;
}

// ---------------------------------------------------------------------------------------------------------------
// URI splitting and well-known locations
// ---------------------------------------------------------------------------------------------------------------

/**
 * Splits a URI into its five components with the expression of RFC 3986 appendix B. Components that are absent are
 * empty strings, the delimiters are not included, and the scheme comes back in lower case. Nothing is validated.
 */
export function splitUri(uri: string): {
  scheme: string;
  authority: string;
  path: string;
  query: string;
  fragment: string;
} {
  if (typeof uri !== 'string') throw invalid('a URI is a string');
  const match = URI_PATTERN.exec(uri);
  return {
    scheme: (match?.[1] ?? '').toLowerCase(),
    authority: match?.[2] ?? '',
    path: match?.[3] ?? '',
    query: match?.[4] ?? '',
    fragment: match?.[5] ?? '',
  };
}

/** A DNS label: 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen. */
function isHostLabel(label: string): boolean {
  return label.length >= 1 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-');
}

function isDotSegment(segment: string): boolean {
  const decoded = segment.replace(/%2e/gi, '.');
  return decoded === '.' || decoded === '..';
}

/**
 * The location of a well-known document for an issuer or server identifier: `/.well-known/<name>` is inserted between
 * the authority and the path, and a terminating `/` of the path is dropped (RFC 8414 section 3, RFC 8615; SD-JWT VC
 * type `jwt-vc-issuer`, OpenID4VCI `openid-credential-issuer`). Only `https` identifiers are accepted, `http` solely
 * for `localhost` and `127.0.0.1`. User information, a host that is not a DNS name or an IPv4 address, a query, a
 * fragment, dot segments, empty path segments, a non-ASCII or blank character and a broken percent escape are
 * INVALID_ARGUMENT.
 */
export function wellKnownUrl(base: string, name: (typeof WELL_KNOWN_NAMES)[number]): string {
  if (!WELL_KNOWN_NAMES.includes(name)) throw invalid('unknown well-known document name');
  if (typeof base !== 'string') throw invalid('the identifier is a string');
  if (!/^[\x21-\x7e]+$/.test(base) || base.includes('\\')) throw invalid('the identifier has an unusable character');
  if (base.includes('?') || base.includes('#')) throw invalid('the identifier has a query or a fragment');
  if (/%(?![0-9A-Fa-f]{2})/.test(base)) throw invalid('the identifier has a broken percent escape');

  const { scheme, authority, path } = splitUri(base);
  const hostAndPort = /^([A-Za-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(authority);
  if (hostAndPort === null || Number(hostAndPort[2] ?? 0) > 65_535) throw invalid('the identifier has no usable host');
  const host = (hostAndPort[1] ?? '').toLowerCase();
  if (host.length > 253 || !host.split('.').every(isHostLabel)) throw invalid('the identifier has no usable host');
  const local = host === 'localhost' || host === '127.0.0.1';
  if (!(scheme === 'https' || (scheme === 'http' && local))) throw invalid('the identifier must be an https address');

  if (path.includes('//')) throw invalid('the identifier has an empty path segment');
  if (path.split('/').some(isDotSegment)) throw invalid('the identifier has dot segments');
  const trimmed = path.endsWith('/') ? path.slice(0, -1) : path;
  return `${scheme}://${authority}/.well-known/${name}${trimmed}`;
}
