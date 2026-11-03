import { parseArgs } from 'node:util';
import {
  LIMITS,
  UmisError,
  base64urlDecode,
  classifyQr,
  decodeFrame,
  decodeJwsUnverified,
  encodeFrameBytes,
  parseQuery,
  splitUri,
  utf8Decode,
} from '@umis/core';
import { EXIT, inputText, runCommand } from './common.js';
import type { CommandIo } from './common.js';

export const INSPECT_USAGE = `usage: umis inspect [<text> | -]

Tells what a piece of text is and decodes it, without checking anything: a UMIS QR frame, an OpenID4VP request or
OpenID4VCI offer link, an SD-JWT credential or presentation, or a compact JWS. Prints the kind, the sizes, the headers,
the payloads and the disclosures as JSON. Nothing is verified, so nothing printed is to be trusted.
Give - (or nothing, with the text piped in) to read the text from standard input.

options:
  -h, --help  show this text

Exit code 0 when the text could be decoded, 2 when it could not, 64 for a mistake in the arguments.`;

type Json = Record<string, unknown>;

const JWS_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

function jws(token: string): Json {
  const { header, payload } = decodeJwsUnverified(token);
  return { type: 'jws', chars: token.length, header, payload };
}

function disclosure(raw: string): Json {
  const parsed: unknown = JSON.parse(utf8Decode(base64urlDecode(raw)));
  if (!Array.isArray(parsed) || (parsed.length !== 2 && parsed.length !== 3)) {
    throw new UmisError('MALFORMED', 'a disclosure is an array of two or three members');
  }
  const [salt, ...rest] = parsed as unknown[];
  return rest.length === 2 ? { salt, name: rest[0], value: rest[1] } : { salt, value: rest[0] };
}

/** An SD-JWT: `<issuer JWT>~<disclosure>~…~<disclosure>~[<key-binding JWT>]`. */
function sdJwt(token: string): Json {
  const pieces = token.split('~');
  const keyBinding = pieces[pieces.length - 1] ?? '';
  const issuer = decodeJwsUnverified(pieces[0] ?? '');
  return {
    type: 'sd-jwt',
    chars: token.length,
    issuerJwt: { header: issuer.header, payload: issuer.payload },
    disclosures: pieces.slice(1, -1).map(disclosure),
    keyBinding: keyBinding === '' ? null : jws(keyBinding),
  };
}

function token(text: string): Json {
  return text.includes('~') ? sdJwt(text) : jws(text);
}

/** The value of a link parameter: a JWS or a JSON document is decoded, anything else is kept as it is. */
function parameter(value: string): unknown {
  if (JWS_SHAPE.test(value)) {
    try {
      return jws(value);
    } catch {
      return value;
    }
  }
  if (value.startsWith('{') || value.startsWith('[')) {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function link(kind: string, text: string): Json {
  const { scheme, authority, path, query } = splitUri(text);
  const parameters = Object.entries(parseQuery(query)).map(([name, value]) => [name, parameter(value)] as const);
  return {
    kind,
    verified: false,
    chars: text.length,
    scheme,
    address: `${authority}${path}`,
    parameters: Object.fromEntries(parameters),
  };
}

function frame(kind: string, text: string): Json {
  const decoded = decodeFrame(text);
  return {
    kind,
    verified: false,
    chars: text.length,
    maxChars: LIMITS.qrMaxChars,
    bleBytes: encodeFrameBytes(decoded).length,
    tokens: decoded.tokens.map(token),
  };
}

/** Decodes `text` by what it looks like; `undefined` when it looks like nothing the tool reads. */
function describe(text: string): Json | undefined {
  const kind = classifyQr(text);
  if (kind === 'oid4vp_request' || kind === 'credential_offer') return link(kind, text);
  if (kind !== 'unknown') return frame(kind, text);
  if (text.includes('~') || JWS_SHAPE.test(text)) {
    const { type, ...decoded } = token(text);
    return { kind: type === 'sd-jwt' ? 'sd_jwt' : 'jws', verified: false, ...decoded };
  }
  return undefined;
}

/**
 * `umis inspect`: classifies a text and prints it decoded, with its sizes, as JSON. Returns 0 when the text could be
 * decoded, 2 when it could not, 64 for a mistake in the arguments.
 */
export async function inspect(args: readonly string[], io: CommandIo): Promise<number> {
  return runCommand('inspect', io, async () => {
    const { values, positionals } = parseArgs({
      args: [...args],
      allowPositionals: true,
      strict: true,
      options: { help: { type: 'boolean', short: 'h' } },
    });
    if (values.help === true) {
      io.out(INSPECT_USAGE);
      return EXIT.ok;
    }
    const text = await inputText(positionals, io, 'the text to inspect');
    let described: Json | undefined;
    try {
      described = describe(text);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      io.err(`umis inspect: cannot decode the text (${reason})`);
      return EXIT.rejected;
    }
    if (described === undefined) {
      io.err('umis inspect: the text is not a UMIS frame, an OpenID4VP or OpenID4VCI link, an SD-JWT or a compact JWS');
      return EXIT.rejected;
    }
    io.out(JSON.stringify(described, null, 2));
    return EXIT.ok;
  });
}
