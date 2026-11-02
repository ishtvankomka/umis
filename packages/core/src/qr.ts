import { frameKindOf } from './frame.js';
import { URI_SCHEMES, type FrameKind } from './profile.js';

export type QrKind =
  | 'credential_offer'
  | 'oid4vp_request'
  | 'umis_oneway'
  | 'umis_full'
  | 'umis_request'
  | 'umis_response'
  | 'umis_mutual_init'
  | 'umis_mutual_reply'
  | 'unknown';

const FRAME_QR_KIND: Readonly<Record<FrameKind, QrKind>> = {
  oneway: 'umis_oneway',
  full: 'umis_full',
  request: 'umis_request',
  response: 'umis_response',
  mutual_init: 'umis_mutual_init',
  mutual_reply: 'umis_mutual_reply',
};

/** URI schemes are case-insensitive, and QR alphanumeric mode is upper case only. */
function startsWithScheme(text: string, scheme: string): boolean {
  return text.slice(0, scheme.length).toLowerCase() === scheme;
}

/**
 * Tells what the text of a scanned QR code is, by its start alone: an OpenID4VCI credential offer, an OpenID4VP
 * request, one of the six UMIS frames, or unknown. Surrounding whitespace is ignored. Nothing is decoded or checked.
 */
export function classifyQr(text: string): QrKind {
  if (typeof text !== 'string') return 'unknown';
  const trimmed = text.trim();
  if (startsWithScheme(trimmed, URI_SCHEMES.credentialOffer)) return 'credential_offer';
  if (startsWithScheme(trimmed, URI_SCHEMES.vpRequest)) return 'oid4vp_request';
  const kind = frameKindOf(trimmed);
  return kind === undefined ? 'unknown' : FRAME_QR_KIND[kind];
}
