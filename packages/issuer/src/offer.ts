import { URI_SCHEMES, formEncode, wellKnownUrl } from '@umis/core';
import type { CredentialOffer } from '@umis/core';
import { assertUrl, invalid, isRecord, isText, own } from './profile.js';

/** The identifiers under which the issuer metadata lists the two credential types, and which offers refer to. */
export const CREDENTIAL_CONFIGURATION_IDS = {
  orgMember: 'umis-org-member-v1',
  roleAuthority: 'umis-role-authority-v1',
} as const;

const PRE_AUTHORIZED_GRANT = 'urn:ietf:params:oauth:grant-type:pre-authorized_code' as const;
/** OpenID4VCI 1.0 section 4.1.1: the description of a transaction code is at most 300 characters. */
const TX_DESCRIPTION_MAX_CHARS = 300;

interface TxCodeInput {
  length?: unknown;
  inputMode?: unknown;
  description?: unknown;
}

/** Checks the parts of an offer and puts them together in the order of the specification. */
function buildOffer(
  credentialIssuer: unknown,
  configurationIds: unknown,
  preAuthorizedCode: unknown,
  txCode: TxCodeInput | undefined,
): CredentialOffer {
  // the issuer identifier must be usable for the lookup of its metadata: https, a host, no query or fragment
  wellKnownUrl(credentialIssuer as string, 'openid-credential-issuer');
  if (!Array.isArray(configurationIds) || configurationIds.length === 0) {
    throw invalid('configurationIds must be a non-empty list');
  }
  const ids = new Set<string>();
  for (const id of configurationIds as unknown[]) {
    if (!isText(id)) throw invalid('every configuration id must be a non-empty string');
    if (ids.has(id)) throw invalid(`the configuration id "${id}" is listed twice`);
    ids.add(id);
  }
  if (typeof preAuthorizedCode !== 'string' || !/^[\x21-\x7e]+$/.test(preAuthorizedCode)) {
    throw invalid('preAuthorizedCode must be a non-empty string of visible ASCII characters');
  }

  let tx: { length?: number; input_mode?: 'numeric' | 'text'; description?: string } | undefined;
  if (txCode !== undefined) {
    const { length, inputMode, description } = txCode;
    tx = {};
    if (length !== undefined) {
      if (typeof length !== 'number' || !Number.isSafeInteger(length) || length < 1) {
        throw invalid('txCode.length must be a positive integer');
      }
      tx.length = length;
    }
    if (inputMode !== undefined) {
      if (inputMode !== 'numeric' && inputMode !== 'text')
        throw invalid('txCode.inputMode must be "numeric" or "text"');
      tx.input_mode = inputMode;
    }
    if (description !== undefined) {
      if (!isText(description) || [...description].length > TX_DESCRIPTION_MAX_CHARS) {
        throw invalid(`txCode.description must be a text of 1 to ${TX_DESCRIPTION_MAX_CHARS} characters`);
      }
      tx.description = description;
    }
  }
  return {
    credential_issuer: credentialIssuer as string,
    credential_configuration_ids: [...ids],
    grants: {
      [PRE_AUTHORIZED_GRANT]: { 'pre-authorized_code': preAuthorizedCode, ...(tx !== undefined && { tx_code: tx }) },
    },
  };
}

/**
 * A credential offer for the pre-authorized code flow (OpenID4VCI 1.0 section 4.1.1): the issuer, the credential
 * configurations on offer and the pre-authorized code, with a transaction code description when the holder must enter a
 * code that reaches them by another channel. The issuer is checked like any issuer identifier (an `https` address
 * without query or fragment, `http` for a loopback host); configuration ids must be unique.
 *
 * The offer is a value. The code behind `preAuthorizedCode`, its lifetime, its single use and the transaction code
 * itself are the issuing service's to keep.
 */
export function createCredentialOffer(i: {
  credentialIssuer: string;
  configurationIds: string[];
  preAuthorizedCode: string;
  txCode?: { length: number; inputMode?: 'numeric' | 'text'; description?: string };
}): CredentialOffer {
  const request: unknown = i;
  if (!isRecord(request)) throw invalid('the offer input must be an object');
  const txCode: unknown = i.txCode;
  if (txCode !== undefined && !isRecord(txCode)) throw invalid('txCode must be an object');
  return buildOffer(i.credentialIssuer, i.configurationIds, i.preAuthorizedCode, txCode as TxCodeInput | undefined);
}

/** Percent-encoded form fields with `%20` for a space, which every wallet decodes, `+` included or not. */
const encodeQuery = (fields: Record<string, string>): string => formEncode(fields).replaceAll('+', '%20');

/**
 * The link for an offer that travels by value (section 4.1): `openid-credential-offer://?credential_offer=<JSON>`. The
 * offer is checked again and written out with only the members of the specification.
 */
export function credentialOfferUri(offer: CredentialOffer): string {
  const given: unknown = offer;
  if (!isRecord(given)) throw invalid('the credential offer must be an object');
  const grants = own(given, 'grants');
  const grant = isRecord(grants) ? own(grants, PRE_AUTHORIZED_GRANT) : undefined;
  if (!isRecord(grant)) throw invalid('the credential offer needs the pre-authorized code grant');
  const tx = own(grant, 'tx_code');
  if (tx !== undefined && !isRecord(tx)) throw invalid('tx_code must be an object');
  const checked = buildOffer(
    own(given, 'credential_issuer'),
    own(given, 'credential_configuration_ids'),
    own(grant, 'pre-authorized_code'),
    tx === undefined
      ? undefined
      : { length: own(tx, 'length'), inputMode: own(tx, 'input_mode'), description: own(tx, 'description') },
  );
  return `${URI_SCHEMES.credentialOffer}?${encodeQuery({ credential_offer: JSON.stringify(checked) })}`;
}

/**
 * The link for an offer that the wallet fetches (section 4.1.3): `openid-credential-offer://?credential_offer_uri=<URL>`,
 * where the URL is an `https` address that serves the offer as JSON (`http` for a loopback host).
 */
export function credentialOfferUriByReference(offerUri: string): string {
  assertUrl(offerUri, 'the offer URL');
  return `${URI_SCHEMES.credentialOffer}?${encodeQuery({ credential_offer_uri: offerUri })}`;
}
