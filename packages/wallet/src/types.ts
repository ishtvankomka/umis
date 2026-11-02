import type { CredentialOffer } from '@umis/core';

/** A credential as a wallet keeps it. This package reads `sdJwtVc` and stores nothing itself. */
export interface StoredCredential {
  id: string;
  /** The credential as issued: `<issuer-jwt>~<disclosure>~...~`, with every disclosure. */
  sdJwtVc: string;
  vct: string;
  issuer: string;
  /** The name under which the holder key lives in the key store. */
  keyAlias: string;
  /** Seconds (NumericDate) at which the wallet received the credential. */
  receivedAt: number;
  label?: string;
}

/**
 * What the holder is shown about a credential offer before accepting it, together with what is needed to redeem it. It
 * is built by `resolveOffer` from the offer and the metadata of the issuer and of its authorization server.
 */
export interface OfferView {
  /** The offer as validated: the issuer, the offered configurations and the pre-authorized-code grant. */
  offer: CredentialOffer;
  credentialIssuer: string;
  /** The offered credential configuration that the wallet takes: the first one in `dc+sd-jwt` format. */
  configurationId: string;
  vct: string;
  preAuthorizedCode: string;
  /** Present when the issuer wants a transaction code that the holder receives out of band. */
  txCode?: { length?: number; inputMode?: 'numeric' | 'text'; description?: string };
  /** Names of the offered credential in the languages the issuer published. */
  display?: Array<{ name: string; locale?: string }>;
  tokenEndpoint: string;
  credentialEndpoint: string;
  nonceEndpoint?: string;
}
