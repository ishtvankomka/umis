# @umis/core

## 0.1.0-alpha.0

### Minor Changes

- [`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add the UMIS profile, shared types and reason codes, byte encodings, WebCrypto and noble ES256 providers, JWK thumbprints and strict compact JWS.

- [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add SD-JWT VC issuance, presentation and verification primitives, authority and delegation rules, QR and BLE frames, presentation requests, and the hash-chained decision journal.

- [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Harden decoding, issuance, one-way decisions and wallet requests: varints must be minimal, `FetchLike` gains a `redirect` option, a key proof without a nonce is `invalid_proof`, a delegate cannot start before its parent, one-way decisions trust an issuer entry with several keys, and wallet requests refuse redirects.
