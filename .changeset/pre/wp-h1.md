---
'@umis/core': minor
'@umis/issuer': minor
'@umis/policy': minor
'@umis/registry': minor
'@umis/status-list': minor
'@umis/verifier': minor
'@umis/wallet': minor
---

Harden decoding, issuance, one-way decisions and wallet requests: varints must be minimal, `FetchLike` gains a `redirect` option, a key proof without a nonce is `invalid_proof`, a delegate cannot start before its parent, one-way decisions trust an issuer entry with several keys, and wallet requests refuse redirects.
