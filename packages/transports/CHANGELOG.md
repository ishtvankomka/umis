# @umis/transports

## 0.1.0-alpha.0

### Minor Changes

- [`c6fe065`](https://github.com/ishtvankomka/umis/commit/c6fe065c17f8e65612ab2cbe40d4894068c5b27c) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add OpenID4VP 1.0 helpers (DCQL query, request by value with a redirect_uri client id, direct_post response check and wallet reply) to the verifier and the wallet under `./oid4vp`, and a transports package with MTU chunking, a size-capped reassembler, an in-memory link and a one-request, one-answer session.

- [`06dd845`](https://github.com/ishtvankomka/umis/commit/06dd84579d1c77ade4f280aa6bc1bf4b2a61d6ab) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Refuse an OpenID4VP request that names a parameter twice or carries `transaction_data`, check verifier names for control characters without a regular expression, take the claims of the reference login from its policy, and state in the transports README that a refused request ends in the asker's `NETWORK` timeout.

### Patch Changes

- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d)]:
  - @umis/core@0.1.0-alpha.0
