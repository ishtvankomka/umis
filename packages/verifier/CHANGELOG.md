# @umis/verifier

## 0.1.0-alpha.0

### Minor Changes

- [`c68b4f1`](https://github.com/ishtvankomka/umis/commit/c68b4f16bb75170dbca54613c1ebc0ea0fb9eaf6) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add the nine-step offline decision for one-way, full, reverse and mutual presentations over QR and Bluetooth, with request creation, a replay store, member-cache entries, decision events and serialisable verifier contexts.

- [`c6fe065`](https://github.com/ishtvankomka/umis/commit/c6fe065c17f8e65612ab2cbe40d4894068c5b27c) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add OpenID4VP 1.0 helpers (DCQL query, request by value with a redirect_uri client id, direct_post response check and wallet reply) to the verifier and the wallet under `./oid4vp`, and a transports package with MTU chunking, a size-capped reassembler, an in-memory link and a one-request, one-answer session.

- [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Harden decoding, issuance, one-way decisions and wallet requests: varints must be minimal, `FetchLike` gains a `redirect` option, a key proof without a nonce is `invalid_proof`, a delegate cannot start before its parent, one-way decisions trust an issuer entry with several keys, and wallet requests refuse redirects.

- [`fea26d7`](https://github.com/ishtvankomka/umis/commit/fea26d7fcd411644464b932ec799acbfb610094a) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Export `observeTime` so that `verifyRelayCommand` tells a replay store without a clock of its own the time, refuse a CORS origin with a wildcard in the relay emulator and name the origin in the error, end `umis` quietly with exit code 0 when its output pipe is closed, and document the key bound, the replay id, the failure tokens of the relay client, the guarantees of the file journal and the credential scope of the emulator.

- [`06dd845`](https://github.com/ishtvankomka/umis/commit/06dd84579d1c77ade4f280aa6bc1bf4b2a61d6ab) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Refuse an OpenID4VP request that names a parameter twice or carries `transaction_data`, check verifier names for control characters without a regular expression, take the claims of the reference login from its policy, and state in the transports README that a refused request ends in the asker's `NETWORK` timeout.

### Patch Changes

- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`3f84085`](https://github.com/ishtvankomka/umis/commit/3f8408517a9703aa5acc6c0dd01ab50741339491), [`20adc81`](https://github.com/ishtvankomka/umis/commit/20adc8173d57fb47e950b08828c48fae9f41a329), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d)]:
  - @umis/core@0.1.0-alpha.0
  - @umis/status-list@0.1.0-alpha.0
  - @umis/policy@0.1.0-alpha.0
  - @umis/registry@0.1.0-alpha.0
