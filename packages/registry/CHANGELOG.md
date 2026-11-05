# @umis/registry

## 0.1.0-alpha.0

### Minor Changes

- [`20adc81`](https://github.com/ishtvankomka/umis/commit/20adc8173d57fb47e950b08828c48fae9f41a329) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add checkpoint policies with risk-class caps, a JSON Schema, signed envelopes, presets and a per-period authority ledger, and the trusted-issuer registry with signed snapshots and issuer resolution.

- [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Harden decoding, issuance, one-way decisions and wallet requests: varints must be minimal, `FetchLike` gains a `redirect` option, a key proof without a nonce is `invalid_proof`, a delegate cannot start before its parent, one-way decisions trust an issuer entry with several keys, and wallet requests refuse redirects.

### Patch Changes

- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d)]:
  - @umis/core@0.1.0-alpha.0
