# @umis/gateway

## 0.1.0-alpha.0

### Minor Changes

- [`5005a86`](https://github.com/ishtvankomka/umis/commit/5005a86c92819a1068c152b72fe1d8915864c2ac) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add signed single-use relay commands bound to the request body and the relay, a Shelly Gen3 relay client with SHA-256 digest authentication, the gateway pipeline that opens a relay only on an accepted decision, a hash-chained file journal, a Shelly relay emulator, and the `umis relay-emu` command.

### Patch Changes

- [`fea26d7`](https://github.com/ishtvankomka/umis/commit/fea26d7fcd411644464b932ec799acbfb610094a) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Export `observeTime` so that `verifyRelayCommand` tells a replay store without a clock of its own the time, refuse a CORS origin with a wildcard in the relay emulator and name the origin in the error, end `umis` quietly with exit code 0 when its output pipe is closed, and document the key bound, the replay id, the failure tokens of the relay client, the guarantees of the file journal and the credential scope of the emulator.
- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`c68b4f1`](https://github.com/ishtvankomka/umis/commit/c68b4f16bb75170dbca54613c1ebc0ea0fb9eaf6), [`c6fe065`](https://github.com/ishtvankomka/umis/commit/c6fe065c17f8e65612ab2cbe40d4894068c5b27c), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d), [`fea26d7`](https://github.com/ishtvankomka/umis/commit/fea26d7fcd411644464b932ec799acbfb610094a), [`06dd845`](https://github.com/ishtvankomka/umis/commit/06dd84579d1c77ade4f280aa6bc1bf4b2a61d6ab)]:
  - @umis/core@0.1.0-alpha.0
  - @umis/verifier@0.1.0-alpha.0
