# @umis/cli

## 0.1.0-alpha.0

### Minor Changes

- [`5005a86`](https://github.com/ishtvankomka/umis/commit/5005a86c92819a1068c152b72fe1d8915864c2ac) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add signed single-use relay commands bound to the request body and the relay, a Shelly Gen3 relay client with SHA-256 digest authentication, the gateway pipeline that opens a relay only on an accepted decision, a hash-chained file journal, a Shelly relay emulator, and the `umis relay-emu` command.

- [`501b310`](https://github.com/ishtvankomka/umis/commit/501b31070645c3c2e2b84c9d063b218814a8bc4e) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add the deterministic demo world with a simulated clock, the runner for steps 1 to 3 of the hero scenario and the public test vectors of the profile to the testkit, and the `umis demo`, `umis verify`, `umis inspect` and `umis keygen` commands.

- [`09525d5`](https://github.com/ishtvankomka/umis/commit/09525d5949e035f337db776f32729b0d0d7d2799) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add the benchmark runner (`runBench`, `benchReport`) and `umis bench`, which time the decision of the verifier in seven scenarios and play the autonomy and revocation timelines on a simulated clock, and add step 4 of the hero scenario, an OpenID4VP login at an intranet.

- [`a8477a7`](https://github.com/ishtvankomka/umis/commit/a8477a7c747edf980361e7c7d14110836b71bc73) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Report the mean of the per-repeat p95 as `p95Mean` and leave `p95Ci95` and `meanCi95` without an interval (`null`) for a single repeat, add the `P95 REP` column, the `n/a` interval and the notes for the rows that are not one decision alone to `umis bench`, and record the commit of a benchmark run only inside this repository's work tree.

### Patch Changes

- [`fea26d7`](https://github.com/ishtvankomka/umis/commit/fea26d7fcd411644464b932ec799acbfb610094a) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Export `observeTime` so that `verifyRelayCommand` tells a replay store without a clock of its own the time, refuse a CORS origin with a wildcard in the relay emulator and name the origin in the error, end `umis` quietly with exit code 0 when its output pipe is closed, and document the key bound, the replay id, the failure tokens of the relay client, the guarantees of the file journal and the credential scope of the emulator.
- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`3f84085`](https://github.com/ishtvankomka/umis/commit/3f8408517a9703aa5acc6c0dd01ab50741339491), [`20adc81`](https://github.com/ishtvankomka/umis/commit/20adc8173d57fb47e950b08828c48fae9f41a329), [`146f95c`](https://github.com/ishtvankomka/umis/commit/146f95caa74a4e2883b6bb76a073f730a2b46ee4), [`c68b4f1`](https://github.com/ishtvankomka/umis/commit/c68b4f16bb75170dbca54613c1ebc0ea0fb9eaf6), [`19cc751`](https://github.com/ishtvankomka/umis/commit/19cc7518305f882dd1b7f6f5f23773f369f3632d), [`5005a86`](https://github.com/ishtvankomka/umis/commit/5005a86c92819a1068c152b72fe1d8915864c2ac), [`501b310`](https://github.com/ishtvankomka/umis/commit/501b31070645c3c2e2b84c9d063b218814a8bc4e), [`c6fe065`](https://github.com/ishtvankomka/umis/commit/c6fe065c17f8e65612ab2cbe40d4894068c5b27c), [`09525d5`](https://github.com/ishtvankomka/umis/commit/09525d5949e035f337db776f32729b0d0d7d2799), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d), [`fea26d7`](https://github.com/ishtvankomka/umis/commit/fea26d7fcd411644464b932ec799acbfb610094a), [`06dd845`](https://github.com/ishtvankomka/umis/commit/06dd84579d1c77ade4f280aa6bc1bf4b2a61d6ab), [`a8477a7`](https://github.com/ishtvankomka/umis/commit/a8477a7c747edf980361e7c7d14110836b71bc73)]:
  - @umis/core@0.1.0-alpha.0
  - @umis/status-list@0.1.0-alpha.0
  - @umis/policy@0.1.0-alpha.0
  - @umis/registry@0.1.0-alpha.0
  - @umis/issuer@0.1.0-alpha.0
  - @umis/verifier@0.1.0-alpha.0
  - @umis/wallet@0.1.0-alpha.0
  - @umis/gateway@0.1.0-alpha.0
  - @umis/testkit@0.1.0-alpha.0
