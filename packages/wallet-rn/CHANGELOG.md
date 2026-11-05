# @umis/wallet-rn

## 0.1.0-alpha.0

### Minor Changes

- [`fb2b724`](https://github.com/ishtvankomka/umis/commit/fb2b724077f58a0005e3eec9685e092488d8aae8) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Add the Expo adapters: crypto and polyfill setup, a key store with hardware keys in development builds and software keys in Expo Go, and a chunked credential store.

- [`3114b85`](https://github.com/ishtvankomka/umis/commit/3114b853ae15ad52b7ffe02db97f16cdae3ae4b7) Thanks [@ishtvankomka](https://github.com/ishtvankomka)! - Remove a credential from its last piece down with the count record last, delete pieces that a failed clean-up left behind, keep a new credential whose index write landed, fall back to a software key only when the device cannot hold a hardware key, delete hardware keys whose making was cut short, run the key calls of one alias one after the other, keep stored key text out of errors, and make `setupCrypto` fail when `installRnPolyfills` has not run.

### Patch Changes

- Updated dependencies [[`0b7e308`](https://github.com/ishtvankomka/umis/commit/0b7e308500ab426e0f3f9c11f1854afce8b5f554), [`2d3b7ff`](https://github.com/ishtvankomka/umis/commit/2d3b7ffe9352e515c65fdb413a36f0870739e9f0), [`19cc751`](https://github.com/ishtvankomka/umis/commit/19cc7518305f882dd1b7f6f5f23773f369f3632d), [`c6fe065`](https://github.com/ishtvankomka/umis/commit/c6fe065c17f8e65612ab2cbe40d4894068c5b27c), [`454e9f5`](https://github.com/ishtvankomka/umis/commit/454e9f5d46dda0e2abaeef27c00a3f2acdf4479d), [`06dd845`](https://github.com/ishtvankomka/umis/commit/06dd84579d1c77ade4f280aa6bc1bf4b2a61d6ab)]:
  - @umis/core@0.1.0-alpha.0
  - @umis/wallet@0.1.0-alpha.0
