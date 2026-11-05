---
'@umis/wallet-rn': minor
---

Remove a credential from its last piece down with the count record last, delete pieces that a failed clean-up left behind, keep a new credential whose index write landed, fall back to a software key only when the device cannot hold a hardware key, delete hardware keys whose making was cut short, run the key calls of one alias one after the other, keep stored key text out of errors, and make `setupCrypto` fail when `installRnPolyfills` has not run.
