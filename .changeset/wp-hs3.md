---
'@umis/verifier': minor
'@umis/gateway': patch
'@umis/cli': patch
---

Export `observeTime` so that `verifyRelayCommand` tells a replay store without a clock of its own the time, refuse a CORS origin with a wildcard in the relay emulator and name the origin in the error, end `umis` quietly with exit code 0 when its output pipe is closed, and document the key bound, the replay id, the failure tokens of the relay client, the guarantees of the file journal and the credential scope of the emulator.
