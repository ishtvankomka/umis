---
'@umis/wallet': minor
'@umis/verifier': minor
'@umis/testkit': minor
'@umis/transports': minor
---

Refuse an OpenID4VP request that names a parameter twice or carries `transaction_data`, check verifier names for control characters without a regular expression, take the claims of the reference login from its policy, and state in the transports README that a refused request ends in the asker's `NETWORK` timeout.
