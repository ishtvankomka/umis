# @umis/transports

UMIS-BLE v1 framing, sessions and an in-memory link.

## A refused request ends in the asker's timeout

A session carries one request and one answer. When the `onRequest` handler given to `serveOverTransport` rejects,
whether the holder declined or the request could not be answered, the serving side sends nothing back and the session
ends without an answer. The asker's `requestOverTransport` then fails with `NETWORK` (`no answer within <timeoutMs> ms`)
once its timeout is over: 10 seconds unless `timeoutMs` says otherwise.

To the asker, a refused request and a lost link look the same. Choose `timeoutMs` for how long the person at the
checkpoint can wait, and report the failure as "no answer" rather than as a refusal.
