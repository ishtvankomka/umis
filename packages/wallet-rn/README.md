# @umis/wallet-rn

React Native and Expo adapters for the UMIS wallet: the cryptographic setup, a key store and a credential store. It
runs in Expo Go and in development builds, and it is the only package of the SDK that touches the phone: the frames,
requests and OpenID4VCI client live in `@umis/wallet`.

- **Key store**: holder keys in the Secure Enclave (iOS) or in StrongBox / the Trusted Execution Environment (Android)
  where the device has them, in the operating system's secret store everywhere else. Every key signs ES256 and
  reports how it is protected.
- **Credential store**: SD-JWT VCs in the secret store of the device, cut into pieces that fit one value.
- **Setup**: picks WebCrypto or the audited `@noble` libraries for the runtime and adds the one global that some
  React Native runtimes lack.

## Install

```sh
npm install @umis/wallet-rn @umis/core @umis/wallet
npx expo install expo-secure-store expo-crypto
```

`expo` (version 58 and up), `expo-secure-store`, `expo-crypto` and `react-native` are peer dependencies of the app. For
hardware keys in a development build add the optional peer `@animo-id/expo-secure-environment`; an app that does not
install it bundles and runs, and its keys are software keys.

## App setup

Run this once at start-up, before any other call of the SDK:

```ts
import { isRunningInExpoGo } from 'expo';
import * as ExpoCrypto from 'expo-crypto';
import { createKeyStore, installRnPolyfills, setupCrypto } from '@umis/wallet-rn';

installRnPolyfills();
setupCrypto({ getRandomValues: ExpoCrypto.getRandomValues });
export const keys = createKeyStore(isRunningInExpoGo() ? 'expo_go' : 'dev_client', { authenticate });
```

`authenticate(prompt)` shows the biometric prompt and resolves to `true` only when the person was recognised. It is
needed for software keys made with `requireBiometric` (see below); with `expo-local-authentication`:

```ts
import * as LocalAuthentication from 'expo-local-authentication';

const authenticate = async (promptMessage: string): Promise<boolean> =>
  (await LocalAuthentication.authenticateAsync({ promptMessage })).success;
```

## What works where

|                            | Development build                                                                                                                         | Expo Go                                        |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| Where new keys are made    | Secure Enclave, StrongBox or Trusted Execution Environment; a software key on a device without them (the iOS Simulator, Android below 11) | secret store of the device (software key)      |
| `protection` of the signer | `'hardware'`, or `'software'` for the fallback                                                                                            | `'software'`                                   |
| Private key                | never leaves the secure hardware                                                                                                          | held by the app while it signs                 |
| Biometric confirmation     | enforced by the secure hardware; the key is invalidated when the enrolled biometrics change                                               | `authenticate` is asked before every signature |
| Native module              | `@animo-id/expo-secure-environment` (optional)                                                                                            | none                                           |
| Key attestation            | none (`attestation: 'none'`)                                                                                                              | none                                           |
| Random numbers and SHA-256 | WebCrypto if the runtime has it, else `@noble` with `expo-crypto`                                                                         | `@noble` with `expo-crypto`                    |

## Key store

```ts
const signer = await keys.create('holder-oleh-1', { requireBiometric: true, prompt: 'Confirm to use your pass' });
signer.protection; // 'hardware' | 'software'
signer.publicJwk; //  P-256 public key, with the RFC 7638 thumbprint as kid
await signer.sign(bytes); // ES256 signature r‖s, 64 bytes; pass the signer to @umis/wallet

await keys.get('holder-oleh-1'); // the signer again, or null
await keys.remove('holder-oleh-1');
```

- An alias is 1 to 64 characters of `A-Z a-z 0-9 _ -`. `create` refuses an alias that is taken: a key is never
  replaced. `remove` of an alias that does not exist does nothing.
- In a development build `create` makes a hardware key. When the module is missing, the device has no suitable
  hardware, the person has no biometrics enrolled for a key that needs them, or the module fails, the key is made in
  software instead and `protection` says so. Hardware means the Secure Enclave, StrongBox or the Trusted Execution
  Environment; anything weaker counts as software.
- A software key is stored under `umis.key.<alias>`, readable only while the device is unlocked and never copied to
  another device. The signer keeps no secret: each signature reads the key, so it is released only after the
  confirmation, and a removed key signs no more.
- With `requireBiometric` a software key awaits `authenticate(prompt)` before every signature. `false`, a rejection or
  any answer other than `true` fails with `USER_CANCELLED`. `create` without an `authenticate` function fails with
  `INVALID_ARGUMENT`. A hardware key leaves the confirmation to the hardware and never calls `authenticate`.
- Failures are `UmisError`s: `INVALID_ARGUMENT`, `USER_CANCELLED`, `KEY_NOT_FOUND` (the key is gone or was
  invalidated), `CRYPTO_UNAVAILABLE`.

## Credential store

```ts
import { createCredentialStore } from '@umis/wallet-rn';

const credentials = createCredentialStore(); // { namespace, chunkChars } are optional
await credentials.put(storedCredential); //     StoredCredential from @umis/wallet
await credentials.list();
await credentials.get(id);
await credentials.remove(id);
```

A credential is JSON, UTF-8 and base64url, cut into pieces of 1 800 characters so that each stays below the 2 048
bytes that the platform stores accept for one value. Piece `n` of credential `id` is `umis.cred.<id>.<n>`, or
`umis.cred.<id>.b<n>` in the second of two sets of pieces. The record `umis.cred.<id>.n` holds the number of pieces,
followed by `b` when the second set is the one in use, and the ids are listed in `umis.creds.index`. A new credential
is written piece by piece, then its count, then the index; it exists once its id is in the index, so a write that fails
leaves the list as it was. A credential that replaces a stored one goes to the set that the record does not name, and
writing the record is what makes it the credential, so a write that fails or is cut short leaves the stored credential
as it was, never a mixture of the two. The old pieces are deleted afterwards. Removing goes the other way: the index
first.

- Ids are 1 to 64 characters of `A-Z a-z 0-9 _ -`. The namespace (default `umis`) replaces the `umis` prefix of every
  key and has the same alphabet, up to 32 characters.
- The index is one value, so it can list about fifty credentials with UUID ids.
- `list` returns the credentials in the order they were first stored and skips one that cannot be read; `get` of such
  a credential fails with `MALFORMED`, and `remove` clears it.
- Operations of a namespace run one after the other, so concurrent `put`s never lose each other's index entry.

## Setup details

`setupCrypto` uses WebCrypto when `globalThis.crypto.subtle` exists and the `@noble` provider of `@umis/core/noble`
otherwise, with the random numbers of the function you pass (default: `expo-crypto`), and makes it the default of the
SDK. It returns the provider.

`installRnPolyfills` adds a UTF-8 `TextDecoder` with the `fatal` option to runtimes that have none, which the SD-JWT
library needs. A runtime that has one keeps it, and calling the function twice changes nothing. Streaming decoding is
not offered.

## Security notes

- A software key lives in the Keychain (iOS) or in Keystore-encrypted storage (Android) behind the secret store, and
  the app process holds it while a signature is made. Code that runs in the app, or a rooted or jailbroken device, can
  read it. `requireBiometric` for a software key is a confirmation the app asks for, not one the hardware enforces.
- A hardware key never leaves the secure hardware, and with `requireBiometric` the hardware refuses to sign without a
  biometric confirmation.
- Keys are not attested: `protection` is what the app reports about its own key, and a verifier cannot check it.
- Nothing is written to the console, and neither key material nor credentials go anywhere but the secret store.
