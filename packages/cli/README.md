# @umis/cli

The `umis` command-line tool: a demo of the hero scenario, offline verification and inspection of QR frames, key
generation and an emulator of a Shelly Gen3 relay.

| Command                                                                                  | What it does                                                             |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `umis demo [--steps 1,2,3] [--qr] [--json]`                                              | runs hero steps 1 to 3 on the demo world and prints a table              |
| `umis verify (--demo <org>:<policy> \| --context <file>) [--now <epoch>] [<frame> \| -]` | decides whether a one-way or full QR frame is accepted, offline          |
| `umis inspect [<text> \| -]`                                                             | tells what a QR text, link or token is and decodes it, verifying nothing |
| `umis keygen --out <dir>`                                                                | makes a P-256 key pair and prints the public key, key id and fingerprint |
| `umis relay-emu --trust <file> [options]`                                                | runs an emulator of a relay that obeys only signed commands              |

Run `umis <command> --help` for the options.

## Try it from a clone

```sh
pnpm install
pnpm build
pnpm -F cli exec umis demo
pnpm -F cli exec umis demo --steps 1 --qr
```

`umis demo` prints a row for every decision (step, actor, decision, reason, milliseconds, characters of the QR text).
`umis verify --demo kovorking-v:door_low --now 1793606400 -` decides on a one-way frame read from standard input, with
the demo door of the coworking space, at the given time; a saved verifier context from `serializeVerifierContext` takes
the place of `--demo` as `--context <file>`.

## Exit codes

| Code | Meaning                                                                                             |
| ---- | --------------------------------------------------------------------------------------------------- |
| 0    | success: every row of the demo is as expected, the frame is accepted, the text is decoded           |
| 2    | the answer asked for is no: an unexpected demo row, a rejected frame, a text that cannot be decoded |
| 64   | a mistake in the arguments or in a file they name                                                   |
| 1    | any other failure                                                                                   |

## Keys

`umis keygen` writes `key.private.jwk.json` (readable by its owner only) and `key.public.jwk.json`, and never prints the
private key. It does not overwrite existing files. Environment variables, where a command takes one, are named, never
passed as values.
