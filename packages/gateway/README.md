# @umis/gateway

Relay commands, Shelly Gen3 RPC client and the gateway decision pipeline.

## Relay emulator: what needs credentials

`startShellyEmulator` (entry `@umis/gateway/node`, and `umis relay-emu` in `@umis/cli`) stands in for a Shelly Gen3
relay with one switch. Only `Switch.Set` needs the signed relay command in `X-Umis-Command` and, when
`digestPasswordEnv` names the variable that holds a password, Shelly digest authentication as well.
`Switch.GetStatus` and `Shelly.GetDeviceInfo` answer without either, so that the status page at `/` can poll the
switch without holding any credential; neither call changes the switch. A real Shelly with authentication enabled asks
for the digest on its status calls too, so a client that reads the status of a real relay has to send the digest there.
