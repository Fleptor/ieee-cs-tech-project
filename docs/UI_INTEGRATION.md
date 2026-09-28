# Dashboard / engine integration review

Reviewed 28 September 2026 against the complete `Technical Project` directory inventory, the current repository, full CIPHER documentation, technical blueprint, general outline, technical FAQ, proposal decks and Startup Alley deck. The older image-based Orange pitch describes Python/Ansible/Dioxus; the Startup Alley deck and current source describe a different, Rust-centered prototype. Implementation follows the current source and the newer deck's emphasis on observable integration correctness.

## What changed

The browser previously attempted to connect to the router-only API-key WebSocket using a user JWT, modeled analysis locally, included fictitious network options and bypass percentages, and could report successful isolation without contacting the daemon. The backend changed device records without delivering those manual actions to the edge.

The console now uses two JWT-authenticated read endpoints:

- `GET /api/networks` returns the authenticated account and its actual memberships.
- `GET /api/dashboard/:network_id` returns that network's devices, retained telemetry, audit history, command history, sensor heartbeat, supervisor configuration and configured intelligence.

`POST /api/change_state` accepts `{network_id, mac, state}` and creates a durable administrator-only request. `state` is `allowed` or `blocked`. The database device state stays at the last confirmed value until a matching acknowledgment arrives. A newer request supersedes an older unfinished request. Reconnection replays unfinished requests and restores known blocks.

The router still sends its existing FlatBuffers reports. The server persists them and discovers devices from valid reports, because the daemon does not normally emit separate registration messages. It rejects telemetry whose network differs from its authenticated socket path. Browser sessions never receive the router key. Router credentials are currently shared across networks; per-sensor keys remain future work.

The daemon and server exchange these JSON control messages over the same authenticated WebSocket:

```json
{"type":"heartbeat","interface":"enp7s0","xdp_attached":true}
{"type":"device_command","id":123,"mac":"02:00:00:00:00:01","state":"blocked"}
{"type":"command_ack","id":123,"applied":true,"detail":""}
{"type":"edge_action","mac":"02:00:00:00:00:01","state":"blocked","reason":"Local heuristic reason"}
```

These are protocol examples, not runtime seed data. Deploy the updated daemon and server together. The older FlatBuffers command listener remains in the daemon for compatibility with older servers, but older daemons cannot acknowledge the new request protocol.

## Supporting fixes

- Enabled the JWT crypto provider; otherwise registration/login panicked at token creation.
- Login tokens use the database account identity, including when logging in by email.
- The first account owns the configured local network; owner provisioning requires the router credential.
- Corrected the C/Rust event field ordering, with a binary-layout regression test and input length checking.
- Counted all observed non-pass events as drops, instead of only legacy-protocol drops.
- Corrected an IPv6 flow-key pointer copy and made MAC lookup use the same internal-device MAC as telemetry.
- Added daemon heartbeats and explicit acknowledgments of kernel map updates; local heuristic isolation is reported as an incident.
- Removed hardcoded and LLM-generated blocklists. Intelligence is empty unless an explicit file is configured.
- Made absent supervisor credentials a handled review failure; added request timeouts and HTTP/empty-response checks.
- Replaced TLS bypass with system/explicit CA validation, supplied local startup scripts, and preserved existing team certificates.
- Removed the wholly blank prototype device row; retained meaningful existing records. No test accounts or devices are added to the installation.
- Deleted-device handling rejects blocked devices and unfinished commands; removal is not offered as a substitute for restoration.

## Validation and remaining evidence

The C program compiles with `-Wall -Werror`. Both Rust binaries build. The ABI unit test and isolated HTTPS/WebSocket integration test pass. Browser checks cover authentication errors, successful sign-in, device search, pending response persistence across reload, logout clearing, offline/recovery behavior, and layouts from 320 to 1440 pixels.

Physical daemon startup on this workstation failed with `Operation not permitted` at BPF map creation. Passwordless sudo was unavailable. Therefore live packet collection, verifier acceptance and actual packet blocking were **not** verified. The UI reports the sensor offline until a privileged daemon connects. No LLM credentials were configured, and no paid model calls were made during validation.

The source still has broader prototype constraints, including single-interface attribution, sampling, volatile baselines, and incomplete autonomous reconnect/offline recovery. These are listed in the README and are not presented as completed product capabilities.
