# CIPHER

The Four Horsemen / IEEE Computer Society network detection and response prototype.

CIPHER collects eBPF/XDP metadata with a Rust edge daemon, sends FlatBuffers reports over a TLS WebSocket, and analyzes them in a Rust/Axum control plane. The static operator console is served by that same server.

## Run locally

From the repository root:

```sh
make ebpf
cargo build --workspace
./scripts/run-server.sh
```

Open **https://localhost:3000**. The startup script creates a development certificate in `.local/`; your browser must trust that certificate (or accept it for this local development site). It does not replace the team's existing certificates. The server binds to localhost by default.

In a second terminal, start the sensor:

```sh
sudo ./scripts/run-daemon.sh
```

The daemon requires BPF/network privileges. Its default interface is `enp7s0`; select another with `sudo env CIPHER_INTERFACE=YOUR_INTERFACE ./scripts/run-daemon.sh`. Run the server first. Ctrl-C stops the daemon and detaches its XDP link.

Both components load the repository `.env`. They must share `ROUTER_SECRET`; the server also needs `JWT_SECRET`. Do not expose either secret to the browser. For another machine, configure `CIPHER_SERVER_URL` and `CIPHER_CA_CERT` on the daemon. Certificate and hostname validation are enabled.

On a fresh database, choose **Sign in → Create an account**. The first account becomes administrator of `CIPHER_NETWORK_ID` (default `NET_123`). Later accounts require explicit network assignment. No sample accounts, devices, traffic, or threat indicators are created.

## Operator console

- **Overview:** observed devices, reported payload/drop counts, traffic history, recent findings and responses.
- **Devices:** search, state filters, CSV export, and isolate/restore requests. Only administrators may request state changes.
- **Incidents:** persisted statistical alerts, supervisor reviews, and local edge isolation events.
- **Threat intelligence:** explicitly configured indicators, never generated examples.
- **Engine health:** sensor heartbeat, reported XDP attachment, interface, telemetry freshness, baseline progress and supervisor configuration.

The browser reads an authenticated snapshot every three seconds. The sensor reports every ten seconds. Device state changes only after an acknowledgment from the daemon; pending, sent, applied, failed, and superseded requests remain visible. Pending requests replay when the sensor reconnects. A map acknowledgment establishes that the map operation succeeded; packet-level enforcement still requires a hardware test.

## Configuration

| Variable | Purpose / default |
| --- | --- |
| `CIPHER_NETWORK_ID` | Sensor network and first-account assignment; `NET_123` |
| `CIPHER_INTERFACE` | Sensor interface; `enp7s0` |
| `CIPHER_BIND` | Server listen address; `127.0.0.1:3000` |
| `CIPHER_DB` | Server SQLite file; `cipher.db` relative to server working directory |
| `CIPHER_SERVER_URL` | Daemon server; `wss://localhost:3000` |
| `CIPHER_TLS_CERT`, `CIPHER_TLS_KEY` | Server certificate paths; set by startup script |
| `CIPHER_CA_CERT` | Daemon trust certificate; set by startup script |
| `CIPHER_THREAT_INTEL_FILE` | Optional JSON file with `banned_ips` and `ad_domains` arrays; defaults empty |
| `LLM_API_KEY`, `LLM_MODEL` | Optional supervisor credentials/model; not needed for dashboard or statistical screening |

The existing SQLx compile-time queries require `DATABASE_URL` pointing to a SQLite database containing the original schema. The repository's current development configuration provides that database.

## Verify

```sh
make ebpf
cargo build --workspace
cargo test --workspace
python tests/integration.py
node --check ui-dashboard/app.js
```

The integration test starts an isolated HTTPS server on port 3001 with a temporary database. It exercises authentication, bootstrap, network authorization, real FlatBuffers ingestion over WebSocket, command acknowledgments, failures and reconnect replay. It requires `flatc` but no Python packages. `--serve` retains that disposable server for browser checks until Ctrl-C.

## Current limits

- XDP attachment and actual packet blocking need privileged hardware validation. The default single-interface mapping observes ingress as WAN traffic; a two-interface gateway configuration and bidirectional attribution remain separate engine work.
- Fast-path sampling and early kernel drops mean telemetry is not a full wire-rate packet counter. The UI labels metrics as observations and does not invent throughput or bypass percentages.
- Telemetry is retained for 24 hours; the console shows at most 5,000 reports from the last hour. Audit and response histories show the latest 100 entries.
- The daemon exits and detaches on cloud disconnection; restart it to reconnect. Durable command replay is implemented, but automatic sensor reconnect and full offline telemetry recovery still need work.
- Hostnames, manufacturers and internal IP addresses are unavailable unless a sensor registration supplies them. The UI shows missing values explicitly.
- Statistical baselines are in memory and need 50 reports per device after reconnection. Supervisor responses and detection accuracy have not been validated against real attacks.

See [the integration review](docs/UI_INTEGRATION.md) for implementation details and the reviewed project material.
