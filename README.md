# CIPHER

The Four Horsemen / IEEE Computer Society network detection and response prototype.

CIPHER collects eBPF/XDP metadata with a Rust sensor, sends acknowledged FlatBuffers reports over a TLS WebSocket, and analyzes them in a Rust/Axum control plane. The server also serves the operator dashboard.

## Start here

- [Booth setup, provider configuration, scenario hooks and recovery](docs/BOOTH_RUNBOOK.md)
- [Readiness audit, delivered features and remaining limits](docs/BOOTH_READINESS.md)
- [Earlier dashboard integration review](docs/UI_INTEGRATION.md)

From the repository root:

```sh
bash setup.sh --demo
python3 scripts/booth.py start
```

Open **https://localhost:3100**. The terminal gives the path to the disposable operator credentials. This is a **labeled simulation** with an offline deterministic supervisor fixture, not an AI model. The real backend performs statistical analysis, persists incidents, and delivers commands to the simulated sensor. In another terminal:

```sh
python3 scripts/booth.py hook scan
python3 scripts/booth.py hook trust
python3 scripts/booth.py hook enforce
python3 scripts/booth.py hook scan
python3 scripts/booth.py hook reset
```

Use `start --llm configured` for real provider calls using `.local/cipher.env`, or `start --llm off` to show statistical alerts without a supervisor. Each start creates a separate session/database on local temporary storage. Ctrl-C stops its processes. Neither scenario runner nor fixture blocks real packets.

## Live sensor

```sh
bash setup.sh
./scripts/run-server.sh
# In a second terminal, choose the interface on your isolated test network:
sudo env CIPHER_INTERFACE=YOUR_INTERFACE ./scripts/run-daemon.sh
```

Open **https://localhost:3000** and create the first operator account. That account becomes administrator of `CIPHER_NETWORK_ID`. Runtime credentials, certificates, databases and logs are stored locally and excluded from Git. New setup creates random secrets in `.local/cipher.env`; it does not import the previously tracked development credentials. SQLx no longer requires a database at build time.

The server binds to localhost by default. The daemon verifies the TLS certificate. See the runbook for another-machine configuration and trust setup.

## Operator controls

- **Devices:** permanently trust/revoke trust, manually isolate/restore, reset a saved baseline, and export the inventory.
- **Trust:** retain monitoring and alerts while exempting a device from automatic cloud and edge isolation. Trust also queues restoration of an existing MAC block. Explicit manual isolation remains possible.
- **Engine health:** switch between monitor/alert and automatic isolation, inspect policy acknowledgment, inspect provider errors and successful review time, test the LLM connection, and export retained telemetry.
- **Incidents:** detection evidence, supervisor status, response reason, and resolve/false-positive/reopen controls.
- **Operator activity:** persisted policy changes and incident reviews.
- **Recovery:** saved baselines, persistent trust/local blocks, reconnecting sensor, bounded telemetry outbox, acknowledgments, deduplicated delivery retries, and command retries with visible failure states.

Monitor/alert is the default response policy. It controls **automatic device isolation**; existing blocks and kernel packet-level filters remain active. Cloud auto-isolation requires enforcement mode, an untrusted device, an open incident, an unchanged policy revision, at least two statistical signals, and a supervisor recommendation with confidence at least 85/100. Model confidence is self-reported and is not a measured probability.

## Configuration

Edit `.local/cipher.env`; restart both components after changing their environment settings. External environment variables override that file.

| Variable | Purpose |
| --- | --- |
| `CIPHER_NETWORK_ID` | Sensor network / first-account assignment; default `NET_123` |
| `CIPHER_INTERFACE` | Sensor interface; default `enp7s0` |
| `CIPHER_ENV_FILE` | Explicit environment file; set by startup scripts |
| `CIPHER_BIND` | Server address; default `127.0.0.1:3000` |
| `CIPHER_DB`, `CIPHER_ROUTER_DB` | Database paths; startup scripts use `.local/` |
| `CIPHER_SERVER_URL` | Sensor's server, e.g. `wss://localhost:3000` |
| `CIPHER_TLS_CERT`, `CIPHER_TLS_KEY`, `CIPHER_CA_CERT` | TLS server certificate, private key, and sensor trust certificate |
| `CIPHER_THREAT_INTEL_FILE` | Optional JSON with `banned_ips` and `ad_domains`; empty by default |
| `LLM_PROVIDER` | `anthropic` or `openai` (Chat Completions compatible) |
| `LLM_MODEL`, `LLM_API_KEY` | Explicit model ID and provider key; optional for statistical screening |
| `LLM_BASE_URL` | Provider `/v1` base URL; HTTPS required except loopback |
| `LLM_TOKEN_PARAMETER` | `max_completion_tokens` by default; `max_tokens` for compatible servers that require it |
| `LLM_TIMEOUT_SECONDS` | Provider deadline, default 20 seconds |
| `CIPHER_ALERT_COOLDOWN_SECONDS` | Per-device alert/review cooldown, default 120 seconds |

## Verify

```sh
make ebpf
cargo build --workspace --locked
cargo test --workspace
cargo test -p daemon transport_reconnects -- --ignored
python3 tests/integration.py
python3 tests/supervisor.py
node --check ui-dashboard/app.js
```

The transport test requires the built backend and OpenSSL. It restarts a real local TLS server and verifies that the daemon transport replays its durable outbox. Python checks use isolated databases and local provider fixtures; they make no paid calls. FlatBuffers Rust bindings were generated with **flatc 25.12.19**, matching the pinned runtime. Use that compiler version if regenerating with `make flatbuffers`.

## Current limits

- Real XDP attachment and packet blocking still require a privileged hardware rehearsal. A daemon map acknowledgment proves the map update, not packet-level enforcement.
- The default mapping uses one interface and observes ingress as WAN traffic. Bidirectional gateway attribution remains incomplete.
- Counters represent sampled packet observations and payload bytes, not complete connection counts or throughput. Existing protocol/IP/domain filters can drop individual packets even in monitor mode or for a trusted device.
- Detection uses four statistical features and 50 representative training reports. Accuracy has not been established against real attacks; no accuracy claims are made.
- Live provider credentials and account/model availability must be checked with **Test LLM connection** before the booth.
- Telemetry retention is 24 hours; dashboard history is capped at 5,000 reports and export at 10,000. The sensor outbox retains at most 10,000 reports, dropping the oldest with a log message if full.
- Report retries are deduplicated after successful ingestion. A process crash between ingest and receipt persistence can still duplicate a report. Historical reports older than 60 seconds are stored without driving current isolation decisions.
- Router authentication still uses a shared secret. Per-sensor credentials, broader rate limiting, model evaluation, and authenticated device identity beyond MAC addresses remain future work.
