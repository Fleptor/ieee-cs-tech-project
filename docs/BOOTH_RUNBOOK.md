# CIPHER booth setup and scenarios

## 1. Prerequisites

Use Linux for the physical eBPF sensor. Install Rust/Cargo with Rust 2024 edition support, a C/C++ compiler toolchain, CMake, pkg-config, OpenSSL development headers, Python 3, OpenSSL CLI, and `flatc`. Live eBPF compilation additionally needs Clang with the BPF target, Linux headers and libbpf headers. Node.js is used for the JavaScript syntax check.

Generated Rust FlatBuffers bindings are committed and use runtime 25.12.19. Regenerating them requires flatc 25.12.19; normal builds do not regenerate them. The booth's JSON-to-binary generation uses `flatc --binary`.

From the repository root:

```sh
bash setup.sh --demo
```

This builds the workspace and creates `.local/cipher.env` with new random JWT/router secrets and a localhost TLS certificate. It preserves an existing `.local/cipher.env`. Builds no longer need `DATABASE_URL` or a prepopulated database.

Previously tracked `.env`, certificate keys and runtime databases are removed from future commits, but remain in historical Git commits. Replace old router/JWT/provider credentials before sharing or deploying an installation. Existing local files are preserved; new startup scripts use the fresh `.local/` installation.

## 2. Fastest reliable booth rehearsal

```sh
python3 scripts/booth.py start
```

Open **https://localhost:3100**. Accept the locally generated development certificate in the browser, or import that session's certificate into a dedicated demo browser. The runner prints the path to `operator.txt` containing the generated operator login. Each run gets a private `cipher-booth-*` session directory on local temporary storage (or `CIPHER_BOOTH_DATA_DIR`); `.local/booth/` holds the hook inbox and current-session pointer; stop it with Ctrl-C. Sessions are retained so logs can be reviewed; the operating system may clean temporary storage after reboot. Choose a local persistent `CIPHER_BOOTH_DATA_DIR` if needed.

The default supervisor is a deterministic local **fixture**, not a model. The dashboard displays a simulation banner, the sensor reports XDP as unattached, and fixture incident titles/explanations are marked DEMO. Statistical analysis, HTTPS authentication, persistence, command delivery and acknowledgments use the real server. No packets are blocked by this runner.

Use another terminal for hooks:

```sh
python3 scripts/booth.py hook normal
python3 scripts/booth.py hook scan
```

For real LLM calls with simulated traffic, configure section 3 and run `python3 scripts/booth.py start --llm configured`. For statistical screening with no LLM, use `--llm off`. Only one booth runner may use the shared hook inbox at a time.

## 3. Configure a real LLM

Edit `.local/cipher.env` locally. Keep keys out of Git and the browser. Pick a model ID enabled for your provider account; no default model is assumed.

Anthropic:

```dotenv
LLM_PROVIDER=anthropic
LLM_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=YOUR_ENABLED_CLAUDE_MODEL_ID
LLM_API_KEY=YOUR_ANTHROPIC_API_KEY
```

OpenAI or a Chat Completions-compatible service:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=YOUR_ENABLED_MODEL_ID
LLM_API_KEY=YOUR_PROVIDER_API_KEY
LLM_TOKEN_PARAMETER=max_completion_tokens
```

For a local compatible server, use its actual `/v1` base URL, e.g. `http://127.0.0.1:11434/v1`, its installed model ID, and a nonempty placeholder API key if it requires no authentication. Some compatible services require `LLM_TOKEN_PARAMETER=max_tokens`. Plain HTTP is accepted only on loopback; other endpoints require HTTPS. This adapter does not install or download a local model.

Restart the server, sign in, open **Engine health → Test LLM connection**. This makes a small real provider request and may incur a charge. Success means the server received a complete, valid verdict. The page exposes missing configuration, connection/timeout/HTTP failures, invalid responses and the last successful review. Keys and provider response bodies are not exposed.

The probe never isolates a device. A failed or busy supervisor leaves a statistical alert for manual review. Only two reviews run concurrently. The default per-device cooldown is 120 seconds. The isolated booth runner uses two seconds to support repeated scenarios.

## 4. Booth stories

Each anomaly hook deliberately relearns the demo device using 50 generated normal reports, then submits the changed observation. This accelerates the rehearsal; live sensors normally need around eight minutes of active reporting. Relearning preserves trust and response mode. Model output from a real provider is not deterministic.

| Hook / sequence | What to show | Expected behavior with the fixture |
| --- | --- | --- |
| `normal` | Baseline and normal traffic | Device remains allowed; no new anomaly |
| `download` | A legitimate large download can look unusual | One feature changes; supervisor explanation; no automatic block |
| `scan` | Many drops and high port entropy | Evidence and a review appear; default monitor mode keeps access |
| `enforce`, then `scan` | Explicit automatic response | Review requests isolation; state changes only after simulated acknowledgment |
| `trust`, then `scan` | Permanent trust | Trust queues restoration; alerts continue, automatic isolation is suppressed |
| `revoke`, then `scan` | Removing the exemption | Automatic isolation is eligible again if enforcement remains enabled |
| `exfil` | Unusual outgoing activity | Multiple measurements change; explain this as an upload anomaly requiring investigation, not proof of theft |
| `isolate`, then `restore` | Operator control | Manual requests work even for a trusted device |
| `command-failure` | A failed response is visible | Next map acknowledgment fails; dashboard retains the previous confirmed state |
| `disconnect` | Network interruption | Sensor is offline for ten seconds; queue a dashboard command during that gap and watch replay after reconnection |
| `llm-outage`, then `scan` | Provider unavailable | Fixture returns HTTP 503; statistical alert remains, no automatic isolation |
| `malformed-llm`, then `scan` | Invalid model output | Invalid verdict is rejected; no automatic isolation |
| `llm-recover`, then `scan` | Provider recovery | Valid reviews resume |
| `export` | Evidence available for analysis | Writes `telemetry-export.json` into the current booth session |
| `reset` | Prepare for the next visitor | Monitor mode, trust revoked, access restoration queued, old open incidents resolved, baseline relearned; history retained |
| `status` | Verify current state | Prints policy, device trust/state, online status and latest incident |

Run hooks as `python3 scripts/booth.py hook NAME`. LLM outage/malformed/recovery hooks require the fixture; they never alter a live provider account. To get an entirely empty session, stop and restart the runner. The hook command returns failure when a scenario fails; inspect the session's `server.log`.

Suggested three-minute walkthrough:

1. `reset` and show normal inventory/engine health.
2. `scan` and open the incident's detection evidence.
3. `enforce`, then `scan`; show requested versus acknowledged isolation.
4. `trust`, then `scan`; show that alerts remain while access stays allowed.
5. `llm-outage`, then `scan`; show graceful fallback.
6. `reset` before the next visitor.

Use a short recording of the rehearsed flow as an event-day backup. Describe the offline fixture explicitly whenever it is active.

## 5. Physical test network

```sh
bash setup.sh
./scripts/run-server.sh
```

Open **https://localhost:3000** and create the first operator account. It owns the configured `CIPHER_NETWORK_ID`. In another terminal:

```sh
ip -br link
sudo env CIPHER_INTERFACE=YOUR_TEST_INTERFACE ./scripts/run-daemon.sh
```

Use an isolated test network whose traffic you control. Even monitor mode leaves the existing kernel protocol/IP/domain packet filters active. The current one-interface mapping does not provide complete bidirectional gateway attribution.

Engine health should show a recent heartbeat, the intended interface, XDP attachment as reported by the daemon, and an acknowledged policy revision. Device rows appear after observed traffic. Baselines are saved across reconnects and restarts; use **Relearn baseline** only with representative normal traffic.

To test enforcement, manually isolate a disposable test client, verify its actual packet behavior, then restore it. The dashboard's acknowledgment alone does not prove the physical topology enforces the block. Verify that trusting the client suppresses automatic isolation while incidents still appear. Unplug/reconnect the cloud link and confirm collection continues and the queue drains.

Startup scripts default to `.local/cipher.db` and `.local/router.db`. Prefer local disk for SQLite; if the checkout is on NFS, choose local paths through environment variables:

```sh
CIPHER_DB=/absolute/local/path/cipher.db ./scripts/run-server.sh
sudo env CIPHER_ROUTER_DB=/absolute/local/path/router.db CIPHER_INTERFACE=YOUR_TEST_INTERFACE ./scripts/run-daemon.sh
```

Create the parent directories first. For an existing installation, stop its processes and back up the database before switching paths. Schema upgrades are automatic; pointing the new startup scripts at `.local/` starts a separate fresh installation by default.

## 6. Server and sensor on different machines

Use a certificate valid for the server hostname/IP; the generated localhost certificate is only for local use. Set `CIPHER_BIND`, `CIPHER_TLS_CERT`, and `CIPHER_TLS_KEY` on the server. On the sensor, set `CIPHER_SERVER_URL=wss://YOUR_SERVER:3000`, the same network ID/router secret, and `CIPHER_CA_CERT` to the issuing CA certificate. Share the CA certificate, not the server private key. Create the operator account before exposing a fresh installation to other clients.

Keep the sensor/server versions together. Updated sensors send report IDs and expect telemetry acknowledgments; an older server will not drain that outbox correctly. The server accepts old telemetry formats for compatibility, but full policy acknowledgment and trust enforcement require the updated daemon.

## 7. Checks before leaving for GJU

```sh
make ebpf
cargo build --workspace --locked
cargo test --workspace
cargo test -p daemon transport_reconnects -- --ignored
python3 tests/integration.py
python3 tests/supervisor.py
node --check ui-dashboard/app.js
```

Run the booth walkthrough with both `--llm fixture` and your intended live provider. Test resolution/false-positive review, trust/revoke, restore, and the sensor acknowledgment indicator. Keep the fixture available for a venue internet outage. Charge the laptop and bring the test router/interface adapters.

If a hook stalls, inspect the booth terminal and its session log. If the live sensor is offline, check the interface, root/BPF privileges, matching network/router credentials and certificate hostname/trust. A server restart does not erase saved trust or baselines. Switching to monitor mode stops new automatic isolation but does not remove existing blocks; use Restore access.
