# CIPHER demonstration guide

## What is ready to show

The reliable booth setup is an isolated **software demonstration**: synthetic FlatBuffers telemetry and sensor acknowledgments drive the real Rust backend, statistical detector, SQLite storage, authenticated dashboard and response policy. The offline supervisor is a scripted fixture, explicitly labeled as such. No physical packet enforcement or attack-detection accuracy is demonstrated.

| Feature | Booth decision | Evidence / qualification |
| --- | --- | --- |
| Inventory and baseline learning | Show | One named demo device; 50 generated baseline reports; ambient normal reports between scenarios |
| Statistical anomaly and evidence | Show | Real detector; benign download, scan-like and unusual-upload inputs |
| LLM incident explanation | Show as scripted by default | Fixture labels appear in banner and incidents; real provider needs credentials and a passed connection test |
| Monitor versus automatic isolation | Show | Real server policy; sensor acknowledgment is simulated |
| Persistent trust, revoke and manual override | Show | Alerts remain; automatic isolation suppressed; manual actions work; restart persistence covered by integration tests |
| Failed commands, provider outages, reconnect/replay | Show | Failure status stays visible; confirmed state is retained; replay exercised |
| Resolve/false-positive review and export | Show | Stored operator workflow; feedback does not retrain the model |
| Physical eBPF/XDP block | Explain architecture only | Compilation passes; no live gateway packet proof in this rehearsal |
| Offline edge collection and durable outbox | Explain with test evidence | Real daemon transport test restarts a TLS backend; booth disconnection only demonstrates simulated sensor response replay |
| Reputation feeds / DNS filtering | Do not lead with it | Booth has no indicators; kernel logic exists but live filtering was not validated |
| Attack attribution, accuracy, throughput, production readiness | Do not claim | No representative accuracy or performance evaluation; gateway attribution remains incomplete |

## Before visitors arrive

```sh
bash setup.sh --demo
python3 scripts/booth.py doctor
python3 scripts/booth.py start
```

Leave that terminal running. Open **https://localhost:3100**, accept the local development certificate, and sign in using the file path printed by the runner. Keep another terminal at the repository root:

```sh
python3 scripts/booth.py rehearse
```

All checks should pass. The command saves a JSON report in the current session and returns to monitoring, untrusted/allowed access, and a learned baseline. It retains incident history, marking open findings resolved. Stop/restart the runner for a completely empty history and new login. Rehearsal is intentionally fixture-only and never calls a paid provider.

The runner sends normal synthetic observations every five seconds between hooks while the demo device is allowed. It renews its operator session so hooks remain usable during a long event. Use `start --no-ambient` if you need only deliberate reports. A blocked simulated device pauses ambient reports; this is storytelling behavior, not packet-level evidence.

## Three-minute presentation

The easiest way to run it is `python3 scripts/booth.py tour`. It runs the steps below and pauses for Enter, printing what changed, a plain-English **SAY** line and a **SHOW** pointer for each step. With `--llm configured`, the fixture-only outage step is skipped, and step 3 switches to an alternative narration if the model declines to recommend blocking. `tour --auto 20 --loop` repeats it unattended. Every incident in the dashboard begins with an **In plain English** sentence. For openers, the analogy and visitor questions, see [CIPHER in plain English](CIPHER_EXPLAINED.md).

Start with: **“This is our working control plane with a simulated edge sensor. The offline supervisor is scripted so we can demonstrate the same policy and failure cases reliably.”**

| Time | Action | Point to make |
| --- | --- | --- |
| 0:00–0:25 | Overview, then Devices; `hook reset` | A learned device, explicit monitoring mode and visible sensor status |
| 0:25–1:00 | `hook scan`; open Security incidents and Detection evidence | Several observations diverge from the baseline; unusual does not mean proven malicious |
| 1:00–1:35 | `hook enforce`, then `hook scan`; Devices | Response is requested and acknowledged; show `applied`, not just the request |
| 1:35–2:10 | `hook trust`, then `hook scan` | Access is restored; alerts continue; the action says `trusted device` |
| 2:10–2:40 | `hook revoke`, `hook llm-outage`, then `hook scan`; Engine health / Incidents | Provider failure is visible; statistical evidence survives and no cloud isolation occurs |
| 2:40–3:00 | `hook llm-recover`, `hook reset` | Close with the next validation step: real gateway behavior and a verified live model |

Every `hook NAME` above means `python3 scripts/booth.py hook NAME`. Hooks wait for reviews and acknowledgments. Keep the visible UI on the relevant view; it refreshes every three seconds. Evidence panels remain open across refreshes.

## Optional deeper stories

- `enforce`, then `download`: a single traffic-volume change is insufficient for automatic isolation.
- `observe`, then `exfil`: unusual upload metadata, not proof of data theft. This historical hook name is not an attack classification.
- `command-failure`: the attempted block fails and confirmed state stays unchanged. Restore first if you want to start allowed.
- `disconnect`: ten seconds offline. During that gap, use the dashboard to queue Isolate or Restore; it stays pending and applies after reconnect.
- `malformed-llm`, then `scan`: invalid output is rejected; follow with `llm-recover`.
- Mark a finding false positive, resolve it, or reopen it. Explain that this is review history, not automatic retraining.
- `export`: writes telemetry JSON into the current session. The dashboard also exports telemetry and device CSV.

## Recovery and event-day fallback

- For stale UI, use Refresh; if logged out, use the current session's login file. A new booth session has a new password.
- For a hook failure, read its error and the session's `server.log`. `hook status` shows policy acknowledgment, the latest command and incident.
- If a real provider fails, Ctrl-C and restart with `--llm fixture`. Announce the mode change. This starts fresh history.
- If the live UI cannot be recovered promptly, play [the recorded software walkthrough](demo/CIPHER_demo.mp4) and use the [PDF deck](presentation/CIPHER_Startup_Alley_Pitch.pdf). The recording uses the fixture and simulated sensor too.
- Rebooting may clear temporary storage. To retain session logs, set `CIPHER_BOOTH_DATA_DIR` to a local persistent directory. Prefer local disk over NFS for SQLite.

Keep the laptop charged and sleep disabled during presenting. The reliable software demo needs no cloud connectivity. Avoid attaching the physical sensor to the event network as a substitute for a rehearsed, controlled gateway test.

Separate instructions: [full laptop setup](SETUP.md), [plain-English explainer](CIPHER_EXPLAINED.md), [showcase page](showcase/index.html), [LLM setup](LLM_SETUP.md), [hardware/runbook](BOOTH_RUNBOOK.md), [readiness audit](BOOTH_READINESS.md), [slide deck and rebuild notes](presentation/README.md).
