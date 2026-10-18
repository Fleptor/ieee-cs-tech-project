# Booth readiness review — 17 October 2026

This review prioritizes failure modes that can interrupt a CIPHER demonstration or produce an unjustified isolation decision. It is not a claim of production readiness.

| Gap | Delivered behavior | Remaining validation |
| --- | --- | --- |
| LLM integration was a single fragile Anthropic call with a retired default model | Anthropic and OpenAI-compatible adapters; explicit model selection; bounded requests and response size; strict verdict validation; visible health and connection test | Configure and test a real account/model |
| No permanent device trust | Persistent trust, revoke, trust-and-restore controls; cloud and local edge heuristics respect exemptions; alerts remain enabled | Real packet rehearsal; MAC identity can be spoofed or change |
| LLM could directly request isolation | Default monitor mode; explicit enforcement switch; trust, incident state, policy revision, multiple signals and confidence checks; manual override | Detection thresholds need evaluation on representative traffic |
| Each anomaly could launch another provider request | Two concurrent reviews maximum; persisted per-device cooldown; busy/failure incident states | Cost/load measurements on a larger installation |
| Baselines vanished at reconnect | SQLite persistence, explicit per-device relearning, variance floors for constant traffic | Long-term drift and training contamination remain open |
| Cloud disconnect stopped the sensor | Reconnecting transport; collection and kernel watchdog continue; bounded durable outbox; server acknowledgments and retry deduplication | Physical gateway outage rehearsal |
| Blocks/policy disappeared with the daemon's memory | Policy cache and local MAC-block persistence; cloud command replay; visible acknowledgment and retry failures | Actual map enforcement after hardware restart |
| No operator incident workflow | Resolve, false-positive, reopen, evidence display and operator audit | Feedback is recorded; it does not automatically retrain a model |
| No repeatable booth stories | Isolated runner; labeled simulation; benign download, scan, upload, trust, outage, failure, reset, and export hooks | Presenter guide, complete-flow rehearsal and recorded software walkthrough; still rehearse on the event laptop |
| Dashboard session could expire mid-event | Authenticated session refresh before expiry while dashboard is active | An expired unattended session still requires sign-in |
| Runtime credentials and databases were tracked | Removed from the current Git tree; ignored runtime paths; fresh-secret initializer; database-free builds | Rotate old credentials; historical commits still contain previously tracked material |

## Deliberately retained limits

A baseline anomaly describes unusual observations, not a confirmed attack. The LLM's confidence is self-reported. The model does not inspect payloads or establish destination attribution from the four baseline features.

Permanent trust prevents automatic **device isolation**. It does not disable packet-level filters. A manual administrator isolation request can block a trusted device. Trust is keyed by network and canonical MAC address; it is not device attestation.

The current single-interface data plane needs bidirectional attribution work and a real gateway test. Do not present the booth simulation as proof of eBPF enforcement or attack-detection accuracy.

Changing policy while a sensor is offline updates server state immediately, but the sensor continues using its last persisted policy until synchronization. Engine health shows whether the sensor acknowledged the current revision. Switching to monitor mode prevents new automatic blocks; restore existing blocks separately.

The outgoing report queue is bounded. Report receipts prevent ordinary reconnect duplicates; ingest/receipt persistence is not one atomic transaction, so a crash at that boundary can duplicate a report. Historic replay is stored without updating the current detector or requesting isolation.

## Provider API references

Implementation uses the documented [Anthropic Messages API](https://platform.claude.com/docs/en/api/messages/create) and [OpenAI Chat Completions API](https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create). Model IDs are configured explicitly because availability and retirement dates change. Compatible providers must support text chat requests and one JSON verdict; token-limit parameter names are configurable.

## Validation performed

The workspace builds and Rust tests pass. The explicit transport integration test passes against a real TLS backend restart. HTTPS/WebSocket integration checks cover authorization, durable trust/policy, session refresh, command acknowledgments/failures/replay and incident review. Both provider adapters pass local fixture checks for success, timeout, HTTP 503, malformed output, cooldowns, historical-report suppression, delivery deduplication, trust granted during a review, and restart persistence. The simulator also survives idle gaps between visitors.

Browser checks exercised trust/revoke, manual isolation/restoration with acknowledgments, response-mode changes, incident review, LLM connection testing, and desktop/mobile layout. eBPF compilation passes. Live provider calls and privileged packet enforcement were not performed.

## Demo preparation follow-up — 17 October 2026

The offline demonstration is the supported booth path. See [DEMO_GUIDE.md](DEMO_GUIDE.md) for the show/explain/defer matrix and presentation script, and [LLM_SETUP.md](LLM_SETUP.md) for the separate live-provider setup steps.

The scenario controller now renews its own operator session, emits normal observations between visitors, waits for actual review/response completion, and provides `doctor` and `rehearse` commands. Missing live-model configuration fails with an actionable message. The scripted upload verdict now describes outbound activity rather than a scan. Booth sessions use an empty intelligence file instead of inheriting live indicators.

Browser rehearsal found and fixed evidence panels collapsing on dashboard refresh, and a 12-second browser timeout that was shorter than the possible supervisor timeout. The connection test now allows 66 seconds, stays disabled while pending across refreshes, and explains the five-second check throttle. Simulation labels explicitly distinguish scripted supervisor scores from real model confidence.

The updated deck and speaker notes reflect delivered controls and keep hardware, live-model and accuracy claims conditional. An offline MP4 records the real dashboard against the simulated sensor/fixture; it is not evidence of packet enforcement. Original workspace slides were preserved locally before replacement.

The complete fixture rehearsal verifies 17 checks and leaves monitoring/allowed access ready for the next visitor. API and provider tests, Rust tests, actual daemon TLS reconnect/outbox testing, eBPF compilation, desktop/mobile browser checks and PDF rendering pass. No live provider credentials or physical gateway were available in this preparation; neither is described as verified.

## Demo completion follow-up — 18 October 2026

- **Plain-English layer.** Every dashboard incident now begins with an "In plain English" sentence derived from its stored review status and action. Booth hooks print a state summary with SAY/SHOW presenter cues (`--json` keeps the full result). `booth.py tour` runs the six-step presenter story with narration, and `tour --auto N --loop` runs it unattended. See [CIPHER_EXPLAINED.md](CIPHER_EXPLAINED.md) and [showcase/index.html](showcase/index.html).
- **Local model verified.** `start --llm configured` was run against Ollama 0.12.11 serving `llama3.2` (3B) on the development laptop. Reviews completed for scan, download and tour scenarios. This exposed a real defect: the model often answered with fractional confidence (`0.2`), and CIPHER rejected every such verdict. The prompt now asks for a whole number from 0 to 100, and the parser accepts any number in 0–100 and rounds it down, so a fractional answer can only lower the value used by the 85-point isolation gate. Unit tests cover this. Even after that fix, about 40% of raw llama3.2 answers broke the format (prose around the JSON, empty names, `"should_block": ""`). The supervisor now retries once when an answer is malformed, but not after timeouts or HTTP errors, and still 3 of 10 booth reviews failed. Those alerts stay visible, as designed. `qwen2.5:3b` returned 20 of 20 valid direct answers and 10 of 10 completed booth reviews at about 7 seconds per scan, so [SETUP.md](SETUP.md) now recommends it. The booth runner also now shuts down cleanly on SIGTERM; previously a runner started in the background ignored Ctrl-C/SIGINT and left the backend running. Hosted Anthropic/OpenAI accounts were still not exercised.
- **Setup guide.** [SETUP.md](SETUP.md) covers system packages, Rust, build, the first fixture run, Ollama/Anthropic/OpenAI configuration, end-to-end verification and the event-day checklist. `doctor` now checks loopback model servers for the configured model.
- **Validation.** Workspace Rust tests, `tests/integration.py`, `tests/supervisor.py` (both adapters), the JavaScript syntax check and eBPF compilation pass. The fixture rehearsal passes 17/17, and the tour completes with both the fixture and the local model.
