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
| No repeatable booth stories | Isolated runner; labeled simulation; benign download, scan, upload, trust, outage, failure, reset, and export hooks | Rehearse narration and backup video |
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
