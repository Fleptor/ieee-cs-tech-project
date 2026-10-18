# CIPHER LLM setup

The adapters are implemented. This checkout has been tested against local fixtures; a real provider account/model still needs the connection test below. No model training is required. The statistical baseline learns separately from 50 reports per device.

## 1. Initialize the local configuration

From the repository root:

```sh
bash setup.sh --demo
nano .local/cipher.env
```

Setup preserves an existing configuration. Edit the existing `LLM_*` entries; do not append duplicate keys. Keep the generated JWT/router secrets. `.local/` is excluded from Git. Put the provider key in this file, not in the dashboard, screenshots, slides or chat.

## 2. Choose one provider

Create a key using the [Anthropic API key instructions](https://platform.claude.com/docs/en/get-api-key) or [official OpenAI documentation](https://developers.openai.com/api/docs/quickstart). Choose an exact model ID enabled for that API account. CIPHER deliberately has no default model ID. Provider calls can incur usage charges.

For Anthropic Messages:

```dotenv
LLM_PROVIDER=anthropic
LLM_BASE_URL=https://api.anthropic.com/v1
LLM_MODEL=YOUR_ENABLED_CLAUDE_MODEL_ID
LLM_API_KEY=YOUR_ANTHROPIC_API_KEY
LLM_TIMEOUT_SECONDS=20
```

For OpenAI Chat Completions:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=YOUR_ENABLED_CHAT_COMPLETIONS_MODEL_ID
LLM_API_KEY=YOUR_OPENAI_API_KEY
LLM_TOKEN_PARAMETER=max_completion_tokens
LLM_TIMEOUT_SECONDS=20
```

For another Chat Completions-compatible endpoint, keep `LLM_PROVIDER=openai` and replace the URL, model and key. The base URL ends in `/v1`; CIPHER appends `/chat/completions`. Some services require `LLM_TOKEN_PARAMETER=max_tokens`.

For a local compatible server such as Ollama (installation and model choice are covered in [SETUP.md](SETUP.md#option-a-local-model-with-ollama-recommended-for-the-booth)), a configuration can look like:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=http://127.0.0.1:11434/v1
LLM_MODEL=YOUR_INSTALLED_MODEL_ID
LLM_API_KEY=local-placeholder
LLM_TOKEN_PARAMETER=max_tokens
LLM_TIMEOUT_SECONDS=60
```

The placeholder is only for a local endpoint that accepts unauthenticated requests. CIPHER does not install a model or start that server. Plain HTTP is allowed only on loopback; other endpoints require HTTPS. The adapter requires text chat messages and a complete JSON verdict, so provider compatibility still needs testing. A malformed verdict is retried once; timeouts and HTTP errors are not. Timeout is clamped to 1–60 seconds.

Shell environment variables override `.local/cipher.env`. If the dashboard shows an unexpected provider or model, check exported `LLM_*` variables and restart. Do not print API keys while troubleshooting.

## 3. Start and verify

Stop an existing booth runner with Ctrl-C, then:

```sh
python3 scripts/booth.py doctor
python3 scripts/booth.py start --llm configured
```

`doctor` checks local requirements and whether values are set; it makes no provider call. For a loopback endpoint it also lists the local server's models and reports whether `LLM_MODEL` is installed. Configured startup stops with an explanation if the server detects missing/invalid configuration. It does not silently substitute the fixture.

Open **https://localhost:3100**. The terminal prints the path to the session's `operator.txt` login. Sign in and open **Engine health → Test LLM connection**. This makes one small real request; success means a complete, valid verdict was received. It does not isolate a device. Wait at least five seconds between connection tests.

Then run in a second terminal:

```sh
python3 scripts/booth.py hook scan
```

Open **Security incidents**, expand **Detection evidence**, and check that the supervisor completed its review. The hook waits for review completion and any response acknowledgment. Remain in monitoring mode for the first test. A real model may recommend investigation without isolation; its decision is not deterministic.

For the physical installation, use `./scripts/run-server.sh` instead of the booth runner. It reads the same local configuration and serves **https://localhost:3000**. See [the runbook](BOOTH_RUNBOOK.md) for sensor setup.

## 4. Understand the three demonstration modes

| Start option | Supervisor | What the audience sees |
| --- | --- | --- |
| `--llm fixture` (default) | Scripted local responses; no model or API key | Explicit DEMO labels; repeatable policy and failure stories |
| `--llm configured` | Real provider or locally hosted model | Real model review of synthetic telemetry; requires successful verification |
| `--llm off` | No supervisor | Statistical alerts with no cloud AI decision |

All three booth modes use a simulated sensor. They do not attach XDP or block physical packets. Provider outage/malformed-response hooks and `rehearse` are available only with the fixture.

The real provider receives the device MAC, statistical measurements/baseline/deviations, recent report metadata and a short instruction. It does not receive packet payloads. Live deployment sends this metadata to the configured endpoint. Booth mode uses invented addresses and synthetic observations.

## 5. Troubleshooting and fallback

| Symptom | Action |
| --- | --- |
| Model/key missing | Edit `.local/cipher.env`; supply both; restart |
| HTTP 401/403 | Check key, endpoint and account/model permissions |
| HTTP 404 | Check the model ID and `/v1` base URL; do not append `/messages` or `/chat/completions` yourself |
| HTTP 429 | Check provider quota/rate limits and retry later |
| Timed out | Check connectivity; optionally raise timeout up to 60; test local model speed before presenting |
| Invalid/incomplete verdict | Check model compatibility and token parameter; the server rejects malformed/truncated responses |
| Busy or checked recently | Wait five seconds or let in-flight reviews finish |
| Config changed but behavior did not | Restart the runner/server and check exported environment overrides |

A supervisor failure preserves the statistical incident and does not request cloud automatic isolation. Edge behavior on physical hardware is separate. For a venue outage, stop the runner and restart with `--llm fixture`. This creates a new isolated session and new login; announce the scripted mode. The prerecorded walkthrough is another fallback.

Use [the demo guide](DEMO_GUIDE.md) for the presenter flow and [the readiness audit](BOOTH_READINESS.md) for claims supported by the tests.
