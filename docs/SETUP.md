# CIPHER setup: from a fresh laptop to a working AI reviewer

This guide covers every step from a clean Linux laptop to a CIPHER demo with a real AI model reviewing alerts. Follow it top to bottom. Each part ends with a check, so you know it worked before moving on.

| Part | You end with | Time |
| --- | --- | --- |
| 1. Laptop and system packages | Compilers, OpenSSL, FlatBuffers | 10–20 min |
| 2. Rust | `cargo` 1.85 or newer | 5 min |
| 3. Get and build CIPHER | A built backend and local secrets | 5–15 min (first build) |
| 4. First demo run (no AI needed) | Dashboard open, rehearsal passing | 5 min |
| 5. Set up the AI reviewer | Local model (Ollama) **or** Anthropic / OpenAI | 10–30 min |
| 6. Verify the AI end to end | A real model reviewing a demo alert | 5 min |
| 7. Event-day checklist | A laptop you can trust at the booth | 10 min |

Optional, after all of the above: [physical sensor on a test network](BOOTH_RUNBOOK.md#5-physical-test-network).

---

## 1. Laptop and system packages

**Use Linux.** The edge sensor uses eBPF/XDP, a Linux kernel feature, and the Rust workspace builds that sensor. Tested on Arch Linux. Ubuntu 22.04 or newer and Fedora 39 or newer should work with the packages below. macOS, Windows and WSL2 are untested; use a Linux laptop or a Linux USB install for the booth.

Minimum: 4 CPU cores, 8 GB RAM and 15 GB free disk. For a local AI model, use 16 GB RAM. A GPU helps but is not required.

Install the packages for your distribution:

**Arch / Manjaro**

```sh
sudo pacman -S --needed base-devel git clang llvm libbpf linux-headers cmake pkgconf openssl python flatbuffers nodejs
```

**Ubuntu / Debian / Mint**

```sh
sudo apt update
sudo apt install -y build-essential git clang llvm libbpf-dev linux-libc-dev linux-headers-$(uname -r) \
  cmake pkg-config libssl-dev openssl python3 nodejs unzip curl
```

**Fedora**

```sh
sudo dnf install -y @development-tools git clang llvm libbpf-devel kernel-headers kernel-devel \
  cmake pkgconf-pkg-config openssl-devel openssl python3 nodejs unzip curl
```

### FlatBuffers compiler (`flatc`)

CIPHER uses `flatc` 25.12.19. Arch ships it. Check yours:

```sh
flatc --version
```

If it is missing or a different version (common on Ubuntu/Fedora), install the official binary:

```sh
cd /tmp
curl -LO https://github.com/google/flatbuffers/releases/download/v25.12.19/Linux.flatc.binary.g++-13.zip
unzip -o Linux.flatc.binary.g++-13.zip flatc
sudo install -m 0755 flatc /usr/local/bin/flatc
hash -r && flatc --version    # flatc version 25.12.19
```

**Check:** `clang --version`, `openssl version`, `python3 --version` and `flatc --version` all print a version.

---

## 2. Rust

Install through [rustup](https://rustup.rs), not your distribution's package, unless it provides Rust 1.85 or newer (CIPHER uses the 2024 edition):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"     # fish: source ~/.cargo/env.fish
```

**Check:** `cargo --version` shows 1.85 or newer.

---

## 3. Get and build CIPHER

```sh
git clone https://github.com/Fleptor/ieee-cs-tech-project.git
cd ieee-cs-tech-project
bash setup.sh --demo
```

`setup.sh --demo`:

- checks for `cargo`, `python3`, `openssl` and `flatc`;
- creates `.local/cipher.env` with fresh random secrets and a localhost TLS certificate (it keeps an existing file);
- builds the backend and sensor with `cargo build --workspace --locked`. The first build downloads crates and takes several minutes.

Run `bash setup.sh` without `--demo` to also compile the eBPF program. You need that only for the physical sensor.

**Keep the checkout on a local disk.** SQLite is unreliable on network shares (NFS/SMB). If your checkout must stay on a share, set `CIPHER_BOOTH_DATA_DIR` to a local folder. The booth already uses local temporary storage by default.

**Check:**

```sh
python3 scripts/booth.py doctor
```

Every line in the first block says `PASS`. `LLM_MODEL: missing` is expected at this point.

---

## 4. First demo run (no AI needed)

The default demo uses a **scripted stand-in** for the AI (the "fixture"). It needs no internet, no account and no model, so it always works. Do this first.

**Terminal 1** (leave it running):

```sh
python3 scripts/booth.py start
```

It prints the dashboard URL (**https://localhost:3100**) and the path to `operator.txt`, which holds a fresh login for this session.

**Browser:** open https://localhost:3100. The certificate is generated on your laptop, so the browser warns about it: choose *Advanced → Proceed / Accept the risk*. Click **Sign in** and use the username and password from `operator.txt`.

**Terminal 2:**

```sh
python3 scripts/booth.py rehearse     # 17 automatic checks, ends with "passed": true
python3 scripts/booth.py tour         # the guided 3-minute story; press Enter for each step
```

`tour` runs each scenario and prints what changed, what to **SAY** to a visitor in plain English, and what to **SHOW** on screen. For an unattended booth screen, run `python3 scripts/booth.py tour --auto 20 --loop`.

Ctrl-C in terminal 1 stops everything. Every `start` creates a fresh, separate session with a new login.

**Check:** `rehearse` reports `"passed": true`, and the dashboard shows the *Booth simulation* banner, one device, and new incidents as you run the tour.

---

## 5. Set up the AI reviewer

CIPHER's statistics decide *whether something is unusual*. The AI reviewer explains the evidence in plain language and gives a second opinion on whether automatic quarantine is justified. Pick **one** option:

| Option | Cost | Internet at booth | Quality | Choose it when |
| --- | --- | --- | --- | --- |
| **A. Local model with Ollama** | Free | Not needed | Good with 7–8B models; fair with 3B | You want a self-contained laptop |
| **B. Anthropic (Claude)** | Pay per use | Required | Best explanations | You have an API key and reliable internet |
| **C. OpenAI or compatible** | Pay per use | Required | Strong | You already have an OpenAI-compatible account |

All three use the same file, `.local/cipher.env`. Edit the existing `LLM_*` lines; do not add duplicates. Keep the generated `JWT_SECRET` and `ROUTER_SECRET`. `.local/` is excluded from Git. Never paste a key into the dashboard, slides, screenshots or chat.

### Option A: local model with Ollama (recommended for the booth)

1. **Install Ollama.**

   ```sh
   # Arch:   sudo pacman -S ollama          (NVIDIA GPU: ollama-cuda, AMD GPU: ollama-rocm)
   # Others: curl -fsSL https://ollama.com/install.sh | sh
   ```

2. **Start it** and make it start at boot:

   ```sh
   sudo systemctl enable --now ollama
   curl -s http://127.0.0.1:11434/v1/models    # prints JSON when it is running
   ```

3. **Download a model.** Pick by RAM:

   | Laptop | Model | Download | Notes |
   | --- | --- | --- | --- |
   | 8 GB RAM or more | `qwen2.5:3b` | 1.9 GB | **Recommended; tested with CIPHER.** 20 of 20 direct answers and 10 of 10 booth reviews were valid, about 7 seconds per scan |
   | 8 GB RAM | `llama3.2` (3B) | 2 GB | Tested; **not recommended.** About 40% of its answers break the format (prose around the JSON, empty names). CIPHER retries once, but about 3 in 10 alerts still end without an AI explanation |
   | 16 GB RAM or a GPU | `qwen2.5:7b` or `llama3.1:8b` | 4.7–4.9 GB | Not tested; may explain better but runs slower on a 4 GB GPU |

   ```sh
   ollama pull qwen2.5:3b
   ollama run qwen2.5:3b "Reply with OK"      # first load can take a while; Ctrl-D to exit
   ```

4. **Configure CIPHER.** Edit `.local/cipher.env`:

   ```dotenv
   LLM_PROVIDER=openai
   LLM_BASE_URL=http://127.0.0.1:11434/v1
   LLM_MODEL=qwen2.5:3b
   LLM_API_KEY=local-placeholder
   LLM_TOKEN_PARAMETER=max_tokens
   LLM_TIMEOUT_SECONDS=60
   ```

   `LLM_PROVIDER=openai` is correct here: Ollama speaks the OpenAI-compatible format. The key is a placeholder because a local server needs no key. Plain `http://` is accepted only for `127.0.0.1`/`localhost`.

5. **Check:** `python3 scripts/booth.py doctor` prints `Local model server: reachable; qwen2.5:3b installed`.

### Option B: Anthropic (Claude)

1. Create an API key in the [Claude Console](https://platform.claude.com/docs/en/get-api-key) and add billing or credits.
2. Choose a model ID that your account can use from the [models overview](https://platform.claude.com/docs/en/about-claude/models/overview). A current Haiku or Sonnet model is fast and inexpensive for this workload. CIPHER deliberately has no default model.
3. Edit `.local/cipher.env`:

   ```dotenv
   LLM_PROVIDER=anthropic
   LLM_BASE_URL=https://api.anthropic.com/v1
   LLM_MODEL=YOUR_CLAUDE_MODEL_ID
   LLM_API_KEY=YOUR_ANTHROPIC_API_KEY
   LLM_TIMEOUT_SECONDS=20
   ```

### Option C: OpenAI or another compatible service

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=YOUR_CHAT_COMPLETIONS_MODEL_ID
LLM_API_KEY=YOUR_OPENAI_API_KEY
LLM_TOKEN_PARAMETER=max_completion_tokens
LLM_TIMEOUT_SECONDS=20
```

For other compatible services (OpenRouter, Groq, LM Studio, vLLM, …), keep `LLM_PROVIDER=openai`, set their `/v1` base URL, model and key, and use `LLM_TOKEN_PARAMETER=max_tokens` if they reject `max_completion_tokens`. Do not add `/chat/completions` yourself.

**What the AI receives:** the device's MAC address, four statistical measurements with their baseline and deviation, and recent report metadata. It never receives packet contents. In the booth, all of it is invented demo data.

---

## 6. Verify the AI end to end

Stop any running booth (Ctrl-C), then:

```sh
python3 scripts/booth.py doctor
python3 scripts/booth.py start --llm configured
```

If the configuration is incomplete, `start` stops with an explanation. It never silently falls back to the fixture.

1. Sign in with the new `operator.txt`, open **Engine health → Test LLM connection**. Success means one real request returned a complete, valid verdict. Wait 5 seconds between tests.
2. In terminal 2:

   ```sh
   python3 scripts/booth.py hook scan
   ```

   The output ends with an `Incident:` line. Open **Security incidents**. The *In plain English* line and the model's own explanation appear, and *Supervisor* says `complete`.
3. Run `python3 scripts/booth.py tour` once with the real model. Real models are not deterministic. In step 3 the model may decline to recommend quarantine; the tour then prints an alternative narration that explains the safety rule. The *AI goes down* step needs the fixture and is skipped.

Results on the development laptop (Arch, GTX 1650 Super 4 GB, Ollama 0.12):

- `qwen2.5:3b`: 10 of 10 `hook scan` reviews completed, 6–8 seconds each including relearning the baseline. Confidence was usually 83–95, and the explanations cited the real measurements (port entropy 7.5 against a baseline of 1.0). In automatic mode it did not recommend quarantine, so the tour used its alternative step 3 narration.
- `llama3.2`: about 15 seconds per scan; 3 of 10 reviews failed even with the retry and stayed visible as *Supervisor: failed*, as designed. Some completed answers contradicted the evidence ("no anomalies found").

Treat threat names and explanations as the model's opinion, not a finding.

### Quick troubleshooting

| Symptom | Fix |
| --- | --- |
| `doctor`: local model server not reachable | `sudo systemctl start ollama` (or `ollama serve` in another terminal) |
| `doctor`: model not found | `ollama pull <model>`; `LLM_MODEL` must match `ollama list` (the `:latest` tag can be omitted) |
| HTTP 401/403 | Wrong key, or the account cannot use that model |
| HTTP 404 | Wrong model ID, or the base URL does not end in `/v1` |
| HTTP 429 | Quota or rate limit; wait or add credits |
| Timed out | The first local request loads the model; run `ollama run <model> "hi"` before presenting, or raise `LLM_TIMEOUT_SECONDS` (max 60) |
| *Supervisor returned an invalid verdict* now and then | The model broke the answer format twice in a row (CIPHER retries once). Use `qwen2.5:3b` rather than `llama3.2` |
| Changes to `.local/cipher.env` ignored | Restart the booth; also check `env | grep LLM_` for exported shell variables, which take priority |

More detail: [LLM_SETUP.md](LLM_SETUP.md).

---

## 7. Event-day checklist

The night before:

- [ ] `git pull`, then `bash setup.sh --demo`, then `python3 scripts/booth.py doctor`.
- [ ] Fixture run: `start`, then `rehearse` passes, then one full `tour`.
- [ ] AI run: `start --llm configured`, then **Test LLM connection**, then one `tour`.
- [ ] Local model: run `ollama run <model> "hi"` once so it is downloaded and loads quickly.
- [ ] The backups open offline: [demo video](demo/CIPHER_demo.mp4), [PDF slides](presentation/CIPHER_Startup_Alley_Pitch.pdf), [showcase page](showcase/index.html).
- [ ] Charger packed. Sleep and screen lock disabled for the day. Browser zoom at 110–125% so visitors can read the screen.

At the booth:

1. `python3 scripts/booth.py start` (fixture, the safe default), or `start --llm configured` with Ollama.
2. Sign in, accept the certificate, open the Overview.
3. `python3 scripts/booth.py rehearse` once, then `tour` for each visitor, or `tour --auto 20 --loop` when nobody is presenting.
4. If anything misbehaves, press Ctrl-C and run `start` again (fixture). That gives a clean session in about 20 seconds. If needed, play the video.

Say it plainly whenever the fixture is active: *"The traffic and the AI answers in this demo are simulated so we can show the same story every time; the backend, detection and controls are real."*

## Cleanup

Each booth session lives in a `cipher-booth-*` folder in your temporary directory, or under `CIPHER_BOOTH_DATA_DIR` if you set it. Delete old ones whenever you like. `.local/` holds your secrets, certificate and AI settings; delete it only to start completely fresh. To remove a local model: `ollama rm <model>`.

## Where to go next

- [CIPHER in plain English](CIPHER_EXPLAINED.md): what to tell visitors
- [Demo guide](DEMO_GUIDE.md): the three-minute script and what can be claimed
- [Booth runbook](BOOTH_RUNBOOK.md): every hook, the physical sensor, and a server and sensor on different machines
- [Readiness audit](BOOTH_READINESS.md): what has and has not been verified
