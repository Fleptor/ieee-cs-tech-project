# CIPHER in plain English

This is for anyone who has to explain CIPHER to someone who is not a network engineer: booth visitors, judges, family or a new teammate. Technical detail is in the [README](../README.md); what we can and cannot claim is in the [demo guide](DEMO_GUIDE.md).

## One sentence

**CIPHER is a security guard for a small office network: it learns each device's normal routine, notices when something behaves strangely, explains why in plain language, and, only if you allow it, quarantines that device.**

## The 30-second version

> Small businesses get hacked through one infected laptop or camera, and they rarely have a security team watching. CIPHER sits on the office router and quietly learns what normal looks like for every device. When a device suddenly behaves differently, like knocking on hundreds of doors or sending out far more data than usual, CIPHER raises an alarm with the evidence. An AI assistant explains it in plain English. If the owner has switched on automatic response, CIPHER can quarantine that one device without taking down the whole network. Trusted devices are never cut off automatically, and a person can always override.

## The analogy: a security guard in an office building

| In the building | In CIPHER |
| --- | --- |
| The guard learns everyone's routine: who arrives when and which doors they use | **Baseline**: for each device, CIPHER learns typical download, upload, blocked-traffic and "how many different doors" patterns from its first 50 reports |
| Someone starts trying every door handle on the floor | **Anomaly**: the device's behaviour is far from its routine (in the demo, a port scan) |
| The guard writes an incident report with what they saw | **Incident + detection evidence**: the exact measurements and how far from normal they are |
| The guard calls a supervisor for a second opinion | **AI reviewer**: a language model reads the evidence and explains it in plain words |
| The guard can lock one office without evacuating the building | **Quarantine (isolation)**: CIPHER blocks one device at the router; everything else keeps working |
| The IT manager has a master pass and is never locked out automatically | **Trusted device**: still reported, never isolated automatically |
| The building manager decides whether guards may lock doors without asking | **Monitor vs. automatic mode**: by default CIPHER only warns; automatic quarantine is a deliberate switch |

## How it works, in four steps

1. **Watch:** a small program inside the router's operating system (eBPF) looks at traffic as it passes. It counts and measures traffic but never reads its contents.
2. **Learn and compare:** the cloud dashboard keeps a "normal" profile for each device and checks every new report against it.
3. **Explain:** when something is far from normal, an AI model writes a short explanation and says whether it would block the device.
4. **Respond safely:** CIPHER blocks a device automatically only if *all* of these are true: automatic mode is on, the device is not trusted, at least two separate measurements are abnormal, and the AI is at least 85/100 sure. Otherwise it only alerts.

## Hooks: openers that work at a booth

Pick whichever fits the visitor. Each one leads into the live demo.

- **"How many devices are on your home Wi-Fi right now? Do you know what each of them is doing?"** Then: *"CIPHER does, for a small office."*
- **"Most small businesses find out they were hacked months later, usually from someone else."** Then: *"We want the router itself to notice in seconds."*
- **"Want to see a computer get caught doing a port scan?"** Then run `tour`.
- **"Your smart TV and your laptop shouldn't behave the same way. CIPHER knows the difference."**
- **"AI that's allowed to say 'I'm not sure'."** For tech-curious visitors, show the AI-outage step: the alarm still fires, and nobody is blocked on a guess.
- **For judges:** *"It's a working control plane: Rust backend, authenticated dashboard, real statistics and a real response policy. Today the sensor traffic is simulated so the demo is repeatable."*

## What the visitor sees, step by step

`python3 scripts/booth.py tour` runs this story and prints what to say at each step.

| Step | On screen | Say |
| --- | --- | --- |
| 1. Meet the office | One device, "monitoring" mode | "CIPHER has learned this computer's normal routine." |
| 2. Something odd | A new incident; **In plain English** line | "It's knocking on hundreds of doors. CIPHER raised the alarm but didn't disconnect anyone." |
| 3. Let it act | Device becomes **blocked** after the sensor confirms | "Now CIPHER may act on its own. Several warning signs agreed, so it quarantined just this device." |
| 4. Trusted device | **Trusted** badge, device allowed, alert still logged | "The IT admin's laptop is allowed to be weird. Still reported, never cut off." |
| 5. AI goes down | Incident says the reviewer failed; device still allowed | "No AI? The alarm still works, and nobody gets blocked on a guess." |
| 6. Reset | Back to monitoring | "Ready for the next visitor; the history is kept." |

Every incident in the dashboard now starts with an **In plain English** sentence written for non-specialists.

## Visitor questions and honest answers

**Does it read my messages or see my passwords?**
No. It looks at *how much* traffic flows and *how varied* it is: counts, sizes and how many different destinations and ports. It never sees contents. The AI receives only those numbers.

**Is this real or a video?**
The dashboard, database, detection statistics, response rules and sign-in are the real software running on this laptop. The office computer and its traffic are simulated, so the story is the same for every visitor. By default the AI answers are scripted too, and the screen says so. When the real AI is switched on, a real model answers.

**Has it caught real hackers?**
Not yet, and we don't claim it has. We have not measured detection accuracy against real attacks. That is the next phase, on a real test network.

**What if the AI is wrong?**
The AI alone can never block anything. Automatic quarantine also needs automatic mode switched on, at least two separate abnormal measurements, and an untrusted device. By default CIPHER only warns. A person can undo any block with one click.

**What if the AI or the internet goes down?**
The statistics keep working and alerts still appear. CIPHER simply doesn't take automatic action without a valid AI review. Step 5 of the tour shows exactly this.

**What's eBPF?**
A safe way to run a tiny program *inside* the Linux kernel, the core of the operating system. It is how big companies such as Cloudflare and Meta inspect traffic at high speed. We use it so the router itself can watch and, when told to, block a device.

**Who is it for?**
Small offices, clinics, schools and shops: places with a router and no full-time security team.

**Does it need the cloud?**
The router keeps collecting data and holds onto it if the connection drops, then catches up afterwards. The AI can run in the cloud (Anthropic, OpenAI) or entirely on a local machine with Ollama.

## Words to use and words to avoid

| Say | Avoid | Why |
| --- | --- | --- |
| "unusual", "doesn't match its routine" | "malicious", "hacked" | An anomaly is not proof of an attack |
| "the AI's opinion", "the reviewer suggests" | "the AI detected" | The statistics detect; the AI explains and advises |
| "quarantine this device" | "stop the attack" | We isolate one device; we don't claim to stop an attacker |
| "simulated traffic, real software" | "live network" | Booth traffic is synthetic |
| "the next step is a real gateway test" | "production-ready", "% accuracy" | Neither has been measured |

## Glossary

- **Baseline:** what "normal" looks like for one device, learned from its first 50 reports.
- **Anomaly:** a report far from that device's baseline.
- **Incident:** a recorded anomaly with its evidence and outcome.
- **Supervisor / AI reviewer:** the language model that explains an incident and recommends whether to block.
- **Fixture:** a scripted stand-in for the AI used in the offline demo. It is clearly labelled `[DEMO]`.
- **Monitor mode:** alert only; CIPHER never blocks on its own. This is the default.
- **Enforcement / automatic mode:** CIPHER may quarantine untrusted devices when the safety rules pass.
- **Trusted device:** always reported, never isolated automatically.
- **Isolate / quarantine:** block one device at the router.
- **Acknowledgment:** the sensor confirming it actually applied a command. The dashboard shows *blocked* only after that.
- **eBPF / XDP:** Linux technology for running small, verified programs in the kernel at the network card's receive path.
