# Demonstration evidence and fallback

- [CIPHER_demo.mp4](CIPHER_demo.mp4): approximately 78 seconds, silent, with captions. Shows the actual dashboard, statistical alert, explicit enforcement, simulated isolation acknowledgment, permanent trust, provider outage and reset.
- [incident-evidence.png](incident-evidence.png): expanded detection evidence in monitoring mode.
- [trusted-alert.png](trusted-alert.png): a new alert remains visible after permanent trust.
- [rehearsal-results.json](rehearsal-results.json): 17 checks against the real backend and offline fixture.

Recorded on 17 October 2026 using the isolated `BOOTH_DEMO` network. Traffic, sensor acknowledgments and supervisor responses are simulated. The backend, detector, persistence and dashboard controls are real. No real packet was blocked, no paid model was called, and no customer data or credentials are included. Presentation captions were added to the recorded browser view; they are not part of the application UI.

These artifacts support the software walkthrough, not attack-detection accuracy or physical enforcement claims. Re-run `python3 scripts/booth.py rehearse` against a running fixture before presenting on another machine. For narration and setup see [the demo guide](../DEMO_GUIDE.md).
