# Startup Alley presentation

- `CIPHER_Startup_Alley_Pitch.pptx`: editable 12-slide deck with speaker notes.
- `CIPHER_Startup_Alley_Pitch.pdf`: portable fallback for presenting without PowerPoint.
- `generate_pitch.py`: editable source; requires `python-pptx`.

```sh
python3 docs/presentation/generate_pitch.py
libreoffice --headless --convert-to pdf --outdir docs/presentation docs/presentation/CIPHER_Startup_Alley_Pitch.pptx
```

Updated after the 17 October 2026 demo preparation. Slides 3, 6, 7, 10 and 12 now reflect monitoring controls, permanent trust, saved baselines, supervisor adapters, response acknowledgments, and recovery. The walkthrough and status slide explicitly identify the simulated sensor and scripted offline supervisor. Speaker notes no longer describe the already-fixed integration gaps as current blockers.

Remaining claims are deliberately bounded: no real provider account verified, no physical packet enforcement demonstrated, no measured attack-detection accuracy or comparative performance. The earlier deck and source were backed up locally before replacing the original workspace copies beside the repository. This directory is the version-controlled copy.

Use [the demo guide](../DEMO_GUIDE.md) for commands and narration, and [the readiness audit](../BOOTH_READINESS.md) for validation scope.
