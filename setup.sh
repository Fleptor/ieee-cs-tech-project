#!/usr/bin/env bash
set -euo pipefail
CIPHER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$CIPHER_ROOT"
for executable in cargo python3 openssl flatc; do
  command -v "$executable" >/dev/null || { echo "Missing prerequisite: $executable (see docs/BOOTH_RUNBOOK.md)" >&2; exit 1; }
done
bash scripts/init-local.sh
cargo build --workspace --locked
if [[ "${1:-}" != "--demo" ]]; then make ebpf; fi
echo 'Build complete. See docs/BOOTH_RUNBOOK.md for live and simulated booth startup.'
