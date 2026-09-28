#!/usr/bin/env bash
set -euo pipefail
CIPHER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CIPHER_ROOT"
export CIPHER_INTERFACE="${CIPHER_INTERFACE:-enp7s0}"
export CIPHER_CA_CERT="${CIPHER_CA_CERT:-$CIPHER_ROOT/.local/localhost.pem}"
if [[ ! -f "$CIPHER_CA_CERT" ]]; then
  echo 'Start scripts/run-server.sh first, or set CIPHER_CA_CERT to the issuing CA certificate.' >&2
  exit 1
fi
exec "$CIPHER_ROOT/target/debug/daemon"
