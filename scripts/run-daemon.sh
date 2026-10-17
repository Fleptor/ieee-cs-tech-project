#!/usr/bin/env bash
set -euo pipefail
CIPHER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$CIPHER_ROOT"
export CIPHER_ENV_FILE="${CIPHER_ENV_FILE:-$CIPHER_ROOT/.local/cipher.env}"
export CIPHER_ROUTER_DB="${CIPHER_ROUTER_DB:-$CIPHER_ROOT/.local/router.db}"
export CIPHER_CA_CERT="${CIPHER_CA_CERT:-$CIPHER_ROOT/.local/localhost.pem}"
if [[ ! -f "$CIPHER_CA_CERT" ]]; then
  echo 'Start scripts/run-server.sh first, or set CIPHER_CA_CERT to the issuing CA certificate.' >&2
  exit 1
fi
exec "$CIPHER_ROOT/target/debug/daemon"
