#!/usr/bin/env bash
set -euo pipefail
CIPHER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$CIPHER_ROOT/scripts/init-local.sh"
export CIPHER_ENV_FILE="${CIPHER_ENV_FILE:-$CIPHER_ROOT/.local/cipher.env}"
export CIPHER_DB="${CIPHER_DB:-$CIPHER_ROOT/.local/cipher.db}"
export CIPHER_TLS_CERT="${CIPHER_TLS_CERT:-$CIPHER_ROOT/.local/localhost.pem}"
export CIPHER_TLS_KEY="${CIPHER_TLS_KEY:-$CIPHER_ROOT/.local/localhost-key.pem}"
cd "$CIPHER_ROOT/Server"
exec "$CIPHER_ROOT/target/debug/cipher_backend"
