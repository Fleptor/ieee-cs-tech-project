#!/usr/bin/env bash
# Sourced by run-server.sh. Generate a local certificate without replacing team files.
set -euo pipefail
if [[ ! -f "$CIPHER_ROOT/.local/localhost.pem" ]]; then
  mkdir -p "$CIPHER_ROOT/.local"
  chmod 700 "$CIPHER_ROOT/.local"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "$CIPHER_ROOT/.local/localhost-key.pem" \
    -out "$CIPHER_ROOT/.local/localhost.pem" \
    -subj '/CN=CIPHER local development' \
    -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -addext 'basicConstraints=critical,CA:TRUE' 2>/dev/null
  chmod 600 "$CIPHER_ROOT/.local/localhost-key.pem"
fi
