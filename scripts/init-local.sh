#!/usr/bin/env bash
set -euo pipefail
CIPHER_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$CIPHER_ROOT/.local"
chmod 700 "$CIPHER_ROOT/.local"
python3 - "$CIPHER_ROOT" <<'PY'
import pathlib, secrets, sys
root=pathlib.Path(sys.argv[1]); target=root/'.local/cipher.env'
if not target.exists():
    text=(root/'.env.example').read_text().replace('replace-with-a-long-random-secret',secrets.token_hex(32)).replace('replace-with-a-different-long-random-secret',secrets.token_hex(32))
    with target.open('x') as f: f.write(text)
    target.chmod(0o600)
    print('Created .local/cipher.env with fresh credentials.')
else:
    print('Keeping existing .local/cipher.env.')
PY
source "$CIPHER_ROOT/scripts/local-tls.sh"
echo 'Local setup ready. Configure the interface and optional supervisor in .local/cipher.env.'
