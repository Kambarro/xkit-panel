#!/usr/bin/env bash
# sign-release.sh — подписать артефакты релиза (SHA-256 + Ed25519).
# Использование: ./sign-release.sh [dist_dir] [key_file]
# Кладёт в dist: SHA256SUMS + SHA256SUMS.sig. Приватный ключ НЕ в репо.
set -euo pipefail
DIST="${1:-dist}"
KEY="${2:-$HOME/.xkit-release/release.key}"
[[ -f "$KEY" ]] || { echo "ключ подписи не найден: $KEY"; exit 1; }
cd "$DIST"
# SHA-256 всех артефактов (бинарники)
sha256sum xkit-panel-linux-* xkit-agent-linux-* > SHA256SUMS
# Ed25519 подпись файла SHA256SUMS (ssh-keygen -Y sign, namespace xkit-release)
ssh-keygen -Y sign -f "$KEY" -n xkit-release SHA256SUMS
# ssh-keygen создаёт SHA256SUMS.sig
echo "подписано: $DIST/SHA256SUMS + SHA256SUMS.sig"
cat SHA256SUMS
