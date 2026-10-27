#!/bin/sh
# First run: Quick Login, then launch the background daemon at login.
# The Red-SecretsXAI password is never an argument. Tokens stay in the OS keyring
# only when the Quick Login server sets remember_device.
set -eu
cd "$(dirname "$0")/.."
if [ -n "${ROTTENCORE_BIN:-}" ]; then
  bin=$ROTTENCORE_BIN
elif [ -x ./rottencore ]; then
  bin=./rottencore
elif command -v rottencore >/dev/null 2>&1; then
  bin=rottencore
else
  echo "rottencore is not on PATH. Set ROTTENCORE_BIN." >&2
  exit 1
fi
"$bin" login
"$bin" daemon install
