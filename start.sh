#!/usr/bin/env bash
# Entrypoint: jalankan Xvfb + EzSolver service (opsional) lalu mirror server.
set -uo pipefail

if [ "${TURNSTILE_SOLVER_ENABLED:-1}" != "0" ]; then
  export DISPLAY="${DISPLAY:-:99}"
  echo "[start] launching Xvfb on ${DISPLAY}"
  Xvfb "${DISPLAY}" -screen 0 1280x900x24 >/tmp/xvfb.log 2>&1 &
  sleep 1
  echo "[start] launching EzSolver Turnstile service"
  ( cd /app/ezsolver && exec python3 service.py ) >/tmp/solver.log 2>&1 &
fi

echo "[start] launching mirror server"
exec node server.js
