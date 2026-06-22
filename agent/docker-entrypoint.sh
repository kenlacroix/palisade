#!/bin/sh
# Demo entrypoint: start the bundled vulnerable target in this container's
# network namespace, wait for the control plane, enroll once (idempotent), then
# run the heartbeat/scan loop.
set -eu

: "${PALISADE_SERVER:?PALISADE_SERVER must be set (control plane base URL)}"
: "${PALISADE_ENROLL_TOKEN:=PLS-DEMO}"
: "${PALISADE_HOME:=/var/lib/palisade}"
export PALISADE_HOME

# 1. Fake-vulnerable LiteLLM target on 0.0.0.0:4000, in THIS netns so the agent
#    discovers it via /proc/net/tcp and can reach it at <hostname>:4000.
echo "palisade-demo: starting fake litellm target on :4000"
python /app/fake_litellm.py &

# 2. Wait for the control plane to be reachable before enrolling.
echo "palisade-demo: waiting for control plane at ${PALISADE_SERVER}"
i=0
until palisade_health=$(python - "$PALISADE_SERVER" <<'PY'
import sys, urllib.request
try:
    urllib.request.urlopen(sys.argv[1].rstrip("/") + "/healthz", timeout=3).read()
    print("ok")
except Exception:
    sys.exit(1)
PY
); do
  i=$((i + 1))
  if [ "$i" -ge 120 ]; then
    echo "palisade-demo: control plane never became reachable; giving up" >&2
    exit 1
  fi
  sleep 2
done
echo "palisade-demo: control plane is up"

# 3. Enroll once. Reuse existing identity on restart; tolerate an already-used
#    single-use token (config.json present means we are already enrolled).
if [ -f "${PALISADE_HOME}/config.json" ]; then
  echo "palisade-demo: already enrolled (${PALISADE_HOME}/config.json present), skipping enroll"
else
  echo "palisade-demo: enrolling"
  # Scope the token to the enroll process only — not exported, so the long-lived
  # `palisade run` below never carries it in its environment (/proc/<pid>/environ).
  if ! PALISADE_ENROLL_TOKEN="$PALISADE_ENROLL_TOKEN" palisade enroll --server "$PALISADE_SERVER"; then
    if [ -f "${PALISADE_HOME}/config.json" ]; then
      echo "palisade-demo: enroll reported an error but config.json exists; continuing"
    else
      echo "palisade-demo: enroll failed and no config written" >&2
      exit 1
    fi
  fi
fi

# 4. Run the loop.
echo "palisade-demo: starting agent loop"
exec palisade run --server "$PALISADE_SERVER"
