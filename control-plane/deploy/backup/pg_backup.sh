#!/bin/sh
# Nightly Postgres backup. Runs inside the `backup` container (postgres:16),
# dumps over the compose network, gzips to /out (host ./backups), and prunes
# dumps older than BACKUP_KEEP_DAYS. Loops once per 24h; restart policy keeps it
# alive across reboots.
set -eu

KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
OUT_DIR=/out
export PGPASSWORD="${POSTGRES_PASSWORD}"

backup_once() {
  ts="$(date +%Y%m%d-%H%M%S)"
  out="${OUT_DIR}/palisade-${ts}.sql.gz"
  echo "[backup] dumping ${POSTGRES_DB} -> ${out}"
  if pg_dump -h "${PGHOST}" -U "${POSTGRES_USER}" "${POSTGRES_DB}" | gzip -9 > "${out}.tmp"; then
    mv "${out}.tmp" "${out}"
    echo "[backup] ok: $(du -h "${out}" | cut -f1)"
  else
    echo "[backup] FAILED" >&2
    rm -f "${out}.tmp"
  fi
  find "${OUT_DIR}" -name 'palisade-*.sql.gz' -mtime "+${KEEP_DAYS}" -print -delete
}

# Backup on boot, then once a day.
while true; do
  backup_once || true
  sleep 86400
done
