#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL is required for backup." >&2
  exit 1
fi

BACKUP_DIR="${BACKUP_DIR:-./backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
TARGET_FILE="${BACKUP_DIR}/consult-${TIMESTAMP}.dump"

mkdir -p "${BACKUP_DIR}"

pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file "${TARGET_FILE}" \
  "${DATABASE_URL}"

find "${BACKUP_DIR}" -type f -name "consult-*.dump" -mtime +"${BACKUP_RETENTION_DAYS}" -delete

echo "Backup created: ${TARGET_FILE}"
