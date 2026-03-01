#!/bin/sh
# Ensure mounted volumes are writable by panguard user
# Railway volumes mount as root, overriding Dockerfile chown
chown -R panguard:panguard /data /backups 2>/dev/null || true

exec su-exec panguard node dist/cli.js \
  --port "${TC_PORT:-8080}" \
  --host "${TC_HOST:-0.0.0.0}" \
  --db "${TC_DB_PATH:-/data/threat-cloud.db}" \
  --backup-dir "${TC_BACKUP_DIR:-/backups}"
