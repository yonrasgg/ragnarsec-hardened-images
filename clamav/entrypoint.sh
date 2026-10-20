#!/bin/sh
set -eu

DB_DIR="${CLAMAV_DB_DIR:-/var/lib/clamav}"

if [ ! -f "$DB_DIR/main.cvd" ] && [ ! -f "$DB_DIR/main.cld" ]; then
    echo "clamav: no signature database in ${DB_DIR}; downloading with freshclam" >&2
    freshclam --quiet
fi

exec clamd "$@"
