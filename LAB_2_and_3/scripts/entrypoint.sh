#!/bin/sh
set -eu

DATABASE_PATH="${APP_DATABASE_PATH:-/app/transport.db}"

mkdir -p "$(dirname "$DATABASE_PATH")"

goose -dir /app/migrations sqlite3 "$DATABASE_PATH" up

/app/server &
APP_PID=$!

nginx -g 'daemon off;' &
NGINX_PID=$!

cleanup() {
    kill "$APP_PID" "$NGINX_PID" 2>/dev/null || true
}

trap cleanup INT TERM

wait "$APP_PID" "$NGINX_PID"
