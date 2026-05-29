#!/bin/sh
set -e

echo "Starting transport_api..."
/app/transport_api &

echo "Starting nginx..."
nginx -g "daemon off;"
