#!/bin/sh
set -eu

docker run --rm \
    -v "$(pwd)":/src \
    -w /src \
    golang:1.24.2-alpine \
    go mod tidy
