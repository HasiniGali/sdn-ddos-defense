#!/bin/bash
# Run an analysis command in the same image, without OVS/privileges.
set -e
cd "$(dirname "$0")/.."
exec docker run --rm --network none -v "$PWD":/work --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e MPLCONFIGDIR=/tmp -e PYTHONPATH=/work --entrypoint python sdnddos:dev "$@"
