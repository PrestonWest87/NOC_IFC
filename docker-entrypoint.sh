#!/bin/sh
set -eu

# Bind-mounted data directories retain host ownership. Repair only this runtime
# directory before dropping privileges for the application process.
if [ -d /app/data ]; then
    chown -R appuser:appuser /app/data
fi

exec gosu appuser "$@"
