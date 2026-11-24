#!/usr/bin/env bash
# Wrapper used by lab/start_run.ps1: runs the matrix driver with all output appended to lab/run.log.
# Usage: lab/run_detached.sh --full | --mini [more run_matrix.sh options]
cd "$(dirname "$0")/.." || exit 2
exec bash lab/run_matrix.sh "$@" >> lab/run.log 2>&1
