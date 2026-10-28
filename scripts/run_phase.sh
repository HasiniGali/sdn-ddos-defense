#!/bin/bash
# Run all pending runs of a phase across N parallel containers.
#   scripts/run_phase.sh <phase> [workers]
# Each container has its own network namespace and OVS instance, so runs are isolated.
cd "$(dirname "$0")/.."
phase=$1; n=${2:-1}
mkdir -p results/logs
for ((w = 0; w < n; w++)); do
    SDNDDOS_WORKER="$phase-$w" scripts/in_container.sh \
        python experiments/run_phase.py "$phase" --worker "$w" --workers "$n" \
        > "results/logs/phase_${phase}_w$w.log" 2>&1 &
done
wait
grep -h "ok=" results/logs/phase_${phase}_w*.log | awk '{print $4}' | sort | uniq -c
