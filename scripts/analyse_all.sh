#!/bin/bash
# Rebuild every table, figure and report fact from the raw runs.
set -e
cd "$(dirname "$0")/.."
for p in A B C; do scripts/analysis.sh analysis/build_dataset.py $p; done
scripts/analysis.sh analysis/eval_detection.py B C
scripts/analysis.sh analysis/eval_mitigation.py B C
scripts/analysis.sh analysis/explain_offline.py
scripts/analysis.sh analysis/cic_experiments.py xdom
scripts/analysis.sh analysis/plots.py
scripts/analysis.sh report/facts.py
