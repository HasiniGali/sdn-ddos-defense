# Intelligent DDoS Detection and Mitigation for SDN (Group 9)

Mininet + Open vSwitch + os-ken (maintained Ryu fork) + scikit-learn / XGBoost.
The controller computes per-source features from OpenFlow flow counters every 2 s,
scores them with several detectors, blocks attackers with drop rules on their ingress
switch, unblocks them when they go quiet, and logs a SHAP explanation for every block.

Team:  Gali Hasini (25BCE2096), Ayush Biswas (25BCE0507), Ustat Kaur (25BAI0022).

## Layout

```
sdnddos/            controller app, features, detectors, mitigation, topology, orchestrator
  controller_app.py   os-ken OpenFlow 1.3 app (switching, polling, detection, mitigation)
  run_controller.py   launcher (os-ken 4.x has no osken-manager)
  flowstats.py        cumulative counters -> per-interval deltas (handles flow expiry)
  features.py         per-source feature vectors
  detectors.py        detector registry (threshold, dt, lr, svm, rf, xgb, ae)
  mitigation.py       block/unblock state machine
  explain.py          per-decision SHAP attributions
  topo.py, traffic.py, benign_client.py, orchestrator.py   experiment harness
experiments/        plan.py (run specs per phase), run_phase.py (runner)
analysis/           dataset building, training, evaluation, CICDDoS2019, plots
scripts/            in_container.sh, analysis.sh, run_phase.sh
results/runs/       one directory per run (spec, manifest, all raw logs)
results/datasets/   per-phase feature tables (parquet)
results/tables/     every number used in the report (CSV)
results/figures/    every figure used in the report
models/             trained detector bundle + training report
report/             report source and the built .docx / .pdf
legacy/             the original prototype, untouched (see REVIEW.md)
```

## Requirements

- Linux host with Docker and the `openvswitch` kernel module (`sudo modprobe openvswitch`).
  Tested on CachyOS kernel 7.3; any Ubuntu 22.04/24.04 host works the same way.
- ~4 GB disk for the image, ~4 GB more if you re-download CICDDoS2019.

Everything else (Mininet 2.3, OVS, os-ken, hping3, iperf3, Python packages) is inside
the image, pinned in `requirements.lock`.

## Reproduce

```bash
# 1. Build the image (~15 min) and check Mininet works
docker build -f docker/Dockerfile -t sdnddos:dev .
scripts/in_container.sh mn --test pingall

# 2. Unit tests
scripts/analysis.sh -m pytest -q tests

# 3. Phase A: training runs (72 runs), dataset, training
python3 experiments/plan.py A
scripts/run_phase.sh A 3
scripts/analysis.sh analysis/build_dataset.py A
scripts/analysis.sh analysis/train.py            # writes models/, picks the proposed model

# 4. Evaluation runs (fresh seeds). PROPOSED is printed by train.py
P=$(python3 -c "import json;print(json.load(open('models/train_report.json'))['proposed'])")
python3 experiments/plan.py B --proposed $P && scripts/run_phase.sh B 4
python3 experiments/plan.py C --proposed $P && scripts/run_phase.sh C 4
for p in B C; do scripts/analysis.sh analysis/build_dataset.py $p; done

# 5. Analysis
scripts/analysis.sh analysis/eval_detection.py B C
scripts/analysis.sh analysis/eval_mitigation.py B C
scripts/analysis.sh analysis/explain_offline.py

# 6. CICDDoS2019 (optional: needs the two CSV zips in data/raw/cicddos2019/)
scripts/analysis.sh -I analysis/cic_prepare.py data/raw/cicddos2019 data/cic/cic_sample.parquet
scripts/analysis.sh analysis/cic_experiments.py cic
scripts/analysis.sh analysis/cic_experiments.py xdom   # after phase B

# 7. Figures and report
scripts/analysis.sh analysis/plots.py
scripts/analysis.sh report/build_report.py
```

Interrupted phases resume: `run_phase.sh` skips runs whose manifest says `done`.

## Running one experiment by hand

```bash
python3 experiments/plan.py B --proposed xgb
scripts/in_container.sh python -m sdnddos.orchestrator results/runs/B/B-udp-high-r0-xgb/spec.json
```

## Safety

Attack traffic (hping3) runs only inside Mininet host namespaces in a container with
no network interface (`--network none`), and `sdnddos/traffic.py` refuses any target
outside `10.0.0.0/24`.

See `REVIEW.md` (review of the original code), `CHANGELOG.md` (fixes),
`RUNLOG.md` (decisions, versions, seeds) and `NOTES_FOR_TEAM.md`.
