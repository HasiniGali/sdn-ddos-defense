# Run log — decisions, versions, seeds

Chronological. Each entry: what was decided or run, and why.

## Host environment (2026-10-28)

- Host: CachyOS (Arch-based), kernel 7.3.0-4-cachyos, 20 CPUs, 15 GiB RAM, ~12 GB free disk.
- Mininet/OVS/hping3/iperf3 are not installed on the host. Docker and passwordless sudo are available.
- The `openvswitch` kernel module exists and was loaded with `sudo modprobe openvswitch`.

## Decisions

| ID | Decision | Reason |
|---|---|---|
| D-01 | Run Mininet + OVS + os-ken inside a privileged Docker container (`docker/Dockerfile`, Ubuntu 24.04) instead of installing on the host. | Same environment as the team's Ubuntu 24.04 machines; one command reproduces it; no host package changes. |
| D-02 | Container runs with `--network none`. | Emulated attack traffic physically cannot leave the container (safety requirement in the brief). |
| D-03 | **os-ken** instead of Ryu 4.34. | Ryu 4.34 + eventlet fails on current Python (see REVIEW.md M1); os-ken is the maintained fork with the same API (`os_ken` imports, `osken-manager`). |
| D-04 | CICDDoS2019 CSVs taken from the Hugging Face mirror `bencorn/CICDDoS2019` (`csvs/CSV-01-12.zip`, `csvs/CSV-03-11.zip`), not from cicresearch.ca. | The official download is behind a personal-data registration form, which I did not fill in on the team's behalf. SHA-256 of both zips is recorded in `data/raw/cicddos2019/SHA256SUMS`. **Team should verify against an official copy.** |
| D-05 | Streamed stratified sample of CICDDoS2019 (all BENIGN rows + ~40k attack rows per CSV, seed 2019) instead of the full 20+ GB. | Disk budget (~12 GB free). Sampling script: `analysis/cic_prepare.py`. |
| D-06 | Flow rules match L3 `(ipv4_src, ipv4_dst, ip_proto)`, not L4 ports. | Per-source attribution needs IPs (REVIEW C2); L4 matching would turn a SYN flood into a packet-in storm. Spoofed-source floods are out of scope (limitation). |
| D-07 | Features are computed only on each source's ingress switch. | Avoid multi-hop double counting (REVIEW H4). Ingress = first switch to send a packet-in for that source. |
| D-08 | All detectors run in **shadow mode** in every evaluation run; one "active" detector drives mitigation. | Every run yields detection metrics for every detector on identical traffic; mitigation comparisons stay paired. |
| D-09 | Server IP is protected from blocking for all detectors. | Standard practice (infrastructure allow-list); applying it to all modes keeps the comparison fair. Shadow detections on the server are still reported. |
| D-10 | Unblock logic reads drop-rule counters (blocked source must be quiet for 2 polls and blocked ≥ 10 s; backoff doubles per repeat offence). | A blocked source looks silent on forwarding flows; see REVIEW §2.1. |
| D-11 | Attackers also browse (light HTTP) before, during and after the attack. | Prevents "host identity" shortcuts and makes unblock/collateral meaningful. |
| D-12 | Model-selection rule fixed before results: proposed = rf or xgb, whichever has higher out-of-fold F1 on phase A (GroupKFold by run). | Avoid choosing the "proposed" method after seeing evaluation results. |
| D-13 | Threshold baseline = pps cut-off tuned for max F1 on phase A. | A tuned threshold is the strongest fair conventional baseline. |
| D-14 | Seeds depend on (condition, repetition), never on defense mode. | Runs of different modes are paired on identical randomness. |
| D-15 | Changes are left uncommitted in the working tree (original files moved with `git mv` to `legacy/`). | Commit only on the user's request; easy to review as one diff. |
| D-16 | os-ken 4.2.2 has no `osken-manager`; added `sdnddos/run_controller.py`. os-ken 4.x runs its hub on native threads (`OSKEN_HUB_TYPE=native`); all handlers run on the app's single event-loop thread. | Discovered when the first smoke run failed (`FileNotFoundError: osken-manager`). |
| D-17 | Phases A (3 workers), B and C (4 workers) run in parallel containers; phase O (CPU overhead) runs alone. | Runs take ~78 s; sequential would need ~9 h. Concurrency was validated: two concurrent smoke runs measured 504.2 and 504.5 pps per attacker, identical to a solo run. Run order shuffled (seed 42) so interference spreads evenly over modes. |
| D-18 | Benign TCP metric = attack-window goodput / offered rate (0.4·B), not / pre-attack baseline. | The threshold baseline falsely blocks the iperf3 host during warm-up, which shrank the baseline and produced ratios > 1 (a harmful defense looked good). Found in the partial-B dry run. |
| D-19 | Autoencoder kept with its a-priori threshold (99th percentile of benign training error) even though CV F1 = 0.0. | Changing the threshold after seeing attack scores would be tuning on labels; reported as a negative result (attack traffic reconstructs well; the server's multi-flow intervals are the outliers). |
| D-20 | Live-vs-offline check compares decisions, not raw scores. | Features are logged with 6 significant digits; RF/XGBoost scores move by up to 0.1 near splits, but 0 of 4,722 decisions differed in the dry run. Table `live_vs_offline.csv`. |
| D-21 | iperf3 UDP loss parsed from the server's text report embedded by `--get-server-output`. | The iperf3 server was started without `--json`. |
| D-22 | Static report numbers come only from `report/facts.json`, generated from `results/tables`. | Prevents transcription errors in the report. |
| D-23 | Phase O (per-detector controller CPU, 40 runs) dropped at the user's request to finish sooner. Overhead is reported from the per-detector inference times every run already logged in shadow mode, plus controller CPU/RSS from phase B. | User: "i need it sooner". `experiments/plan.py O` still exists if wanted later. |

## Versions

Host: Intel Core i7-13650HX (20 logical CPUs), 15 GiB RAM, CachyOS, kernel 7.3.0-4-cachyos, Docker 29.9.2.
Container (`sdnddos:dev`): Ubuntu 24.04.5, Mininet 2.3.0-1.1, Open vSwitch 3.3.9, hping3 3.a2.ds2-10build2, iperf3 3.16, Python 3.12.3.
Python packages: see `requirements.lock` (os-ken 4.2.2, scikit-learn 1.9.1, xgboost 3.4.1, shap 0.54.1, numpy 2.5.4, pandas 3.1.0, eventlet 0.41.3).
Report: docx (npm) 9.15.0, LibreOffice for PDF conversion.

## Run log

| ID | What | Outcome |
|---|---|---|
| R-001 | Evidence for REVIEW.md from the committed CSVs | max pps 10.4; constant flow counts 19/27/19; poll gaps 4–6 s; session gaps 129 s and 326 s |
| R-002 | `mn --test pingall` in container | 0 % dropped |
| R-003 | Unit tests | 25 passed |
| R-004 | Smoke run (UDP 500 pps, mode none) | attackers measured ~500 pps; benign TCP 4.0 → 2.9 Mb/s; ping RTT p50 453 ms during attack |
| R-005 | Phase A (72 runs) | 72/72 ok; 15 558 rows, 3 213 attack rows |
| R-006 | Training (`analysis/train.py`) | OOF F1: xgb 0.996, svm 0.992, rf 0.987, dt 0.980, lr 0.804, threshold 0.527, ae 0.000 → proposed = xgb; tuned threshold 171 pps |
| R-007 | Closed-loop check B-udp-high-r0-xgb | 3/3 attackers blocked 3.6 s after start; unblocked 6 s after attack end; benign TCP 98.5 % of baseline; 0 false blocks |
| R-008 | CICDDoS2019 sample | 889 321 rows from 2 zips (seed 2019) |
| R-009 | Independent code review | 4 bugs fixed (see CHANGELOG); deployed model kept, clean re-train selects the same model |
| R-010 | Phase B (180 runs) | 180/180 ok |
| R-011 | Phase C (195 runs, fixed controller) | 195/195 ok |
| R-012 | `scripts/analyse_all.sh` + report build | 579 facts; report 34 pages (30 + 4 appendix) |

## Seeds

| Use | Seed |
|---|---|
| Phase A plan generator | 1000 (runs use 1000–1071) |
| Phase B core runs | 5000 + 10·condition + rep |
| Phase C OFAT runs | 7000 + 10·condition + rep |
| Run order shuffle | 42 |
| Model training | 7 |
| CICDDoS2019 sampling | 2019 |
