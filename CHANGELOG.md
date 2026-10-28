# Changelog

Issue IDs refer to `REVIEW.md`.

## [Unreleased] — full system rewrite (2026-10-28)

### Environment
- **M1** Replaced the Ryu 4.34 + eventlet monkey-patch setup with **os-ken 4.2.2** in a
  pinned Ubuntu 24.04 Docker image (`docker/Dockerfile`, `requirements.lock`).
  os-ken 4.x no longer ships `osken-manager`, so `sdnddos/run_controller.py`
  reproduces what `ryu-manager` did (eventlet patch, option parsing, app start).
- Container runs with `--network none` so emulated attack traffic cannot leave it
  (`scripts/in_container.sh`).
- **M7** Added README with reproduction steps, `requirements.txt` + lock file,
  unit tests (`tests/`), and seeds in every run manifest.

### Controller (`sdnddos/controller_app.py`, new)
- **C1** New OpenFlow 1.3 app: learning switch, flow-stats polling, per-source
  features, detection, mitigation and logging. Replaces the stock
  `simple_switch_13` + `ofctl_rest` combination and the REST pollers.
- **C2** Forwarding flows match `eth_type, ipv4_src, ipv4_dst, ip_proto`, so every
  counter is attributable to a source IP.
- **H3** Forwarding flows have a 10 s idle timeout and `OFPFF_SEND_FLOW_REM`.
- **H4** Features use only each source's ingress switch; the table-miss flow is
  excluded.
- **M5** Unix-epoch timestamps with millisecond resolution, shared with the
  orchestrator.
- **M6** Statistics come straight from OpenFlow multipart replies (multi-part replies
  are reassembled) instead of a REST round trip.

### Statistics and features (`sdnddos/flowstats.py`, `sdnddos/features.py`, new)
- **C3, H2** Per-flow delta tracker: deltas between polls, restart detection
  (counter or duration went backwards), and final counters from `OFPFlowRemoved`
  so expired flows are not lost. Unit-tested.
- **H1** Rates divide by the measured time between stats replies, not a constant.
- Ten per-source features (`sdnddos/config.py: FEATURES`): the six from the brief plus
  `new_flows` and per-protocol packet shares.

### Mitigation (`sdnddos/mitigation.py`, new)
- Drop rule (priority 100) on the source's ingress switch after `confirm_intervals`
  consecutive positive intervals. Unblock only after the minimum block time **and**
  two quiet polls measured on the drop rule's own counters; the minimum block time
  doubles for repeat offenders. Server IP is protected. Unit-tested.

### Detection and explainability (`sdnddos/detectors.py`, `sdnddos/explain.py`, new)
- Detector registry: tuned static pps threshold, decision tree, logistic regression,
  RBF SVM (Platt-calibrated), random forest, XGBoost, autoencoder (benign-only).
- All detectors run in shadow mode every poll; one drives mitigation.
- Every block decision logs its top-5 feature attributions (exact TreeSHAP for tree
  models).

### Experiments (`sdnddos/orchestrator.py`, `experiments/`, new)
- **C4, H7** One directory per run (`results/runs/<phase>/<run_id>/`) with spec,
  manifest (ground-truth attack start/end per attacker, same clock as the controller),
  controller logs, iperf3/ping/HTTP logs and resource samples.
- **M2** Parameterised topologies (`small`: 1 switch, 3 benign + 3 attackers + server;
  `large`: 2 switches, 8 benign + 4 attackers + server) over `TCLink` with
  bandwidth, delay and loss.
- **H6** TSO/GSO/GRO disabled on every host interface.
- Attack commands refuse any target outside `10.0.0.0/24` (`sdnddos/traffic.py`).
- Phase plans with seeds tied to (condition, repetition), resumable runner, parallel
  containers.

### Removed / moved
- **H5, M3, M4** `traffic_monitor.py`, `traffic_features.py`, `ip_traffic_collector.py`,
  `topology.py`, `start_ryu.py`, `eventlet_compat.py` and the three CSVs moved to
  `legacy/` unchanged, for reference. Nothing in the new pipeline uses them.

## Fixes from an independent code review during evaluation (2026-10-28)

A second, independent review of the new code ran while phase B was executing. Fixes:

- **Transit-switch FlowRemoved (controller).** `_flow_removed` now applies the same
  ingress filter as the stats handler. Before, in the two-switch topology, a transit
  switch's flow expiry was counted as one interval's traffic (53 spurious rows in phase A).
  Fixed before phase C; phase B uses one switch and is unaffected.
  `analysis/build_dataset.py` drops non-ingress rows from older logs. The deployed model
  (trained before the fix) is kept for consistency with the live runs; a re-train on the
  cleaned data (`models/retrain_clean/`) selects the same model and threshold.
- **iperf3 JSON parsing.** When iperf3 is stopped at the end of a run it can write
  diagnostic text around its JSON; `run_metrics` now extracts the JSON object
  (`raw_decode`). At review time this affected 12 of the first 81 phase-B runs (TCP goodput NaN), mostly
  undefended/threshold runs, which had biased comparisons. The orchestrator's grace
  period before stopping clients was raised from 2 s to 6 s (teardown only).
- **False blocks by ground truth.** A block is false unless its source was attacking at
  that moment (+4 s grace), judged from the run manifest instead of the address plan, so
  blocks of attacker hosts in benign-only runs now count.
- **Ping loss.** Send times of lost probes are interpolated between received probes and
  the total comes from ping's own summary, instead of assuming exact 0.2 s spacing.
- **Timing averages** exclude polls with no sources.
- **Cross-domain flow records** subtract the 10 s idle timeout from idle-expired flow
  durations and keep ingress-switch records only.
- `sdnddos/topo.py: ingress_switch()` is the single source of host placement, used by the
  topology and the analysis (unit-tested).
