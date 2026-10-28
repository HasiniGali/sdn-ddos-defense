# Critical review of the original repository (commit `8b00bb5`)

Reviewed: every file in the initial commit — `topology.py`, `traffic_monitor.py`,
`traffic_features.py`, `ip_traffic_collector.py`, `start_ryu.py`, `eventlet_compat.py`,
`.gitignore`, and the three committed CSVs. Evidence quoted below was computed from the
committed files themselves (see the command in `RUNLOG.md`, entry R-001).

## 0. The repository is not the one described in the project brief

The brief describes `topo.py` (1 switch, web server, 3 benign hosts, 3 attackers,
bandwidth/delay/loss parameters) and `ryu_ddos_app.py` (OpenFlow 1.3 app with
per-source features, ML model, threshold fallback and drop-rule mitigation).
**Neither file exists in the repository.** What exists is a monitoring-only prototype:

| File | What it actually does |
|---|---|
| `topology.py` | 3 linear switches, 6 hosts, plain links (no bw/delay/loss), no roles |
| `traffic_monitor.py` | polls the Ryu REST API (`ofctl_rest`), sums all flow counters per switch |
| `traffic_features.py` | same polling, writes `src_ip=UNKNOWN`, rates hard-coded to 0 |
| `ip_traffic_collector.py` | scapy sniffer on one interface, per-source 5 s windows |
| `start_ryu.py`, `eventlet_compat.py` | launcher with a monkey-patch for `eventlet.wsgi.ALREADY_HANDLED` |

So there is **no detection, no mitigation, no ML, no labels, no attack traffic and no
controller application of our own**. The review below therefore covers (a) bugs in the
code that exists and (b) design pitfalls the brief's planned design would hit, which the
rewrite has to avoid.

## 1. Issues ranked by severity

### Critical — these make the stated research objective impossible as-is

| ID | Issue | Evidence | Fix (see CHANGELOG) |
|---|---|---|---|
| C1 | No controller app, detector or mitigation exists. The project relies on Ryu's stock `simple_switch_13` + `ofctl_rest` (inferred from the `/stats/flow/<dpid>` endpoint; the launch command is not documented anywhere). | No `ryu.base.app_manager` subclass in the repo. | New os-ken app `sdnddos/controller_app.py` with detection, mitigation, shadow-mode logging. |
| C2 | Flows installed by `simple_switch_13` match only `in_port, eth_src, eth_dst`. Flow stats therefore cannot yield **per-source-IP** features; `traffic_features.py` admits this and writes `src_ip=UNKNOWN`, `n_dst=0`, `proto=UNKNOWN`. | All 12 rows of `traffic_features.csv` have `src_ip=UNKNOWN`, `pkt_rate=0`, `byte_rate=0`. | Flow rules now match `eth_type=IPv4, ipv4_src, ipv4_dst, ip_proto`, so every flow is attributable to a source. |
| C3 | `traffic_features.py` writes **cumulative** counters (`packet_count` since flow install) into columns named as per-window values. Consecutive "windows" are byte-identical. | Rows at 11:43:25…11:43:40 all read `766, 64876` for s1. | Per-flow delta tracker `sdnddos/flowstats.py`, keyed by flow identity, with counter-reset handling. |
| C4 | No labels anywhere (`label` column empty in every CSV) and no attack traffic was ever recorded: the maximum packet rate in `switch_traffic.csv` is **10.4 pps**. No supervised model could have been trained on this data. | 534 rows, max `packet_rate` 10.4. | Orchestrator logs ground-truth attack windows on the same clock as the controller; labels are derived automatically (`sdnddos/labels.py`). |

### High — produce wrong numbers silently

| ID | Issue | Evidence | Fix |
|---|---|---|---|
| H1 | Rates divide by a hard-coded `INTERVAL=5` instead of the measured elapsed time; the loop period is actually `5 s + 3 HTTP round-trips`. | Observed gaps between polls: 4 s (7×), 5 s (160×), 6 s (8×) → up to ±20 % rate error. | Rates use the switch-reported `duration_sec/nsec` delta of each flow, falling back to reply timestamps. |
| H2 | Counter resets are clamped with `max(0, new - old)`. When a flow expires and is re-created, the new flow's packets are discarded, so traffic is **under-counted exactly when flows churn** (i.e. during floods). | `traffic_monitor.py:80`. | Delta tracker detects re-creation (counter or duration went backwards) and takes the new counter as the delta; final counters of expired flows are recovered from `OFPFlowRemoved` messages. |
| H3 | Flows never expire (`simple_switch_13` sets no timeouts): flow tables grow without bound and stale flows dominate totals. | `flow_count` is constant 19/27/19 for all 534 rows. | Forwarding flows get `idle_timeout`; drop rules get `hard_timeout`; both set `OFPFF_SEND_FLOW_REM`. |
| H4 | Switch-level sums **double/triple count** a packet that crosses s1→s2→s3, and include the table-miss flow (packets sent to the controller). | 30 of 51 non-zero-rate timestamps show identical rates on all three switches. | Features are computed only from the **ingress edge switch** of each source; table-miss and drop rules are tracked separately. |
| H5 | `ip_traffic_collector.py` sniffs a single trunk port (`s1-eth3`), so it misses intra-switch traffic, and it bypasses SDN entirely (data-plane capture, not controller statistics). A per-packet Python callback also drops packets under flood load, under-counting exactly during attacks. | Interface name is hard-coded; link order in `topology.py` makes `s1-eth3` the s1–s2 trunk. | Removed from the pipeline; kept under `legacy/` for reference. |
| H6 | Segmentation offload was not disabled, so the sniffer captured 64 KB super-packets: `avg_pkt_size` = **52 322 – 53 050 bytes**, impossible on a 1500-byte MTU link. Any packet-size feature from this collector is meaningless. | `ip_traffic.csv` rows for 10.0.0.1. | Not needed by the new pipeline (OpenFlow counters count wire packets); TSO/GSO are disabled on all host interfaces anyway so iperf3 behaves like a real NIC. |
| H7 | CSVs are opened in append mode with no run identifier: separate sessions are concatenated into one file (gaps of 129 s and 326 s in `switch_traffic.csv`). A random train/test split over such a file leaks across sessions. | Gaps at 11:25:56→11:28:05 and 11:30:50→11:36:16. | Every run writes to its own directory `results/runs/<run_id>/` with a manifest (seed, parameters, versions). |

### Medium

| ID | Issue | Fix |
|---|---|---|
| M1 | `eventlet_compat.py` patches `ALREADY_HANDLED` but Ryu 4.34 still fails on current Python (`TypeError: cannot set 'is_timeout' attribute of immutable type 'TimeoutError'`, as reported in the brief). | Switched to **os-ken** (maintained Ryu fork) inside a pinned Docker image; no monkey-patching. |
| M2 | Topology has no server/benign/attacker roles, no link bandwidth/delay/loss, no size parameter. | `sdnddos/topo.py`: parameterised star (1 switch) and two-switch topologies over `TCLink`. |
| M3 | Hard-coded API URL, switch list, interface name, intervals and output paths; one script writes relative to CWD, the others next to the script. | All parameters in `sdnddos/config.py` and per-experiment JSON plans. |
| M4 | `fetch_stats` and the field list are duplicated across two files. | Single statistics path inside the controller. |
| M5 | Timestamps are local-time strings truncated to whole seconds. | Unix epoch floats (ms resolution), one clock shared by controller and orchestrator. |
| M6 | Only `URLError`/`TimeoutError` are caught; `ConnectionResetError` or a JSON error crashes the monitor. | REST polling removed; stats come from OpenFlow replies inside the controller. |
| M7 | No README, requirements, setup instructions, tests, seeds or provenance for the committed CSVs. | README, pinned requirements + Dockerfile, pytest suite, seeds in every manifest. |

### Low

- `print` instead of logging; no log levels or files.
- `time.sleep(INTERVAL)` after the poll means the period drifts with API latency.
- The final partial window in `ip_traffic_collector.py` is lost on Ctrl+C (daemon writer thread), and the first window is a partial window divided by the full 5 s.

## 2. Pitfalls in the brief's *planned* design (avoided in the rewrite)

These concern `ryu_ddos_app.py` as described in the brief. The file does not exist, so they
are design risks rather than observed bugs.

1. **Blocked sources keep counting.** If mitigation simply drops traffic, the drop rule's
   counters are the only evidence the attack continues. An unblock rule based on "the
   source looks quiet" must read the drop rule's counters, or it will unblock an active
   attacker as soon as it is blocked (the source appears silent because it is dropped).
2. **Packet-in storms.** Matching on L4 ports turns a SYN flood with rotating source
   ports into one packet-in per packet. We match on L3 (src, dst, proto) and rate-limit
   packet-ins via the flow install itself; spoofed-source floods remain a limitation.
3. **Thread/greenlet safety.** Polling and packet-in handlers share flow state. Ryu ran
   everything as eventlet greenthreads; os-ken 4.x defaults to **native threads**
   (`OSKEN_HUB_TYPE=native`). In our app every event handler (packet-in, stats reply,
   flow-removed, state change) runs on the app's single event-loop thread, so all
   mutable state has one writer; the polling thread only snapshots the datapath list and
   calls `send_msg` (a `queue.Queue` put). A long model inference still delays packet-in
   handling, so inference time per poll is measured.
4. **Feature mismatch with CICDDoS2019.** CICFlowMeter computes ~80 bidirectional per-flow
   features (inter-arrival times, flag counts, idle/active times) that an OpenFlow 1.3
   switch cannot report. The controller sees unidirectional per-flow packet/byte counters
   and durations. Training on full CIC features and deploying on controller features is
   invalid; we quantify the gap instead (experiment `E-CIC`).
5. **Leakage.** Windows from one run are strongly autocorrelated. Random row-level
   splits overstate accuracy. We split by run and evaluate on runs generated later with
   unseen seeds.
6. **"Improvement over baselines" needs a fair baseline.** A static threshold with a
   tuned value is a strong baseline for volumetric floods. The claim only holds if it is
   tested on conditions where thresholds fail (low-rate attacks, elephant benign flows,
   server reply traffic), and we must report where it does not hold.

## 3. Security and safety

- No attack tooling existed in the original repo. The new attack scripts run `hping3`
  **only inside Mininet host namespaces** and refuse any target outside the emulated
  `10.0.0.0/24` network (`sdnddos/traffic.py`, `assert_internal_target`).
- Experiments run inside a dedicated Docker container; the emulated network has no route
  to the host's interfaces.
