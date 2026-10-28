# Notes for the team

Short version: everything in the report was run for real, on one machine, and every
number traces back to a file in `results/`. Please read the "verify yourself" list
before submitting.

## What was run where

| Part | Where | Status |
|---|---|---|
| Mininet + OVS + os-ken experiments (phases A, B, C: 447 runs) | Docker container (Ubuntu 24.04) on a CachyOS laptop, i7-13650HX, 15 GiB RAM, host kernel OVS datapath | Done, all raw logs in `results/runs/` |
| Training, evaluation, SHAP, plots | Same Docker image, no privileges | Done |
| CICDDoS2019 experiments | Same image, on a stratified sample (889 321 rows) | Done |
| Report build | Node (docx 9.15) + LibreOffice for the PDF | Done |

Nothing in the report is estimated or illustrative. Where something was not run
(spoofed-source floods, reflection attacks, rate-limit mitigation, full-factorial
conditions, controller-targeted attacks), the report says so in Section 9.2 and
Section 10.

## What could not be done, or was done differently from the brief

- **Repository mismatch.** The brief describes `topo.py` and `ryu_ddos_app.py`, but the
  repo only had monitoring scripts. The controller, ML, mitigation and experiments were
  written from scratch (see `REVIEW.md`, `CHANGELOG.md`). The originals are in `legacy/`.
- **Ryu → os-ken.** Ryu 4.34 does not run on current Python. os-ken 4.2.2 is used
  instead. It has no `osken-manager` command, so `python -m sdnddos.run_controller` is
  the launcher.
- **Mininet runs in Docker**, not on the host (`scripts/in_container.sh`). On your
  Ubuntu machine the same commands work once Docker is installed and
  `sudo modprobe openvswitch` succeeds.
- **CICDDoS2019 download.** The official site asks for a registration form, which I did
  not fill in with your details. The two CSV zips came from the Hugging Face mirror
  `bencorn/CICDDoS2019`. SHA-256 hashes are in `data/raw/cicddos2019/SHA256SUMS`. The
  zips were deleted afterwards to save disk; the 64 MB sample
  (`data/cic/cic_sample.parquet`) is git-ignored and is rebuilt by
  `analysis/cic_prepare.py` from the zips (seed 2019).
- **Experiment matrix.** One-factor-at-a-time around a default, not full factorial (a full
  factorial would be >3 000 runs). Five repetitions per condition, as required.
- **Parallel runs.** Phases A–C ran 3–4 containers at once. See RUNLOG D-17 for the check
  that this did not change attack rates.
- **Phase O (per-detector CPU overhead) was dropped** to finish sooner (RUNLOG D-23).
  Overhead in the report comes from the inference times every run logged anyway.

## Things you should verify yourself

1. **References** (`docs/references_verification.md` has the details):
   - All 10 assigned papers exist, and volume, article number, year and DOI match Crossref.
   - Authors were missing in the brief for CANDICE [8] and eX-NIDS [10], and incomplete
     for [7] and [9]. I filled them in from Crossref.
   - eX-NIDS: the brief says "vol. 129, **Part B**". Crossref has no part for it, so the
     report leaves "Part B" out. Check ScienceDirect and add it back if it is there.
   - "A. A. Korba" in [5] is "A. Amara Korba" (family name "Amara Korba").
   - Lanvin et al. [23]: LNCS volume 13857 comes from a secondary source.
   - Abstracts of several Elsevier papers could only be read from repository pages or
     snippets (ScienceDirect blocked automated access). The related-work table
     paraphrases abstracts only; re-read [4], [6], [8], [9] if you want to add detail.
2. **CICDDoS2019 hashes** against an official copy, if you have one.
3. **Re-run one condition** on your own machine to see the numbers reproduce, e.g.
   `python3 experiments/plan.py B --proposed xgb` and then
   `scripts/in_container.sh python -m sdnddos.orchestrator results/runs/B/B-udp-high-r0-xgb/spec.json`.
4. **Defend these claims carefully** in a viva:
   - XGBoost beats the threshold by a lot. It does **not** clearly beat a decision tree.
     The report says this; do not overclaim.
   - The near-perfect F1 is on hping3 floods with fixed packet sizes. SHAP shows the
     models rely on packet size and protocol mix, which an attacker could imitate.
   - The autoencoder failed (F1 = 0 at its a-priori threshold). That is a real negative
     result, not a bug.

## Exact commands

See `README.md` § Reproduce. The full pipeline takes about 3 hours of experiment time on
a 20-thread machine with 3–4 parallel workers, plus ~15 min to build the image.
`scripts/analyse_all.sh` rebuilds every table, figure and report number; then
`node report/build_report.js` and LibreOffice produce the .docx and .pdf.

## Key results (for quick reference)

- Held-out detection F1: XGBoost 0.998, random forest 0.998, decision tree 0.994, tuned threshold 0.570 (threshold FPR 32.51 %), autoencoder 0.000.
- Closed loop, phase B (9 attack conditions × 5 reps): benign TCP goodput / offered = 1.00 (XGBoost), 1.00 (decision tree), 0.36 (threshold), 0.62 (no defense). Time to mitigation 3.19 s. False blocks per run: 0.00 (XGBoost) vs 2.38 (threshold).
- XGBoost vs decision tree in the closed loop: no significant difference on any metric. Vs threshold: much better goodput and far fewer false blocks, but a few ms worse ping RTT (the threshold had blocked the iperf host, freeing the queue).
- CICDDoS2019: XGBoost F1 0.997 with all features vs 0.850 with OpenFlow-computable features (train day 1, test day 2). Cross-domain transfer is poor.
- XGBoost inference in the controller: 1.540 ms per poll.
