# Methodology

This document fixes the experimental protocol *before* any model is trained. Every later
result in this repository (model card, paper, CI model-quality gate) is reported under
this protocol, and any deviation is listed in the paper's limitations section.

## 1. Problem statement

Given a bidirectional network flow summarised by CICFlowMeter-style statistics, decide
(a) whether the flow is malicious (binary detector) and (b) if so, which attack family it
belongs to (multi-class classifier). The system must run on live traffic: features are
computed by our own extractor from packets, not read from the published CSVs, so the
extractor must reproduce the training-time feature semantics (train/serve parity).

Operational objective: maximise recall on attack flows at an *operator-chosen* false-positive
budget, with calibrated scores so the alert threshold is meaningful across days and sites.

## 2. Datasets

| Dataset | Capture dates | Flows (published) | Attack families | Role |
|---|---|---|---|---|
| CIC-IDS2017 | 3-7 Jul 2017, 5 days | 2,830,743 | 14 + BENIGN | primary train / in-distribution test |
| CSE-CIC-IDS2018 | 14 Feb - 2 Mar 2018, 10 days | ~16.2M (6 days used, see data card) | 14 + Benign | cross-dataset generalisation test and secondary training |

See [DATA_CARD.md](DATA_CARD.md) for provenance, known labelling errors and the exact
clean-up applied. The *fixes* are part of the methodology because they change the results
materially (Engelen et al. 2021; Lanvin et al. 2023; Liu et al. 2022).

## 3. Leakage controls

Leakage is the dominant source of inflated NIDS results. Controls, each enforced by a test
in `tests/test_splits.py` and `tests/test_data_pipeline.py`:

1. **Temporal split, never random.** Random row splits put the two halves of the same
   attack burst in train and test and are forbidden. The main protocol is the *campaign*
   split (`nids.data.splits`, `SplitConfig(protocol="campaign")`): a campaign is one label on
   one day (one attack family's run, or that day's benign traffic), and each campaign is cut
   60/20/20 into train/validation/test in its own time order. Every family that occurs on a
   day is therefore present in every fold, and its evaluation flows are strictly later than
   its training flows. The per-day split (`protocol="day"`, the whole day cut in time order)
   is reported as an ablation: on our data it leaves 13 of 26 attack families without a
   single test flow, because several days are one burst (16-02-2018: 87% of rows in one
   5-minute bucket of DoS-Hulk) or run an attack only late in the day. Whole days or whole
   datasets can additionally be held out for out-of-time and cross-dataset evaluation.
2. **Group integrity.** Folds are assigned on contiguous time blocks, never on single rows:
   60-second blocks for the campaign split and 5-minute blocks for the day split when
   timestamps exist, blocks of 5,000 rows in capture order for CIC-IDS2017 (no timestamps).
   A campaign shorter than five blocks is cut on 20 equal row blocks in time order, which is
   the weakest guarantee in the protocol and is visible in the `group_id` (`:r` suffix).
   `assert_no_leakage` checks that no block spans two folds and that, within every
   campaign (or day), all training rows precede all validation rows, which precede all test
   rows. CSE-CIC-IDS2018 timestamps are printed on a 12-hour clock without AM/PM and are
   corrected before any ordering (DATA_CARD section 2).
3. **Deduplication and purge.** Exact duplicate rows are removed during cleaning. After the
   split, every validation/test row whose model-input vector also occurs in the training
   fold is removed, first within the day and then across all days (cross-day purge on a
   64-bit hash of the 59 model inputs), so the model is never evaluated on an input it was
   fitted on. Purge counts are written to `artifacts/reports/split_summary_<protocol>.csv`.
4. **Fit-on-train-only preprocessing.** Imputation constants, clipping bounds and scalers
   are fit on the training fold inside a `Pipeline`; the test fold never touches them.
   Verified by a test that mutates the test fold and asserts the fitted transformer is
   unchanged.
5. **No identifier features.** Flow ID, IPs, source port and timestamp are dropped from the
   feature matrix. Destination port is kept *only* as a bucketed categorical (well-known /
   registered / ephemeral) in the default feature set, because the raw destination port is
   a label proxy in CIC datasets (the attack machines target fixed ports).
6. **Day-of-capture is not a feature** and class priors are not tuned on test days.
7. **Cross-dataset evaluation** trains on one dataset and tests on the other with *no*
   re-fitting of anything, including thresholds.

## 4. Feature set

The canonical feature schema (`nids.data.schema.FEATURES`) is the intersection of
CICFlowMeter v3 features present in both datasets, after:

* dropping the duplicated `Fwd Header Length.1` column (CIC-IDS2017 bug);
* dropping the eight features that are constant zero in both datasets
  (`Bwd PSH Flags`, `Bwd URG Flags`, `Fwd Avg Bytes/Bulk`, `Fwd Avg Packets/Bulk`,
  `Fwd Avg Bulk Rate`, `Bwd Avg Bytes/Bulk`, `Bwd Avg Packets/Bulk`, `Bwd Avg Bulk Rate`);
* mapping the 2018 column names to the 2017 names (`nids.data.schema.CSE2018_RENAME`);
* excluding the ten TCP flag columns (`FIN`..`ECE` flag counts, `Fwd PSH Flags`,
  `Fwd URG Flags`) from the model inputs (`nids.data.schema.UNREPRODUCIBLE`). On the
  14-02-2018 victim capture the published flag values follow neither the packets' TCP flags
  nor the released CICFlowMeter source (published `PSH` tracks SYN, `ACK`/`URG` track FIN,
  `SYN`/`FIN`/`RST` are always 0), so a deployed extractor could not reproduce them. That
  leaves 58 flow statistics plus the destination-port bucket (59 inputs).

Real-traffic parity (`scripts/parity_report.py`, `reports/parity_report.md`): of 383,002
flows extracted from the 853 MB capture, 382,586 (99.9%) match a published row on start
second, destination port, protocol and packet/byte totals, and all 58 model-input statistics
agree within tolerance on at least 99.9% of matched flows.

The feature extractor in `nids.features.flow` computes exactly this schema from packets.
Train/serve parity is tested by extracting features from synthetic PCAPs whose flow
statistics are known analytically, and from recorded traffic whose CICFlowMeter output is
published, with per-feature tolerances documented in `tests/test_parity.py`.

## 5. Models

* **Baselines:** majority class; logistic regression on standardised features; random
  forest.
* **Primary:** LightGBM (binary) with class weighting, and LightGBM (multi-class) for the
  attack-family stage. XGBoost is trained as a cross-check.
* **Hyper-parameters** are chosen by Optuna on the *validation* fold only (time-ordered,
  from the training days); objective = PR-AUC.
* **Calibration:** isotonic regression fit on the validation fold; reported with
  expected calibration error (ECE, 15 bins) and reliability diagrams.
* **Thresholding:** the operating threshold is chosen on validation to meet a target
  false-positive rate (default 0.1%) and is frozen before any test evaluation.
* **Unsupervised complement:** an Isolation Forest on benign-only training flows provides
  an anomaly score for novel attacks; it is evaluated leave-one-family-out and never on
  families it saw.

## 6. Evaluation protocol

All metrics are reported on (i) the in-time test fold, (ii) held-out days, and
(iii) the other dataset. Metrics:

* PR-AUC (primary, robust to the class skew), ROC-AUC (secondary).
* Recall at FPR = 0.1% and at FPR = 1% (the operator-facing numbers).
* Per-family recall and macro-F1 for the multi-class stage.
* Calibration: ECE and Brier score.
* Latency: p50/p95/p99 inference time per flow, single core, batch sizes 1 and 512.

Confidence intervals are bootstrap percentile intervals (1,000 resamples over flows,
stratified by day). Seeds are fixed (`nids.config.SEED = 20170703`) and every run is logged
to MLflow with the data manifest hash, git commit and environment.

## 7. Ablations

Each ablation re-runs the full protocol with one change:

1. random split instead of temporal (to quantify the leakage inflation);
2. no deduplication;
3. raw destination port included as a numeric feature;
4. no label corrections (original CSV labels);
5. features restricted to the 20 most important (SHAP) features;
6. training on 2017 only vs. 2017 + 2018.

## 8. Reproducibility

`nids reproduce` runs: download with checksum verification -> canonicalise -> validate ->
split -> train -> evaluate -> write `reports/`. Every table in the paper is generated by
code in `scripts/` from the MLflow run store; no number is typed in by hand.

## 9. Ethics and scope

The datasets are synthetic testbed captures released for research by the Canadian
Institute for Cybersecurity; they contain no real user data. The live capture agent must
only be deployed on networks the operator is authorised to monitor
(see [SECURITY.md](../SECURITY.md) and [THREAT_MODEL.md](THREAT_MODEL.md)).

## References

* Sharafaldin, Lashkari, Ghorbani. *Toward Generating a New Intrusion Detection Dataset and
  Intrusion Traffic Characterization.* ICISSP 2018.
* Engelen, Rimmer, Joosen. *Troubleshooting an Intrusion Detection Dataset: the CICIDS2017
  Case Study.* IEEE S&P Workshops 2021.
* Lanvin, Gimenez, Han, Majorczyk, Me, Totel. *Errors in the CICIDS2017 Dataset and the
  Significant Differences in Detection Performances It Makes.* CRiSIS 2022.
* Liu, Engelen, Lynar, Essam, Joosen. *Error Prevalence in NIDS Datasets: A Case Study on
  CIC-IDS-2017 and CSE-CIC-IDS-2018.* IEEE CNS 2022.
* Arp et al. *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security 2022.
