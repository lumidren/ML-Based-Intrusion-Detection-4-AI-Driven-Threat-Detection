# Threat Model

Scope: the detection system itself, not the monitored network. We ask how an adversary who
knows this repository could defeat, poison, blind or abuse the detector, and what the code
does about it. Every mitigation is tied to a `file:line` location; `scripts/audit_threat_model.py`
re-resolves each reference and fails CI if a referenced symbol no longer exists.

## Assets

| Asset | Why it matters |
|---|---|
| Detection model (weights, thresholds, calibrator) | Integrity -> detection quality; confidentiality -> evasion is easier with white-box access |
| Training and feedback data | Poisoning target |
| Capture agent and its host | Sensor tampering, privilege (raw sockets) |
| Alert pipeline (Kafka topics, SIEM sinks, dashboard) | Flooding, injection, information disclosure |
| Operator attention | Alert fatigue is a denial of service on the humans |

## Adversary capabilities assumed

* **A1 Network attacker**: controls hosts on the monitored segment, can craft arbitrary
  packets, knows the feature set (it is public) and may hold a copy of the model.
* **A2 Feedback insider / compromised analyst account**: can submit label feedback through
  the dashboard API.
* **A3 Host-level attacker on a sensor node**: can stop, replace or starve the capture agent.
* **A4 Supply-chain attacker**: can attempt to alter model artifacts or images in transit.

Out of scope: encrypted-payload inspection, zero-day exploits against the capture library
itself, physical access to the Kafka brokers.

## Threats and mitigations

### T1 Adversarial evasion (A1)

*Attack.* Perturb flow statistics (packet sizes, timing, padding, splitting a scan across
many source ports/hosts) so the flow crosses the decision boundary while keeping the
malicious effect. Gradient-free attacks on tree ensembles are practical, and problem-space
constraints (you cannot reduce bytes below the payload you need) limit but do not eliminate
them.

*Mitigations.*
1. Monotonic constraints on features an attacker can only *increase* at a cost: the model
   may not reward an increase of SYN/RST counts or packet rate with a lower score.
   MITIGATION T1.1 -> `src/nids/models/train.py` `MONOTONE_CONSTRAINTS`
2. Ensemble disagreement: binary LightGBM, XGBoost cross-check and Isolation Forest scores
   are combined; large disagreement produces an "uncertain" verdict instead of silently
   trusting one model.
   MITIGATION T1.2 -> `src/nids/models/ensemble.py` `EnsembleScorer.score`
3. Evasion robustness is *measured*: a feature-space attack under problem-space constraints
   is run and the success rate is reported in the model card.
   MITIGATION T1.3 -> `src/nids/explain/evasion.py` `evasion_success_rate`
4. Source-host window aggregates (flows/min, distinct destination ports) make splitting an
   attack across flows a signal in itself.
   MITIGATION T1.4 -> `src/nids/streaming/aggregates.py` `HostWindowAggregator`
5. Model artifacts are mounted from a Secret and the inference pod runs read-only, limiting
   white-box access.
   MITIGATION T1.5 -> `infra/helm/nids/templates/inference-deployment.yaml` `readOnlyRootFilesystem`

### T2 Poisoning via the feedback loop (A2)

*Attack.* Submit many "false positive" labels for genuinely malicious flows so the next
retraining learns to ignore the attack (label flipping), or submit mislabelled benign flows
to raise the false-positive rate (availability poisoning).

*Mitigations.*
1. Feedback is **never** trained on directly. It enters a quarantine state with reviewer
   identity, and only feedback confirmed by a second reviewer becomes training data.
   MITIGATION T2.1 -> `src/nids/alerting/feedback.py` `FeedbackStore.promote`
2. Per-reviewer rate limits and a cap on the fraction of the retraining set that may come
   from feedback (default 5%).
   MITIGATION T2.2 -> `src/nids/drift/retrain.py` `RetrainPolicy.max_feedback_fraction`
3. Retraining is gated: the candidate must not lower PR-AUC on the frozen held-out set and
   must not lower recall on any attack family by more than the tolerance; otherwise it is
   rejected and an alert is raised.
   MITIGATION T2.3 -> `src/nids/drift/retrain.py` `promote_if_better`
4. The feedback label distribution is itself monitored; a surge of "false positive"
   feedback for one family triggers review.
   MITIGATION T2.4 -> `src/nids/drift/detectors.py` `FeedbackDriftMonitor`
5. Every feedback row is immutable and bound to the submitting principal; the store is
   append-only.
   MITIGATION T2.5 -> `src/nids/alerting/feedback.py` `FeedbackRecord`

### T3 Sensor tampering (A3)

*Attack.* Kill or starve the capture agent, drop packets with a BPF filter, replay stale
PCAPs, or feed fabricated flows into the Kafka topic.

*Mitigations.*
1. Heartbeat and liveness: the agent publishes a heartbeat with packet and drop counters;
   the alert engine raises `SENSOR_SILENT` / `SENSOR_DROPPING` when a sensor misses two
   beats or the kernel drop rate exceeds the threshold.
   MITIGATION T3.1 -> `src/nids/streaming/capture.py` `CaptureAgent.heartbeat`
   MITIGATION T3.1b -> `src/nids/alerting/engine.py` `AlertEngine.check_sensors`
2. Flow messages carry an HMAC over (sensor id, sequence, timestamp, payload) with a
   per-sensor key; the consumer rejects unauthenticated or stale messages.
   MITIGATION T3.2 -> `src/nids/streaming/messages.py` `verify_flow`
3. Kafka ACLs: the agent principal may only produce to the flows topic; only the inference
   service may consume it.
   MITIGATION T3.3 -> `infra/k8s/kafka-acls.yaml` `nids-agent`
4. The agent runs as a DaemonSet with a read-only root filesystem and only
   `NET_RAW`/`NET_ADMIN` capabilities.
   MITIGATION T3.4 -> `infra/helm/nids/templates/agent-daemonset.yaml` `NET_RAW`
5. Monotonic sequence numbers per sensor; gaps are metered.
   MITIGATION T3.5 -> `src/nids/streaming/messages.py` `SequenceTracker`

### T4 Alert flooding (A1)

*Attack.* Generate huge numbers of cheap, obviously malicious flows (e.g. a SYN scan from
spoofed sources) to bury a real intrusion in noise and exhaust the SIEM budget.

*Mitigations.*
1. Alert deduplication and aggregation: alerts sharing (family, source, destination) within
   a window collapse into one alert with a count.
   MITIGATION T4.1 -> `src/nids/alerting/engine.py` `AlertEngine.aggregate`
2. Per-source and global token-bucket rate limits with an explicit `ALERT_RATE_LIMITED`
   meta-alert so that suppression is itself visible.
   MITIGATION T4.2 -> `src/nids/alerting/engine.py` `TokenBucket`
3. Severity is computed from calibrated probability and asset criticality; SIEM sinks
   receive only medium and above by default.
   MITIGATION T4.3 -> `src/nids/alerting/severity.py` `severity_for`
4. Back-pressure: the consumer is bounded and the HPA scales inference on Kafka lag; alerts
   are never dropped silently (metric `nids_alerts_suppressed_total`).
   MITIGATION T4.4 -> `infra/helm/nids/templates/inference-hpa.yaml` `kafka_consumergroup_lag`

### T5 Model artifact tampering (A4)

Model artifacts carry a SHA-256 manifest written at training time and verified at load.
Container images are signed with cosign in CI and the Helm chart pins image digests.
MITIGATION T5.1 -> `src/nids/models/registry.py` `verify_manifest`
MITIGATION T5.2 -> `.github/workflows/ci.yml` `cosign sign`

### T6 Information disclosure through explanations

SHAP explanations could expose feature values of other tenants' flows. Explanations are
scoped to the alert the requester may see, and raw payload is never stored, only flow
statistics.
MITIGATION T6.1 -> `src/nids/dashboard_api/app.py` `get_alert_explanation`

### T7 Denial of service against the inference API

Request bodies are size-limited, batch size is capped and the service has a per-replica
concurrency limit.
MITIGATION T7.1 -> `src/nids/streaming/inference_service.py` `MAX_BATCH`

## Residual risk

* Problem-space evasion by a patient low-and-slow attacker remains feasible; the detector
  is one layer, not the only one.
* Poisoning by a *majority* of colluding reviewers defeats two-person review; the cap on
  feedback fraction bounds the damage per retraining cycle.
* A sensor host with root compromise can forge heartbeats; the HMAC key must then be
  rotated (RUNBOOK.md, "Sensor compromise").
