#!/usr/bin/env bash
# Download CIC-IDS2017 (MachineLearningCVE CSVs, open mirror) and selected CSE-CIC-IDS2018 days.
# Usage: scripts/download_datasets.sh [data/raw]
set -euo pipefail
ROOT="${1:-data/raw}"
HF="https://huggingface.co/datasets/c01dsnap/CIC-IDS2017/resolve/main"
S3="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"
mkdir -p "$ROOT/cicids2017" "$ROOT/cseids2018"
fetch() { # url dest
  if [ -s "$2" ]; then echo "exists $2"; return; fi
  curl -L --fail --retry 5 --retry-delay 5 -C - -o "$2.part" "$1" && mv "$2.part" "$2" && echo "done $2"
}
for f in Monday-WorkingHours.pcap_ISCX.csv Tuesday-WorkingHours.pcap_ISCX.csv Wednesday-workingHours.pcap_ISCX.csv \
         Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv \
         Friday-WorkingHours-Morning.pcap_ISCX.csv Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv \
         Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv; do
  fetch "$HF/$f" "$ROOT/cicids2017/$f"
done
for f in Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv Friday-16-02-2018_TrafficForML_CICFlowMeter.csv \
         Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv Friday-23-02-2018_TrafficForML_CICFlowMeter.csv \
         Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv Friday-02-03-2018_TrafficForML_CICFlowMeter.csv; do
  fetch "$S3/$f" "$ROOT/cseids2018/$f"
done
echo ALL_DONE
