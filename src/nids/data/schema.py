"""Canonical flow-feature schema shared by CIC-IDS2017, CSE-CIC-IDS2018 and the live extractor.

Design rules (see docs/METHODOLOGY.md section 4):

* one canonical snake_case name per CICFlowMeter statistic;
* the duplicated ``Fwd Header Length`` column of CIC-IDS2017 is dropped;
* the eight bulk/backward-flag statistics that are constant zero are dropped;
* identifiers (IPs, source port, timestamp, Flow ID) are metadata, never features;
* destination port enters the model only as a coarse bucket.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    cic2017: str
    cse2018: str
    kind: str  # "count" | "bytes" | "duration_us" | "rate" | "stat" | "flag" | "ratio" | "window"
    nonneg: bool = True


# fmt: off
FEATURE_SPECS: Final[tuple[FeatureSpec, ...]] = (
    FeatureSpec("flow_duration",        "Flow Duration",                "Flow Duration",     "duration_us"),
    FeatureSpec("tot_fwd_pkts",         "Total Fwd Packets",            "Tot Fwd Pkts",      "count"),
    FeatureSpec("tot_bwd_pkts",         "Total Backward Packets",       "Tot Bwd Pkts",      "count"),
    FeatureSpec("totlen_fwd_pkts",      "Total Length of Fwd Packets",  "TotLen Fwd Pkts",   "bytes"),
    FeatureSpec("totlen_bwd_pkts",      "Total Length of Bwd Packets",  "TotLen Bwd Pkts",   "bytes"),
    FeatureSpec("fwd_pkt_len_max",      "Fwd Packet Length Max",        "Fwd Pkt Len Max",   "bytes"),
    FeatureSpec("fwd_pkt_len_min",      "Fwd Packet Length Min",        "Fwd Pkt Len Min",   "bytes"),
    FeatureSpec("fwd_pkt_len_mean",     "Fwd Packet Length Mean",       "Fwd Pkt Len Mean",  "stat"),
    FeatureSpec("fwd_pkt_len_std",      "Fwd Packet Length Std",        "Fwd Pkt Len Std",   "stat"),
    FeatureSpec("bwd_pkt_len_max",      "Bwd Packet Length Max",        "Bwd Pkt Len Max",   "bytes"),
    FeatureSpec("bwd_pkt_len_min",      "Bwd Packet Length Min",        "Bwd Pkt Len Min",   "bytes"),
    FeatureSpec("bwd_pkt_len_mean",     "Bwd Packet Length Mean",       "Bwd Pkt Len Mean",  "stat"),
    FeatureSpec("bwd_pkt_len_std",      "Bwd Packet Length Std",        "Bwd Pkt Len Std",   "stat"),
    FeatureSpec("flow_byts_s",          "Flow Bytes/s",                 "Flow Byts/s",       "rate"),
    FeatureSpec("flow_pkts_s",          "Flow Packets/s",               "Flow Pkts/s",       "rate"),
    FeatureSpec("flow_iat_mean",        "Flow IAT Mean",                "Flow IAT Mean",     "duration_us"),
    FeatureSpec("flow_iat_std",         "Flow IAT Std",                 "Flow IAT Std",      "duration_us"),
    FeatureSpec("flow_iat_max",         "Flow IAT Max",                 "Flow IAT Max",      "duration_us"),
    FeatureSpec("flow_iat_min",         "Flow IAT Min",                 "Flow IAT Min",      "duration_us", nonneg=False),
    FeatureSpec("fwd_iat_tot",          "Fwd IAT Total",                "Fwd IAT Tot",       "duration_us"),
    FeatureSpec("fwd_iat_mean",         "Fwd IAT Mean",                 "Fwd IAT Mean",      "duration_us"),
    FeatureSpec("fwd_iat_std",          "Fwd IAT Std",                  "Fwd IAT Std",       "duration_us"),
    FeatureSpec("fwd_iat_max",          "Fwd IAT Max",                  "Fwd IAT Max",       "duration_us"),
    FeatureSpec("fwd_iat_min",          "Fwd IAT Min",                  "Fwd IAT Min",       "duration_us", nonneg=False),
    FeatureSpec("bwd_iat_tot",          "Bwd IAT Total",                "Bwd IAT Tot",       "duration_us"),
    FeatureSpec("bwd_iat_mean",         "Bwd IAT Mean",                 "Bwd IAT Mean",      "duration_us"),
    FeatureSpec("bwd_iat_std",          "Bwd IAT Std",                  "Bwd IAT Std",       "duration_us"),
    FeatureSpec("bwd_iat_max",          "Bwd IAT Max",                  "Bwd IAT Max",       "duration_us"),
    FeatureSpec("bwd_iat_min",          "Bwd IAT Min",                  "Bwd IAT Min",       "duration_us", nonneg=False),
    FeatureSpec("fwd_psh_flags",        "Fwd PSH Flags",                "Fwd PSH Flags",     "flag"),
    FeatureSpec("fwd_urg_flags",        "Fwd URG Flags",                "Fwd URG Flags",     "flag"),
    FeatureSpec("fwd_header_len",       "Fwd Header Length",            "Fwd Header Len",    "bytes"),
    FeatureSpec("bwd_header_len",       "Bwd Header Length",            "Bwd Header Len",    "bytes"),
    FeatureSpec("fwd_pkts_s",           "Fwd Packets/s",                "Fwd Pkts/s",        "rate"),
    FeatureSpec("bwd_pkts_s",           "Bwd Packets/s",                "Bwd Pkts/s",        "rate"),
    FeatureSpec("pkt_len_min",          "Min Packet Length",            "Pkt Len Min",       "bytes"),
    FeatureSpec("pkt_len_max",          "Max Packet Length",            "Pkt Len Max",       "bytes"),
    FeatureSpec("pkt_len_mean",         "Packet Length Mean",           "Pkt Len Mean",      "stat"),
    FeatureSpec("pkt_len_std",          "Packet Length Std",            "Pkt Len Std",       "stat"),
    FeatureSpec("pkt_len_var",          "Packet Length Variance",       "Pkt Len Var",       "stat"),
    FeatureSpec("fin_flag_cnt",         "FIN Flag Count",               "FIN Flag Cnt",      "flag"),
    FeatureSpec("syn_flag_cnt",         "SYN Flag Count",               "SYN Flag Cnt",      "flag"),
    FeatureSpec("rst_flag_cnt",         "RST Flag Count",               "RST Flag Cnt",      "flag"),
    FeatureSpec("psh_flag_cnt",         "PSH Flag Count",               "PSH Flag Cnt",      "flag"),
    FeatureSpec("ack_flag_cnt",         "ACK Flag Count",               "ACK Flag Cnt",      "flag"),
    FeatureSpec("urg_flag_cnt",         "URG Flag Count",               "URG Flag Cnt",      "flag"),
    FeatureSpec("cwe_flag_cnt",         "CWE Flag Count",               "CWE Flag Count",    "flag"),
    FeatureSpec("ece_flag_cnt",         "ECE Flag Count",               "ECE Flag Cnt",      "flag"),
    FeatureSpec("down_up_ratio",        "Down/Up Ratio",                "Down/Up Ratio",     "ratio"),
    FeatureSpec("pkt_size_avg",         "Average Packet Size",          "Pkt Size Avg",      "stat"),
    FeatureSpec("fwd_seg_size_avg",     "Avg Fwd Segment Size",         "Fwd Seg Size Avg",  "stat"),
    FeatureSpec("bwd_seg_size_avg",     "Avg Bwd Segment Size",         "Bwd Seg Size Avg",  "stat"),
    FeatureSpec("subflow_fwd_pkts",     "Subflow Fwd Packets",          "Subflow Fwd Pkts",  "count"),
    FeatureSpec("subflow_fwd_byts",     "Subflow Fwd Bytes",            "Subflow Fwd Byts",  "bytes"),
    FeatureSpec("subflow_bwd_pkts",     "Subflow Bwd Packets",          "Subflow Bwd Pkts",  "count"),
    FeatureSpec("subflow_bwd_byts",     "Subflow Bwd Bytes",            "Subflow Bwd Byts",  "bytes"),
    FeatureSpec("init_fwd_win_byts",    "Init_Win_bytes_forward",       "Init Fwd Win Byts", "window", nonneg=False),
    FeatureSpec("init_bwd_win_byts",    "Init_Win_bytes_backward",      "Init Bwd Win Byts", "window", nonneg=False),
    FeatureSpec("fwd_act_data_pkts",    "act_data_pkt_fwd",             "Fwd Act Data Pkts", "count"),
    FeatureSpec("fwd_seg_size_min",     "min_seg_size_forward",         "Fwd Seg Size Min",  "bytes"),
    FeatureSpec("active_mean",          "Active Mean",                  "Active Mean",       "duration_us"),
    FeatureSpec("active_std",           "Active Std",                   "Active Std",        "duration_us"),
    FeatureSpec("active_max",           "Active Max",                   "Active Max",        "duration_us"),
    FeatureSpec("active_min",           "Active Min",                   "Active Min",        "duration_us"),
    FeatureSpec("idle_mean",            "Idle Mean",                    "Idle Mean",         "duration_us"),
    FeatureSpec("idle_std",             "Idle Std",                     "Idle Std",          "duration_us"),
    FeatureSpec("idle_max",             "Idle Max",                     "Idle Max",          "duration_us"),
    FeatureSpec("idle_min",             "Idle Min",                     "Idle Min",          "duration_us"),
)
# fmt: on

FLOW_FEATURES: Final[tuple[str, ...]] = tuple(s.name for s in FEATURE_SPECS)
"""The 68 CICFlowMeter statistics shared by both datasets."""

DST_PORT_BUCKET: Final[str] = "dst_port_bucket"
UNREPRODUCIBLE: Final[tuple[str, ...]] = (
    "fin_flag_cnt",
    "syn_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "ack_flag_cnt",
    "urg_flag_cnt",
    "cwe_flag_cnt",
    "ece_flag_cnt",
    "fwd_psh_flags",
    "fwd_urg_flags",
)
"""Published columns whose values cannot be recomputed from packets (train/serve parity).

The CSE-CIC-IDS2018 flag columns follow neither the TCP flags of the flow nor the released
CICFlowMeter source (reports/parity_report.md, nids.features.flow Q11 note), so a model
trained on them would see different values in production. They stay in the canonical data
for analysis but are never model inputs."""

FEATURES: Final[tuple[str, ...]] = (
    *(f for f in FLOW_FEATURES if f not in UNREPRODUCIBLE),
    DST_PORT_BUCKET,
)
"""Model input columns, in order (58 flow statistics + destination-port bucket = 59)."""

#: Columns dropped on purpose. Kept here so the data card and tests can assert on them.
DROPPED_2017: Final[tuple[str, ...]] = (
    "Fwd Header Length.1",  # exact duplicate of 'Fwd Header Length'
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
)
DROPPED_2018: Final[tuple[str, ...]] = (
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "Fwd Byts/b Avg",
    "Fwd Pkts/b Avg",
    "Fwd Blk Rate Avg",
    "Bwd Byts/b Avg",
    "Bwd Pkts/b Avg",
    "Bwd Blk Rate Avg",
)

#: Metadata columns carried through the canonical parquet files (never model inputs).
META_COLUMNS: Final[tuple[str, ...]] = (
    "dataset",
    "day",
    "row_id",
    "timestamp",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "label_raw",
    "label",
    "attack_class",
    "is_attack",
    "label_reliable",
)

CIC2017_RENAME: Final[dict[str, str]] = {s.cic2017: s.name for s in FEATURE_SPECS} | {
    "Destination Port": "dst_port",
    "Label": "label_raw",
}
CSE2018_RENAME: Final[dict[str, str]] = {s.cse2018: s.name for s in FEATURE_SPECS} | {
    "Dst Port": "dst_port",
    "Protocol": "protocol",
    "Timestamp": "timestamp",
    "Label": "label_raw",
    "Flow ID": "flow_id",
    "Src IP": "src_ip",
    "Src Port": "src_port",
    "Dst IP": "dst_ip",
}


class Dataset(StrEnum):
    CIC2017 = "cicids2017"
    CSE2018 = "cseids2018"


class AttackClass(StrEnum):
    """Coarse taxonomy shared by both datasets; used for the multi-class stage."""

    BENIGN = "benign"
    DOS = "dos"
    DDOS = "ddos"
    BRUTEFORCE = "bruteforce"
    WEB = "web"
    BOTNET = "botnet"
    SCAN = "scan"
    INFILTRATION = "infiltration"
    HEARTBLEED = "heartbleed"


#: Fine-grained canonical label -> coarse attack class.
LABEL_TO_CLASS: Final[dict[str, AttackClass]] = {
    "benign": AttackClass.BENIGN,
    "dos_hulk": AttackClass.DOS,
    "dos_goldeneye": AttackClass.DOS,
    "dos_slowloris": AttackClass.DOS,
    "dos_slowhttptest": AttackClass.DOS,
    "ddos_loic_http": AttackClass.DDOS,
    "ddos_loic_udp": AttackClass.DDOS,
    "ddos_hoic": AttackClass.DDOS,
    "bruteforce_ftp": AttackClass.BRUTEFORCE,
    "bruteforce_ssh": AttackClass.BRUTEFORCE,
    "web_bruteforce": AttackClass.WEB,
    "web_xss": AttackClass.WEB,
    "web_sqli": AttackClass.WEB,
    "botnet": AttackClass.BOTNET,
    "portscan": AttackClass.SCAN,
    "infiltration": AttackClass.INFILTRATION,
    "heartbleed": AttackClass.HEARTBLEED,
}

_RAW_LABEL_PATTERNS: Final[tuple[tuple[re.Pattern[str], str], ...]] = (
    (re.compile(r"^benign$", re.I), "benign"),
    (re.compile(r"^dos[ _-]*hulk$|^dos attacks-hulk$", re.I), "dos_hulk"),
    (re.compile(r"^dos[ _-]*goldeneye$|^dos attacks-goldeneye$", re.I), "dos_goldeneye"),
    (re.compile(r"^dos[ _-]*slowloris$|^dos attacks-slowloris$", re.I), "dos_slowloris"),
    (re.compile(r"^dos[ _-]*slowhttptest$|^dos attacks-slowhttptest$", re.I), "dos_slowhttptest"),
    (re.compile(r"^ddos$|^ddos attacks-loic-http$", re.I), "ddos_loic_http"),
    (re.compile(r"^ddos attack-loic-udp$", re.I), "ddos_loic_udp"),
    (re.compile(r"^ddos attack-hoic$", re.I), "ddos_hoic"),
    (re.compile(r"^ftp-?patator$|^ftp-?bruteforce$", re.I), "bruteforce_ftp"),
    (re.compile(r"^ssh-?patator$|^ssh-?bruteforce$", re.I), "bruteforce_ssh"),
    (re.compile(r"^web attack.*brute ?force$|^brute force -web$", re.I), "web_bruteforce"),
    (re.compile(r"^web attack.*xss$|^brute force -xss$", re.I), "web_xss"),
    (re.compile(r"^web attack.*sql injection$|^sql injection$", re.I), "web_sqli"),
    (re.compile(r"^bot$", re.I), "botnet"),
    (re.compile(r"^portscan$", re.I), "portscan"),
    (re.compile(r"^infil?t[e]?ration$", re.I), "infiltration"),
    (re.compile(r"^heartbleed$", re.I), "heartbleed"),
)


def normalise_label(raw: str) -> str:
    """Map a raw CSV label (either dataset, any encoding glitch) to the canonical fine label.

    >>> normalise_label("Web Attack � Brute Force")
    'web_bruteforce'
    >>> normalise_label("DoS attacks-SlowHTTPTest")
    'dos_slowhttptest'
    """
    s = re.sub(r"\s+", " ", raw.replace("�", "-").replace("\x96", "-")).strip()
    for pat, canon in _RAW_LABEL_PATTERNS:
        if pat.match(s):
            return canon
    raise ValueError(f"unknown label {raw!r}")


def dst_port_bucket(port: int) -> int:
    """0 = well-known (<1024), 1 = registered (<49152), 2 = ephemeral, 3 = invalid/unknown."""
    if port < 0 or port > 65535:
        return 3
    if port < 1024:
        return 0
    if port < 49152:
        return 1
    return 2


@dataclass(frozen=True)
class DayInfo:
    dataset: Dataset
    day: str
    filename: str
    expected_rows: int | None
    attacks: tuple[str, ...]
    label_reliable: bool = True
    note: str = ""


#: Registry of the raw files used. Expected row counts are data rows excluding the header and
#: (2018) the header rows repeated inside the files; verified by ``nids data validate``.
DAYS: Final[tuple[DayInfo, ...]] = (
    DayInfo(Dataset.CIC2017, "2017-07-03-mon", "Monday-WorkingHours.pcap_ISCX.csv", 529_918, ()),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-04-tue",
        "Tuesday-WorkingHours.pcap_ISCX.csv",
        445_909,
        ("bruteforce_ftp", "bruteforce_ssh"),
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-05-wed",
        "Wednesday-workingHours.pcap_ISCX.csv",
        692_703,
        ("dos_hulk", "dos_goldeneye", "dos_slowloris", "dos_slowhttptest", "heartbleed"),
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-06-thu-am",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        170_366,
        ("web_bruteforce", "web_xss", "web_sqli"),
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-06-thu-pm",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        288_602,
        ("infiltration",),
        label_reliable=False,
        note="36 infiltration flows; Engelen et al. show most malicious traffic of this day is unlabelled",
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-07-fri-am",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        191_033,
        ("botnet",),
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-07-fri-pm-scan",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        286_467,
        ("portscan",),
    ),
    DayInfo(
        Dataset.CIC2017,
        "2017-07-07-fri-pm-ddos",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        225_745,
        ("ddos_loic_http",),
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-02-14-wed",
        "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
        1_048_575,
        ("bruteforce_ftp", "bruteforce_ssh"),
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-02-16-fri",
        "Friday-16-02-2018_TrafficForML_CICFlowMeter.csv",
        1_048_574,
        ("dos_hulk", "dos_slowhttptest"),
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-02-21-wed",
        "Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv",
        1_048_575,
        ("ddos_loic_udp", "ddos_hoic"),
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-02-23-fri",
        "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        1_048_575,
        ("web_bruteforce", "web_xss", "web_sqli"),
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-03-01-thu",
        "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
        331_100,
        ("infiltration",),
        label_reliable=False,
        note="Infiltration labels cover ordinary traffic of the victim host (Liu et al. 2022)",
    ),
    DayInfo(
        Dataset.CSE2018,
        "2018-03-02-fri",
        "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
        1_048_575,
        ("botnet",),
    ),
)


def days_for(dataset: Dataset) -> tuple[DayInfo, ...]:
    return tuple(d for d in DAYS if d.dataset == dataset)
