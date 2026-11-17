# Train/serve parity report

PCAP `Wednesday-14-02-2018_UCAP172.31.69.25.pcap`, CICFlowMeter-compatible mode; extraction 77 s, peak memory 1481 MB.

* flows extracted: **383,002**
* published rows in the capture's time window: 1,040,440
* flows matched to a published row: **382,586** (99.9%); unambiguous (key unique on both sides): 37,809
* matched labels: bruteforce_ftp: 193,360, bruteforce_ssh: 187,589, benign: 1,637
* features agreeing on >= 99.9% of matched flows: **61 / 68**; model inputs: **58 / 58**
* columns marked (excluded) are published values that cannot be recomputed from packets and are not model inputs (`schema.UNREPRODUCIBLE`)

| Feature | Agreement | Agreement (unambiguous) | Mean abs diff (disagreeing) | Max abs diff |
|---|---:|---:|---:|---:|
| `fwd_psh_flags` (excluded) | 24.65% | 2.36% | 1 | 1 |
| `syn_flag_cnt` (excluded) | 24.65% | 2.36% | 1 | 1 |
| `ack_flag_cnt` (excluded) | 24.65% | 2.40% | 1 | 1 |
| `psh_flag_cnt` (excluded) | 49.19% | 97.37% | 1 | 1 |
| `rst_flag_cnt` (excluded) | 49.19% | 97.40% | 1 | 1 |
| `fin_flag_cnt` (excluded) | 50.83% | 2.74% | 1 | 1 |
| `urg_flag_cnt` (excluded) | 75.36% | 97.77% | 1 | 1 |
| `fwd_act_data_pkts` | 99.99% | 99.90% | 1 | 1 |
| `fwd_seg_size_min` | 99.99% | 99.90% | 8 | 8 |
| `init_bwd_win_byts` | 99.99% | 100.00% | 10 | 10 |
| `bwd_pkts_s` | 100.00% | 100.00% | 0 | 0 |
| `flow_byts_s` | 100.00% | 100.00% | 0 | 0 |
| `fwd_pkts_s` | 100.00% | 100.00% | 0.01048 | 0.01314 |
| `active_max` | 100.00% | 100.00% | 3.572e+06 | 4.063e+06 |
| `active_mean` | 100.00% | 100.00% | 3.572e+06 | 4.063e+06 |
| `active_min` | 100.00% | 100.00% | 3.572e+06 | 4.063e+06 |
| `cwe_flag_cnt` (excluded) | 100.00% | 100.00% | 1 | 1 |
| `flow_duration` | 100.00% | 100.00% | 3.139e+07 | 3.721e+07 |
| `flow_iat_max` | 100.00% | 100.00% | 2.136e+07 | 2.767e+07 |
| `flow_iat_mean` | 100.00% | 100.00% | 1.569e+07 | 1.861e+07 |
| `flow_iat_min` | 100.00% | 100.00% | 5.275e+07 | 5.324e+07 |
| `flow_iat_std` | 100.00% | 100.00% | 5.24e+07 | 5.721e+07 |
| `flow_pkts_s` | 100.00% | 100.00% | 0.01048 | 0.01314 |
| `fwd_iat_max` | 100.00% | 100.00% | 2.136e+07 | 2.767e+07 |
| `fwd_iat_mean` | 100.00% | 100.00% | 1.569e+07 | 1.861e+07 |
| `fwd_iat_min` | 100.00% | 100.00% | 5.275e+07 | 5.324e+07 |
| `fwd_iat_std` | 100.00% | 100.00% | 5.24e+07 | 5.721e+07 |
| `fwd_iat_tot` | 100.00% | 100.00% | 3.139e+07 | 3.721e+07 |
| `idle_max` | 100.00% | 100.00% | 2.136e+07 | 2.767e+07 |
| `idle_mean` | 100.00% | 100.00% | 2.136e+07 | 2.767e+07 |
| `idle_min` | 100.00% | 100.00% | 2.136e+07 | 2.767e+07 |
| `idle_std` | 100.00% | 100.00% | 27.58 | 50.2 |
| `active_std` | 100.00% | 100.00% | 0 | 0 |
| `bwd_header_len` | 100.00% | 100.00% | 0 | 0 |
| `bwd_iat_max` | 100.00% | 100.00% | 0 | 0 |
| `bwd_iat_mean` | 100.00% | 100.00% | 0 | 0 |
| `bwd_iat_min` | 100.00% | 100.00% | 0 | 0 |
| `bwd_iat_std` | 100.00% | 100.00% | 0 | 0 |
| `bwd_iat_tot` | 100.00% | 100.00% | 0 | 0 |
| `bwd_pkt_len_max` | 100.00% | 100.00% | 0 | 0 |
| `bwd_pkt_len_mean` | 100.00% | 100.00% | 0 | 0 |
| `bwd_pkt_len_min` | 100.00% | 100.00% | 0 | 0 |
| `bwd_pkt_len_std` | 100.00% | 100.00% | 0 | 0 |
| `bwd_seg_size_avg` | 100.00% | 100.00% | 0 | 0 |
| `down_up_ratio` | 100.00% | 100.00% | 0 | 0 |
| `ece_flag_cnt` (excluded) | 100.00% | 100.00% | 0 | 0 |
| `fwd_header_len` | 100.00% | 100.00% | 0 | 0 |
| `fwd_pkt_len_max` | 100.00% | 100.00% | 0 | 0 |
| `fwd_pkt_len_mean` | 100.00% | 100.00% | 0 | 0 |
| `fwd_pkt_len_min` | 100.00% | 100.00% | 0 | 0 |
| `fwd_pkt_len_std` | 100.00% | 100.00% | 0 | 0 |
| `fwd_seg_size_avg` | 100.00% | 100.00% | 0 | 0 |
| `fwd_urg_flags` (excluded) | 100.00% | 100.00% | 0 | 0 |
| `init_fwd_win_byts` | 100.00% | 100.00% | 0 | 0 |
| `pkt_len_max` | 100.00% | 100.00% | 0 | 0 |
| `pkt_len_mean` | 100.00% | 100.00% | 0 | 0 |
| `pkt_len_min` | 100.00% | 100.00% | 0 | 0 |
| `pkt_len_std` | 100.00% | 100.00% | 0 | 0 |
| `pkt_len_var` | 100.00% | 100.00% | 0 | 0 |
| `pkt_size_avg` | 100.00% | 100.00% | 0 | 0 |
| `subflow_bwd_byts` | 100.00% | 100.00% | 0 | 0 |
| `subflow_bwd_pkts` | 100.00% | 100.00% | 0 | 0 |
| `subflow_fwd_byts` | 100.00% | 100.00% | 0 | 0 |
| `subflow_fwd_pkts` | 100.00% | 100.00% | 0 | 0 |
| `tot_bwd_pkts` | 100.00% | 100.00% | 0 | 0 |
| `tot_fwd_pkts` | 100.00% | 100.00% | 0 | 0 |
| `totlen_bwd_pkts` | 100.00% | 100.00% | 0 | 0 |
| `totlen_fwd_pkts` | 100.00% | 100.00% | 0 | 0 |
