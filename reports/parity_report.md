# Train/serve parity report

PCAP `Wednesday-14-02-2018_UCAP172.31.69.25.pcap`, CICFlowMeter-compatible mode; extraction 76 s, peak memory 1763 MB.

* flows extracted: **383,002**
* published rows in the capture's time window: 384,281
* flows matched to a published row: **193,996** (50.6%)
* matched labels: bruteforce_ftp: 193,361, benign: 635
* features agreeing on >= 99.9% of matched flows: **56 / 68**

| Feature | Agreement | Mean abs diff (disagreeing) | Max abs diff |
|---|---:|---:|---:|
| `fwd_psh_flags` | 0.04% | 1 | 1 |
| `syn_flag_cnt` | 0.04% | 1 | 1 |
| `ack_flag_cnt` | 0.04% | 1 | 1 |
| `psh_flag_cnt` | 0.06% | 1 | 1 |
| `rst_flag_cnt` | 0.07% | 1 | 1 |
| `flow_pkts_s` | 16.43% | 1.062e+06 | 1.968e+06 |
| `fwd_pkts_s` | 16.43% | 5.311e+05 | 9.841e+05 |
| `bwd_pkts_s` | 16.43% | 5.311e+05 | 9.841e+05 |
| `flow_iat_max` | 32.03% | 853 | 3.372e+07 |
| `flow_duration` | 32.04% | 1010 | 3.721e+07 |
| `flow_iat_mean` | 32.04% | 427 | 1.861e+07 |
| `flow_iat_min` | 32.04% | 816.8 | 5.324e+07 |
| `fin_flag_cnt` | 99.95% | 1 | 1 |
| `init_bwd_win_byts` | 99.98% | 2.622e+04 | 2.688e+04 |
| `urg_flag_cnt` | 99.98% | 1 | 1 |
| `fwd_seg_size_min` | 99.99% | 9.333 | 28 |
| `fwd_act_data_pkts` | 99.99% | 1 | 1 |
| `flow_iat_std` | 99.99% | 1.105e+07 | 5.721e+07 |
| `fwd_iat_max` | 99.99% | 3.362e+06 | 2.767e+07 |
| `bwd_iat_max` | 99.99% | 5.679e+06 | 3.399e+07 |
| `bwd_iat_mean` | 99.99% | 6.194e+06 | 3.399e+07 |
| `bwd_iat_min` | 99.99% | 6.193e+06 | 3.399e+07 |
| `bwd_iat_tot` | 99.99% | 6.196e+06 | 3.399e+07 |
| `fwd_iat_mean` | 99.99% | 2.698e+06 | 1.861e+07 |
| `fwd_iat_tot` | 99.99% | 5.317e+06 | 3.721e+07 |
| `fwd_iat_min` | 100.00% | 1.065e+07 | 5.324e+07 |
| `fwd_iat_std` | 100.00% | 1.165e+07 | 5.721e+07 |
| `bwd_iat_std` | 100.00% | 3329 | 1.269e+04 |
| `flow_byts_s` | 100.00% | 3.366e+04 | 2.583e+05 |
| `active_max` | 100.00% | 1.934e+06 | 4.063e+06 |
| `active_mean` | 100.00% | 1.934e+06 | 4.063e+06 |
| `active_min` | 100.00% | 1.934e+06 | 4.063e+06 |
| `fwd_header_len` | 100.00% | 25.33 | 44 |
| `idle_max` | 100.00% | 2.786e+07 | 3.437e+07 |
| `idle_mean` | 100.00% | 2.786e+07 | 3.437e+07 |
| `idle_min` | 100.00% | 2.786e+07 | 3.437e+07 |
| `bwd_header_len` | 100.00% | 12 | 12 |
| `idle_std` | 100.00% | 27.58 | 50.2 |
| `init_fwd_win_byts` | 100.00% | 1.939e+04 | 3.865e+04 |
| `active_std` | 100.00% | 0 | 0 |
| `bwd_pkt_len_max` | 100.00% | 0 | 0 |
| `bwd_pkt_len_mean` | 100.00% | 0 | 0 |
| `bwd_pkt_len_min` | 100.00% | 0 | 0 |
| `bwd_pkt_len_std` | 100.00% | 0 | 0 |
| `bwd_seg_size_avg` | 100.00% | 0 | 0 |
| `cwe_flag_cnt` | 100.00% | 0 | 0 |
| `down_up_ratio` | 100.00% | 0 | 0 |
| `ece_flag_cnt` | 100.00% | 0 | 0 |
| `fwd_pkt_len_max` | 100.00% | 0 | 0 |
| `fwd_pkt_len_mean` | 100.00% | 0 | 0 |
| `fwd_pkt_len_min` | 100.00% | 0 | 0 |
| `fwd_pkt_len_std` | 100.00% | 0 | 0 |
| `fwd_seg_size_avg` | 100.00% | 0 | 0 |
| `fwd_urg_flags` | 100.00% | 0 | 0 |
| `pkt_len_max` | 100.00% | 0 | 0 |
| `pkt_len_mean` | 100.00% | 0 | 0 |
| `pkt_len_min` | 100.00% | 0 | 0 |
| `pkt_len_std` | 100.00% | 0 | 0 |
| `pkt_len_var` | 100.00% | 0 | 0 |
| `pkt_size_avg` | 100.00% | 0 | 0 |
| `subflow_bwd_byts` | 100.00% | 0 | 0 |
| `subflow_bwd_pkts` | 100.00% | 0 | 0 |
| `subflow_fwd_byts` | 100.00% | 0 | 0 |
| `subflow_fwd_pkts` | 100.00% | 0 | 0 |
| `tot_bwd_pkts` | 100.00% | 0 | 0 |
| `tot_fwd_pkts` | 100.00% | 0 | 0 |
| `totlen_bwd_pkts` | 100.00% | 0 | 0 |
| `totlen_fwd_pkts` | 100.00% | 0 | 0 |
