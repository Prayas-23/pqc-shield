"""Explicit, versioned feature lists for each dataset (no wildcards).

Every column the loaders produce is either a feature (in a *_FEATURES tuple) or listed in
a *_EXCLUDED dict with a reason. Change a list => bump FEATURES_VERSION. The audit that
backs these lists is docs/feature_audit.md (regenerate with scripts/feature_audit.py).

Flow-feature extraction from our own packet captures (pcap.py) will also live here later.
"""

from __future__ import annotations

FEATURES_VERSION = "3"  # v2: PQC_DRIFT_FEATURES; v3: LAB_* feature views

# --- CIC-PQC_OAV: the 32 engineered columns of ml_features_and_labels.csv -------------------
# Names are exactly as the loader returns them (one-hot columns keep their dataset names).
PQC_HANDSHAKE_FEATURES: tuple[str, ...] = (
    "e2c_total_bytes",
    "e4_entropy_h",
    "e5_entropy_c",
    "e6_time_char",
    "e6b_flow_duration_ms",
    "e2_client_size",
    "e2_client_record_len",
    "e2_server_record_len",
    "e3_cert_parsed",
    "e1_alg_suite_Unknown(0x11eb)",
    "e1_alg_suite_Unknown(0x11ec)",
    "e1_alg_suite_mlkem1024",
    "e1_alg_suite_mlkem768",
    "e1_alg_suite_x25519",
    "e1_alg_suite_nan",
    "e8_proto_context_TLSv1.2_or_older",
    "e8_proto_context_TLSv1.3",
    "e9_conn_outcome_Failure",
    "e9_conn_outcome_Incomplete",
    "e9_conn_outcome_Success",
    "e3_sig_alg_Unknown(0x0028)",
    "e3_sig_alg_nan",
    "e1b_tls_version_SSL3.0",
    "e1b_tls_version_TLS1.0",
    "e1b_ciphersuite_2",
    "e1b_ciphersuite_54",
    "e1b_ciphersuite_60",
    "e2b_tls_version_SSL3.0",
    "e2b_tls_version_TLS1.0",
    "e2b_ciphersuite_2",
    "e2b_ciphersuite_54",
    "e2b_ciphersuite_60",
)

# The 8 PQC features used for drift analysis: the non-one-hot features that vary on normal rows
# (docs/feature_audit.md). 4 size, 2 timing, 2 entropy. All one-hot and constant features are
# excluded; the kem one-hots would show up as perfect "drift" because they ARE the kem label.
PQC_DRIFT_FEATURES: tuple[str, ...] = (
    "e2c_total_bytes",
    "e2_client_size",
    "e2_client_record_len",
    "e2_server_record_len",
    "e6_time_char",
    "e6b_flow_duration_ms",
    "e4_entropy_h",
    "e5_entropy_c",
)

PQC_EXCLUDED: dict[str, str] = {
    "source": "dataset provenance tag, constant within one dataset",
    "ID": "row identifier (run id)",
    "manifest_id": "row identifier from the manifest join (ID + '.pcap')",
    "label_ml": "label as shipped in the ml file (target, not a feature)",
    "label_raw": "manifest anomaly_label (target, not a feature)",
    "label_binary": "derived 0/1 target",
    "taxonomy": "scenario family; determines the label (leaks the target)",
    "taxonomy_class": "scenario family from the manifest; determines the label (leaks the target)",
    "split": "dataset's own train/val/test assignment; not a handshake property",
    "scenario_id": "experiment configuration id; names the kem/auth design and the anomaly type",
    "subtype": "anomaly subtype; determines the label (leaks the target)",
    "operational_class": "scenario class; determines the label (leaks the target)",
    "run_idx": "repeat index of a scenario run; not a handshake property",
    "kem_scenario": "design factor parsed from scenario_id (normal rows only); used as a grouping factor, not a feature",
    "auth_scenario": "design factor parsed from scenario_id (normal rows only); used as a grouping factor, not a feature",
    "kem_observed": "raw e1_alg_suite string; already represented by the e1_alg_suite_* one-hots",
}

# --- CIC-IDS2017: CICFlowMeter flow features ------------------------------------------------
# Names are stripped of whitespace, as the loader returns them. 'Protocol' is a numeric code
# (6 = TCP, 17 = UDP, 0 = other) kept as a feature; review when ablating.
IDS_FLOW_FEATURES: tuple[str, ...] = (
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
)

IDS_EXCLUDED: dict[str, str] = {
    "Flow ID": "identifier (5-tuple string); memorisable, not a behavioural feature",
    "Source IP": "identifier; ties a flow to a capture-specific host",
    "Destination IP": "identifier; ties a flow to a capture-specific host",
    "Source Port": "identifier; ephemeral client port with no behavioural meaning",
    "Timestamp": "time-of-capture; leaks the capture day/time of each attack",
    "Destination Port": "excluded by default, ablate later: strongly service-specific and can shortcut attack detection",
    "Label": "target (not a feature)",
    "label_binary": "derived 0/1 target",
    "source": "dataset provenance tag, constant within one dataset",
    "source_file": "provenance: daily file of origin; determines which attacks appear",
    "day": "provenance: capture day; determines which attacks appear",
}


# --- Lab flows (data/flows/lab_flows.csv, source = "pq_lab"): three views + exclusions ------------------
# v3. hs_* = handshake phase, app_* = application phase (see docs/pcap_method.md). All packet-based features
# are only valid when the manifest says capture_offload_ok = true.
LAB_HS_FEATURES: tuple[str, ...] = (
    "hs_c2s_bytes",
    "hs_s2c_bytes",
    "hs_c2s_pkts",
    "hs_s2c_pkts",
    "hs_duration",
    "hs_records",
)

LAB_APP_FEATURES: tuple[str, ...] = (
    "app_c2s_bytes",
    "app_s2c_bytes",
    "app_c2s_pkts",
    "app_s2c_pkts",
    "app_pkt_len_mean",
    "app_pkt_len_std",
    "app_pkt_len_max",
    "app_iat_mean",
    "app_iat_std",
    "app_iat_max",
    "app_duration",
    "app_tiny_client_pkts",
    "app_c2s_size_1",
    "app_c2s_size_2",
    "app_c2s_size_3",
    "app_c2s_size_4",
    "app_c2s_size_5",
    "app_c2s_size_6",
    "app_c2s_size_7",
    "app_c2s_size_8",
    "app_c2s_size_9",
    "app_c2s_size_10",
    "app_s2c_size_1",
    "app_s2c_size_2",
    "app_s2c_size_3",
    "app_s2c_size_4",
    "app_s2c_size_5",
    "app_s2c_size_6",
    "app_s2c_size_7",
    "app_s2c_size_8",
    "app_s2c_size_9",
    "app_s2c_size_10",
)

# What an off-the-shelf flow-feature detector would see: whole-connection totals and statistics over ALL
# packets of the connection (handshake and application phase together), CICFlowMeter style.
LAB_FLOW_FEATURES: tuple[str, ...] = (
    "flow_c2s_bytes",
    "flow_s2c_bytes",
    "flow_c2s_pkts",
    "flow_s2c_pkts",
    "flow_pkt_len_mean",
    "flow_pkt_len_std",
    "flow_pkt_len_max",
    "flow_iat_mean",
    "flow_iat_std",
    "flow_iat_max",
    "flow_duration",
)

LAB_EXCLUDED: dict[str, str] = {
    "source": "dataset provenance tag, constant ('pq_lab')",
    "kem": "ground truth: the crypto profile (what the analysis explains, never a feature)",
    "auth": "ground truth: the crypto profile (what the analysis explains, never a feature)",
    "chain": "ground truth: the crypto profile (chain length)",
    "workload": "ground truth: identifies the workload",
    "label": "ground truth: benign / attack",
    "pcap_file": "identifier of the capture file",
    "conn_index": "identifier: position of the connection in its pcap",
    "intended_sessions": "capture bookkeeping from the manifest",
    "tcpdump_dropped": "capture bookkeeping from the manifest",
    "capture_offload_ok": "capture bookkeeping from the manifest (validity flag for packet features)",
    "max_tcp_payload": "capture bookkeeping from the manifest",
    "client_port": "identifier: ephemeral client port",
    "start_time": "time-of-capture: leaks the position in the run",
    "closed": "capture artefact: whether FIN/RST was seen",
    "handshake_complete": "parser status flag",
    "sh_group_id": "ground truth: ServerHello group id identifies the KEM",
    "sh_group_name": "ground truth: ServerHello group name identifies the KEM",
    "sh_cipher_suite": "constant AEAD choice; protocol metadata, not behaviour",
    "total_bytes": "redundant: equals flow_c2s_bytes + flow_s2c_bytes without retransmissions",
    "total_pkts": "redundant: payload-packet count, covered by the per-direction flow_* counts",
    "retransmitted_pkts": "capture/parser bookkeeping",
}
