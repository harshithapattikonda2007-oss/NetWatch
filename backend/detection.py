import math
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple

try:
    from .config import DEFAULT_SETTINGS, is_in_maintenance_window, is_trusted_server
except ImportError:
    from config import DEFAULT_SETTINGS, is_in_maintenance_window, is_trusted_server


def match_approved_activity(
    host: str,
    dest: Optional[str],
    ports: List[int],
    approved_list: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """Checks if activity matches an explicitly configured approved activity."""
    for act in approved_list:
        if act.get("source_ip") == host:
            # Check destination if specified
            if act.get("destination_ip") and dest and act.get("destination_ip") != dest:
                continue
            # Check ports if specified
            act_ports = act.get("ports", [])
            if act_ports and ports:
                if not any(p in act_ports for p in ports if p is not None):
                    continue
            return act
    return None


def detect_anomalies(
    eval_df: pd.DataFrame,
    baseline: Dict[str, Any],
    config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Executes the 7 rule-based detection engines against the evaluation period DataFrame.
    """
    if eval_df.empty:
        return []

    rules_cfg = config.get("rules", {})
    approved_activities = config.get("approved_activities", [])
    host_baselines = baseline.get("host_baselines", {})
    all_baseline_pairs = set(baseline.get("all_observed_pairs", []))

    findings: List[Dict[str, Any]] = []
    finding_counter = 1

    # Ensure timestamp is datetime
    eval_df = eval_df.copy()
    if not pd.api.types.is_datetime64_any_dtype(eval_df["timestamp"]):
        eval_df["timestamp"] = pd.to_datetime(eval_df["timestamp"])

    eval_df = eval_df.sort_values("timestamp").reset_index(drop=True)

    # =========================================================================
    # RULE A: Unusual Data Transfer
    # =========================================================================
    cfg_a = rules_cfg.get("unusual_data_transfer", {})
    if cfg_a.get("enabled", True):
        mult = float(cfg_a.get("baseline_multiplier", 3.0))
        std_mult = float(cfg_a.get("std_dev_multiplier", 2.5))
        min_bytes = int(cfg_a.get("min_bytes_threshold", 10485760))

        # Check per host total or large transfer flows
        for host, h_group in eval_df.groupby("src_ip"):
            b_info = host_baselines.get(host)
            base_mean = b_info.get("bytes_sent_mean", 50000.0) if b_info else 50000.0
            base_std = b_info.get("bytes_sent_std", 20000.0) if b_info else 20000.0
            base_max = b_info.get("bytes_sent_max", 100000) if b_info else 100000

            threshold = max(min_bytes, base_mean + (std_mult * base_std), base_mean * mult)

            # Find flows exceeding threshold
            large_flows = h_group[h_group["bytes_sent"] >= threshold]
            if not large_flows.empty:
                for _, row in large_flows.iterrows():
                    observed_bytes = int(row["bytes_sent"])
                    dest_ip = str(row["dst_ip"])
                    rec_id = row["record_id"]
                    ratio = observed_bytes / max(threshold, 1)

                    sev = "Critical" if ratio >= 5.0 else ("High" if ratio >= 2.0 else "Medium")
                    time_str = str(row["timestamp"])

                    # Check approved activity
                    matched_app = match_approved_activity(host, dest_ip, [row.get("dst_port")], approved_activities)

                    findings.append({
                        "finding_id": f"FND-{finding_counter:04d}",
                        "rule_id": "RULE_DATA_TRANSFER",
                        "rule_name": "Unusual Data Transfer",
                        "affected_host": host,
                        "relevant_destination": dest_ip,
                        "timestamp": time_str,
                        "time_window": f"{time_str} (Single Flow)",
                        "observed_value": f"{observed_bytes:,} bytes ({observed_bytes / (1024*1024):.2f} MB)",
                        "baseline_threshold": f"Baseline Mean: {base_mean:,.0f} B, Threshold: {threshold:,.0f} B",
                        "severity": sev,
                        "deviation_ratio": round(ratio, 2),
                        "explanation": (
                            f"Host {host} transferred {observed_bytes / (1024*1024):.2f} MB to {dest_ip}, "
                            f"exceeding normal baseline ({base_mean / 1024:.1f} KB) by {ratio:.1f}x."
                        ),
                        "supporting_record_ids": [rec_id],
                        "is_approved_activity": matched_app is not None,
                        "approved_activity_name": matched_app.get("name") if matched_app else None,
                        "possible_benign_explanations": [
                            "Legitimate large file transfer or authorized database export",
                            "Scheduled operating system or application update",
                            "Routine scheduled backup operation"
                        ]
                    })
                    finding_counter += 1

    # =========================================================================
    # RULE B: Port Probing
    # =========================================================================
    cfg_b = rules_cfg.get("port_probing", {})
    if cfg_b.get("enabled", True):
        port_thresh = int(cfg_b.get("distinct_port_threshold", 15))
        win_secs = int(cfg_b.get("time_window_seconds", 300))

        for host, h_group in eval_df.groupby("src_ip"):
            if len(h_group) < port_thresh:
                continue

            h_sorted = h_group.sort_values("timestamp")
            # Rolling window check
            start_idx = 0
            n_rows = len(h_sorted)

            for i in range(n_rows):
                t_i = h_sorted.iloc[i]["timestamp"]
                # Window: [t_i, t_i + win_secs]
                t_end = t_i + timedelta(seconds=win_secs)
                sub = h_sorted[(h_sorted["timestamp"] >= t_i) & (h_sorted["timestamp"] <= t_end)]
                
                valid_ports = sub["dst_port"].dropna().unique()
                if len(valid_ports) >= port_thresh:
                    # Found port probe in window
                    rec_ids = sub["record_id"].tolist()
                    target_dsts = list(sub["dst_ip"].unique())
                    primary_dst = target_dsts[0] if len(target_dsts) == 1 else "Multiple Targets"

                    matched_app = match_approved_activity(host, None, [int(p) for p in valid_ports], approved_activities)

                    sev = "High" if len(valid_ports) >= 20 else "Medium"

                    findings.append({
                        "finding_id": f"FND-{finding_counter:04d}",
                        "rule_id": "RULE_PORT_PROBE",
                        "rule_name": "Port Probing",
                        "affected_host": host,
                        "relevant_destination": primary_dst,
                        "timestamp": str(t_i),
                        "time_window": f"{t_i} to {t_end}",
                        "observed_value": f"{len(valid_ports)} distinct ports probed across {len(sub)} connections",
                        "baseline_threshold": f"Threshold: {port_thresh} ports per {win_secs}s",
                        "severity": sev,
                        "deviation_ratio": round(len(valid_ports) / port_thresh, 2),
                        "explanation": (
                            f"Host {host} contacted {len(valid_ports)} distinct destination ports on {primary_dst} "
                            f"within {win_secs} seconds, indicative of active port scanning or service enumeration."
                        ),
                        "supporting_record_ids": rec_ids,
                        "is_approved_activity": matched_app is not None,
                        "approved_activity_name": matched_app.get("name") if matched_app else None,
                        "possible_benign_explanations": [
                            "Authorized vulnerability scanner running discovery",
                            "Network discovery software (e.g. printer or service discovery)",
                            "Misconfigured local service attempting multiple connection ports"
                        ]
                    })
                    finding_counter += 1
                    break  # Avoid duplicate sub-findings for the same scan wave

    # =========================================================================
    # RULE C: Network Sweep (one source contacting many destination hosts)
    # =========================================================================
    cfg_sweep = rules_cfg.get("network_sweep", {})
    if cfg_sweep.get("enabled", True):
        host_thresh = int(cfg_sweep.get("distinct_host_threshold", 10))
        win_secs = int(cfg_sweep.get("time_window_seconds", 120))

        for host, h_group in eval_df.groupby("src_ip"):
            h_sorted = h_group.sort_values("timestamp")
            for _, row in h_sorted.iterrows():
                t_i = row["timestamp"]
                t_end = t_i + timedelta(seconds=win_secs)
                sub = h_sorted[(h_sorted["timestamp"] >= t_i) & (h_sorted["timestamp"] <= t_end)]
                destinations = sub["dst_ip"].dropna().unique()
                if len(destinations) < host_thresh:
                    continue

                rec_ids = sub["record_id"].tolist()
                matched_app = match_approved_activity(
                    host, None, sub["dst_port"].dropna().astype(int).tolist(), approved_activities
                )
                findings.append({
                    "finding_id": f"FND-{finding_counter:04d}",
                    "rule_id": "RULE_NETWORK_SWEEP",
                    "rule_name": "Network Sweep",
                    "affected_host": host,
                    "relevant_destination": f"{len(destinations)} hosts (e.g. {destinations[0]})",
                    "timestamp": str(t_i),
                    "time_window": f"{t_i} to {t_end}",
                    "observed_value": f"{len(destinations)} distinct destination hosts contacted",
                    "baseline_threshold": f"Threshold: {host_thresh} hosts per {win_secs}s",
                    "severity": "High" if len(destinations) >= host_thresh * 2 else "Medium",
                    "deviation_ratio": round(len(destinations) / host_thresh, 2),
                    "explanation": (
                        f"Host {host} contacted {len(destinations)} distinct destination hosts within "
                        f"{win_secs} seconds, consistent with a horizontal network sweep."
                    ),
                    "supporting_record_ids": rec_ids,
                    "is_approved_activity": matched_app is not None,
                    "approved_activity_name": matched_app.get("name") if matched_app else None,
                    "possible_benign_explanations": [
                        "Authorized vulnerability scanner operating within its approved scope",
                        "Inventory discovery or endpoint-management polling"
                    ]
                })
                finding_counter += 1
                break

    # =========================================================================
    # RULE D: Destination Diversity
    # =========================================================================
    cfg_c = rules_cfg.get("destination_diversity", {})
    if cfg_c.get("enabled", True):
        dest_mult = float(cfg_c.get("baseline_multiplier", 3.0))
        min_dest = int(cfg_c.get("min_dest_threshold", 10))
        win_secs = int(cfg_c.get("time_window_seconds", 300))

        for host, h_group in eval_df.groupby("src_ip"):
            b_info = host_baselines.get(host)
            base_dest_cnt = b_info.get("distinct_dest_count", 3) if b_info else 3
            eff_thresh = max(min_dest, int(base_dest_cnt * dest_mult))

            h_sorted = h_group.sort_values("timestamp")
            n_rows = len(h_sorted)

            for i in range(n_rows):
                t_i = h_sorted.iloc[i]["timestamp"]
                t_end = t_i + timedelta(seconds=win_secs)
                sub = h_sorted[(h_sorted["timestamp"] >= t_i) & (h_sorted["timestamp"] <= t_end)]
                distinct_dsts = sub["dst_ip"].unique()

                if len(distinct_dsts) >= eff_thresh:
                    rec_ids = sub["record_id"].tolist()
                    ratio = len(distinct_dsts) / max(base_dest_cnt, 1)
                    sev = "High" if len(distinct_dsts) >= 15 else "Medium"

                    matched_app = match_approved_activity(host, None, [], approved_activities)

                    findings.append({
                        "finding_id": f"FND-{finding_counter:04d}",
                        "rule_id": "RULE_DEST_DIVERSITY",
                        "rule_name": "Destination Diversity",
                        "affected_host": host,
                        "relevant_destination": f"{len(distinct_dsts)} endpoints (e.g. {distinct_dsts[0]})",
                        "timestamp": str(t_i),
                        "time_window": f"{t_i} to {t_end}",
                        "observed_value": f"{len(distinct_dsts)} distinct destination IPs contacted",
                        "baseline_threshold": f"Baseline: {base_dest_cnt} destinations, Threshold: {eff_thresh}",
                        "severity": sev,
                        "deviation_ratio": round(ratio, 2),
                        "explanation": (
                            f"Host {host} contacted {len(distinct_dsts)} unique destination IPs within {win_secs}s, "
                            f"substantially exceeding its normal baseline of {base_dest_cnt} endpoints."
                        ),
                        "supporting_record_ids": rec_ids,
                        "is_approved_activity": matched_app is not None,
                        "approved_activity_name": matched_app.get("name") if matched_app else None,
                        "possible_benign_explanations": [
                            "Peer-to-peer file synchronization or distributed client query",
                            "High-concurrency web crawling or analytics script",
                            "Subnet-wide monitoring ping from IT administrator tool"
                        ]
                    })
                    finding_counter += 1
                    break

    # =========================================================================
    # RULE E: Lateral Movement Across Internal Hosts
    # =========================================================================
    cfg_lateral = rules_cfg.get("lateral_movement", {})
    if cfg_lateral.get("enabled", True):
        internal_prefixes = [
            prefix for prefix in (
                cfg_lateral.get("internal_prefix"),
                cfg_lateral.get("internal_prefix_extra")
            ) if prefix
        ]
        if isinstance(cfg_lateral.get("internal_prefixes"), list):
            internal_prefixes.extend(cfg_lateral["internal_prefixes"])
        sensitive_ports = {int(port) for port in cfg_lateral.get(
            "sensitive_ports", [22, 23, 135, 139, 445, 3389, 5985, 5986]
        )}
        min_hops = int(cfg_lateral.get("min_lateral_hops", 3))
        win_secs = int(cfg_lateral.get("time_window_seconds", 600))

        for host, h_group in eval_df.groupby("src_ip"):
            lateral_flows = h_group[
                h_group["dst_ip"].astype(str).apply(
                    lambda dst: any(dst.startswith(prefix) for prefix in internal_prefixes)
                ) & h_group["dst_port"].isin(sensitive_ports)
            ].sort_values("timestamp")
            for _, row in lateral_flows.iterrows():
                t_i = row["timestamp"]
                t_end = t_i + timedelta(seconds=win_secs)
                sub = lateral_flows[
                    (lateral_flows["timestamp"] >= t_i) & (lateral_flows["timestamp"] <= t_end)
                ]
                destinations = sub["dst_ip"].dropna().unique()
                if len(destinations) < min_hops:
                    continue

                rec_ids = sub["record_id"].tolist()
                ports = sub["dst_port"].dropna().astype(int).unique().tolist()
                matched_app = match_approved_activity(host, None, ports, approved_activities)
                findings.append({
                    "finding_id": f"FND-{finding_counter:04d}",
                    "rule_id": "RULE_LATERAL_MOVEMENT",
                    "rule_name": "Lateral Movement",
                    "affected_host": host,
                    "relevant_destination": f"{len(destinations)} internal hosts",
                    "timestamp": str(t_i),
                    "time_window": f"{t_i} to {t_end}",
                    "observed_value": (
                        f"{len(destinations)} internal targets over sensitive ports "
                        f"{', '.join(map(str, sorted(ports)))}"
                    ),
                    "baseline_threshold": f"Threshold: {min_hops} internal hosts per {win_secs}s",
                    "severity": "High" if len(destinations) >= min_hops + 2 else "Medium",
                    "deviation_ratio": round(len(destinations) / min_hops, 2),
                    "explanation": (
                        f"Host {host} reached {len(destinations)} internal hosts over administrative or "
                        f"remote-service ports within {win_secs} seconds, which may indicate lateral spread."
                    ),
                    "supporting_record_ids": rec_ids,
                    "is_approved_activity": matched_app is not None,
                    "approved_activity_name": matched_app.get("name") if matched_app else None,
                    "possible_benign_explanations": [
                        "Approved patch, configuration-management, or endpoint-security deployment",
                        "Administrator performing a documented multi-host maintenance task"
                    ]
                })
                finding_counter += 1
                break

    # =========================================================================
    # RULE F: Periodic Connections (Beaconing Detection)
    # =========================================================================
    cfg_d = rules_cfg.get("periodic_connections", {})
    if cfg_d.get("enabled", True):
        min_occ = int(cfg_d.get("min_occurrences", 4))
        cv_thresh = float(cfg_d.get("cv_threshold", 0.15))

        for (host, dst), pair_group in eval_df.groupby(["src_ip", "dst_ip"]):
            if len(pair_group) < min_occ:
                continue

            pair_sorted = pair_group.sort_values("timestamp")
            times = pair_sorted["timestamp"].tolist()
            # Compute deltas in seconds
            deltas = [(times[k] - times[k-1]).total_seconds() for k in range(1, len(times))]
            valid_deltas = [d for d in deltas if d >= 5.0]  # ignore micro bursts

            if len(valid_deltas) >= min_occ - 1:
                mean_delta = np.mean(valid_deltas)
                std_delta = np.std(valid_deltas)
                cv = std_delta / mean_delta if mean_delta > 0 else 1.0

                if cv <= cv_thresh and mean_delta >= 15.0:
                    rec_ids = pair_sorted["record_id"].tolist()
                    matched_app = match_approved_activity(host, dst, pair_sorted["dst_port"].dropna().astype(int).tolist(), approved_activities)
                    connection_timeline = []
                    previous_time = None
                    for _, connection in pair_sorted.iterrows():
                        connection_time = connection["timestamp"]
                        gap_seconds = (
                            (connection_time - previous_time).total_seconds()
                            if previous_time is not None else None
                        )
                        connection_timeline.append({
                            "record_id": connection["record_id"],
                            "timestamp": str(connection_time),
                            "gap_seconds": round(gap_seconds, 2) if gap_seconds is not None else None
                        })
                        previous_time = connection_time

                    findings.append({
                        "finding_id": f"FND-{finding_counter:04d}",
                        "rule_id": "RULE_BEACONING",
                        "rule_name": "Periodic Connections",
                        "affected_host": host,
                        "relevant_destination": dst,
                        "timestamp": str(times[0]),
                        "time_window": f"{times[0]} to {times[-1]}",
                        "observed_value": f"Interval: {mean_delta:.1f}s +/- {std_delta:.2f}s (CV: {cv:.3f}, {len(pair_sorted)} connections)",
                        "baseline_threshold": f"CV <= {cv_thresh} (Strict periodicity)",
                        "beaconing_metrics": {
                            "mean_interval_seconds": round(float(mean_delta), 2),
                            "standard_deviation_seconds": round(float(std_delta), 2),
                            "coefficient_of_variation": round(float(cv), 4),
                            "interval_count": len(valid_deltas),
                            "threshold_cv": cv_thresh
                        },
                        "connection_timeline": connection_timeline,
                        "severity": "High",
                        "deviation_ratio": round(1.0 / max(cv, 0.01), 2),
                        "explanation": (
                            f"Host {host} connects to {dst} at highly regular intervals of ~{mean_delta:.0f} seconds "
                            f"(variance coefficient {cv:.3f}), exhibiting classic automated C2 beaconing behavior."
                        ),
                        "supporting_record_ids": rec_ids,
                        "is_approved_activity": matched_app is not None,
                        "approved_activity_name": matched_app.get("name") if matched_app else None,
                        "possible_benign_explanations": [
                            "Automated NTP, software telemetry, or agent health heartbeat",
                            "Periodic telemetry poll from monitoring agent (e.g. Datadog, Zabbix)",
                            "Persistent keep-alive ping for VPN tunnel"
                        ]
                    })
                    finding_counter += 1

    # =========================================================================
    # RULE G: Unexpected Host Communication
    # =========================================================================
    cfg_e = rules_cfg.get("unexpected_host_communication", {})
    if cfg_e.get("enabled", True):
        min_base_flows = int(cfg_e.get("min_baseline_flows", 5))

        for (host, dst), pair_group in eval_df.groupby(["src_ip", "dst_ip"]):
            pair_str = f"{host}->{dst}"
            b_info = host_baselines.get(host)

            # Only evaluate if host was well-established in baseline
            if b_info and b_info.get("conn_count", 0) >= min_base_flows:
                if pair_str not in all_baseline_pairs:
                    # Unseen communication pair
                    ports = pair_group["dst_port"].dropna().astype(int).tolist()
                    ports_str = ", ".join(map(str, sorted(list(set(ports))))) if ports else "N/A"
                    rec_ids = pair_group["record_id"].tolist()
                    first_time = str(pair_group["timestamp"].min())

                    matched_app = match_approved_activity(host, dst, ports, approved_activities)

                    # Sensitive ports escalate severity
                    sensitive_ports = {22, 3389, 445, 1433, 3306, 5432, 88}
                    is_sensitive = any(p in sensitive_ports for p in ports)
                    sev = "High" if is_sensitive else "Medium"

                    findings.append({
                        "finding_id": f"FND-{finding_counter:04d}",
                        "rule_id": "RULE_UNEXPECTED_COMM",
                        "rule_name": "Unexpected Host Communication",
                        "affected_host": host,
                        "relevant_destination": dst,
                        "timestamp": first_time,
                        "time_window": f"{first_time} to {pair_group['timestamp'].max()}",
                        "observed_value": f"New connection to {dst} on port(s) {ports_str} ({len(pair_group)} flows)",
                        "baseline_threshold": "Never observed during baseline learning period",
                        "severity": sev,
                        "deviation_ratio": 2.5 if is_sensitive else 1.5,
                        "explanation": (
                            f"Host {host} established communication with {dst} on port(s) {ports_str}. "
                            f"This communication pair was never observed during the baseline period."
                        ),
                        "supporting_record_ids": rec_ids,
                        "is_approved_activity": matched_app is not None,
                        "approved_activity_name": matched_app.get("name") if matched_app else None,
                        "possible_benign_explanations": [
                            "New employee workstation connecting to internal resources for the first time",
                            "New network service or server recently deployed",
                            "Authorized ad-hoc remote administration session"
                        ]
                    })
                    finding_counter += 1

    # =========================================================================
    # RULE H: DNS Behaviour Analysis
    # =========================================================================
    cfg_f = rules_cfg.get("dns_behaviour", {})
    if cfg_f.get("enabled", True):
        vol_mult = float(cfg_f.get("query_volume_multiplier", 3.0))
        min_dns_vol = int(cfg_f.get("min_query_volume", 15))
        unique_ratio_thresh = float(cfg_f.get("unique_query_ratio_threshold", 0.75))

        dns_flows = eval_df[eval_df["dns_query"] != ""].copy()
        if not dns_flows.empty:
            for host, h_dns in dns_flows.groupby("src_ip"):
                total_queries = len(h_dns)
                if total_queries >= min_dns_vol:
                    unique_queries = len(h_dns["dns_query"].unique())
                    ratio = unique_queries / total_queries

                    b_info = host_baselines.get(host)
                    base_dns_count = b_info.get("dns_query_count", 5) if b_info else 5

                    if ratio >= unique_ratio_thresh or total_queries >= (base_dns_count * vol_mult):
                        rec_ids = h_dns["record_id"].tolist()
                        sample_domains = h_dns["dns_query"].head(3).tolist()
                        matched_app = match_approved_activity(host, None, [53], approved_activities)

                        sev = "High" if ratio >= 0.85 else "Medium"

                        findings.append({
                            "finding_id": f"FND-{finding_counter:04d}",
                            "rule_id": "RULE_DNS_ANOMALY",
                            "rule_name": "DNS Behaviour Analysis",
                            "affected_host": host,
                            "relevant_destination": str(h_dns["dst_ip"].iloc[0]),
                            "timestamp": str(h_dns["timestamp"].min()),
                            "time_window": f"{h_dns['timestamp'].min()} to {h_dns['timestamp'].max()}",
                            "observed_value": f"{total_queries} queries, {unique_queries} unique ({ratio:.1%} unique ratio)",
                            "baseline_threshold": f"Baseline: {base_dns_count} queries, Unique Ratio Thresh: {unique_ratio_thresh:.0%}",
                            "severity": sev,
                            "deviation_ratio": round(ratio * 2.5, 2),
                            "explanation": (
                                f"Host {host} performed {total_queries} DNS requests with {unique_queries} unique domains "
                                f"(e.g. {sample_domains[0]}), indicating potential DNS tunneling or DGA malware activity."
                            ),
                            "supporting_record_ids": rec_ids,
                            "is_approved_activity": matched_app is not None,
                            "approved_activity_name": matched_app.get("name") if matched_app else None,
                            "possible_benign_explanations": [
                                "Anti-spam or DNS-based blacklist lookup service running on mail host",
                                "Web scraper or search spider resolving external links",
                                "Security agent verifying threat intelligence domains"
                            ]
                        })
                        finding_counter += 1

    # =========================================================================
    # RULE I: Blocked or Failed Connections
    # =========================================================================
    cfg_g = rules_cfg.get("blocked_failed_connections", {})
    if cfg_g.get("enabled", True):
        rate_thresh = float(cfg_g.get("failure_rate_threshold", 0.35))
        min_fails = int(cfg_g.get("min_failed_count", 5))
        b_mult = float(cfg_g.get("baseline_multiplier", 2.5))

        failed_actions = ["DENY", "DROP", "REJECT", "BLOCKED", "FAILED", "RESET"]
        eval_with_action = eval_df[eval_df["action"] != ""].copy()

        if not eval_with_action.empty:
            for host, h_group in eval_with_action.groupby("src_ip"):
                total_conns = len(h_group)
                failed_flows = h_group[h_group["action"].isin(failed_actions)]
                failed_cnt = len(failed_flows)

                if failed_cnt >= min_fails:
                    fail_rate = failed_cnt / total_conns
                    b_info = host_baselines.get(host)
                    base_fail_rate = b_info.get("failed_rate", 0.05) if b_info else 0.05

                    if fail_rate >= rate_thresh or (base_fail_rate > 0 and fail_rate >= base_fail_rate * b_mult):
                        rec_ids = failed_flows["record_id"].tolist()
                        dst_sample = str(failed_flows["dst_ip"].iloc[0])
                        matched_app = match_approved_activity(host, None, [], approved_activities)

                        sev = "High" if failed_cnt >= 12 else "Medium"

                        findings.append({
                            "finding_id": f"FND-{finding_counter:04d}",
                            "rule_id": "RULE_BLOCKED_CONNS",
                            "rule_name": "Blocked or Failed Connections",
                            "affected_host": host,
                            "relevant_destination": dst_sample,
                            "timestamp": str(failed_flows["timestamp"].min()),
                            "time_window": f"{failed_flows['timestamp'].min()} to {failed_flows['timestamp'].max()}",
                            "observed_value": f"{failed_cnt} blocked connections ({fail_rate:.1%} failure rate)",
                            "baseline_threshold": f"Baseline rate: {base_fail_rate:.1%}, Threshold: {rate_thresh:.1%}",
                            "severity": sev,
                            "deviation_ratio": round(fail_rate / max(base_fail_rate, 0.01), 2),
                            "explanation": (
                                f"Host {host} experienced {failed_cnt} blocked/denied connections to {dst_sample} "
                                f"({fail_rate:.1%} of traffic), suggesting policy violations or failed authentication."
                            ),
                            "supporting_record_ids": rec_ids,
                            "is_approved_activity": matched_app is not None,
                            "approved_activity_name": matched_app.get("name") if matched_app else None,
                            "possible_benign_explanations": [
                                "User entered wrong password repeatedly causing firewall lockout",
                                "Recent firewall rule update that legitimately blocks legacy service",
                                "Stale network share mapping attempting reconnect"
                            ]
                        })
                        finding_counter += 1

    trusted_roles = {server.get("ip"): server.get("role", "Trusted Server")
                     for server in config.get("trusted_servers", [])}
    scoring_cfg = config.get("scoring", {})
    trusted_multipliers = scoring_cfg.get("trusted_activity_multipliers", {})
    for finding in findings:
        supporting_rows = eval_df[eval_df["record_id"].isin(finding.get("supporting_record_ids", []))]
        suppression_reason = None
        maintenance_matches = []
        for _, row in supporting_rows.iterrows():
            timestamp = row["timestamp"]
            if isinstance(timestamp, pd.Timestamp):
                timestamp = timestamp.to_pydatetime()
            window_name = is_in_maintenance_window(timestamp, str(row["src_ip"]), config)
            maintenance_matches.append(window_name)
        if maintenance_matches and all(maintenance_matches):
            window_names = ", ".join(sorted(set(maintenance_matches)))
            suppression_reason = f"Scheduled maintenance: {window_names}"

        if suppression_reason is None and finding.get("is_approved_activity"):
            suppression_reason = f"Approved activity: {finding.get('approved_activity_name')}"

        trusted_roles = sorted({
            role for _, row in supporting_rows.iterrows()
            if (role := is_trusted_server(str(row["dst_ip"]), config))
        })
        if trusted_roles:
            finding["trusted_server_roles"] = trusted_roles
        if suppression_reason is None and finding.get("severity") == "Low" and trusted_roles:
            suppression_reason = f"Low-severity traffic to trusted server: {', '.join(trusted_roles)}"

        finding["is_suppressed"] = suppression_reason is not None
        finding["suppression_reason"] = suppression_reason
        if suppression_reason and suppression_reason.startswith("Scheduled maintenance:"):
            trusted_multiplier = float(trusted_multipliers.get("maintenance", 0.0))
        elif suppression_reason and finding.get("is_approved_activity"):
            trusted_multiplier = float(trusted_multipliers.get("approved_activity", 0.0))
        elif trusted_roles:
            trusted_multiplier = float(trusted_multipliers.get("trusted_server", 0.8))
        else:
            trusted_multiplier = 1.0
        finding["trusted_activity_adjustment_multiplier"] = min(1.0, max(0.0, trusted_multiplier))
        rule_weights = scoring_cfg.get("rule_weights", DEFAULT_SETTINGS["scoring"]["rule_weights"])
        finding["rule_weight"] = float(rule_weights.get(
            finding.get("rule_id"), scoring_cfg.get("default_rule_weight", 50)
        ))
        finding["risk_score"] = calculate_incident_score([finding], scoring_cfg)[0]

    return findings


def calculate_incident_score(
    findings: List[Dict[str, Any]],
    scoring_cfg: Dict[str, Any]
) -> Tuple[int, str, Dict[str, float]]:
    """
    Computes a deterministic, configurable incident risk score from its findings.
    """
    defaults = DEFAULT_SETTINGS["scoring"]
    default_weights = defaults["weights"]
    configured_weights = scoring_cfg.get("weights", default_weights)
    weights = {
        key: float(configured_weights.get(key, default_weights[key]))
        for key in default_weights
    }
    base_points = scoring_cfg.get("severity_base_points", defaults["severity_base_points"])
    rule_weights = scoring_cfg.get("rule_weights", defaults["rule_weights"])

    # 1. Severity Factor: maximum severity among constituent findings
    severities = [f.get("severity", "Medium") for f in findings]
    severity_values = [
        float(base_points.get(severity, base_points.get("Medium", defaults["severity_base_points"]["Medium"])))
        for severity in severities
    ]
    severity_score = max(severity_values) if severity_values else float(base_points.get("Low", defaults["severity_base_points"]["Low"]))

    # 2. Deviation Factor: normalized from the largest observed rule deviation.
    ratios = [f.get("deviation_ratio", 1.0) for f in findings]
    max_ratio = max(ratios) if ratios else 1.0
    deviation_base = float(scoring_cfg.get("deviation_base_points", defaults["deviation_base_points"]))
    deviation_step = float(scoring_cfg.get("deviation_points_per_ratio", defaults["deviation_points_per_ratio"]))
    deviation_saturation = float(scoring_cfg.get("deviation_saturation_ratio", defaults["deviation_saturation_ratio"]))
    deviation_ratio = min(max_ratio, max(1.0, deviation_saturation))
    deviation_score = min(100.0, max(0.0, deviation_base + (deviation_ratio - 1.0) * deviation_step))

    # 3. Persistence Factor: distinct supporting flow evidence.
    all_record_ids = {
        record_id
        for finding in findings
        for record_id in finding.get("supporting_record_ids", [])
    }
    record_count = len(all_record_ids)
    persistence_base = float(scoring_cfg.get("persistence_base_points", defaults["persistence_base_points"]))
    persistence_step = float(scoring_cfg.get("persistence_points_per_log2_record", defaults["persistence_points_per_log2_record"]))
    persistence_saturation = max(1, int(scoring_cfg.get(
        "persistence_saturation_records", defaults["persistence_saturation_records"]
    )))
    scored_record_count = min(record_count, persistence_saturation)
    persistence_score = min(
        100.0,
        max(0.0, persistence_base + math.log2(max(scored_record_count, 1) + 1) * persistence_step)
    )

    rule_ids = sorted({finding.get("rule_id", "UNKNOWN") for finding in findings})
    rule_names = {
        finding.get("rule_id", "UNKNOWN"): finding.get("rule_name", finding.get("rule_id", "Unknown rule"))
        for finding in findings
    }
    category_points = scoring_cfg.get("category_diversity_points", defaults["category_diversity_points"])
    category_key = str(len(rule_ids))
    category_score = float(category_points.get(
        category_key,
        scoring_cfg.get("category_diversity_max_points", defaults["category_diversity_max_points"]) if rule_ids else 0
    ))

    # Rule priority is an average across distinct triggered rules, not finding count.
    rule_priority_values = {
        rule_id: float(rule_weights.get(rule_id, scoring_cfg.get("default_rule_weight", defaults["default_rule_weight"])))
        for rule_id in rule_ids
    }
    rule_priority_score = (
        sum(rule_priority_values.values()) / len(rule_priority_values)
        if rule_priority_values else 0.0
    )

    # Corroboration grows with multiple findings and saturates at the configured value.
    correlation_step = float(scoring_cfg.get(
        "correlation_points_per_additional_finding",
        defaults["correlation_points_per_additional_finding"]
    ))
    correlation_score = min(
        100.0,
        max(0, len(findings) - 1) * correlation_step
    )

    component_scores = {
        "severity": severity_score,
        "deviation": deviation_score,
        "persistence": persistence_score,
        "category_diversity": category_score,
        "rule_priority": rule_priority_score,
        "correlation": correlation_score
    }
    component_points = {
        key: component_scores[key] * weights[key]
        for key in weights
    }
    pre_adjustment_score = sum(component_points.values())
    trusted_defaults = defaults["trusted_activity_multipliers"]
    finding_multipliers = []
    for finding in findings:
        if "trusted_activity_adjustment_multiplier" in finding:
            finding_multipliers.append(float(finding["trusted_activity_adjustment_multiplier"]))
        elif finding.get("is_approved_activity"):
            finding_multipliers.append(float(trusted_defaults["approved_activity"]))
        else:
            finding_multipliers.append(1.0)
    trusted_multiplier = min(finding_multipliers, default=1.0)
    trusted_multiplier = min(1.0, max(0.0, trusted_multiplier))
    final_score = int(round(min(100.0, max(0.0, pre_adjustment_score * trusted_multiplier))))

    rule_contributions = []
    for rule_id in rule_ids:
        weighted_points = (
            rule_priority_values[rule_id]
            * weights["rule_priority"]
            / len(rule_ids)
            * trusted_multiplier
        )
        rule_contributions.append({
            "rule_id": rule_id,
            "rule_name": rule_names[rule_id],
            "configured_weight": rule_priority_values[rule_id],
            "finding_count": sum(finding.get("rule_id") == rule_id for finding in findings),
            "weighted_points": round(weighted_points, 2)
        })

    breakdown = {
        **{f"{key}_score": round(value, 1) for key, value in component_scores.items()},
        **{f"{key}_weight": value for key, value in weights.items()},
        "component_points": {key: round(value, 2) for key, value in component_points.items()},
        "raw_weighted_total": round(pre_adjustment_score, 2),
        "trusted_activity_multiplier": round(trusted_multiplier, 3),
        "trusted_activity_adjustment_points": round(pre_adjustment_score * (1.0 - trusted_multiplier), 2),
        "supporting_record_count": record_count,
        "scored_supporting_record_count": scored_record_count,
        "distinct_rule_count": len(rule_ids),
        "rule_contributions": rule_contributions
    }

    explanation = (
        f"Score {final_score}/100 from configured severity, deviation, evidence persistence, "
        f"rule diversity, rule priority, and correlation weights; "
        f"trusted-activity multiplier {trusted_multiplier:.2f} applied to {pre_adjustment_score:.2f} raw points."
    )

    return final_score, explanation, breakdown


def get_incident_severity(score: int, score_thresholds: Dict[str, Any]) -> str:
    """Maps deterministic score to Low, Medium, High, or Critical severity."""
    low_max = score_thresholds.get("Low", 35)
    med_max = score_thresholds.get("Medium", 65)
    high_max = score_thresholds.get("High", 85)

    if score <= low_max:
        return "Low"
    elif score <= med_max:
        return "Medium"
    elif score <= high_max:
        return "High"
    else:
        return "Critical"


def group_findings_into_incidents(
    findings: List[Dict[str, Any]],
    config: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Groups individual anomaly findings into coherent security incidents
    based on affected host, destination overlap, and temporal proximity.
    """
    findings = [finding for finding in findings if not finding.get("is_suppressed", False)]
    if not findings:
        return []

    scoring_cfg = config.get("scoring", {})
    score_thresholds = scoring_cfg.get("score_thresholds", {
        "Low": 35,
        "Medium": 65,
        "High": 85,
        "Critical": 100
    })

    # Group findings primarily by affected host
    host_groups: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        host = f["affected_host"]
        host_groups.setdefault(host, []).append(f)

    incidents: List[Dict[str, Any]] = []
    inc_counter = 1
    attack_stages = {
        "RULE_UNEXPECTED_COMM": "Initial Access / Reconnaissance",
        "RULE_PORT_PROBE": "Discovery",
        "RULE_NETWORK_SWEEP": "Discovery",
        "RULE_DEST_DIVERSITY": "Discovery",
        "RULE_LATERAL_MOVEMENT": "Lateral Movement",
        "RULE_BEACONING": "Command and Control",
        "RULE_DNS_ANOMALY": "Command and Control",
        "RULE_DATA_TRANSFER": "Exfiltration",
        "RULE_BLOCKED_CONNS": "Credential Access / Impact"
    }

    for host, host_findings in host_groups.items():
        # Within each host, check if findings share destination or are temporally grouped
        # For simplicity and clarity, findings on the same host form an incident cluster
        all_dests = set()
        all_rules = set()
        all_rec_ids = set()
        timestamps = []
        is_approved = any(f.get("is_approved_activity", False) for f in host_findings)
        app_name = next((f.get("approved_activity_name") for f in host_findings if f.get("approved_activity_name")), None)

        benign_explanations = set()
        investigation_steps = [
            f"Review process tree and active sessions on host {host}",
            "Check local endpoint security logs (EDR/antivirus) for correlated alerts",
            "Verify with asset owner if activity corresponds to scheduled operational tasks",
            "Examine firewall and gateway proxy logs for destination payload details"
        ]

        for f in host_findings:
            if f.get("relevant_destination"):
                all_dests.add(f["relevant_destination"])
            all_rules.add(f["rule_name"])
            all_rec_ids.update(f.get("supporting_record_ids", []))
            if f.get("timestamp"):
                timestamps.append(f["timestamp"])
            for ben in f.get("possible_benign_explanations", []):
                benign_explanations.add(ben)

        sorted_times = sorted(timestamps)
        first_seen = sorted_times[0] if sorted_times else "Unknown"
        last_seen = sorted_times[-1] if sorted_times else "Unknown"

        score, score_exp, breakdown = calculate_incident_score(host_findings, scoring_cfg)
        severity = get_incident_severity(score, score_thresholds)

        # Build incident title
        primary_rule = list(all_rules)[0] if len(all_rules) == 1 else f"{len(all_rules)} Anomaly Patterns"
        title = f"Unusual Activity on {host} ({primary_rule})"

        incidents.append({
            "incident_id": f"INC-{inc_counter:03d}",
            "title": title,
            "affected_hosts": [host],
            "destinations": sorted(list(all_dests)),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "related_rules": sorted(list(all_rules)),
            "contributing_rules": breakdown["rule_contributions"],
            "findings_count": len(host_findings),
            "findings": host_findings,
            "timeline": [
                {
                    "timestamp": finding.get("timestamp"),
                    "finding_id": finding.get("finding_id"),
                    "rule_id": finding.get("rule_id"),
                    "rule_name": finding.get("rule_name"),
                    "attack_stage": attack_stages.get(finding.get("rule_id"), "Behavioral Anomaly"),
                    "severity": finding.get("severity"),
                    "explanation": finding.get("explanation")
                }
                for finding in sorted(host_findings, key=lambda item: item.get("timestamp", ""))
            ],
            "attack_stages": list(dict.fromkeys(
                attack_stages.get(finding.get("rule_id"), "Behavioral Anomaly")
                for finding in sorted(host_findings, key=lambda item: item.get("timestamp", ""))
            )),
            "supporting_record_ids": sorted(list(all_rec_ids)),
            "severity": severity,
            "score": score,
            "score_explanation": score_exp,
            "score_breakdown": breakdown,
            "is_approved_activity": is_approved,
            "approved_activity_name": app_name,
            "possible_benign_explanations": sorted(list(benign_explanations)),
            "suggested_investigation_steps": investigation_steps
        })
        inc_counter += 1

    # Sort incidents by priority score descending
    incidents.sort(key=lambda x: x["score"], reverse=True)
    return incidents
