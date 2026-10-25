import math
import ipaddress
import numpy as np
import pandas as pd
from datetime import datetime
from typing import Dict, List, Any, Optional


def get_traffic_over_time(
    df: pd.DataFrame,
    interval_minutes: int = 5
) -> List[Dict[str, Any]]:
    """
    Bins network traffic over time (1m, 5m, 60m) and returns time-series data
    with bytes sent, bytes received, connection counts, and packet totals.
    """
    if df.empty:
        return []

    df_copy = df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_copy["timestamp"]):
        df_copy["timestamp"] = pd.to_datetime(df_copy["timestamp"])

    freq_map = {1: "1min", 5: "5min", 60: "60min"}
    rule = freq_map.get(interval_minutes, "5min")

    df_copy.set_index("timestamp", inplace=True)
    resampled = df_copy.resample(rule).agg({
        "bytes_sent": "sum",
        "bytes_received": "sum",
        "packets": "sum",
        "record_id": "count"
    }).rename(columns={"record_id": "connections"}).reset_index()
    resampled = resampled[resampled["connections"] > 0]

    result = []
    for _, row in resampled.iterrows():
        b_sent = int(row["bytes_sent"]) if pd.notna(row["bytes_sent"]) else 0
        b_recv = int(row["bytes_received"]) if pd.notna(row["bytes_received"]) else 0
        pkts = int(row["packets"]) if pd.notna(row["packets"]) else 0
        conns = int(row["connections"]) if pd.notna(row["connections"]) else 0

        # Skip completely empty intervals to keep charts crisp if dataset spans days
        result.append({
            "timestamp": str(row["timestamp"]),
            "bytes_sent": b_sent,
            "bytes_received": b_recv,
            "total_bytes": b_sent + b_recv,
            "packets": pkts,
            "connections": conns
        })

    return result


def get_protocol_distribution(df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Calculates protocol breakdown by connection count and total volume."""
    if df.empty:
        return []

    grouped = df.groupby("protocol").agg({
        "record_id": "count",
        "bytes_sent": "sum",
        "bytes_received": "sum"
    }).reset_index()

    result = []
    for _, row in grouped.iterrows():
        proto = str(row["protocol"]) if pd.notna(row["protocol"]) else "OTHER"
        cnt = int(row["record_id"])
        b_sent = int(row["bytes_sent"])
        b_recv = int(row["bytes_received"])
        result.append({
            "protocol": proto,
            "count": cnt,
            "total_bytes": b_sent + b_recv
        })

    result.sort(key=lambda x: x["count"], reverse=True)
    return result


def get_top_talkers(df: pd.DataFrame, limit: int = 10) -> List[Dict[str, Any]]:
    """Calculates top source hosts by total bytes, packets, and connections."""
    if df.empty:
        return []

    grouped = df.groupby("src_ip").agg({
        "bytes_sent": "sum",
        "bytes_received": "sum",
        "packets": "sum",
        "record_id": "count",
        "dst_ip": "nunique"
    }).reset_index()

    result = []
    for _, row in grouped.iterrows():
        b_sent = int(row["bytes_sent"])
        b_recv = int(row["bytes_received"])
        result.append({
            "host": str(row["src_ip"]),
            "bytes_sent": b_sent,
            "bytes_received": b_recv,
            "total_bytes": b_sent + b_recv,
            "packets": int(row["packets"]),
            "connections": int(row["record_id"]),
            "distinct_destinations": int(row["dst_ip"])
        })

    result.sort(key=lambda x: x["total_bytes"], reverse=True)
    return result[:limit]


def get_host_analysis(
    df: pd.DataFrame,
    host_ip: str,
    baseline: Optional[Dict[str, Any]] = None,
    incidents: Optional[List[Dict[str, Any]]] = None,
    observed_df: Optional[pd.DataFrame] = None
) -> Dict[str, Any]:
    """Provides complete deep-dive analysis for an individual host."""
    outgoing_flows = df[df["src_ip"] == host_ip].copy()
    incoming_flows = df[df["dst_ip"] == host_ip].copy()
    if outgoing_flows.empty and incoming_flows.empty:
        return {"error": f"Host {host_ip} not found in current dataset"}

    host_flows = pd.concat([outgoing_flows, incoming_flows]).drop_duplicates("record_id")
    total_conns = len(host_flows)
    bytes_sent = int(outgoing_flows["bytes_sent"].sum() + incoming_flows["bytes_received"].sum())
    bytes_recv = int(outgoing_flows["bytes_received"].sum() + incoming_flows["bytes_sent"].sum())
    packets = int(host_flows["packets"].sum())

    dest_counts = outgoing_flows["dst_ip"].value_counts().head(10).to_dict()
    top_destinations = [{"destination": d, "count": int(c)} for d, c in dest_counts.items()]
    source_counts = incoming_flows["src_ip"].value_counts().head(10).to_dict()
    top_sources = [{"source": source, "count": int(count)} for source, count in source_counts.items()]

    valid_ports = host_flows["dst_port"].dropna().astype(int)
    port_counts = valid_ports.value_counts().head(10).to_dict()
    top_ports = [{"port": int(p), "count": int(c)} for p, c in port_counts.items()]

    proto_counts = host_flows["protocol"].value_counts().to_dict()
    protocols = [{"protocol": p, "count": int(c)} for p, c in proto_counts.items()]

    # Baseline comparison
    host_base = None
    if baseline and "host_baselines" in baseline:
        host_base = baseline["host_baselines"].get(host_ip)

    comparison = None
    if host_base and baseline and observed_df is not None:
        observed_outgoing = observed_df[observed_df["src_ip"] == host_ip]
        learning_start = pd.to_datetime(baseline["learning_start"])
        learning_end = pd.to_datetime(baseline["learning_end"])
        learning_hours = max((learning_end - learning_start).total_seconds() / 3600, 1 / 3600)
        if state_eval_start := observed_df["timestamp"].min():
            observed_start = pd.to_datetime(state_eval_start)
            observed_end = pd.to_datetime(observed_df["timestamp"].max())
            observed_hours = max((observed_end - observed_start).total_seconds() / 3600, 1 / 3600)
        else:
            observed_start = observed_end = learning_start
            observed_hours = learning_hours

        observed_failures = int(observed_outgoing["action"].isin(
            ["DENY", "DROP", "REJECT", "BLOCKED", "FAILED", "RESET"]
        ).sum())
        observed_connections = len(observed_outgoing)
        observed_dest_count = int(observed_outgoing["dst_ip"].nunique())
        observed_bytes_sent = float(observed_outgoing["bytes_sent"].sum())
        normal_total_bytes = float(host_base.get("bytes_sent_mean", 0)) * int(host_base.get("conn_count", 0))
        def comparison_metric(key: str, label: str, unit: str, normal: float, observed: float) -> Dict[str, Any]:
            return {
                "key": key,
                "label": label,
                "unit": unit,
                "normal": round(normal, 2),
                "observed": round(observed, 2),
                "change_percent": round((observed - normal) / normal * 100, 2) if normal else None
            }

        comparison = {
            "learning_window": f"{learning_start} to {learning_end}",
            "evaluation_window": f"{observed_start} to {observed_end}",
            "metrics": [
                comparison_metric(
                    "connections_per_hour", "Outgoing connections per hour", "/hour",
                    host_base.get("conn_count", 0) / learning_hours,
                    observed_connections / observed_hours
                ),
                comparison_metric(
                    "bytes_sent_per_hour", "Bytes sent per hour", "B/hour",
                    normal_total_bytes / learning_hours,
                    observed_bytes_sent / observed_hours
                ),
                comparison_metric(
                    "average_bytes_per_flow", "Average bytes sent per flow", "B/flow",
                    float(host_base.get("bytes_sent_mean", 0)),
                    observed_bytes_sent / observed_connections if observed_connections else 0
                ),
                comparison_metric(
                    "distinct_destinations", "Distinct destinations", "hosts",
                    host_base.get("distinct_dest_count", 0), observed_dest_count
                ),
                comparison_metric(
                    "failed_rate", "Failed connection rate", "%",
                    float(host_base.get("failed_rate", 0)) * 100,
                    observed_failures / observed_connections * 100 if observed_connections else 0
                )
            ]
        }

    # Associated incidents
    host_incidents = []
    if incidents:
        for inc in incidents:
            if host_ip in inc.get("affected_hosts", []):
                host_incidents.append({
                    "incident_id": inc["incident_id"],
                    "title": inc["title"],
                    "severity": inc["severity"],
                    "score": inc["score"]
                })

    # Evidence records sample
    evidence_flows = host_flows.head(50).to_dict(orient="records")
    for flow in evidence_flows:
        if pd.notna(flow["timestamp"]):
            flow["timestamp"] = str(flow["timestamp"])

    return {
        "host": host_ip,
        "total_connections": total_conns,
        "outgoing_connections": len(outgoing_flows),
        "incoming_connections": len(incoming_flows),
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_recv,
        "total_bytes": bytes_sent + bytes_recv,
        "packets": packets,
        "top_destinations": top_destinations,
        "distinct_destination_count": int(outgoing_flows["dst_ip"].nunique()),
        "top_sources": top_sources,
        "distinct_source_count": int(incoming_flows["src_ip"].nunique()),
        "top_ports": top_ports,
        "protocols": protocols,
        "baseline_profile": host_base,
        "behavior_comparison": comparison,
        "incidents": host_incidents,
        "evidence_flows": evidence_flows
    }


def get_port_analysis(
    df: pd.DataFrame,
    host_filter: Optional[str] = None,
    protocol_filter: Optional[str] = None
) -> Dict[str, Any]:
    """
    Analyzes destination port usage, common service ports,
    and builds host-versus-port matrix. Handles missing ports cleanly.
    """
    sub_df = df.copy()

    if host_filter:
        sub_df = sub_df[(sub_df["src_ip"] == host_filter) | (sub_df["dst_ip"] == host_filter)]
    if protocol_filter:
        sub_df = sub_df[sub_df["protocol"] == protocol_filter]

    # Filter out missing destination ports (DO NOT TREAT AS ZERO)
    ports_df = sub_df[sub_df["dst_port"].notna()].copy()
    ports_df["dst_port"] = ports_df["dst_port"].astype(int)

    # Common well-known port labels
    PORT_LABELS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "Sonar/Dev"
    }

    port_stats = ports_df.groupby("dst_port").agg({
        "record_id": "count",
        "bytes_sent": "sum",
        "bytes_received": "sum",
        "src_ip": "nunique"
    }).reset_index()

    common_ports = []
    for _, row in port_stats.iterrows():
        p = int(row["dst_port"])
        common_ports.append({
            "port": p,
            "service": PORT_LABELS.get(p, f"Port {p}"),
            "connections": int(row["record_id"]),
            "total_bytes": int(row["bytes_sent"] + row["bytes_received"]),
            "unique_source_hosts": int(row["src_ip"])
        })

    common_ports.sort(key=lambda x: x["connections"], reverse=True)

    # Build Host vs Port heatmap matrix (Top 10 hosts x Top 10 ports)
    top_ports_list = [cp["port"] for cp in common_ports[:10]]
    top_hosts_list = ports_df["src_ip"].value_counts().head(10).index.tolist()

    heatmap_matrix = []
    if top_ports_list and top_hosts_list:
        matrix_df = ports_df[
            ports_df["dst_port"].isin(top_ports_list) &
            ports_df["src_ip"].isin(top_hosts_list)
        ]
        crosstab = pd.crosstab(matrix_df["src_ip"], matrix_df["dst_port"])

        for host in top_hosts_list:
            row_data = {"host": host}
            for p in top_ports_list:
                row_data[f"port_{p}"] = int(crosstab.loc[host, p]) if host in crosstab.index and p in crosstab.columns else 0
            heatmap_matrix.append(row_data)

    return {
        "common_ports": common_ports[:25],
        "top_ports_list": top_ports_list,
        "heatmap_matrix": heatmap_matrix,
        "total_flows_with_port": len(ports_df),
        "total_flows_missing_port": len(sub_df) - len(ports_df)
    }


def get_dns_analysis(df: pd.DataFrame) -> Dict[str, Any]:
    """Summarize DNS flows and, when logged, queried domain names."""
    query_names = df[df["dns_query"].notna() & (df["dns_query"].astype(str).str.strip() != "")].copy()
    port_53 = df[df["dst_port"] == 53].copy()
    dns_df = pd.concat([port_53, query_names]).drop_duplicates("record_id")
    if dns_df.empty:
        return {
            "available": False,
            "message": "No DNS query names or flows to destination port 53 are present in this dataset."
        }

    domain_data_available = not query_names.empty
    total_queries = len(query_names) if domain_data_available else len(dns_df)
    unique_domains = int(query_names["dns_query"].nunique()) if domain_data_available else None

    top_domains = []
    domain_counts = query_names["dns_query"].value_counts().head(15).to_dict()
    for d, c in domain_counts.items():
        top_domains.append({"domain": d, "count": int(c)})

    # Top querying hosts
    host_dns_counts = dns_df["src_ip"].value_counts().head(10).to_dict()
    top_hosts = [{"host": h, "queries": int(c)} for h, c in host_dns_counts.items()]

    return {
        "available": True,
        "domain_data_available": domain_data_available,
        "total_queries": total_queries,
        "unique_domains": unique_domains,
        "unique_ratio": round(unique_domains / max(total_queries, 1), 3) if domain_data_available else None,
        "top_domains": top_domains,
        "top_querying_hosts": top_hosts
    }


def build_network_graph(
    df: pd.DataFrame,
    incidents: Optional[List[Dict[str, Any]]] = None,
    max_edges: int = 150
) -> Dict[str, Any]:
    """
    Builds Cytoscape-compatible network topology graph from actual observed communications.
    Annotates anomalous nodes and edges involved in incidents.
    """
    if df.empty:
        return {"elements": {"nodes": [], "edges": []}, "summary": {"nodes": 0, "edges": 0}}

    # Collect anomalous hosts and edges
    anomalous_hosts = set()
    incident_edge_pairs = set()

    if incidents:
        for inc in incidents:
            for h in inc.get("affected_hosts", []):
                anomalous_hosts.add(h)
            for f in inc.get("findings", []):
                src = f.get("affected_host")
                dst = f.get("relevant_destination")
                if src and dst and " " not in dst:
                    incident_edge_pairs.add((src, dst))

    # Aggregate communications by (src_ip, dst_ip)
    edge_group = df.groupby(["src_ip", "dst_ip"]).agg({
        "bytes_sent": "sum",
        "bytes_received": "sum",
        "record_id": "count",
        "protocol": "first"
    }).reset_index()

    edge_group["total_bytes"] = edge_group["bytes_sent"] + edge_group["bytes_received"]
    edge_group = edge_group.sort_values("total_bytes", ascending=False)
    high_volume_edges = edge_group.head(max_edges)
    incident_edges = edge_group[
        edge_group.apply(lambda row: (row["src_ip"], row["dst_ip"]) in incident_edge_pairs, axis=1)
    ]
    edge_group = pd.concat([high_volume_edges, incident_edges]).drop_duplicates(["src_ip", "dst_ip"])

    nodes_dict = {}
    edges_list = []

    def classify_role(ip: str) -> str:
        try:
            return "Private Address" if ipaddress.ip_address(ip).is_private else "Public Address"
        except ValueError:
            return "Unknown Address"

    for _, row in edge_group.iterrows():
        s = str(row["src_ip"])
        d = str(row["dst_ip"])
        conns = int(row["record_id"])
        vol = int(row["total_bytes"])
        proto = str(row["protocol"])

        # Node S
        if s not in nodes_dict:
            is_anom = s in anomalous_hosts
            nodes_dict[s] = {
                "data": {
                    "id": s,
                    "label": s,
                    "role": classify_role(s),
                    "is_anomalous": is_anom,
                    "type": "source"
                }
            }

        # Node D
        if d not in nodes_dict:
            is_anom = d in anomalous_hosts
            nodes_dict[d] = {
                "data": {
                    "id": d,
                    "label": d,
                    "role": classify_role(d),
                    "is_anomalous": is_anom,
                    "type": "destination"
                }
            }

        has_inc = (s, d) in incident_edge_pairs
        # Scale edge weight [1..8] based on volume
        weight = min(8, max(1, int(math.log(vol + 1, 10))))

        edges_list.append({
            "data": {
                "id": f"{s}_{d}",
                "source": s,
                "target": d,
                "protocol": proto,
                "connections": conns,
                "total_bytes": vol,
                "weight": weight,
                "has_incident": has_inc
            }
        })

    for host in anomalous_hosts:
        if host not in nodes_dict:
            nodes_dict[host] = {
                "data": {
                    "id": host,
                    "label": host,
                    "role": classify_role(host),
                    "is_anomalous": True,
                    "type": "incident"
                }
            }

    nodes_list = list(nodes_dict.values())

    return {
        "elements": {
            "nodes": nodes_list,
            "edges": edges_list
        },
        "summary": {
            "total_nodes": len(nodes_list),
            "total_edges": len(edges_list),
            "anomalous_nodes": len([n for n in nodes_list if n["data"]["is_anomalous"]]),
            "incident_edges": len([e for e in edges_list if e["data"]["has_incident"]])
        }
    }
