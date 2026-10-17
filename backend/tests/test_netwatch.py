import os
import io
import sys
import uuid
import pytest
import pandas as pd
from datetime import datetime, timedelta

# Ensure backend directory is in python module path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if "config" in sys.modules and not hasattr(sys.modules["config"], "load_settings"):
    del sys.modules["config"]

from fastapi.testclient import TestClient
try:
    from backend.config import load_settings, save_settings, validate_settings, DEFAULT_SETTINGS
    from backend.data_processor import (
        suggest_column_mapping,
        validate_and_process_csv,
        validate_temporal_separation,
        build_host_baseline,
        is_valid_ip
    )
    from backend.detection import (
        detect_anomalies,
        group_findings_into_incidents,
        calculate_incident_score,
        get_incident_severity
    )
    from backend.analytics import (
        get_traffic_over_time,
        get_protocol_distribution,
        get_top_talkers,
        get_host_analysis,
        get_port_analysis,
        get_dns_analysis,
        build_network_graph
    )
    from backend.auth import ADMIN_ROLE, ANALYST_ROLE, bootstrap_configured_accounts, create_account, configured_demo_accounts
    from backend.main import app, state
except ImportError:
    from config import load_settings, save_settings, validate_settings, DEFAULT_SETTINGS
    from data_processor import (
        suggest_column_mapping,
        validate_and_process_csv,
        validate_temporal_separation,
        build_host_baseline,
        is_valid_ip
    )
    from detection import (
        detect_anomalies,
        group_findings_into_incidents,
        calculate_incident_score,
        get_incident_severity
    )
    from analytics import (
        get_traffic_over_time,
        get_protocol_distribution,
        get_top_talkers,
        get_host_analysis,
        get_port_analysis,
        get_dns_analysis,
        build_network_graph
    )
    from auth import ADMIN_ROLE, ANALYST_ROLE, bootstrap_configured_accounts, create_account, configured_demo_accounts
    from main import app, state


@pytest.fixture
def client():
    state.reset()
    test_client = TestClient(app)
    email = f"netwatch-test-{uuid.uuid4().hex}@example.test"
    password = "Test-Suite-Password-2026!"
    create_account(email, password, ADMIN_ROLE)
    login_response = test_client.post("/api/auth/login", json={
        "email": email,
        "password": password
    })
    assert login_response.status_code == 200
    return test_client


def test_authentication_signup_login_and_protected_api():
    anonymous_client = TestClient(app)
    assert anonymous_client.get("/api/dashboard").status_code == 401
    email = f"auth-{uuid.uuid4().hex}@example.test"
    password = "Long-Enough-Test-Password-2035!"

    signup = anonymous_client.post("/api/auth/signup", json={"email": email, "password": password})
    assert signup.status_code == 201
    assert signup.json()["user"]["email"] == email
    assert "password" not in signup.json()["user"]
    assert anonymous_client.get("/api/dashboard").status_code == 401

    assert anonymous_client.post("/api/auth/login", json={
        "email": email,
        "password": "incorrect-password"
    }).status_code == 401
    login = anonymous_client.post("/api/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    assert "httponly" in login.headers["set-cookie"].lower()
    assert anonymous_client.get("/api/auth/session").json()["authenticated"] is True
    assert anonymous_client.get("/api/dashboard").status_code == 200
    assert anonymous_client.post("/api/auth/logout").status_code == 200
    assert anonymous_client.get("/api/dashboard").status_code == 401


def test_signup_rejects_weak_password():
    response = TestClient(app).post("/api/auth/signup", json={
        "email": f"weak-{uuid.uuid4().hex}@example.test",
        "password": "short"
    })
    assert response.status_code == 400
    assert "12 characters" in response.json()["detail"]


def test_role_permissions_enforced_for_admin_and_analyst():
    state.reset()
    admin_email = f"admin-{uuid.uuid4().hex}@example.test"
    admin_password = "Long-Enough-Admin-Password-2035!"
    analyst_email = f"analyst-{uuid.uuid4().hex}@example.test"
    analyst_password = "Long-Enough-Analyst-Password-2035!"
    create_account(admin_email, admin_password, ADMIN_ROLE)

    admin_client = TestClient(app)
    admin_login = admin_client.post("/api/auth/login", json={
        "email": admin_email,
        "password": admin_password
    })
    assert admin_login.status_code == 200
    assert "*" in admin_login.json()["user"]["permissions"]
    assert admin_client.get("/api/admin/users").status_code == 200
    assert admin_client.get("/api/admin/permissions").status_code == 200
    assert admin_client.get("/api/admin/audit").status_code == 200
    assert admin_client.get("/api/config").status_code == 200
    assert admin_client.get("/api/baseline").status_code == 200
    assert admin_client.post("/api/baseline/build", json={
        "learning_start": "2026-01-01",
        "learning_end": "2026-01-02"
    }).status_code == 400

    created = admin_client.post("/api/admin/users", json={
        "email": analyst_email,
        "password": analyst_password,
        "role": ANALYST_ROLE
    })
    assert created.status_code == 201
    analyst = created.json()["user"]
    assert analyst["role"] == ANALYST_ROLE
    assert "password" not in analyst

    analyst_client = TestClient(app)
    analyst_login = analyst_client.post("/api/auth/login", json={
        "email": analyst_email,
        "password": analyst_password
    })
    assert analyst_login.status_code == 200
    analyst_permissions = analyst_login.json()["user"]["permissions"]
    assert "incidents:manage" in analyst_permissions
    assert "baseline:view" in analyst_permissions
    assert "baseline:build" not in analyst_permissions
    assert analyst_client.get("/api/admin/users").status_code == 403
    assert analyst_client.get("/api/config").status_code == 403

    assert admin_client.patch(f"/api/admin/users/{analyst['id']}/role", json={
        "role": ADMIN_ROLE
    }).status_code == 200
    assert analyst_client.get("/api/admin/users").status_code == 200
    assert admin_client.patch(f"/api/admin/users/{analyst['id']}/role", json={
        "role": ANALYST_ROLE
    }).status_code == 200
    assert analyst_client.get("/api/admin/users").status_code == 403
    assert admin_client.patch(f"/api/admin/users/{analyst['id']}/role", json={
        "role": "unknown"
    }).status_code == 400
    assert admin_client.get("/api/admin/audit").json()["events"]

    assert analyst_client.get("/api/baseline").json()["available"] is False
    assert analyst_client.post("/api/baseline/build", json={
        "learning_start": "2026-01-01",
        "learning_end": "2026-01-02"
    }).status_code == 403
    assert analyst_client.patch("/api/incidents/unknown/status", json={
        "status": "resolved"
    }).status_code == 404
    assert admin_client.get("/api/not-a-real-endpoint").status_code == 403
    assert admin_client.get("/api/admin/users").json()["users"]


def test_demo_accounts_are_opt_in_and_environment_configured(monkeypatch, tmp_path):
    demo_admin_email = f"demo-admin-{uuid.uuid4().hex}@example.test"
    demo_analyst_email = f"demo-analyst-{uuid.uuid4().hex}@example.test"
    monkeypatch.setenv("NETWATCH_AUTH_DB", str(tmp_path / "demo-auth.sqlite3"))
    monkeypatch.setenv("NETWATCH_ENABLE_DEMO_ACCOUNTS", "true")
    monkeypatch.setenv("NETWATCH_DEMO_ADMIN_EMAIL", demo_admin_email)
    monkeypatch.setenv("NETWATCH_DEMO_ADMIN_PASSWORD", "Long-Enough-Demo-Admin-2035!")
    monkeypatch.setenv("NETWATCH_DEMO_ANALYST_EMAIL", demo_analyst_email)
    monkeypatch.setenv("NETWATCH_DEMO_ANALYST_PASSWORD", "Long-Enough-Demo-Analyst-2035!")

    bootstrap_configured_accounts()
    accounts = configured_demo_accounts()
    assert {account["role"] for account in accounts} == {ADMIN_ROLE, ANALYST_ROLE}
    assert {account["email"] for account in accounts} == {demo_admin_email, demo_analyst_email}
    response_accounts = TestClient(app).get("/api/auth/demo-accounts")
    assert response_accounts.status_code == 200
    assert {account["role"] for account in response_accounts.json()["accounts"]} == {ADMIN_ROLE, ANALYST_ROLE}

    monkeypatch.setenv("NETWATCH_ENABLE_DEMO_ACCOUNTS", "false")
    assert configured_demo_accounts() == []


# -----------------------------------------------------------------------------
# 1. CSV Upload and Column Mapping Tests
# -----------------------------------------------------------------------------
def test_suggest_column_mapping():
    cols = ["Source IP", "Destination IP", "Source Port", "Destination Port", "DateTime", "Bytes Sent", "Protocol"]
    mapping = suggest_column_mapping(cols)
    assert mapping["src_ip"] == "Source IP"
    assert mapping["dst_ip"] == "Destination IP"
    assert mapping["src_port"] == "Source Port"
    assert mapping["dst_port"] == "Destination Port"
    assert mapping["timestamp"] == "DateTime"
    assert mapping["bytes_sent"] == "Bytes Sent"
    assert mapping["protocol"] == "Protocol"


def test_zeek_schema_maps_to_canonical_fields_and_matches_default():
    profile = next(p for p in load_settings()["schema_profiles"] if p["id"] == "zeek_conn")
    raw = pd.DataFrame({
        "ts": ["2026-03-02 09:00:00"],
        "id.orig_h": ["192.168.1.40"],
        "id.resp_h": ["10.0.0.20"],
        "id.orig_p": [51000],
        "id.resp_p": [443],
        "proto": ["tcp"],
        "orig_bytes": [25000000],
        "resp_bytes": [800],
        "orig_pkts": [4],
        "duration": [1.5],
        "conn_state": ["SF"],
        "uid": ["C123"]
    })
    mapping = suggest_column_mapping(list(raw.columns), [profile])
    clean, quality = validate_and_process_csv(raw, mapping)

    assert quality["valid_records"] == 1
    assert clean.iloc[0][["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "bytes_sent"]].tolist() == [
        pd.Timestamp("2026-03-02 09:00:00"), "192.168.1.40", "10.0.0.20", 51000, 443, "TCP", 25000000
    ]
    canonical = pd.DataFrame({
        "timestamp": ["2026-03-02 09:00:00"], "src_ip": ["192.168.1.40"],
        "dst_ip": ["10.0.0.20"], "src_port": [51000], "dst_port": [443],
        "protocol": ["TCP"], "bytes_sent": [25000000], "bytes_received": [800],
        "packets": [4], "duration": [1.5], "action": ["SF"], "record_id": ["C123"]
    })
    canonical_clean, _ = validate_and_process_csv(canonical)
    baseline = {"host_baselines": {}, "all_observed_pairs": []}
    cfg = load_settings()
    zeek_findings = detect_anomalies(clean, baseline, cfg)
    canonical_findings = detect_anomalies(canonical_clean, baseline, cfg)
    assert [(f["rule_id"], f["affected_host"], f["supporting_record_ids"]) for f in zeek_findings] == [
        (f["rule_id"], f["affected_host"], f["supporting_record_ids"]) for f in canonical_findings
    ]
    assert "RULE_DATA_TRANSFER" in {finding["rule_id"] for finding in zeek_findings}


def test_zeek_tsv_upload_auto_maps_columns(client):
    contents = (
        "ts\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\torig_bytes\tresp_bytes\tuid\n"
        "2026-03-02 09:00:00\t192.168.1.40\t10.0.0.20\t51000\t443\ttcp\t25000000\t800\tC123\n"
    )
    response = client.post(
        "/api/upload",
        files={"file": ("zeek_conn.txt", contents.encode(), "text/plain")}
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["suggested_mapping"]["src_ip"] == "id.orig_h"
    assert payload["suggested_mapping"]["dst_ip"] == "id.resp_h"
    assert payload["auto_validated"] is True
    assert payload["quality_summary"]["valid_records"] == 1
    assert client.get("/api/health").json()["dataset_loaded"] is True
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["status"] == "ready"
    assert dashboard["valid_records"] == 1
    validation = client.post("/api/dataset/map-and-validate", json={"mapping": payload["suggested_mapping"]})
    assert validation.status_code == 200
    assert validation.json()["quality"]["valid_records"] == 1


def test_uploaded_custom_dataset_populates_dashboard_analysis(client):
    rows = []
    for index in range(12):
        rows.append({
            "timestamp": (datetime(2026, 10, 1, 8) + timedelta(minutes=index)).isoformat(),
            "src_ip": "203.0.113.10", "dst_ip": "203.0.113.20",
            "src_port": 50000 + index, "dst_port": 9443, "protocol": "TCP",
            "bytes_sent": 100, "bytes_received": 200, "packets": 2,
            "duration": 0.1, "dns_query": ""
        })
    for index in range(12):
        rows.append({
            "timestamp": (datetime(2026, 10, 2, 8) + timedelta(minutes=index)).isoformat(),
            "src_ip": "203.0.113.10", "dst_ip": "203.0.113.20",
            "src_port": 51000 + index, "dst_port": 9443, "protocol": "TCP",
            "bytes_sent": 25000000 if index == 11 else 100,
            "bytes_received": 200, "packets": 2, "duration": 0.1, "dns_query": ""
        })
    contents = pd.DataFrame(rows).to_csv(index=False).encode()

    response = client.post(
        "/api/upload",
        files={"file": ("custom_flows.csv", contents, "text/csv")}
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["auto_validated"] is True
    assert payload["auto_analysis"]["complete"] is True
    assert payload["auto_analysis"]["total_findings"] > 0
    dashboard = client.get("/api/dashboard").json()
    assert dashboard["dataset_name"] == "custom_flows.csv"
    assert dashboard["total_hosts"] == 2
    assert dashboard["valid_records"] == 24
    assert dashboard["total_findings"] > 0
    assert dashboard["total_incidents"] > 0
    assert dashboard["severity_score_thresholds"] == load_settings()["scoring"]["score_thresholds"]
    assert sum(dashboard["severity_distribution"].values()) == dashboard["total_incidents"]
    assert dashboard["top_ports"][0]["port"] == 9443
    host_comparison = client.get("/api/analytics/host/203.0.113.10").json()["behavior_comparison"]
    assert host_comparison["learning_window"]
    assert host_comparison["evaluation_window"]
    assert {metric["key"] for metric in host_comparison["metrics"]} >= {
        "connections_per_hour", "bytes_sent_per_hour", "failed_rate"
    }
    traffic = client.get("/api/analytics/traffic?interval=5").json()
    assert traffic["anomaly_markers"]
    assert sum(bucket["anomaly_count"] for bucket in traffic["time_series"]) > 0
    preview = client.get("/api/dataset/preview").json()
    assert preview["dataset_name"] == "custom_flows.csv"
    assert preview["quality_summary"]["valid_records"] == 24
    assert preview["auto_analysis"]["complete"] is True
    assert preview["auto_analysis"]["total_findings"] == dashboard["total_findings"]


def test_dashboard_stays_empty_until_valid_dataset_is_loaded(client):
    response = client.get("/api/dashboard")
    assert response.status_code == 200
    assert response.json()["status"] == "empty"
    assert "valid_records" not in response.json()


def test_time_range_recommends_disjoint_observed_periods(client):
    assert client.post("/api/sample/load").status_code == 200
    response = client.get("/api/dataset/time-range")
    assert response.status_code == 200
    data = response.json()
    assert data["split_available"] is True
    assert pd.Timestamp(data["suggested_learning_end"]) < pd.Timestamp(data["suggested_evaluation_start"])
    assert pd.Timestamp(data["min_timestamp"]) <= pd.Timestamp(data["suggested_learning_end"])
    assert pd.Timestamp(data["suggested_evaluation_start"]) <= pd.Timestamp(data["max_timestamp"])


def test_is_valid_ip():
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("10.0.0.254") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("invalid-ip") is False
    assert is_valid_ip("") is False
    assert is_valid_ip(None) is False


# -----------------------------------------------------------------------------
# 2. Invalid Records and Duplicate Handling
# -----------------------------------------------------------------------------
def test_data_validation_and_rejections():
    data = {
        "timestamp": ["2026-03-01 10:00:00", "invalid-date", "2026-03-01 10:02:00", "2026-03-01 10:02:00", "2026-03-01 10:03:00"],
        "src_ip": ["192.168.1.10", "192.168.1.10", "bad.ip.address", "192.168.1.10", "192.168.1.10"],
        "dst_ip": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.1"],
        "src_port": [50000, 50000, 50000, 50000, 70000],  # 70000 is invalid port > 65535
        "dst_port": [80, 80, 80, 80, -5],  # -5 is invalid port < 0
        "bytes_sent": [1000, 1000, 1000, 1000, -100],  # negative bytes
        "bytes_received": [2000, 2000, 2000, 2000, 2000],
        "protocol": ["TCP", "TCP", "TCP", "TCP", "TCP"]
    }
    raw_df = pd.DataFrame(data)
    clean_df, quality = validate_and_process_csv(raw_df)

    assert quality["total_records"] == 5
    # Row 0: valid
    # Row 1: invalid timestamp
    # Row 2: invalid IP
    # Row 3: duplicate of row 0/1/2? Has duplicate flag
    # Row 4: invalid ports and negative bytes
    assert quality["rejected_records"] >= 3
    assert quality["valid_records"] <= 2
    assert len(clean_df) == quality["valid_records"]


# -----------------------------------------------------------------------------
# 3. Temporal Separation & Baseline Creation
# -----------------------------------------------------------------------------
def test_temporal_separation():
    # Valid non-overlapping
    valid, msg = validate_temporal_separation(
        "2026-03-01 08:00:00", "2026-03-01 18:00:00",
        "2026-03-02 08:00:00", "2026-03-02 18:00:00"
    )
    assert valid is True

    # Invalid overlapping (leakage prevention)
    valid_overlap, msg = validate_temporal_separation(
        "2026-03-01 08:00:00", "2026-03-02 12:00:00",
        "2026-03-02 08:00:00", "2026-03-02 18:00:00"
    )
    assert valid_overlap is False
    assert "Overlap" in msg


def test_baseline_creation_insufficient_records():
    # Insufficient records warning/error
    small_df = pd.DataFrame({
        "record_id": [1, 2],
        "timestamp": [pd.to_datetime("2026-03-01 10:00:00"), pd.to_datetime("2026-03-01 11:00:00")],
        "src_ip": ["192.168.1.1", "192.168.1.1"],
        "dst_ip": ["10.0.0.1", "10.0.0.1"],
        "src_port": [50000, 50001],
        "dst_port": [80, 80],
        "bytes_sent": [1000, 1500],
        "bytes_received": [2000, 2500],
        "action": ["ALLOW", "ALLOW"],
        "dns_query": ["", ""]
    })
    baseline, err = build_host_baseline(small_df, "2026-03-01 08:00:00", "2026-03-01 18:00:00", min_records=10)
    assert baseline is None
    assert "Insufficient baseline records" in err


# -----------------------------------------------------------------------------
# 4. Detection Rules Tests (All 7 Rules)
# -----------------------------------------------------------------------------
def test_all_seven_detection_rules():
    cfg = load_settings()

    # Create dummy baseline
    baseline = {
        "learning_start": "2026-03-01 08:00:00",
        "learning_end": "2026-03-01 18:00:00",
        "hosts_profiled_count": 1,
        "host_baselines": {
            "192.168.1.50": {
                "conn_count": 20,
                "bytes_sent_mean": 5000.0,
                "bytes_sent_std": 1000.0,
                "bytes_sent_max": 8000,
                "distinct_dest_count": 2,
                "dns_query_count": 3,
                "failed_rate": 0.05
            }
        },
        "all_observed_pairs": ["192.168.1.50->10.0.0.1"]
    }

    # Evaluation dataframe with specific triggers
    now = datetime(2026, 3, 2, 9, 0, 0)
    flows = []
    r_id = 1

    # Rule A: Unusual Data Transfer (192.168.1.50 sends 25 MB)
    flows.append({
        "record_id": r_id, "timestamp": now, "src_ip": "192.168.1.50", "dst_ip": "10.0.0.1",
        "src_port": 50000, "dst_port": 443, "protocol": "TCP", "bytes_sent": 25000000, "bytes_received": 1000,
        "packets": 500, "duration": 10.0, "action": "ALLOW", "dns_query": "", "label": ""
    })
    r_id += 1

    # Rule B: Port Probing (contacts 20 distinct ports within 2 mins)
    for p in range(20):
        flows.append({
            "record_id": r_id, "timestamp": now + timedelta(seconds=p * 4), "src_ip": "192.168.1.60", "dst_ip": "10.0.0.5",
            "src_port": 51000 + p, "dst_port": 100 + p, "protocol": "TCP", "bytes_sent": 64, "bytes_received": 0,
            "packets": 1, "duration": 0.01, "action": "DENY", "dns_query": "", "label": ""
        })
        r_id += 1

    # Rule C: Destination Diversity (contacts 12 distinct destinations)
    for d in range(12):
        flows.append({
            "record_id": r_id, "timestamp": now + timedelta(seconds=d * 5), "src_ip": "192.168.1.70", "dst_ip": f"10.0.2.{d}",
            "src_port": 52000 + d, "dst_port": 80, "protocol": "TCP", "bytes_sent": 100, "bytes_received": 0,
            "packets": 1, "duration": 0.01, "action": "ALLOW", "dns_query": "", "label": ""
        })
        r_id += 1

    # Rule D: Periodic Beaconing (6 connections with exact 60s intervals)
    for b in range(6):
        flows.append({
            "record_id": r_id, "timestamp": now + timedelta(seconds=b * 60), "src_ip": "192.168.1.80", "dst_ip": "198.51.100.99",
            "src_port": 53000 + b, "dst_port": 8443, "protocol": "TCP", "bytes_sent": 200, "bytes_received": 200,
            "packets": 2, "duration": 0.1, "action": "ALLOW", "dns_query": "", "label": ""
        })
        r_id += 1

    # Rule E: Unexpected Host Communication (192.168.1.50 connects to new destination 10.0.0.99 on 3389)
    flows.append({
        "record_id": r_id, "timestamp": now + timedelta(minutes=10), "src_ip": "192.168.1.50", "dst_ip": "10.0.0.99",
        "src_port": 54000, "dst_port": 3389, "protocol": "TCP", "bytes_sent": 5000, "bytes_received": 5000,
        "packets": 10, "duration": 5.0, "action": "ALLOW", "dns_query": "", "label": ""
    })
    r_id += 1

    # Rule F: DNS Behaviour (16 distinct DGA queries)
    for q in range(16):
        flows.append({
            "record_id": r_id, "timestamp": now + timedelta(seconds=q * 2), "src_ip": "192.168.1.90", "dst_ip": "192.168.1.2",
            "src_port": 55000 + q, "dst_port": 53, "protocol": "UDP", "bytes_sent": 100, "bytes_received": 100,
            "packets": 2, "duration": 0.05, "action": "ALLOW", "dns_query": f"sub{q}.evil-domain.cc", "label": ""
        })
        r_id += 1

    # Rule G: Blocked or Failed Connections (8 consecutive DENY flows)
    for k in range(8):
        flows.append({
            "record_id": r_id, "timestamp": now + timedelta(seconds=k * 3), "src_ip": "192.168.1.95", "dst_ip": "10.0.0.20",
            "src_port": 56000 + k, "dst_port": 22, "protocol": "TCP", "bytes_sent": 100, "bytes_received": 0,
            "packets": 1, "duration": 0.02, "action": "DENY", "dns_query": "", "label": ""
        })
        r_id += 1

    eval_df = pd.DataFrame(flows)
    findings = detect_anomalies(eval_df, baseline, cfg)

    # Check each rule was triggered
    rule_ids = {f["rule_id"] for f in findings}
    assert "RULE_DATA_TRANSFER" in rule_ids
    assert "RULE_PORT_PROBE" in rule_ids
    assert "RULE_DEST_DIVERSITY" in rule_ids
    assert "RULE_BEACONING" in rule_ids
    assert "RULE_UNEXPECTED_COMM" in rule_ids
    assert "RULE_DNS_ANOMALY" in rule_ids
    assert "RULE_BLOCKED_CONNS" in rule_ids


# -----------------------------------------------------------------------------
# 5. Missing DNS and Outcome Fields Handling
# -----------------------------------------------------------------------------
def test_missing_dns_and_outcome_fields():
    cfg = load_settings()
    baseline = {
        "learning_start": "2026-03-01 08:00:00",
        "learning_end": "2026-03-01 18:00:00",
        "hosts_profiled_count": 0,
        "host_baselines": {},
        "all_observed_pairs": []
    }
    # Flow without DNS and without action
    flows = [{
        "record_id": 1, "timestamp": pd.to_datetime("2026-03-02 09:00:00"),
        "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 50000, "dst_port": 80,
        "protocol": "TCP", "bytes_sent": 1000, "bytes_received": 1000, "packets": 4, "duration": 1.0,
        "action": "", "dns_query": "", "label": ""
    }]
    eval_df = pd.DataFrame(flows)
    findings = detect_anomalies(eval_df, baseline, cfg)
    # Should not crash, and should not generate DNS or outcome findings
    assert "RULE_DNS_ANOMALY" not in {f["rule_id"] for f in findings}
    assert "RULE_BLOCKED_CONNS" not in {f["rule_id"] for f in findings}


def test_analytics_include_destination_hosts_dns_flows_and_nonempty_buckets():
    df = pd.DataFrame([
        {
            "record_id": 1, "timestamp": pd.Timestamp("2026-10-01 10:00:00"),
            "src_ip": "10.1.0.4", "dst_ip": "10.2.0.9", "src_port": 50123,
            "dst_port": 53, "protocol": "UDP", "bytes_sent": 700,
            "bytes_received": 100, "packets": 3, "dns_query": ""
        },
        {
            "record_id": 2, "timestamp": pd.Timestamp("2026-10-01 10:12:00"),
            "src_ip": "10.1.0.4", "dst_ip": "10.2.0.9", "src_port": 50124,
            "dst_port": 443, "protocol": "TCP", "bytes_sent": 200,
            "bytes_received": 400, "packets": 4, "dns_query": ""
        },
        {
            "record_id": 3, "timestamp": pd.Timestamp("2026-10-01 10:02:00"),
            "src_ip": "10.3.0.4", "dst_ip": "10.4.0.9", "src_port": 50125,
            "dst_port": 443, "protocol": "TCP", "bytes_sent": 10000,
            "bytes_received": 10000, "packets": 20, "dns_query": ""
        }
    ])

    host = get_host_analysis(df, "10.2.0.9")
    dns = get_dns_analysis(df)
    ports = get_port_analysis(df, host_filter="10.2.0.9")
    buckets = get_traffic_over_time(df, interval_minutes=5)
    graph = build_network_graph(df, [{
        "affected_hosts": ["10.1.0.4"],
        "findings": [{"affected_host": "10.1.0.4", "relevant_destination": "10.2.0.9"}]
    }], max_edges=1)

    assert host["incoming_connections"] == 2
    assert host["outgoing_connections"] == 0
    assert host["bytes_received"] == 900
    assert host["top_sources"] == [{"source": "10.1.0.4", "count": 2}]
    assert dns["available"] is True
    assert dns["domain_data_available"] is False
    assert dns["total_queries"] == 1
    assert dns["unique_domains"] is None
    assert ports["common_ports"][0]["port"] == 53
    assert len(buckets) == 2
    assert graph["summary"]["incident_edges"] == 1


def test_beacon_timeline_and_approved_periodic_false_positive():
    cfg = load_settings()
    for rule_name, rule_cfg in cfg["rules"].items():
        rule_cfg["enabled"] = rule_name == "periodic_connections"
    cfg["rules"]["periodic_connections"]["min_occurrences"] = 5
    start = datetime(2026, 10, 5, 10, 0)
    rows = []
    record_id = 1
    hosts = [
        ("203.0.113.80", "198.51.100.44", 8443),
        ("192.168.1.180", "192.168.1.50", 514)
    ]
    for source, destination, port in hosts:
        for index in range(6):
            rows.append({
                "record_id": record_id,
                "timestamp": start + timedelta(seconds=index * 60),
                "src_ip": source,
                "dst_ip": destination,
                "src_port": 50000 + record_id,
                "dst_port": port,
                "protocol": "TCP",
                "bytes_sent": 500,
                "bytes_received": 100,
                "packets": 4,
                "duration": 0.5,
                "action": "ALLOW",
                "dns_query": "",
                "label": ""
            })
            record_id += 1

    findings = detect_anomalies(
        pd.DataFrame(rows), {"host_baselines": {}, "all_observed_pairs": []}, cfg
    )
    suspicious = next(finding for finding in findings if finding["affected_host"] == "203.0.113.80")
    approved = next(finding for finding in findings if finding["affected_host"] == "192.168.1.180")
    assert suspicious["rule_id"] == "RULE_BEACONING"
    assert suspicious["is_suppressed"] is False
    assert suspicious["beaconing_metrics"]["coefficient_of_variation"] == 0
    assert [item["gap_seconds"] for item in suspicious["connection_timeline"]] == [None, 60, 60, 60, 60, 60]
    assert approved["is_suppressed"] is True
    assert approved["approved_activity_name"] == "Nightly Log Aggregation Agent"
    incidents = group_findings_into_incidents(findings, cfg)
    assert [incident["affected_hosts"] for incident in incidents] == [["203.0.113.80"]]
    assert incidents[0]["timeline"][0]["attack_stage"] == "Command and Control"


def test_sweep_lateral_detection_and_legitimate_activity_suppression():
    cfg = load_settings()
    cfg["rules"]["port_probing"]["enabled"] = False
    cfg["rules"]["destination_diversity"]["enabled"] = False
    cfg["rules"]["unusual_data_transfer"]["enabled"] = True
    cfg["rules"]["periodic_connections"]["enabled"] = False
    cfg["rules"]["unexpected_host_communication"]["enabled"] = False
    cfg["rules"]["dns_behaviour"]["enabled"] = False
    cfg["rules"]["blocked_failed_connections"]["enabled"] = False
    cfg["rules"]["network_sweep"]["distinct_host_threshold"] = 4
    cfg["rules"]["lateral_movement"]["min_lateral_hops"] = 3
    start = datetime(2026, 3, 2, 9, 0)
    rows = []
    for i in range(4):
        rows.append({
            "record_id": i + 1, "timestamp": start + timedelta(seconds=i * 5),
            "src_ip": "192.168.1.60", "dst_ip": f"10.0.1.{i + 1}",
            "src_port": 50000 + i, "dst_port": 80, "protocol": "TCP",
            "bytes_sent": 100, "bytes_received": 0, "packets": 1,
            "duration": 0.1, "action": "ALLOW", "dns_query": "", "label": ""
        })
    rows.append({
        "record_id": 12, "timestamp": start + timedelta(minutes=15),
        "src_ip": "192.168.1.99", "dst_ip": "10.0.0.50", "src_port": 53000,
        "dst_port": 445, "protocol": "TCP", "bytes_sent": 250000000,
        "bytes_received": 1000, "packets": 10000, "duration": 300.0,
        "action": "ALLOW", "dns_query": "", "label": ""
    })
    for i in range(3):
        rows.append({
            "record_id": i + 5, "timestamp": start + timedelta(minutes=5, seconds=i * 5),
            "src_ip": "192.168.1.70", "dst_ip": f"192.168.2.{i + 1}",
            "src_port": 51000 + i, "dst_port": 445, "protocol": "TCP",
            "bytes_sent": 100, "bytes_received": 0, "packets": 1,
            "duration": 0.1, "action": "ALLOW", "dns_query": "", "label": ""
        })
    for i in range(4):
        rows.append({
            "record_id": i + 8, "timestamp": start + timedelta(minutes=10, seconds=i * 5),
            "src_ip": "192.168.1.250", "dst_ip": f"10.0.2.{i + 1}",
            "src_port": 52000 + i, "dst_port": 80, "protocol": "TCP",
            "bytes_sent": 100, "bytes_received": 0, "packets": 1,
            "duration": 0.1, "action": "ALLOW", "dns_query": "", "label": ""
        })

    findings = detect_anomalies(pd.DataFrame(rows), {"host_baselines": {}, "all_observed_pairs": []}, cfg)
    by_rule = {finding["rule_id"]: finding for finding in findings}
    assert "RULE_NETWORK_SWEEP" in by_rule
    assert "RULE_LATERAL_MOVEMENT" in by_rule
    assert by_rule["RULE_NETWORK_SWEEP"]["is_suppressed"] is False
    assert by_rule["RULE_LATERAL_MOVEMENT"]["risk_score"] > 0
    scanner_finding = next(f for f in findings if f["affected_host"] == "192.168.1.250")
    assert scanner_finding["is_suppressed"] is True
    assert "Authorized Vulnerability Scanner" in scanner_finding["suppression_reason"]
    backup_finding = next(f for f in findings if f["affected_host"] == "192.168.1.99")
    assert backup_finding["rule_id"] == "RULE_DATA_TRANSFER"
    assert backup_finding["is_suppressed"] is True
    assert "Nightly Database Backup" in backup_finding["suppression_reason"]
    incidents = group_findings_into_incidents(findings, cfg)
    assert all("192.168.1.250" not in incident["affected_hosts"] for incident in incidents)
    assert all("192.168.1.99" not in incident["affected_hosts"] for incident in incidents)
    assert all(incident["timeline"] for incident in incidents)


# -----------------------------------------------------------------------------
# 6. Incident Grouping & Deterministic Scoring
# -----------------------------------------------------------------------------
def test_incident_grouping_and_scoring():
    cfg = load_settings()
    findings = [
        {
            "finding_id": "FND-0001",
            "rule_id": "RULE_PORT_PROBE",
            "rule_name": "Port Probing",
            "affected_host": "192.168.1.110",
            "relevant_destination": "10.0.0.1",
            "timestamp": "2026-03-02 10:00:00",
            "observed_value": "20 ports",
            "baseline_threshold": "15 ports",
            "severity": "High",
            "deviation_ratio": 2.0,
            "explanation": "Port scan",
            "supporting_record_ids": [1, 2, 3, 4],
            "is_approved_activity": False,
            "possible_benign_explanations": ["Scanner test"]
        },
        {
            "finding_id": "FND-0002",
            "rule_id": "RULE_BLOCKED_CONNS",
            "rule_name": "Blocked Connections",
            "affected_host": "192.168.1.110",
            "relevant_destination": "10.0.0.1",
            "timestamp": "2026-03-02 10:01:00",
            "observed_value": "10 denied",
            "baseline_threshold": "5 denied",
            "severity": "High",
            "deviation_ratio": 2.5,
            "explanation": "Failed conns",
            "supporting_record_ids": [5, 6, 7],
            "is_approved_activity": False,
            "possible_benign_explanations": ["Lockout"]
        }
    ]

    incidents = group_findings_into_incidents(findings, cfg)
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc["affected_hosts"] == ["192.168.1.110"]
    assert inc["findings_count"] == 2
    assert inc["score"] >= 65  # High score due to multi-rule high severity
    assert 0 <= inc["score"] <= 100
    assert "deterministic" in inc["score_explanation"].lower() or "score" in inc["score_explanation"].lower()
    assert inc["severity"] in ["High", "Critical"]
    assert len(inc["contributing_rules"]) == 2
    assert inc["score_breakdown"]["correlation_score"] > 0
    assert abs(
        sum(rule["weighted_points"] for rule in inc["contributing_rules"])
        - inc["score_breakdown"]["component_points"]["rule_priority"]
    ) < 0.02


def test_incident_score_uses_configured_rule_and_trusted_activity_weights():
    scoring = load_settings()["scoring"]
    findings = [{
        "rule_id": "RULE_PORT_PROBE",
        "rule_name": "Port Probing",
        "severity": "High",
        "deviation_ratio": 2.0,
        "supporting_record_ids": [1, 2],
    }]
    baseline_score, _, baseline_breakdown = calculate_incident_score(findings, scoring)

    correlated = findings + [{
        "rule_id": "RULE_BLOCKED_CONNS",
        "rule_name": "Blocked Connections",
        "severity": "High",
        "deviation_ratio": 2.5,
        "supporting_record_ids": [3, 4],
    }]
    correlated_score, _, correlated_breakdown = calculate_incident_score(correlated, scoring)
    assert correlated_score > baseline_score
    assert correlated_breakdown["correlation_score"] > baseline_breakdown["correlation_score"]
    assert {rule["rule_id"] for rule in correlated_breakdown["rule_contributions"]} == {
        "RULE_PORT_PROBE", "RULE_BLOCKED_CONNS"
    }

    adjusted = [dict(correlated[0], trusted_activity_adjustment_multiplier=0.5)] + correlated[1:]
    adjusted_score, _, adjusted_breakdown = calculate_incident_score(adjusted, scoring)
    assert adjusted_breakdown["trusted_activity_multiplier"] == 0.5
    assert adjusted_score == round(adjusted_breakdown["raw_weighted_total"] * 0.5)


def test_incident_severity_score_boundaries():
    thresholds = load_settings()["scoring"]["score_thresholds"]
    expected = {
        0: "Low", 35: "Low", 36: "Medium", 65: "Medium",
        66: "High", 85: "High", 86: "Critical", 100: "Critical"
    }
    assert {score: get_incident_severity(score, thresholds) for score in expected} == expected


def test_qualcomm_analysis_returns_verified_results_when_runtime_is_pending(client, monkeypatch):
    monkeypatch.delenv("QUALCOMM_GENIEX_BASE_URL", raising=False)
    monkeypatch.delenv("QUALCOMM_GENIEX_API_KEY", raising=False)
    assert client.post("/api/sample/load").status_code == 200
    incidents = client.get("/api/incidents").json()["incidents"]
    assert incidents
    incident = incidents[0]

    response = client.get(f"/api/incidents/{incident['incident_id']}/qualcomm-analysis")
    assert response.status_code == 200
    result = response.json()
    assert result["provider"] == "Qualcomm AI Hub / GenieX"
    assert result["integration_status"] == "pending"
    assert result["model"] == "ai-hub-models/Qwen3-4B-Instruct-2507"
    assert result["ai_assessment"] is None
    assert result["model_confidence"] is None
    assert result["verified_analysis"]["risk_assessment"]["score"] == incident["score"]
    assert result["verified_analysis"]["validation"]["checks"]["overall"] == "verified"
    assert result["verified_analysis"]["evidence"]["returned_record_count"] > 0

    response = client.post(f"/api/incidents/{incident['incident_id']}/qualcomm-analysis")
    assert response.status_code == 200
    assert response.json()["ai_assessment"] is None


def test_qualcomm_rejects_remote_runtime_urls(client, monkeypatch):
    monkeypatch.setenv("QUALCOMM_GENIEX_BASE_URL", "https://example.com/v1")
    assert client.post("/api/sample/load").status_code == 200
    incident = client.get("/api/incidents").json()["incidents"][0]
    result = client.get(f"/api/incidents/{incident['incident_id']}/qualcomm-analysis").json()
    assert result["integration_status"] == "unavailable"
    assert "loopback" in result["status_message"]
    assert result["ai_assessment"] is None


# -----------------------------------------------------------------------------
# 7. Configuration Validation
# -----------------------------------------------------------------------------
def test_configuration_validation():
    valid_cfg = DEFAULT_SETTINGS.copy()
    ok, msg = validate_settings(valid_cfg)
    assert ok is True

    # Bad weights
    bad_cfg = DEFAULT_SETTINGS.copy()
    bad_cfg["scoring"] = {"weights": {"severity": 0.9, "deviation": 0.9}}
    ok, msg = validate_settings(bad_cfg)
    assert ok is False


# -----------------------------------------------------------------------------
# 8. Full End-to-End API Integration & Exports
# -----------------------------------------------------------------------------
def test_api_sample_load_and_workflow(client):
    # 1. Health check
    res = client.get("/api/health")
    assert res.status_code == 200

    # 2. Load sample dataset
    res = client.post("/api/sample/load")
    assert res.status_code == 200
    data = res.json()
    assert data["total_raw_rows"] > 500
    assert data["quality_summary"]["valid_records"] > 500
    assert data["auto_analysis"]["complete"] is True
    assert data["auto_analysis"]["total_findings"] > 0
    loaded_dashboard = client.get("/api/dashboard").json()
    assert loaded_dashboard["analysis_complete"] is True
    assert loaded_dashboard["total_findings"] == data["auto_analysis"]["total_findings"]
    assert loaded_dashboard["total_incidents"] == data["auto_analysis"]["total_incidents"]
    assert sum(loaded_dashboard["severity_distribution"].values()) == loaded_dashboard["total_incidents"]
    traffic_result = client.get("/api/analytics/traffic?interval=5").json()
    assert traffic_result["anomaly_markers"]
    assert any(marker["is_suppressed"] for marker in traffic_result["anomaly_markers"])
    assert any(bucket["anomaly_count"] > 0 for bucket in traffic_result["time_series"])

    # 3. Get time range
    res = client.get("/api/dataset/time-range")
    assert res.status_code == 200
    tr = res.json()
    assert tr["available"] is True

    # 4. Build baseline (Day 1: 2026-03-01 08:00 to 18:00)
    res = client.post("/api/baseline/build", json={
        "learning_start": "2026-03-01 08:00:00",
        "learning_end": "2026-03-01 18:00:00",
        "min_records": 10
    })
    assert res.status_code == 200
    b_res = res.json()
    assert b_res["success"] is True
    assert b_res["baseline_summary"]["hosts_profiled_count"] > 5

    # 5. Overlapping analysis rejection
    res = client.post("/api/analysis/run", json={
        "eval_start": "2026-03-01 12:00:00",
        "eval_end": "2026-03-02 12:00:00"
    })
    assert res.status_code == 400
    assert "Overlap" in res.json()["detail"]

    # 6. Valid Evaluation Analysis (Day 2: 2026-03-02 08:00 to 18:00)
    res = client.post("/api/analysis/run", json={
        "eval_start": "2026-03-02 08:00:00",
        "eval_end": "2026-03-02 18:00:00"
    })
    assert res.status_code == 200
    an_res = res.json()
    assert an_res["total_findings"] > 0
    assert an_res["total_incidents"] > 0

    # 7. Dashboard check
    res = client.get("/api/dashboard")
    assert res.status_code == 200
    dash = res.json()
    assert dash["status"] == "ready"
    assert dash["total_findings"] > 0
    assert dash["total_incidents"] > 0

    # 8. Network Graph check
    res = client.get("/api/graph")
    assert res.status_code == 200
    graph = res.json()
    assert len(graph["elements"]["nodes"]) > 0

    # 9. Incidents and Evidence check
    res = client.get("/api/incidents")
    assert res.status_code == 200
    incs = res.json()["incidents"]
    assert len(incs) > 0
    first_inc_id = incs[0]["incident_id"]
    assert incs[0]["status"] == "open"
    status_update = client.patch(f"/api/incidents/{first_inc_id}/status", json={"status": "acknowledged"})
    assert status_update.status_code == 200
    assert client.get(f"/api/incidents/{first_inc_id}").json()["status"] == "acknowledged"
    assert client.patch(f"/api/incidents/{first_inc_id}/status", json={"status": "invalid"}).status_code == 400
    incident_export = client.get("/api/export/incidents")
    assert "Status" in incident_export.text
    assert "acknowledged" in incident_export.text

    res = client.get(f"/api/incidents/{first_inc_id}")
    assert res.status_code == 200
    incident_detail = res.json()
    assert incident_detail["timeline"]
    assert all(event.get("attack_stage") for event in incident_detail["timeline"])
    assert incident_detail["attack_stages"]

    res = client.get(f"/api/incidents/{first_inc_id}/evidence")
    assert res.status_code == 200
    assert len(res.json()["records"]) > 0

    res = client.get(f"/api/incidents/{first_inc_id}/graph")
    assert res.status_code == 200
    assert res.json()["incident_id"] == first_inc_id
    assert len(res.json()["elements"]["nodes"]) > 0
    assert len(res.json()["elements"]["edges"]) > 0
    assert res.json()["summary"]["incident_edges"] > 0

    # 10. AI / Rule explanation
    res = client.post(f"/api/incidents/{first_inc_id}/ai-explain")
    assert res.status_code == 200
    ai_data = res.json()
    assert "explanation" in ai_data
    assert len(ai_data["explanation"]) > 20

    # 11. Exports check (CSV & HTML)
    for endpoint in ["/api/export/findings", "/api/export/incidents", "/api/export/evidence", "/api/export/hosts", "/api/export/ports", "/api/export/data-quality"]:
        r = client.get(endpoint)
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]

    r_html = client.get("/api/export/report-html")
    assert r_html.status_code == 200
    assert "text/html" in r_html.headers["content-type"]
    assert "NETWATCH SECURITY INVESTIGATION REPORT" in r_html.text
