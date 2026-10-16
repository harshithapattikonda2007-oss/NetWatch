import io
import os
import csv
import html
import json
import httpx
import pandas as pd
from urllib.parse import urlsplit
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import sys
import os

# Ensure backend directory is at the front of sys.path
backend_dir = os.path.dirname(os.path.abspath(__file__))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Evict root-level 'config' namespace package from sys.modules if present
if "config" in sys.modules and not hasattr(sys.modules["config"], "load_settings"):
    del sys.modules["config"]

try:
    from .config import load_settings, save_settings, validate_settings
    from .data_processor import (
        suggest_column_mapping,
        validate_and_process_csv,
        validate_temporal_separation,
        build_host_baseline
    )
    from .detection import (
        detect_anomalies,
        group_findings_into_incidents
    )
    from .analytics import (
        get_traffic_over_time,
        get_protocol_distribution,
        get_top_talkers,
        get_host_analysis,
        get_port_analysis,
        get_dns_analysis,
        build_network_graph
    )
except ImportError:
    try:
        from backend.config import load_settings, save_settings, validate_settings
        from backend.data_processor import (
            suggest_column_mapping,
            validate_and_process_csv,
            validate_temporal_separation,
            build_host_baseline
        )
        from backend.detection import (
            detect_anomalies,
            group_findings_into_incidents
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
    except ImportError:
        from config import load_settings, save_settings, validate_settings
        from data_processor import (
            suggest_column_mapping,
            validate_and_process_csv,
            validate_temporal_separation,
            build_host_baseline
        )
        from detection import (
            detect_anomalies,
            group_findings_into_incidents
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

app = FastAPI(
    title="NetWatch API",
    description="Network Traffic Anomaly Detection & Incident Investigation Engine",
    version="1.0.0"
)

# Enable CORS for local Vite dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# In-Memory State for Active Investigation Session
class ApplicationState:
    def __init__(self):
        self.raw_df: Optional[pd.DataFrame] = None
        self.clean_df: Optional[pd.DataFrame] = None
        self.dataset_name: str = "None"
        self.column_mapping: Dict[str, Optional[str]] = {}
        self.quality_summary: Dict[str, Any] = {}
        self.baseline: Optional[Dict[str, Any]] = None
        self.findings: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []
        self.analysis_complete: bool = False
        self.analysis_message: Optional[str] = None
        self.evaluation_records: int = 0
        self.eval_start: Optional[str] = None
        self.eval_end: Optional[str] = None
        self.last_analysis_time: Optional[str] = None

    def reset(self):
        self.__init__()


state = ApplicationState()


def run_automatic_analysis() -> Dict[str, Any]:
    """Run a first-pass analysis using disjoint chronological halves of the active dataset."""
    state.baseline = None
    state.findings = []
    state.incidents = []
    state.analysis_complete = False
    state.analysis_message = None
    state.evaluation_records = 0
    state.eval_start = None
    state.eval_end = None

    if state.clean_df is None or state.clean_df.empty:
        state.analysis_message = "No valid records are available for analysis."
        return {"complete": False, "message": state.analysis_message}

    timestamps = state.clean_df["timestamp"].drop_duplicates().sort_values().reset_index(drop=True)
    if len(timestamps) < 2:
        state.analysis_message = "Automatic detection needs at least two distinct timestamps."
        return {"complete": False, "message": state.analysis_message}

    split_index = len(timestamps) // 2
    learning_start = str(timestamps.iloc[0])
    learning_end = str(timestamps.iloc[split_index - 1])
    eval_start = str(timestamps.iloc[split_index])
    eval_end = str(timestamps.iloc[-1])

    cfg = load_settings()
    min_records = int(cfg.get("baseline", {}).get("min_records", 10))
    baseline, error = build_host_baseline(
        state.clean_df, learning_start, learning_end, min_records
    )
    if error:
        state.analysis_message = error
        return {"complete": False, "message": error}

    eval_df = state.clean_df[
        (state.clean_df["timestamp"] >= pd.to_datetime(eval_start))
        & (state.clean_df["timestamp"] <= pd.to_datetime(eval_end))
    ].copy()
    if eval_df.empty:
        state.analysis_message = "No records fall in the automatic evaluation period."
        return {"complete": False, "message": state.analysis_message}

    state.baseline = baseline
    state.findings = detect_anomalies(eval_df, baseline, cfg)
    state.incidents = group_findings_into_incidents(state.findings, cfg)
    state.analysis_complete = True
    state.analysis_message = "Automatic analysis used separate chronological learning and evaluation periods."
    state.evaluation_records = len(eval_df)
    state.eval_start = eval_start
    state.eval_end = eval_end
    state.last_analysis_time = datetime.now().isoformat()
    return {
        "complete": True,
        "message": state.analysis_message,
        "learning_start": learning_start,
        "learning_end": learning_end,
        "evaluation_start": eval_start,
        "evaluation_end": eval_end,
        "evaluation_records": len(eval_df),
        "total_findings": len(state.findings),
        "total_incidents": len(state.incidents)
    }


def sanitize_csv_cell(value: Any) -> Any:
    """Protects CSV cells against Formula Injection (CSV Injection / DDE)."""
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in ("=", "+", "-", "@", "\t", "\r"):
            return f"'{value}"
    return value


# -----------------------------------------------------------------------------
# Request Schemas
# -----------------------------------------------------------------------------
class MappingRequest(BaseModel):
    mapping: Dict[str, Optional[str]]


class BaselineRequest(BaseModel):
    learning_start: str
    learning_end: str
    min_records: Optional[int] = None


class AnalysisRequest(BaseModel):
    eval_start: str
    eval_end: str


# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "app": "NetWatch",
        "timestamp": datetime.now().isoformat(),
        "dataset_loaded": state.clean_df is not None and not state.clean_df.empty,
        "dataset_name": state.dataset_name if state.clean_df is not None and not state.clean_df.empty else None,
        "valid_records": len(state.clean_df) if state.clean_df is not None else 0,
        "baseline_ready": state.baseline is not None,
        "analysis_ready": state.analysis_complete
    }


@app.post("/api/upload")
async def upload_dataset(file: UploadFile = File(...)):
    """Uploads user CSV, previews records, and provides suggested column mappings."""
    cfg = load_settings()
    max_mb = cfg.get("upload", {}).get("max_file_size_mb", 50)
    
    contents = await file.read()
    if len(contents) > max_mb * 1024 * 1024:
        raise HTTPException(status_code=400, detail=f"File exceeds maximum upload size of {max_mb} MB")

    try:
        df_raw = pd.read_csv(io.BytesIO(contents), sep=None, engine="python")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV file: {str(e)}")

    if df_raw.empty:
        raise HTTPException(status_code=400, detail="Uploaded CSV file contains no records")

    state.reset()
    state.raw_df = df_raw
    state.dataset_name = file.filename or "uploaded_dataset.csv"
    state.column_mapping = suggest_column_mapping(
        list(df_raw.columns), cfg.get("schema_profiles", [])
    )

    auto_validated = False
    mapping_error = None
    if all(state.column_mapping.get(field) for field in ("timestamp", "src_ip", "dst_ip")):
        try:
            clean_df, quality = validate_and_process_csv(df_raw, state.column_mapping)
            state.clean_df = clean_df
            state.quality_summary = quality
            auto_validated = True
        except (ValueError, KeyError) as e:
            mapping_error = str(e)

    auto_analysis = run_automatic_analysis() if auto_validated else {
        "complete": False,
        "message": mapping_error or "Map the timestamp, source IP, and destination IP columns to analyze this dataset."
    }

    preview_rows = df_raw.head(10).fillna("").to_dict(orient="records")

    return {
        "dataset_name": state.dataset_name,
        "total_raw_rows": len(df_raw),
        "columns": list(df_raw.columns),
        "suggested_mapping": state.column_mapping,
        "auto_validated": auto_validated,
        "quality_summary": state.quality_summary if auto_validated else None,
        "auto_analysis": auto_analysis,
        "mapping_error": mapping_error,
        "preview": preview_rows
    }


@app.post("/api/sample/load")
def load_sample_dataset():
    """Loads the pre-generated realistic synthetic sample dataset."""
    sample_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "sample_network_flows.csv")
    if not os.path.exists(sample_path):
        raise HTTPException(status_code=404, detail="Sample dataset file not found at data/sample_network_flows.csv")

    try:
        df_raw = pd.read_csv(sample_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading sample dataset: {str(e)}")

    state.reset()
    state.raw_df = df_raw
    state.dataset_name = "sample_network_flows.csv"
    state.column_mapping = suggest_column_mapping(
        list(df_raw.columns), load_settings().get("schema_profiles", [])
    )

    # Automatically validate with standard mappings
    clean_df, quality = validate_and_process_csv(df_raw, state.column_mapping)
    state.clean_df = clean_df
    state.quality_summary = quality
    auto_analysis = run_automatic_analysis()

    preview_rows = df_raw.head(10).fillna("").to_dict(orient="records")

    return {
        "dataset_name": state.dataset_name,
        "total_raw_rows": len(df_raw),
        "columns": list(df_raw.columns),
        "suggested_mapping": state.column_mapping,
        "preview": preview_rows,
        "quality_summary": quality,
        "auto_analysis": auto_analysis
    }


@app.get("/api/dataset/preview")
def get_dataset_preview():
    if state.raw_df is None:
        return {"loaded": False, "message": "No dataset currently loaded"}

    return {
        "loaded": True,
        "dataset_name": state.dataset_name,
        "total_raw_rows": len(state.raw_df),
        "columns": list(state.raw_df.columns),
        "suggested_mapping": state.column_mapping,
        "auto_validated": state.clean_df is not None and not state.clean_df.empty,
        "quality_summary": state.quality_summary or None,
        "analysis_complete": state.analysis_complete,
        "analysis_message": state.analysis_message,
        "auto_analysis": {
            "complete": state.analysis_complete,
            "message": state.analysis_message,
            "evaluation_records": state.evaluation_records,
            "total_findings": len(state.findings),
            "total_incidents": len(state.incidents)
        },
        "preview": state.raw_df.head(10).fillna("").to_dict(orient="records")
    }


@app.post("/api/dataset/map-and-validate")
def map_and_validate(req: MappingRequest):
    """Applies user-selected column mappings and performs rigorous validation."""
    if state.raw_df is None:
        raise HTTPException(status_code=400, detail="No dataset uploaded to validate")

    try:
        clean_df, quality = validate_and_process_csv(state.raw_df, req.mapping)
        state.clean_df = clean_df
        state.column_mapping = req.mapping
        state.quality_summary = quality
        auto_analysis = run_automatic_analysis()

        return {
            "success": True,
            "quality": quality,
            "auto_analysis": auto_analysis,
            "columns_mapped": req.mapping
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/data-quality")
def get_data_quality():
    if not state.quality_summary:
        return {"loaded": False, "message": "No validation data available"}
    return state.quality_summary


@app.get("/api/dataset/time-range")
def get_time_range():
    if state.clean_df is None or state.clean_df.empty:
        return {"available": False, "message": "No valid dataset available"}

    min_ts = str(state.clean_df["timestamp"].min())
    max_ts = str(state.clean_df["timestamp"].max())
    total_valid = len(state.clean_df)

    # Split at distinct observed timestamps so inclusive filters cannot share records.
    timestamps = state.clean_df["timestamp"].drop_duplicates().sort_values().reset_index(drop=True)
    split_index = len(timestamps) // 2
    split_available = len(timestamps) >= 2
    learning_end = str(timestamps.iloc[split_index - 1]) if split_available else None
    evaluation_start = str(timestamps.iloc[split_index]) if split_available else None
    midpoint_ts = str(timestamps.iloc[split_index]) if split_available else str(timestamps.iloc[0])

    return {
        "available": True,
        "min_timestamp": min_ts,
        "max_timestamp": max_ts,
        "total_records": total_valid,
        "suggested_midpoint": midpoint_ts,
        "split_available": split_available,
        "suggested_learning_end": learning_end,
        "suggested_evaluation_start": evaluation_start
    }


@app.post("/api/baseline/build")
def build_baseline(req: BaselineRequest):
    """Builds historical normal behavioral baseline for hosts."""
    if state.clean_df is None or state.clean_df.empty:
        raise HTTPException(status_code=400, detail="No validated dataset loaded")

    cfg = load_settings()
    min_rec = req.min_records or cfg.get("baseline", {}).get("min_records", 10)

    baseline_data, err = build_host_baseline(state.clean_df, req.learning_start, req.learning_end, min_rec)
    if err:
        raise HTTPException(status_code=400, detail=err)

    state.baseline = baseline_data
    state.findings = []
    state.incidents = []
    state.analysis_complete = False
    state.analysis_message = "Baseline updated. Run evaluation to refresh anomaly findings."
    state.evaluation_records = 0
    state.eval_start = None
    state.eval_end = None
    return {
        "success": True,
        "message": f"Successfully built baseline for {baseline_data['hosts_profiled_count']} hosts",
        "baseline_summary": {
            "learning_start": baseline_data["learning_start"],
            "learning_end": baseline_data["learning_end"],
            "learning_records_count": baseline_data["learning_records_count"],
            "hosts_profiled_count": baseline_data["hosts_profiled_count"],
            "created_at": baseline_data["created_at"]
        }
    }


@app.post("/api/analysis/run")
def run_analysis(req: AnalysisRequest):
    """
    Validates temporal separation, executes detection engine on evaluation records,
    groups findings into incidents, and computes investigation priority scores.
    """
    if state.clean_df is None or state.clean_df.empty:
        raise HTTPException(status_code=400, detail="No validated dataset loaded")

    if state.baseline is None:
        raise HTTPException(status_code=400, detail="Baseline must be established before running evaluation")

    # Critical requirement: strictly reject overlapping learning and evaluation periods
    is_valid, sep_msg = validate_temporal_separation(
        state.baseline["learning_start"],
        state.baseline["learning_end"],
        req.eval_start,
        req.eval_end
    )
    if not is_valid:
        raise HTTPException(status_code=400, detail=sep_msg)

    # Filter evaluation dataset
    e_start = pd.to_datetime(req.eval_start)
    e_end = pd.to_datetime(req.eval_end)
    eval_df = state.clean_df[(state.clean_df["timestamp"] >= e_start) & (state.clean_df["timestamp"] <= e_end)].copy()

    if eval_df.empty:
        raise HTTPException(status_code=400, detail=f"No records found within evaluation window {req.eval_start} to {req.eval_end}")

    cfg = load_settings()

    findings = detect_anomalies(eval_df, state.baseline, cfg)
    incidents = group_findings_into_incidents(findings, cfg)

    state.findings = findings
    state.incidents = incidents
    state.analysis_complete = True
    state.analysis_message = "Analysis completed for the selected evaluation period."
    state.evaluation_records = len(eval_df)
    state.eval_start = req.eval_start
    state.eval_end = req.eval_end
    state.last_analysis_time = datetime.now().isoformat()

    return {
        "success": True,
        "evaluation_records": len(eval_df),
        "total_findings": len(findings),
        "total_incidents": len(incidents),
        "incidents": incidents
    }


@app.get("/api/dashboard")
def get_dashboard_metrics():
    """Returns actual aggregated dashboard statistics."""
    if state.clean_df is None or state.clean_df.empty:
        return {
            "status": "empty",
            "message": "Upload or load a dataset to view metrics"
        }

    total_hosts = len(set(state.clean_df["src_ip"].dropna()) | set(state.clean_df["dst_ip"].dropna()))
    total_valid = len(state.clean_df)
    rejected = state.quality_summary.get("rejected_records", 0)
    total_findings = len(state.findings)
    total_incidents = len(state.incidents)
    scoring_cfg = load_settings().get("scoring", {})
    score_thresholds = scoring_cfg.get("score_thresholds", {
        "Low": 35,
        "Medium": 65,
        "High": 85,
        "Critical": 100
    })

    # Severity distribution of incidents
    sev_dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for inc in state.incidents:
        sev = inc.get("severity", "Medium")
        sev_dist[sev] = sev_dist.get(sev, 0) + 1

    # Active dataset flows
    traffic_series = get_traffic_over_time(state.clean_df, interval_minutes=15)
    top_talkers = get_top_talkers(state.clean_df, limit=5)
    port_data = get_port_analysis(state.clean_df)

    return {
        "status": "ready",
        "dataset_name": state.dataset_name,
        "total_hosts": total_hosts,
        "valid_records": total_valid,
        "rejected_records": rejected,
        "total_findings": total_findings,
        "total_incidents": total_incidents,
        "analysis_complete": state.analysis_complete,
        "analysis_message": state.analysis_message,
        "evaluation_records": state.evaluation_records,
        "evaluation_start": state.eval_start,
        "evaluation_end": state.eval_end,
        "severity_distribution": sev_dist,
        "severity_score_thresholds": score_thresholds,
        "traffic_overview": traffic_series[:24],
        "top_talkers": top_talkers,
        "top_ports": port_data.get("common_ports", [])[:5],
        "recent_incidents": state.incidents[:5],
        "baseline_ready": state.baseline is not None,
        "analysis_ready": state.analysis_complete
    }


@app.get("/api/analytics/traffic")
def get_traffic_analytics(interval: int = Query(5, description="Interval in minutes (1, 5, 60)")):
    if state.clean_df is None or state.clean_df.empty:
        return {"data": [], "protocols": []}

    traffic = get_traffic_over_time(state.clean_df, interval_minutes=interval)
    protocols = get_protocol_distribution(state.clean_df)
    talkers = get_top_talkers(state.clean_df, limit=10)
    bucket_findings: Dict[str, List[Dict[str, Any]]] = {}
    for finding in state.findings:
        try:
            bucket_time = pd.to_datetime(finding["timestamp"]).floor(f"{interval}min")
        except (KeyError, TypeError, ValueError):
            continue
        bucket_key = str(bucket_time)
        bucket_findings.setdefault(bucket_key, []).append(finding)

    for bucket in traffic:
        matching_findings = bucket_findings.get(bucket["timestamp"], [])
        bucket["anomaly_count"] = sum(not finding.get("is_suppressed", False) for finding in matching_findings)
        bucket["approved_activity_count"] = sum(finding.get("is_suppressed", False) for finding in matching_findings)
        bucket["anomaly_rules"] = sorted({finding.get("rule_name", "Anomaly") for finding in matching_findings})

    return {
        "interval_minutes": interval,
        "time_series": traffic,
        "protocols": protocols,
        "top_talkers": talkers,
        "anomaly_markers": [
            {
                "timestamp": finding.get("timestamp"),
                "finding_id": finding.get("finding_id"),
                "rule_id": finding.get("rule_id"),
                "rule_name": finding.get("rule_name"),
                "affected_host": finding.get("affected_host"),
                "observed_value": finding.get("observed_value"),
                "baseline_threshold": finding.get("baseline_threshold"),
                "explanation": finding.get("explanation"),
                "risk_score": finding.get("risk_score"),
                "is_suppressed": finding.get("is_suppressed", False),
                "suppression_reason": finding.get("suppression_reason")
            }
            for finding in state.findings
        ]
    }


@app.get("/api/analytics/hosts")
def get_all_hosts():
    if state.clean_df is None or state.clean_df.empty:
        return {"hosts": []}

    hosts = sorted(set(state.clean_df["src_ip"].dropna()) | set(state.clean_df["dst_ip"].dropna()))
    return {"hosts": hosts}


@app.get("/api/analytics/host/{host_ip}")
def get_individual_host_analysis(host_ip: str):
    if state.clean_df is None or state.clean_df.empty:
        raise HTTPException(status_code=400, detail="No dataset loaded")

    observed_df = state.clean_df
    if state.eval_start and state.eval_end:
        observed_df = state.clean_df[
            (state.clean_df["timestamp"] >= pd.to_datetime(state.eval_start))
            & (state.clean_df["timestamp"] <= pd.to_datetime(state.eval_end))
        ].copy()
    result = get_host_analysis(
        state.clean_df, host_ip, state.baseline, state.incidents, observed_df
    )
    return result


@app.get("/api/analytics/ports")
def get_ports_analytics(
    host: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None)
):
    if state.clean_df is None or state.clean_df.empty:
        return {"common_ports": [], "heatmap_matrix": []}

    return get_port_analysis(state.clean_df, host_filter=host, protocol_filter=protocol)


@app.get("/api/analytics/dns")
def get_dns_report():
    if state.clean_df is None or state.clean_df.empty:
        return {"available": False, "message": "No dataset loaded"}

    return get_dns_analysis(state.clean_df)


@app.get("/api/graph")
def get_network_graph():
    if state.clean_df is None or state.clean_df.empty:
        return {"elements": {"nodes": [], "edges": []}, "summary": {"total_nodes": 0, "total_edges": 0}}

    return build_network_graph(state.clean_df, state.incidents)


@app.get("/api/incidents")
def get_incidents_list(severity: Optional[str] = Query(None)):
    if not state.incidents:
        return {"incidents": []}

    if severity:
        filtered = [inc for inc in state.incidents if inc.get("severity") == severity]
        return {"incidents": filtered}

    return {"incidents": state.incidents}


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    for inc in state.incidents:
        if inc["incident_id"] == incident_id:
            return inc
    raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")


@app.get("/api/incidents/{incident_id}/evidence")
def get_incident_evidence(incident_id: str):
    incident = None
    for inc in state.incidents:
        if inc["incident_id"] == incident_id:
            incident = inc
            break

    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    rec_ids = incident.get("supporting_record_ids", [])
    if state.clean_df is None or not rec_ids:
        return {"records": []}

    evidence_df = state.clean_df[state.clean_df["record_id"].isin(rec_ids)].copy()
    records = evidence_df.to_dict(orient="records")
    for r in records:
        if pd.notna(r["timestamp"]):
            r["timestamp"] = str(r["timestamp"])

    return {
        "incident_id": incident_id,
        "total_evidence_records": len(records),
        "records": records
    }


@app.get("/api/incidents/{incident_id}/graph")
def get_incident_graph(incident_id: str):
    incident = next((item for item in state.incidents if item["incident_id"] == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    if state.clean_df is None or state.clean_df.empty:
        return {"incident_id": incident_id, "elements": {"nodes": [], "edges": []}, "summary": {}}

    evidence_ids = set(incident.get("supporting_record_ids", []))
    evidence_df = state.clean_df[state.clean_df["record_id"].isin(evidence_ids)].copy()
    graph = build_network_graph(evidence_df, [incident], max_edges=max(len(evidence_df), 1))
    return {"incident_id": incident_id, **graph}


@app.get("/api/findings")
def get_findings_list(host: Optional[str] = Query(None)):
    if host:
        return {"findings": [f for f in state.findings if f.get("affected_host") == host]}
    return {"findings": state.findings}


@app.get("/api/config")
def get_configuration():
    return load_settings()


@app.put("/api/config")
def update_configuration(new_settings: Dict[str, Any]):
    success, msg = save_settings(new_settings)
    if not success:
        raise HTTPException(status_code=400, detail=msg)
    return {"success": True, "message": msg, "settings": new_settings}


QUALCOMM_DEFAULT_MODEL = "ai-hub-models/Qwen3-4B-Instruct-2507"


def _qualcomm_runtime_settings() -> Dict[str, str]:
    return {
        "base_url": os.getenv("QUALCOMM_GENIEX_BASE_URL", "").strip().rstrip("/"),
        "model": os.getenv("QUALCOMM_GENIEX_MODEL", QUALCOMM_DEFAULT_MODEL).strip(),
        "api_key": os.getenv("QUALCOMM_GENIEX_API_KEY", "").strip()
    }


def _verified_incident_analysis(incident: Dict[str, Any]) -> Dict[str, Any]:
    findings = incident.get("findings", [])
    expected_record_ids = set(incident.get("supporting_record_ids", []))
    if state.clean_df is None:
        evidence_df = pd.DataFrame()
    else:
        evidence_df = state.clean_df[state.clean_df["record_id"].isin(expected_record_ids)].copy()

    found_record_ids = set(evidence_df["record_id"].tolist()) if not evidence_df.empty else set()
    evidence_rows = evidence_df.head(50).to_dict(orient="records")
    for row in evidence_rows:
        if pd.notna(row.get("timestamp")):
            row["timestamp"] = str(row["timestamp"])

    breakdown = incident.get("score_breakdown", {})
    component_points = breakdown.get("component_points", {})
    raw_points = sum(float(value) for value in component_points.values())
    trust_multiplier = float(breakdown.get("trusted_activity_multiplier", 1.0))
    recomputed_score = int(round(min(100.0, max(0.0, raw_points * trust_multiplier))))
    finding_rule_ids = {finding.get("rule_id") for finding in findings}
    contributing_rule_ids = {
        rule.get("rule_id") for rule in incident.get("contributing_rules", [])
    }
    related_hosts = set(incident.get("affected_hosts", []))
    suppressed_host_findings = [
        finding for finding in state.findings
        if finding.get("affected_host") in related_hosts and finding.get("is_suppressed")
    ]

    checks = {
        "risk_score_matches_breakdown": recomputed_score == incident.get("score"),
        "supporting_records_present": expected_record_ids.issubset(found_record_ids),
        "contributing_rules_have_findings": contributing_rule_ids.issubset(finding_rule_ids)
    }
    checks["overall"] = "verified" if all(checks.values()) else "review_required"

    return {
        "incident_id": incident["incident_id"],
        "risk_assessment": {
            "score": incident.get("score"),
            "severity": incident.get("severity"),
            "explanation": incident.get("score_explanation"),
            "score_breakdown": breakdown,
            "contributing_rules": incident.get("contributing_rules", [])
        },
        "triggered_rules": [
            {
                "finding_id": finding.get("finding_id"),
                "rule_id": finding.get("rule_id"),
                "rule_name": finding.get("rule_name"),
                "severity": finding.get("severity"),
                "observed_value": finding.get("observed_value"),
                "baseline_threshold": finding.get("baseline_threshold"),
                "explanation": finding.get("explanation"),
                "supporting_record_ids": finding.get("supporting_record_ids", [])
            }
            for finding in findings
        ],
        "evidence": {
            "expected_record_count": len(expected_record_ids),
            "returned_record_count": len(found_record_ids),
            "records": evidence_rows
        },
        "validation": {
            "checks": checks,
            "suppressed_activity_for_affected_hosts": [
                {
                    "finding_id": finding.get("finding_id"),
                    "rule_name": finding.get("rule_name"),
                    "reason": finding.get("suppression_reason")
                }
                for finding in suppressed_host_findings
            ],
            "summary": (
                "Risk score, rules, and evidence were cross-checked against the active dataset."
                if checks["overall"] == "verified"
                else "One or more verification checks did not reconcile with the active dataset."
            )
        }
    }


async def _qualcomm_runtime_status(runtime: Dict[str, str]) -> Dict[str, str]:
    base_url = runtime["base_url"]
    if not base_url:
        return {"status": "pending", "message": "GenieX is not configured. Verified NetWatch results are available below."}

    parsed_url = urlsplit(base_url)
    if (
        parsed_url.scheme != "http"
        or parsed_url.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed_url.username is not None
        or parsed_url.password is not None
    ):
        return {"status": "unavailable", "message": "Only a loopback GenieX server is supported; remote inference endpoints are disabled."}

    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{base_url}/models")
        response.raise_for_status()
        available_models = {
            item.get("id") for item in response.json().get("data", [])
            if isinstance(item, dict) and item.get("id")
        }
        if available_models and runtime["model"] not in available_models:
            return {"status": "unavailable", "message": f"GenieX is running but model {runtime['model']} is not loaded."}
        return {"status": "available", "message": "Local GenieX runtime and configured model are available."}
    except Exception:
        return {"status": "unavailable", "message": "Could not connect to the configured local GenieX runtime."}


def _qualcomm_response(incident: Dict[str, Any], runtime_status: Dict[str, str], runtime: Dict[str, str]) -> Dict[str, Any]:
    return {
        "provider": "Qualcomm AI Hub / GenieX",
        "model": runtime["model"],
        "integration_status": runtime_status["status"],
        "status_message": runtime_status["message"],
        "ai_assessment": None,
        "model_confidence": None,
        "confidence_note": "GenieX chat responses do not provide a calibrated confidence score.",
        "verified_analysis": _verified_incident_analysis(incident)
    }


@app.get("/api/incidents/{incident_id}/qualcomm-analysis")
async def get_qualcomm_incident_analysis(incident_id: str):
    incident = next((item for item in state.incidents if item["incident_id"] == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    runtime = _qualcomm_runtime_settings()
    status = await _qualcomm_runtime_status(runtime)
    return _qualcomm_response(incident, status, runtime)


@app.post("/api/incidents/{incident_id}/qualcomm-analysis")
async def run_qualcomm_incident_analysis(incident_id: str):
    incident = next((item for item in state.incidents if item["incident_id"] == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    runtime = _qualcomm_runtime_settings()
    status = await _qualcomm_runtime_status(runtime)
    result = _qualcomm_response(incident, status, runtime)
    if status["status"] != "available":
        return result

    verified = result["verified_analysis"]
    evidence_facts = {
        "risk_assessment": verified["risk_assessment"],
        "triggered_rules": verified["triggered_rules"],
        "supporting_flow_records": verified["evidence"]["records"][:20],
        "deterministic_validation": verified["validation"]["checks"]
    }
    messages = [
        {
            "role": "system",
            "content": (
                "Assist a network security analyst using only the supplied verified NetWatch evidence. "
                "Distinguish observed facts from hypotheses, discuss plausible false-positive explanations, "
                "and recommend validation steps. Never change the deterministic risk score or claim confidence."
            )
        },
        {"role": "user", "content": json.dumps(evidence_facts, default=str)}
    ]
    headers = {}
    if runtime["api_key"]:
        headers["Authorization"] = f"Bearer {runtime['api_key']}"
    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                f"{runtime['base_url']}/chat/completions",
                headers=headers,
                json={
                    "model": runtime["model"],
                    "messages": messages,
                    "max_tokens": 700,
                    "temperature": 0.2,
                    "stream": False,
                    "enable_think": False
                }
            )
        response.raise_for_status()
        assessment = response.json().get("choices", [{}])[0].get("message", {}).get("content")
        if not isinstance(assessment, str) or not assessment.strip():
            raise ValueError("GenieX returned no assessment text")
        result["ai_assessment"] = assessment.strip()
        result["status_message"] = "Assessment generated by the configured local GenieX runtime."
    except Exception:
        result["integration_status"] = "unavailable"
        result["status_message"] = "The GenieX request failed; verified NetWatch results remain available."
    return result


# -----------------------------------------------------------------------------
# Optional AI Incident Explanation (Local Ollama with Rule-Based Fallback)
# -----------------------------------------------------------------------------
@app.post("/api/incidents/{incident_id}/ai-explain")
async def explain_incident_ai(incident_id: str):
    """
    Generates plain-language SOC explanation using locally installed Ollama if available,
    otherwise returns a rich deterministic rule-based analysis. Never modifies scores!
    """
    incident = next((inc for inc in state.incidents if inc["incident_id"] == incident_id), None)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    host = incident["affected_hosts"][0] if incident["affected_hosts"] else "Unknown"
    rules_str = ", ".join(incident["related_rules"])
    score = incident["score"]
    sev = incident["severity"]
    findings_cnt = incident["findings_count"]

    # Check if local Ollama service is reachable
    ollama_available = False
    ai_text = ""

    prompt = (
        f"You are a cybersecurity incident analyst examining a detected network anomaly.\n"
        f"Incident: {incident_id}\n"
        f"Target Host: {host}\n"
        f"Severity: {sev} (Investigation Priority Score: {score}/100)\n"
        f"Detected Rules: {rules_str}\n"
        f"Evidence Findings Count: {findings_cnt}\n"
        f"Instructions: Provide a concise 2-paragraph SOC triage summary. "
        f"State observed anomalies based only on these facts. "
        f"Provide 2 plausible benign explanations and 3 prioritized next investigation steps. "
        f"Do not invent facts or declare an attack confirmed."
    )

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post("http://localhost:11434/api/generate", json={
                "model": "llama3",
                "prompt": prompt,
                "stream": False
            })
            if resp.status_code == 200:
                data = resp.json()
                ai_text = data.get("response", "").strip()
                if ai_text:
                    ollama_available = True
    except Exception:
        ollama_available = False

    if not ollama_available:
        # High quality built-in cybersecurity analyst synthesis
        benign_str = "\n".join([f"- {b}" for b in incident.get("possible_benign_explanations", ["Legitimate operational workload"])])
        steps_str = "\n".join([f"- {s}" for s in incident.get("suggested_investigation_steps", ["Review host security logs"])])

        ai_text = (
            f"**SOC Triage Assessment for {incident_id} ({host})**\n\n"
            f"Host {host} exhibited anomalous network behavior triggering **{rules_str}** with "
            f"an investigation priority score of **{score}/100 ({sev})** across {findings_cnt} observed finding(s).\n\n"
            f"**Context & Possible Benign Explanations:**\n{benign_str}\n\n"
            f"**Recommended Next Steps:**\n{steps_str}"
        )

    return {
        "incident_id": incident_id,
        "ollama_available": ollama_available,
        "explanation": ai_text
    }


# -----------------------------------------------------------------------------
# Exports & Reports (CSV Formula Protected & HTML Escaped)
# -----------------------------------------------------------------------------

@app.get("/api/export/findings")
def export_findings_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID", "Rule Name", "Affected Host", "Destination",
        "Timestamp", "Observed Value", "Baseline / Threshold",
        "Severity", "Explanation", "Is Approved Activity"
    ])

    for f in state.findings:
        writer.writerow([
            sanitize_csv_cell(f.get("finding_id")),
            sanitize_csv_cell(f.get("rule_name")),
            sanitize_csv_cell(f.get("affected_host")),
            sanitize_csv_cell(f.get("relevant_destination")),
            sanitize_csv_cell(f.get("timestamp")),
            sanitize_csv_cell(f.get("observed_value")),
            sanitize_csv_cell(f.get("baseline_threshold")),
            sanitize_csv_cell(f.get("severity")),
            sanitize_csv_cell(f.get("explanation")),
            "Yes" if f.get("is_approved_activity") else "No"
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netwatch_findings.csv"'}
    )


@app.get("/api/export/incidents")
def export_incidents_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Incident ID", "Title", "Affected Hosts", "Destinations",
        "Severity", "Score", "First Seen", "Last Seen",
        "Related Rules", "Findings Count", "Is Approved"
    ])

    for inc in state.incidents:
        writer.writerow([
            sanitize_csv_cell(inc.get("incident_id")),
            sanitize_csv_cell(inc.get("title")),
            sanitize_csv_cell(", ".join(inc.get("affected_hosts", []))),
            sanitize_csv_cell(", ".join(inc.get("destinations", []))),
            sanitize_csv_cell(inc.get("severity")),
            inc.get("score"),
            sanitize_csv_cell(inc.get("first_seen")),
            sanitize_csv_cell(inc.get("last_seen")),
            sanitize_csv_cell(", ".join(inc.get("related_rules", []))),
            inc.get("findings_count"),
            "Yes" if inc.get("is_approved_activity") else "No"
        ])

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netwatch_incidents.csv"'}
    )


@app.get("/api/export/evidence")
def export_evidence_csv(incident_id: Optional[str] = Query(None)):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Record ID", "Timestamp", "Source IP", "Destination IP",
        "Source Port", "Destination Port", "Protocol",
        "Bytes Sent", "Bytes Received", "Packets", "Duration", "Action", "DNS Query"
    ])

    if state.clean_df is not None and not state.clean_df.empty:
        sub_df = state.clean_df
        if incident_id:
            inc = next((i for i in state.incidents if i["incident_id"] == incident_id), None)
            if inc:
                sub_df = sub_df[sub_df["record_id"].isin(inc.get("supporting_record_ids", []))]

        for _, row in sub_df.iterrows():
            writer.writerow([
                row["record_id"],
                sanitize_csv_cell(str(row["timestamp"])),
                sanitize_csv_cell(str(row["src_ip"])),
                sanitize_csv_cell(str(row["dst_ip"])),
                row["src_port"] if pd.notna(row["src_port"]) else "",
                row["dst_port"] if pd.notna(row["dst_port"]) else "",
                sanitize_csv_cell(str(row["protocol"])),
                row["bytes_sent"],
                row["bytes_received"],
                row["packets"],
                row["duration"],
                sanitize_csv_cell(str(row["action"])),
                sanitize_csv_cell(str(row["dns_query"]))
            ])

    csv_data = output.getvalue()
    filename = f"netwatch_evidence_{incident_id}.csv" if incident_id else "netwatch_all_evidence.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/api/export/hosts")
def export_hosts_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Host IP", "Total Bytes", "Bytes Sent", "Bytes Received", "Packets", "Connections", "Distinct Destinations"])

    if state.clean_df is not None and not state.clean_df.empty:
        talkers = get_top_talkers(state.clean_df, limit=1000)
        for h in talkers:
            writer.writerow([
                sanitize_csv_cell(h["host"]),
                h["total_bytes"],
                h["bytes_sent"],
                h["bytes_received"],
                h["packets"],
                h["connections"],
                h["distinct_destinations"]
            ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netwatch_hosts_summary.csv"'}
    )


@app.get("/api/export/ports")
def export_ports_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Port", "Service", "Connections", "Total Bytes", "Unique Source Hosts"])

    if state.clean_df is not None and not state.clean_df.empty:
        port_data = get_port_analysis(state.clean_df)
        for p in port_data.get("common_ports", []):
            writer.writerow([
                p["port"],
                sanitize_csv_cell(p["service"]),
                p["connections"],
                p["total_bytes"],
                p["unique_source_hosts"]
            ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netwatch_ports_summary.csv"'}
    )


@app.get("/api/export/data-quality")
def export_data_quality_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Row Index", "Record ID", "Rejection Reason"])

    for item in state.quality_summary.get("rejection_reasons", []):
        r_idx = item.get("row_index")
        rec_id = item.get("record_id")
        reasons = "; ".join(item.get("reasons", []))
        writer.writerow([r_idx, rec_id, sanitize_csv_cell(reasons)])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="netwatch_data_quality_rejections.csv"'}
    )


@app.get("/api/export/report-html")
def export_html_investigation_report():
    """Generates a professional standalone HTML cybersecurity investigation report."""
    dataset_name = html.escape(state.dataset_name)
    total_records = len(state.clean_df) if state.clean_df is not None else 0
    total_findings = len(state.findings)
    total_incidents = len(state.incidents)
    eval_window = f"{html.escape(str(state.eval_start))} to {html.escape(str(state.eval_end))}" if state.eval_start else "N/A"
    learning_window = f"{html.escape(str(state.baseline['learning_start']))} to {html.escape(str(state.baseline['learning_end']))}" if state.baseline else "N/A"
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Render incident rows
    incident_rows = []
    for inc in state.incidents:
        sev_color = "#ef4444" if inc["severity"] == "Critical" else ("#f97316" if inc["severity"] == "High" else ("#eab308" if inc["severity"] == "Medium" else "#3b82f6"))
        approved_badge = '<span style="background:#065f46;color:#34d399;padding:2px 8px;border-radius:4px;font-size:12px;margin-left:8px;">Approved Activity</span>' if inc.get("is_approved_activity") else ""
        
        findings_html = "".join([
            f"<li style='margin-bottom:6px;'><strong>{html.escape(f['rule_name'])}:</strong> {html.escape(f['explanation'])} "
            f"<br/><small style='color:#94a3b8;'>Observed: {html.escape(str(f['observed_value']))} | {html.escape(str(f['baseline_threshold']))}</small></li>"
            for f in inc.get("findings", [])
        ])

        investigation_steps_html = "".join([
            f"<li>{html.escape(step)}</li>" for step in inc.get("suggested_investigation_steps", [])
        ])

        incident_rows.append(f"""
        <div class="incident-card" style="border-left: 4px solid {sev_color};">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <h3 style="margin:0; font-size:18px;">
                    {html.escape(inc['incident_id'])}: {html.escape(inc['title'])} {approved_badge}
                </h3>
                <span style="background:{sev_color}; color:#fff; padding:4px 12px; border-radius:12px; font-weight:bold; font-size:13px;">
                    {html.escape(inc['severity'])} — Score {inc['score']}/100
                </span>
            </div>
            <p style="color:#94a3b8; font-size:14px; margin: 8px 0;">
                <strong>Affected Host:</strong> {html.escape(', '.join(inc.get('affected_hosts', [])))} | 
                <strong>Destinations:</strong> {html.escape(', '.join(inc.get('destinations', [])))} | 
                <strong>Active Window:</strong> {html.escape(str(inc.get('first_seen')))} to {html.escape(str(inc.get('last_seen')))}
            </p>
            <div style="background:#0f172a; padding:12px; border-radius:6px; margin:10px 0; font-size:14px;">
                <strong>Deterministic Risk Score Breakdown:</strong> {html.escape(inc.get('score_explanation', ''))}
            </div>
            <h4 style="margin:12px 0 6px 0; color:#38bdf8;">Supporting Detection Findings ({inc.get('findings_count', 0)}):</h4>
            <ul style="color:#cbd5e1; font-size:14px; padding-left:20px;">
                {findings_html}
            </ul>
            <h4 style="margin:12px 0 6px 0; color:#38bdf8;">Suggested SOC Investigation Steps:</h4>
            <ul style="color:#cbd5e1; font-size:14px; padding-left:20px;">
                {investigation_steps_html}
            </ul>
        </div>
        """)

    all_incidents_rendered = "\n".join(incident_rows) if incident_rows else "<p style='color:#94a3b8;'>No incidents identified in this evaluation window.</p>"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetWatch Cybersecurity Investigation Report — {dataset_name}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b0f19;
            color: #e2e8f0;
            line-height: 1.6;
            padding: 30px;
            margin: 0;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid #1e293b;
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .logo {{
            font-size: 26px;
            font-weight: 800;
            color: #38bdf8;
            letter-spacing: -0.5px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .meta-box {{
            background: #1e293b;
            padding: 16px;
            border-radius: 8px;
            border: 1px solid #334155;
        }}
        .meta-box .label {{
            font-size: 12px;
            text-transform: uppercase;
            color: #94a3b8;
            font-weight: 600;
        }}
        .meta-box .value {{
            font-size: 22px;
            font-weight: 700;
            color: #f8fafc;
            margin-top: 4px;
        }}
        .incident-card {{
            background: #1e293b;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #334155;
        }}
        .footer {{
            border-top: 1px solid #1e293b;
            margin-top: 40px;
            padding-top: 20px;
            text-align: center;
            font-size: 13px;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo">NETWATCH SECURITY INVESTIGATION REPORT</div>
                <div style="color:#94a3b8; font-size:14px; margin-top:4px;">Target Dataset: {dataset_name} | Generated: {generated_at}</div>
            </div>
            <div style="text-align:right; font-size:13px; color:#94a3b8;">
                <div>Evaluation Period: {eval_window}</div>
                <div>Learning Baseline: {learning_window}</div>
            </div>
        </div>

        <div class="meta-grid">
            <div class="meta-box">
                <div class="label">Valid Flow Records</div>
                <div class="value">{total_records:,}</div>
            </div>
            <div class="meta-box">
                <div class="label">Anomaly Findings</div>
                <div class="value">{total_findings}</div>
            </div>
            <div class="meta-box">
                <div class="label">Correlated Incidents</div>
                <div class="value">{total_incidents}</div>
            </div>
            <div class="meta-box">
                <div class="label">Analysis Status</div>
                <div class="value" style="color:#34d399; font-size:18px;">Completed</div>
            </div>
        </div>

        <h2 style="border-bottom:1px solid #334155; padding-bottom:8px; margin-bottom:20px;">Executive Incident Summary</h2>
        {all_incidents_rendered}

        <div class="footer">
            NetWatch Network Traffic Anomaly Detection System &bull; Confidential Cyber Intelligence Report &bull; Generated locally without external telemetry
        </div>
    </div>
</body>
</html>"""

    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": 'attachment; filename="netwatch_investigation_report.html"'}
    )
