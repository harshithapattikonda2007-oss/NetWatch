import os
import yaml
from datetime import datetime
from typing import Dict, Any, List, Optional

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "settings.yaml")

DEFAULT_SETTINGS: Dict[str, Any] = {
    "rules": {
        "unusual_data_transfer": {
            "enabled": True,
            "baseline_multiplier": 3.0,
            "std_dev_multiplier": 2.5,
            "min_bytes_threshold": 10485760,
            "description": "Detects hosts transferring significantly more volume than historical baseline"
        },
        "port_probing": {
            "enabled": True,
            "distinct_port_threshold": 15,
            "time_window_seconds": 300,
            "description": "Detects hosts contacting an unusually large number of distinct ports in short succession"
        },
        "network_sweep": {
            "enabled": True,
            "distinct_host_threshold": 10,
            "time_window_seconds": 120,
            "description": "Detects horizontal network sweeps - single source scanning many destination IPs"
        },
        "lateral_movement": {
            "enabled": True,
            "internal_prefix": "192.168.",
            "internal_prefix_extra": "10.0.",
            "sensitive_ports": [22, 23, 135, 139, 445, 3389, 5985, 5986],
            "min_lateral_hops": 3,
            "time_window_seconds": 600,
            "description": "Detects one host reaching multiple internal hosts over administrative ports"
        },
        "lateral_movement": {
            "enabled": True,
            "internal_prefix": "192.168.",
            "internal_prefix_extra": "10.0.",
            "sensitive_ports": [22, 23, 135, 139, 445, 3389, 5985, 5986],
            "min_lateral_hops": 3,
            "description": "Detects host moving laterally inside the network via admin/lateral movement ports"
        },
        "destination_diversity": {
            "enabled": True,
            "baseline_multiplier": 3.0,
            "min_dest_threshold": 10,
            "time_window_seconds": 300,
            "description": "Detects sudden surges in distinct external or internal destinations contacted"
        },
        "periodic_connections": {
            "enabled": True,
            "min_occurrences": 4,
            "tolerance_seconds": 5.0,
            "cv_threshold": 0.15,
            "description": "Detects regular automated beaconing behavior with low interval variance"
        },
        "unexpected_host_communication": {
            "enabled": True,
            "min_baseline_flows": 5,
            "flag_external_unseen": True,
            "description": "Detects communications between hosts that never communicated during baseline"
        },
        "dns_behaviour": {
            "enabled": True,
            "query_volume_multiplier": 3.0,
            "min_query_volume": 15,
            "unique_query_ratio_threshold": 0.75,
            "description": "Detects spikes in DNS queries and high unique domain ratios (tunneling/DGA)"
        },
        "blocked_failed_connections": {
            "enabled": True,
            "failure_rate_threshold": 0.35,
            "min_failed_count": 5,
            "baseline_multiplier": 2.5,
            "description": "Detects abnormal increases in denied, dropped, or failed connections"
        }
    },
    "baseline": {
        "min_records": 10,
        "description": "Minimum records required in learning period to establish valid baseline"
    },
    "scoring": {
        "weights": {
            "severity": 0.30,
            "deviation": 0.20,
            "persistence": 0.15,
            "category_diversity": 0.15,
            "rule_priority": 0.10,
            "correlation": 0.10
        },
        "severity_base_points": {
            "Low": 20,
            "Medium": 45,
            "High": 75,
            "Critical": 95
        },
        "score_thresholds": {
            "Low": 35,
            "Medium": 65,
            "High": 85,
            "Critical": 100
        },
        "rule_weights": {
            "RULE_DATA_TRANSFER": 85,
            "RULE_PORT_PROBE": 75,
            "RULE_NETWORK_SWEEP": 80,
            "RULE_DEST_DIVERSITY": 55,
            "RULE_LATERAL_MOVEMENT": 90,
            "RULE_BEACONING": 90,
            "RULE_UNEXPECTED_COMM": 60,
            "RULE_DNS_ANOMALY": 80,
            "RULE_BLOCKED_CONNS": 50
        },
        "default_rule_weight": 50,
        "category_diversity_points": {"0": 0, "1": 35, "2": 70, "3": 100},
        "category_diversity_max_points": 100,
        "deviation_saturation_ratio": 5.0,
        "deviation_base_points": 30.0,
        "deviation_points_per_ratio": 17.5,
        "persistence_saturation_records": 20,
        "persistence_base_points": 25.0,
        "persistence_points_per_log2_record": 15.0,
        "correlation_points_per_additional_finding": 55,
        "trusted_activity_multipliers": {
            "approved_activity": 0.0,
            "maintenance": 0.0,
            "trusted_server": 0.8
        }
    },
    "upload": {
        "max_file_size_mb": 50,
        "allowed_extensions": [".csv", ".txt"]
    },
    "approved_activities": [
        {
            "id": "APP-01",
            "name": "Nightly Database Backup",
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.50",
            "ports": [445, 873, 22],
            "description": "Scheduled high-volume server synchronization to cold storage"
        },
        {
            "id": "APP-02",
            "name": "Authorized Vulnerability Scanner",
            "source_ip": "192.168.1.250",
            "destination_ip": None,
            "ports": [],
            "description": "Scheduled vulnerability scan appliance"
        },
        {
            "id": "APP-03",
            "name": "Windows Patch Server Push",
            "source_ip": "192.168.1.200",
            "destination_ip": None,
            "ports": [80, 443, 8530, 8531],
            "description": "Approved WSUS/SCCM patch distribution"
        },
        {
            "id": "APP-04",
            "name": "Nightly Log Aggregation Agent",
            "source_ip": "192.168.1.180",
            "destination_ip": None,
            "ports": [514, 6514, 9200, 5044],
            "description": "Approved centralized log collection"
        }
    ],
    "maintenance_windows": [],
    "trusted_servers": [],
    "schema_profiles": []
}


def load_settings() -> Dict[str, Any]:
    """Loads configuration settings from YAML file, falling back to defaults if missing or corrupted."""
    if not os.path.exists(CONFIG_PATH):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()

    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            if not isinstance(data, dict):
                return DEFAULT_SETTINGS.copy()
            # Merge with defaults for any missing top-level keys
            merged = DEFAULT_SETTINGS.copy()
            merged.update(data)
            return merged
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in settings file: {e}")
    except Exception:
        return DEFAULT_SETTINGS.copy()


def validate_settings(settings: Dict[str, Any]) -> tuple:
    """Validates configuration dictionary for required keys and positive thresholds."""
    if not isinstance(settings, dict):
        return False, "Settings must be a dictionary"

    if "rules" not in settings:
        return False, "Missing 'rules' configuration section"

    rules = settings.get("rules", {})
    for rule_name, rule_cfg in rules.items():
        if not isinstance(rule_cfg, dict):
            return False, f"Rule configuration for '{rule_name}' must be an object"
        if "enabled" in rule_cfg and not isinstance(rule_cfg["enabled"], bool):
            return False, f"Rule '{rule_name}' 'enabled' must be boolean"

    # Validate scoring weights sum to roughly 1.0
    if "scoring" in settings and "weights" in settings["scoring"]:
        weights = settings["scoring"]["weights"]
        try:
            weight_values = [float(weight) for weight in weights.values()]
        except (TypeError, ValueError):
            return False, "Scoring weights must be numeric"
        if any(weight < 0 or weight > 1 for weight in weight_values):
            return False, "Scoring weights must be between 0 and 1"
        total = sum(weight_values)
        if abs(total - 1.0) > 0.05:
            return False, f"Scoring weights must sum to 1.0 (current sum: {total:.2f})"

    if "scoring" in settings:
        scoring = settings["scoring"]
        for section in ("rule_weights", "severity_base_points"):
            values = scoring.get(section, {})
            try:
                numeric_values = [float(value) for value in values.values()]
            except (TypeError, ValueError):
                return False, f"Scoring {section} must contain numeric values"
            if any(value < 0 or value > 100 for value in numeric_values):
                return False, f"Scoring {section} values must be between 0 and 100"

        multipliers = scoring.get("trusted_activity_multipliers", {})
        try:
            multiplier_values = [float(value) for value in multipliers.values()]
        except (TypeError, ValueError):
            return False, "Trusted activity multipliers must be numeric"
        if any(value < 0 or value > 1 for value in multiplier_values):
            return False, "Trusted activity multipliers must be between 0 and 1"

        thresholds = scoring.get("score_thresholds", {})
        threshold_order = [thresholds.get(key) for key in ("Low", "Medium", "High", "Critical")]
        if any(not isinstance(value, (int, float)) or value < 0 or value > 100 for value in threshold_order):
            return False, "Score thresholds must be numeric values between 0 and 100"
        if threshold_order != sorted(threshold_order):
            return False, "Score thresholds must be in ascending severity order"

    # Validate baseline min_records
    if "baseline" in settings:
        min_rec = settings["baseline"].get("min_records", 0)
        if not isinstance(min_rec, (int, float)) or min_rec < 1:
            return False, "Baseline min_records must be an integer >= 1"

    return True, "Valid configuration"


def save_settings(settings: Dict[str, Any]) -> tuple:
    """Validates and saves settings dictionary to YAML file."""
    is_valid, msg = validate_settings(settings)
    if not is_valid:
        return False, msg

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.safe_dump(settings, f, default_flow_style=False, sort_keys=False)

    return True, "Configuration successfully saved"


def get_schema_profiles() -> List[Dict[str, Any]]:
    """Returns available schema profiles for dataset column mapping."""
    cfg = load_settings()
    return cfg.get("schema_profiles", [])


def get_schema_profile_by_id(profile_id: str) -> Optional[Dict[str, Any]]:
    """Returns a named schema profile by its ID string."""
    for profile in get_schema_profiles():
        if profile.get("id") == profile_id:
            return profile
    return None


def is_in_maintenance_window(timestamp: datetime, source_ip: str, settings: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """
    Checks if a given timestamp+source_ip falls inside a configured maintenance window.
    Returns the window name if matched, else None.
    """
    if settings is None:
        settings = load_settings()

    windows = settings.get("maintenance_windows", [])
    for w in windows:
        # Day-of-week check (0=Monday)
        allowed_days = w.get("days", list(range(7)))
        if timestamp.weekday() not in allowed_days:
            continue

        # Time window check (UTC hours)
        start_h = w.get("start_hour", 0)
        start_m = w.get("start_minute", 0)
        end_h = w.get("end_hour", 23)
        end_m = w.get("end_minute", 59)

        t_mins = timestamp.hour * 60 + timestamp.minute
        start_mins = start_h * 60 + start_m
        end_mins = end_h * 60 + end_m

        if not (start_mins <= t_mins <= end_mins):
            continue

        # Source IP check
        allowed_ips = w.get("source_ips", [])
        if allowed_ips and source_ip not in allowed_ips:
            continue

        return w.get("name", f"Maintenance Window {w.get('id', '')}")

    return None


def is_trusted_server(ip: str, settings: Optional[Dict[str, Any]] = None) -> Optional[str]:
    """Returns the role string if IP is a trusted server, else None."""
    if settings is None:
        settings = load_settings()
    for srv in settings.get("trusted_servers", []):
        if srv.get("ip") == ip:
            return srv.get("role", "Trusted Server")
    return None
