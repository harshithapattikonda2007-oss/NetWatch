# NetWatch — Network Traffic Anomaly Detection & Incident Investigation

NetWatch is a local, full-stack cybersecurity web application designed to analyze network-flow CSV datasets, detect unusual behavioral anomalies across individual hosts, correlate related findings into prioritized security incidents, and assist analysts with evidence-backed forensic investigation.

NetWatch requires account sign-in. Passwords are stored as salted PBKDF2 hashes, and authenticated API access uses signed, HttpOnly session cookies. On Render Free, the SQLite account database is on ephemeral storage and can be lost when the service restarts or spins down; configure durable storage/database before relying on persistent accounts. Investigation datasets also remain in process memory and are not isolated per user.

### Roles and demo access

- **Admin** can access every application feature, manage accounts and role assignments, review the permission matrix and audit log, configure detection settings, and build baselines.
- **Security Analyst** can upload and analyze traffic, view baseline and investigation data, manage incident status, and export reports. Analyst API requests cannot manage accounts, edit detection settings, or build baselines.
- API authorization is enforced server-side for every protected route; unclassified API routes are denied. Frontend navigation and page controls reflect the same role capabilities.

There are no built-in demo passwords. To provision an administrator on first startup, configure `NETWATCH_BOOTSTRAP_ADMIN_EMAIL` and `NETWATCH_BOOTSTRAP_ADMIN_PASSWORD` (minimum 12 characters). To show clickable login-page demo accounts, explicitly set `NETWATCH_ENABLE_DEMO_ACCOUNTS=true` and provide `NETWATCH_DEMO_ADMIN_EMAIL`, `NETWATCH_DEMO_ADMIN_PASSWORD`, `NETWATCH_DEMO_ANALYST_EMAIL`, and `NETWATCH_DEMO_ANALYST_PASSWORD`. Demo credentials are only returned by the public demo-account endpoint while this opt-in is enabled and the configured accounts authenticate with the expected roles. Keep demo accounts disabled outside an isolated demo environment.

---

## 🛠️ Technical Stack

### 🎨 Frontend

* **React.js** – Component-based user interface for the security dashboard.
* **JavaScript (JSX)** – Frontend logic and interactive components.
* **CSS3** – Styling and responsive dashboard design.
* **Vite** – Frontend development server and build tool.

### ⚙️ Backend

* **Python** – Core processing and network anomaly detection logic.
* **FastAPI** – REST API framework connecting the frontend with backend services.

### 🔍 Detection & Analysis

* **Rule-Based Detection Engine** – Identifies suspicious network activity using configurable detection rules.
* **Behavioral Baselines** – Helps identify deviations from typical network traffic patterns.
* **YAML** – Configuration of detection rules, thresholds, and approved activities.
* **Python Data Processing** – Parses and analyzes uploaded network-flow datasets.

### 📊 Visualization

* **Cytoscape.js** – Visualizes network relationships and traffic connections.
* **Dashboard Charts** – Presents traffic statistics, anomalies, and investigation findings.

### 🤖 AI Integration

* **Ollama (Optional)** – Supports local AI-assisted security incident assessment without requiring a cloud-based AI API.

### 🧪 Testing

* **Pytest** – Tests backend functionality and detection logic.

### 📁 Data & Reporting

* **CSV** – Input format for network-flow datasets and exported analysis results.
* **HTML** – Generates readable forensic and investigation reports.

---

## Key Features

1. **Local Processing & Privacy**: Complete local execution. No cloud API or remote telemetry required.
2. **Robust CSV Ingestion & Validation**:
   - Auto-suggests and manually binds columns (Source/Destination IP, Ports, Timestamps, Bytes, Packets, Protocols, Actions, DNS queries).
   - Validates IP formats, port boundaries ($0 \le \text{port} \le 65535$), negative numbers, and malformed rows.
   - Missing fields are never fabricated; missing ports are never treated as port zero.
3. **Temporal Baseline Profiling (No Data Leakage)**:
   - Separate historical learning period and evaluation period.
   - Strictly rejects overlapping timeframes to prevent data leakage.
   - Profiles normal traffic volume, typical communication partners, service ports, and failure rates.
4. **9 Rule-Based Anomaly Detection Engines**:
   - **Rule A (Unusual Data Transfer)**: Host sending/receiving volume significantly exceeding baseline multipliers.
   - **Rule B (Port Probing)**: Host contacting an unusual count of distinct destination ports within a short time window.
   - **Rule C (Network Sweep)**: Single source reaching many destination hosts in a configurable short window.
   - **Rule D (Destination Diversity)**: Sudden surge in distinct destination endpoints contacted.
   - **Rule E (Lateral Movement)**: One host reaching multiple internal hosts over sensitive administrative ports.
   - **Rule F (Periodic Connections / C2 Beaconing)**: Regular automated connections with low coefficient of variation ($CV \le 0.15$).
   - **Rule G (Unexpected Host Communication)**: New, unobserved communication pairs with sensitive port escalation.
   - **Rule H (DNS Behaviour Analysis)**: Spikes in lookup volume and high unique domain ratios indicative of DGA / tunneling.
   - **Rule I (Blocked or Failed Connections)**: Abnormal surges in firewall denials or authentication failures.
5. **Incident Grouping & Deterministic Priority Scoring (0–100)**:
   - Groups related findings by affected host, time window, and attack category.
    - Calculates each incident's deterministic 0-100 risk score from configured severity, deviation, evidence persistence, rule diversity, rule priority, and incident-correlation factors, then applies the trusted-activity multiplier:
       $$\text{Score} = \operatorname{clamp}_{0..100}\left(\left(\sum_i w_i S_i\right) \times M_{\text{trust}}\right)$$
    - Shows component points, configured weights, per-rule priority contributions, finding counts, trust adjustment, and supporting flow evidence for each incident.
   - Provides plausible benign explanations and standardized SOC investigation checklists.
   - Keeps findings for audit, but excludes configured approved activities and scheduled maintenance from incident scoring; trusted-server suppression is limited to low-severity findings.
6. **14 Complete Application Views**:
   - Dashboard, Upload & Mapping, Data Quality, Baseline & Learning, Traffic Analytics, Host Analysis, Port Heatmap Analysis, DNS Analysis, Cytoscape.js Network Graph, Incidents Queue, Incident Details & Evidence, Detection Settings, Reports & Exports, and Admin & Access Control.
7. **Forensic Exports**:
   - CSV exports protected against formula injection (`=`, `+`, `-`, `@` prepended with `'`).
   - Standalone HTML forensic intelligence report with fully escaped untrusted text.
8. **Optional Local Ollama Support**:
   - If a local Ollama instance is running, provides local AI triage assessment; otherwise falls back gracefully to deterministic cybersecurity synthesis.
9. **Qualcomm AI Evidence Analysis**:
   - Uses official local GenieX runtime with verified incident rules, risk calculation, and supporting traffic evidence; deterministic results remain available when GenieX is not configured.
   - Model confidence is reported as unavailable because GenieX chat does not provide a calibrated confidence value.

---

## Project Structure

```text
netwatch/
├── backend/
│   ├── main.py                     # FastAPI REST API endpoints
│   ├── auth.py                     # Password hashing, sessions, roles, and account storage
│   ├── data_processor.py           # CSV parsing, mapping, validation & baseline computation
│   ├── detection.py                # 7 rule anomaly engines, incident grouping & deterministic scoring
│   ├── analytics.py                # Traffic series, port heatmap, host profiling & network graph
│   ├── config.py                   # YAML settings manager and validator
│   ├── generate_sample.py          # Synthetic dataset generator
│   ├── requirements.txt            # Python dependencies
│   └── tests/
│       └── test_netwatch.py        # API, role authorization, and analytics test suite
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── Sidebar.jsx         # Navigation sidebar with status indicators
│   │   │   └── TopBar.jsx          # Header with dataset status & sample loading
│   │   ├── pages/
│   │   │   ├── AdminPage.jsx       # Account roles, permission matrix, and audit log
│   │   │   ├── AuthPage.jsx        # Sign-in, signup, and opt-in demo account autofill
│   │   │   ├── DashboardPage.jsx   # Metrics, charts, top talkers, incident queue
│   │   │   ├── UploadPage.jsx      # CSV upload, preview & column mapping
│   │   │   ├── DataQualityPage.jsx # Audit of valid, rejected & duplicate records
│   │   │   ├── BaselinePage.jsx    # Learning period training & evaluation execution
│   │   │   ├── TrafficAnalyticsPage.jsx # Multi-interval traffic and protocol breakdown
│   │   │   ├── HostAnalysisPage.jsx # Host deep-dive, baseline comparison & flows
│   │   │   ├── PortAnalysisPage.jsx # Port analysis and host-vs-port heatmap
│   │   │   ├── DnsAnalysisPage.jsx  # Domain query volume and DGA entropy
│   │   │   ├── NetworkGraphPage.jsx # Interactive Cytoscape.js topology canvas
│   │   │   ├── IncidentsPage.jsx   # Filterable incident investigation queue
│   │   │   ├── IncidentDetailPage.jsx # Incident score breakdown, evidence & AI triage
│   │   │   ├── SettingsPage.jsx    # Live editor for config/settings.yaml
│   │   │   └── ReportsPage.jsx     # CSV and HTML report exports
│   │   ├── services/
│   │   │   └── api.js              # Centralized backend API client
│   │   ├── App.jsx                 # Route configuration
│   │   ├── index.css               # Dark navy cybersecurity design system
│   │   └── main.jsx
│   ├── package.json
│   ├── vite.config.js              # Vite server with /api proxy
│   └── index.html
├── config/
│   └── settings.yaml               # Configurable detection rules, thresholds & approved tasks
├── data/
│   └── sample_network_flows.csv    # 596 synthetic records with 7 anomaly scenarios
├── README.md
└── .gitignore
```

---

## Windows Setup & Quick Start

Open two PowerShell terminals:

### Terminal 1: Backend Setup & Launch

```powershell
# Navigate to project root
cd c:\Users\harsh\OneDrive\Desktop\netwatch

# Create and activate virtual environment (if not already created)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r backend\requirements.txt

# Start FastAPI backend server (Option A: from project root)
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000

# OR (Option B: from backend folder)
cd backend
python -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The interactive API documentation is available at `http://127.0.0.1:8000/docs`.

### Terminal 2: Frontend Setup & Launch

```powershell
# Navigate to frontend folder
cd c:\Users\harsh\OneDrive\Desktop\netwatch\frontend

# Install node dependencies
npm install

# Start Vite development server
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## Deploy on Render Free

The repository includes a single-service Docker deployment. Render builds the Vite frontend, copies it into the FastAPI image, and serves the UI and `/api` from the same origin.

1. Push this repository to GitHub.
2. In Render, choose **New > Blueprint**, connect the GitHub repository, and deploy the root `render.yaml`.
3. Wait for the first build, then open the `onrender.com` URL and the direct `/login` URL. Both should serve the React app; Render checks `/api/health`.

Render generates `NETWATCH_SESSION_SECRET` through `render.yaml`; do not commit session secrets or passwords. Local development generates a process-local session secret unless `NETWATCH_SESSION_SECRET` is set.

For local demo logins, set the demo-account environment variables above before starting the backend. The login screen fills the selected account credentials only; the user must still submit **Sign in**. Set `NETWATCH_CORS_ORIGINS` to a comma-separated list of trusted frontend origins when the frontend and API are served from different origins. Same-origin deployments need no extra CORS origins.

No production frontend API URL or secret is required. Optional Qualcomm GenieX stays pending on Render Free: it requires a local supported Qualcomm device and loopback server, which a generic Render container does not provide.

**Render Free limitations:** the web service spins down after 15 minutes without inbound traffic and can take about a minute to wake. Its filesystem is ephemeral, and NetWatch currently keeps uploaded datasets, baselines, findings, and incidents in process memory. They are lost on restarts, deploys, or spin-down and aren't shared across instances. This setup is suitable for demos/testing, not durable multi-user production. Durable storage requires a backend persistence design; Render Free Postgres expires after 30 days and is not a permanent free production store.

To smoke-test the production image locally:

```powershell
docker build -t netwatch .
docker run --rm -p 10000:10000 netwatch
```

Then open `http://localhost:10000` and check `http://localhost:10000/api/health`.

---

## Workflow Guide

### 1. Load Synthetic Demonstration Dataset
- Click **"Load Synthetic Sample"** in the top navigation bar or on the Dashboard.
- NetWatch loads `data/sample_network_flows.csv` (596 records spanning 2026-03-01 to 2026-03-02).

### 2. Column Mapping & Data Quality Audit
- Navigate to **Upload Dataset** to verify auto-suggested column mappings.
- Click **"Confirm Mapping & Validate Data"**.
- Navigate to **Data Quality** to inspect valid/rejected record counts, duplicate checks, and feature capability indicators (DNS query tracking, firewall action decisions).

### 3. Establish Behavioral Baseline
- Navigate to **Learning & Baseline**.
- For the sample dataset, the recommended non-overlapping intervals are pre-filled:
  - **Learning Period**: `2026-03-01 08:00:00` to `2026-03-01 18:00:00`
  - **Evaluation Period**: `2026-03-02 08:00:00` to `2026-03-02 18:00:00`
- Click **"Build Historical Baseline"**. Host baseline profiles are calculated.

### 4. Execute Anomaly Detectors
- On the same page, click **"Execute Anomaly Detectors"**.
- NetWatch runs the 7 detection engines over the evaluation records and groups related findings into incidents.

### 5. Investigate Incidents & Evidence
- Navigate to **Incidents** to browse the prioritized queue.
- Click **"Investigate"** on any incident to open the **Incident Details & Evidence** view:
  - Examine the **deterministic priority score breakdown** (Severity, Statistical Deviation, Persistence, and Category Diversity).
  - Review **plausible benign explanations** and **suggested SOC investigation steps**.
  - Click **"Generate / Refresh Triage Assessment"** for AI/expert narrative explanation.
  - Inspect the table of raw supporting flow records with exact timestamps, ports, and bytes.

### 6. Explore Analytics & Network Graph
- **Traffic Analytics**: Toggle 1-min, 5-min, or 1-hour time buckets; view volume sent/received and protocol distributions.
- **Host Analysis**: Deep-dive into individual hosts with baseline vs observed comparisons.
- **Port Analysis**: View top destination ports and the interactive host-versus-port heatmap.
- **DNS Analysis**: Review lookup volume, top queried domains, and DGA/tunneling indicators.
- **Network Graph**: Interactive Cytoscape.js canvas showing real observed communications, with anomalous hosts glowing red and incident edges highlighted.

### 7. Configure Rules & Export Reports
- **Detection Settings**: Edit rule multipliers, thresholds, time windows, scoring weights, and approved maintenance lists. Changes take effect on the next analysis run.
- **Reports & Exports**: Download CSV exports of findings, incidents, evidence, hosts, ports, data quality audit, or generate the complete standalone formatted HTML forensic report.

---

## Running Verification Tests

- Trusted sources, scanner/patch/backup activities, maintenance windows, trusted servers, and dataset schema profiles are managed in `config/settings.yaml`.
- The Zeek `conn.log` profile maps `ts`, `id.orig_h`, `id.resp_h`, `id.orig_p`, and `id.resp_p` to the same canonical flow fields used by the native dataset. Both formats pass through the same validator and detector.
- Findings include per-finding risk scores, rule explanations, supporting record IDs, and suppression reasons. Incidents include a timestamp-ordered timeline and retain flow evidence.
- Regression scenarios assert detection of a suspicious horizontal sweep and internal spread, while an authorized scanner retains an auditable finding but creates no scored incident. This is scenario-based validation, not a statistically representative production accuracy estimate.
- Limitations: configured internal networks are prefix-based; maintenance schedules use local timestamps treated as UTC; approved source identities are IP-based and should be tightly controlled. Encrypted payloads and process-level attribution are outside flow-log visibility.

### Mission 03 Notes
- Host Analysis compares evaluation-period connection rate, bytes sent, average flow size, destination diversity, and failure rate against the host's learning baseline.
- Traffic Analytics marks actionable findings by time bucket and shows the observed measurement, configured threshold, and rule explanation. Approved/scheduled activity remains visible but is visually distinguished.
- Beacon findings include each supporting connection timestamp and measured inter-arrival gap, with mean interval, standard deviation, and coefficient of variation.
- Incident timelines label likely behavioral stages; incident detail includes a communication graph built from that incident's supporting flow records and score/rule/evidence breakdowns.
- Regression scenarios compare a suspicious regular beacon against a configured periodic log-aggregation service to validate false-positive handling.

### Qualcomm GenieX Setup
Qualcomm AI Hub lists [Qwen3-4B-Instruct-2507](https://aihub.qualcomm.com/models/qwen3_4b_instruct_2507) as an instruction-following model and documents its GenieX deployment path. GenieX provides a local OpenAI-compatible server; AI Hub Workbench is used for device compile/profile/inference jobs, not as a generic hosted chat endpoint. NetWatch only connects to loopback addresses.

1. On a supported Qualcomm Windows ARM device, install the [GenieX CLI](https://geniex.aihub.qualcomm.com/en/run/cli/install/).
2. Pull the model and start the local server:

```powershell
geniex pull ai-hub-models/Qwen3-4B-Instruct-2507
geniex serve
```

3. In the backend's PowerShell session, configure the local endpoint and model before starting/restarting NetWatch:

```powershell
$env:QUALCOMM_GENIEX_BASE_URL = "http://127.0.0.1:18181/v1"
$env:QUALCOMM_GENIEX_MODEL = "ai-hub-models/Qwen3-4B-Instruct-2507"
```

The local GenieX server does not require an API token. If a local authenticated proxy is used, set `QUALCOMM_GENIEX_API_KEY` in the backend environment; it is never returned to or used by the frontend. Without a running local GenieX server, NetWatch labels the integration pending/unavailable and continues to show only verified detector results. AI narrative is advisory and does not alter risk scores or claim model confidence.

### Backend Pytest Suite
Run the backend test suite from the project root:

```powershell
cd c:\Users\harsh\OneDrive\Desktop\netwatch
.venv\Scripts\pytest backend\tests -v
```

- `test_suggest_column_mapping` (Auto-aliasing of common flow headers)
- `test_zeek_schema_maps_to_canonical_fields_and_matches_default` (Alternate field names normalize to the canonical flow schema)
- `test_zeek_tsv_upload_auto_maps_columns` (Tab-delimited upload selects the configured schema profile)
- `test_is_valid_ip` (IPv4 / IPv6 format verification)
- `test_data_validation_and_rejections` (Handling of invalid timestamps, ports, and negative numbers)
- `test_temporal_separation` (Strict enforcement of non-overlapping learning/evaluation periods)
- `test_baseline_creation_insufficient_records` (Validation of minimum required baseline record counts)
- `test_all_seven_detection_rules` (Verification of Rules A through G)
- `test_sweep_lateral_detection_and_legitimate_activity_suppression` (Suspicious sweep/spread detection and authorized scanner false-positive reduction)
- `test_missing_dns_and_outcome_fields` (Graceful handling without data fabrication)
- `test_incident_grouping_and_scoring` (Correlation and deterministic formula calculation)
- `test_incident_score_uses_configured_rule_and_trusted_activity_weights` (Configured rule priority, correlation gain, and trusted multiplier)
- `test_incident_severity_score_boundaries` (Low/Medium/High/Critical score-band boundaries)
- `test_qualcomm_analysis_returns_verified_results_when_runtime_is_pending` (Evidence-grounded pending response with no fabricated AI result)
- `test_qualcomm_rejects_remote_runtime_urls` (Local-only GenieX endpoint enforcement)
- `test_analytics_include_destination_hosts_dns_flows_and_nonempty_buckets` (Analytics reflect both flow endpoints, DNS transport, nonempty time bins, and incident edges)
- `test_configuration_validation` (Settings schema and weight sum validation)
- `test_api_sample_load_and_workflow` (End-to-end integration test of all API routes and exports)

## 🔄 System Workflow
1. **Data Ingestion** – Upload network-flow CSV files through the dashboard.
2. **Data Processing** – Validate and process the uploaded records using Python.
3.  **Behavioral Analysis** – Establish or use historical traffic baselines to understand normal activity.
4. **Anomaly Detection** – Apply configurable rules to identify suspicious traffic patterns.
5. **Incident Assessment** – Correlate findings and prioritize suspicious activities for investigation.
6. **Visualization** – Display traffic analytics, anomalies, and network relationships.
7. **Report Generation** – Export investigation results in CSV or HTML format.

**Results (26/26 Passed)**:
- `test_authentication_signup_login_and_protected_api` (Signed session cookies, protected APIs, and logout)
- `test_role_permissions_enforced_for_admin_and_analyst` (Admin/analyst access and live role changes)
- `test_demo_accounts_are_opt_in_and_environment_configured` (Environment-configured demo accounts and opt-in exposure)
- `test_signup_rejects_weak_password` (Minimum password length)

### Frontend Production Build
Validate the React frontend build:

```powershell
cd c:\Users\harsh\OneDrive\Desktop\netwatch\frontend
npm run build
```
Builds cleanly with zero errors.

