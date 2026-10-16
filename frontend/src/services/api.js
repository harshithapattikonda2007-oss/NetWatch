/**
 * Central API Service for NetWatch
 * Connects to the FastAPI backend with real endpoint calls.
 */

const BASE_URL = import.meta.env.VITE_API_URL || '';

async function request(endpoint, options = {}) {
  const url = `${BASE_URL}${endpoint}`;
  try {
    const response = await fetch(url, options);
    if (!response.ok) {
      let errMsg = `Request failed with status ${response.status}`;
      try {
        const errJson = await response.json();
        if (errJson && errJson.detail) {
          errMsg = errJson.detail;
        }
      } catch (e) {
        // Not JSON
      }
      throw new Error(errMsg);
    }
    return await response.json();
  } catch (error) {
    console.error(`API Error on ${endpoint}:`, error);
    throw error;
  }
}

export const api = {
  // System Health
  getHealth: () => request('/api/health'),

  // Upload & Sample
  uploadDataset: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/api/upload', {
      method: 'POST',
      body: formData,
    });
  },

  loadSampleDataset: () => request('/api/sample/load', { method: 'POST' }),

  getDatasetPreview: () => request('/api/dataset/preview'),

  mapAndValidate: (mapping) =>
    request('/api/dataset/map-and-validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mapping }),
    }),

  getDataQuality: () => request('/api/data-quality'),

  getTimeRange: () => request('/api/dataset/time-range'),

  // Baseline & Analysis
  buildBaseline: (learningStart, learningEnd, minRecords = null) =>
    request('/api/baseline/build', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        learning_start: learningStart,
        learning_end: learningEnd,
        min_records: minRecords,
      }),
    }),

  runAnalysis: (evalStart, evalEnd) =>
    request('/api/analysis/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        eval_start: evalStart,
        eval_end: evalEnd,
      }),
    }),

  // Dashboard
  getDashboard: () => request('/api/dashboard'),

  // Analytics
  getTrafficAnalytics: (interval = 5) =>
    request(`/api/analytics/traffic?interval=${interval}`),

  getAllHosts: () => request('/api/analytics/hosts'),

  getHostAnalysis: (hostIp) => request(`/api/analytics/host/${encodeURIComponent(hostIp)}`),

  getPortsAnalytics: (host = '', protocol = '') => {
    const params = new URLSearchParams();
    if (host) params.append('host', host);
    if (protocol) params.append('protocol', protocol);
    return request(`/api/analytics/ports?${params.toString()}`);
  },

  getDnsAnalysis: () => request('/api/analytics/dns'),

  // Network Graph
  getNetworkGraph: () => request('/api/graph'),

  // Incidents & Findings
  getIncidents: (severity = '') => {
    const query = severity ? `?severity=${encodeURIComponent(severity)}` : '';
    return request(`/api/incidents${query}`);
  },

  getIncidentDetail: (incidentId) => request(`/api/incidents/${encodeURIComponent(incidentId)}`),

  getIncidentEvidence: (incidentId) =>
    request(`/api/incidents/${encodeURIComponent(incidentId)}/evidence`),

  getIncidentGraph: (incidentId) =>
    request(`/api/incidents/${encodeURIComponent(incidentId)}/graph`),

  getQualcommIncidentAnalysis: (incidentId) =>
    request(`/api/incidents/${encodeURIComponent(incidentId)}/qualcomm-analysis`),

  runQualcommIncidentAnalysis: (incidentId) =>
    request(`/api/incidents/${encodeURIComponent(incidentId)}/qualcomm-analysis`, {
      method: 'POST',
    }),

  getFindings: (host = '') => {
    const query = host ? `?host=${encodeURIComponent(host)}` : '';
    return request(`/api/findings${query}`);
  },

  // AI / Rule Explanation
  explainIncidentAi: (incidentId) =>
    request(`/api/incidents/${encodeURIComponent(incidentId)}/ai-explain`, {
      method: 'POST',
    }),

  // Configuration
  getConfig: () => request('/api/config'),

  updateConfig: (settings) =>
    request('/api/config', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings),
    }),

  // Export URLs for direct browser downloads
  getExportUrl: (type, params = {}) => {
    const qs = new URLSearchParams(params).toString();
    const queryStr = qs ? `?${qs}` : '';
    return `${BASE_URL}/api/export/${type}${queryStr}`;
  },
};
