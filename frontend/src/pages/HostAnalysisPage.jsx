import React, { useState, useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import {
  Server,
  Activity,
  Network,
  ShieldAlert,
  ArrowRight,
  Database,
  Search,
  ExternalLink
} from 'lucide-react';
import { api } from '../services/api';

export default function HostAnalysisPage({ dataRevision }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const [hostsList, setHostsList] = useState([]);
  const [selectedHost, setSelectedHost] = useState(searchParams.get('host') || '');
  const [hostDetails, setHostDetails] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loadingHosts, setLoadingHosts] = useState(true);

  // Load available hosts
  useEffect(() => {
    setLoadingHosts(true);
    api.getAllHosts()
      .then((data) => {
        const hosts = data.hosts || [];
        setHostsList(hosts);
        if (!hosts.includes(selectedHost)) {
          setSelectedHost(hosts[0] || '');
        }
      })
      .catch((err) => console.error(err))
      .finally(() => setLoadingHosts(false));
  }, [dataRevision]);

  // Fetch host analysis whenever selectedHost changes
  useEffect(() => {
    if (selectedHost) {
      setLoading(true);
      setSearchParams({ host: selectedHost });
      api.getHostAnalysis(selectedHost)
        .then((data) => setHostDetails(data))
        .catch((err) => console.error(err))
        .finally(() => setLoading(false));
    }
  }, [selectedHost, dataRevision]);

  if (loadingHosts) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }

  if (hostsList.length === 0) {
    return (
      <div className="card empty-state">
        <Server className="empty-icon" />
        <h2 className="empty-title">No Host Records Available</h2>
        <p className="empty-text">Load or upload flow records to inspect individual host behavioral footprints.</p>
        <button className="btn btn-primary" onClick={() => navigate('/upload')}>
          Upload Dataset
        </button>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Server color="#38bdf8" /> Individual Host Behavioral Inspection
          </h1>
          <p className="page-subtitle">
            Inspect communication partners, service ports, baseline comparisons, and evidence flows.
          </p>
        </div>

        {/* Host Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label style={{ fontSize: 13, color: '#94a3b8' }}>Select Host IP:</label>
          <select
            className="form-control mono"
            style={{ width: 220 }}
            value={selectedHost}
            onChange={(e) => setSelectedHost(e.target.value)}
          >
            {hostsList.map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
          <div className="spinner" style={{ width: 36, height: 36 }} />
        </div>
      ) : hostDetails ? (
        <>
          {/* Host Metrics Bar */}
          <div className="stats-grid">
            <div className="stat-box">
              <div className="stat-header">
                <span>Related Flow Records</span>
                <Activity size={18} color="#38bdf8" />
              </div>
              <div className="stat-value">{hostDetails.total_connections}</div>
              <div className="stat-desc">Outgoing: {hostDetails.outgoing_connections} | Incoming: {hostDetails.incoming_connections}</div>
            </div>

            <div className="stat-box">
              <div className="stat-header">
                <span>Total Data Volume</span>
                <Database size={18} color="#10b981" />
              </div>
              <div className="stat-value">{(hostDetails.total_bytes / 1024).toFixed(1)} KB</div>
              <div className="stat-desc">
                Sent: {(hostDetails.bytes_sent / 1024).toFixed(1)} KB | Recv: {(hostDetails.bytes_received / 1024).toFixed(1)} KB
              </div>
            </div>

            <div className="stat-box">
              <div className="stat-header">
                <span>Contacted Targets</span>
                <Network size={18} color="#6366f1" />
              </div>
              <div className="stat-value">{hostDetails.distinct_destination_count || 0}</div>
              <div className="stat-desc">Distinct outgoing destinations</div>
            </div>

            <div className="stat-box">
              <div className="stat-header">
                <span>Security Incidents</span>
                <ShieldAlert size={18} color="#ef4444" />
              </div>
              <div className="stat-value" style={{ color: hostDetails.incidents?.length > 0 ? '#ef4444' : '#10b981' }}>
                {hostDetails.incidents?.length || 0}
              </div>
              <div className="stat-desc">Correlated investigation cases</div>
            </div>
          </div>

          {/* Baseline Comparison Card */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div className="card-title">
              <span>Historical Baseline Profile vs Observed Evaluation</span>
              {hostDetails.baseline_profile ? (
                <span className="badge badge-low">Baseline Established</span>
              ) : (
                <span className="badge badge-medium">No Baseline Established for this Host</span>
              )}
            </div>
            {hostDetails.baseline_profile ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
                <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>Baseline Mean Bytes Sent:</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: '#38bdf8', marginTop: 4 }}>
                    {(hostDetails.baseline_profile.bytes_sent_mean / 1024).toFixed(1)} KB
                  </div>
                </div>

                <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>Baseline Mean Bytes Received:</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: '#38bdf8', marginTop: 4 }}>
                    {(hostDetails.baseline_profile.bytes_recv_mean / 1024).toFixed(1)} KB
                  </div>
                </div>

                <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>Normal Distinct Destinations:</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', marginTop: 4 }}>
                    {hostDetails.baseline_profile.distinct_dest_count} endpoints
                  </div>
                </div>

                <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>Baseline Failure Rate:</div>
                  <div className="mono" style={{ fontSize: 16, fontWeight: 700, color: '#f8fafc', marginTop: 4 }}>
                    {(hostDetails.baseline_profile.failed_rate * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
            ) : (
              <p style={{ color: '#94a3b8', fontSize: 13 }}>
                This host was not observed during the selected learning period or had fewer than the minimum required baseline records.
              </p>
            )}
          </div>

          {hostDetails.behavior_comparison && (
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="card-title">Normal vs Observed Network Behavior</div>
              <p style={{ color: '#94a3b8', fontSize: 12, marginBottom: 14 }}>
                Baseline: {hostDetails.behavior_comparison.learning_window} | Evaluation: {hostDetails.behavior_comparison.evaluation_window}
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
                {hostDetails.behavior_comparison.metrics.map((metric) => {
                  const maximum = Math.max(metric.normal, metric.observed, 1);
                  const observedColor = metric.change_percent >= 50 || (metric.normal === 0 && metric.observed > 0)
                    ? '#ef4444'
                    : '#38bdf8';
                  const formatValue = (value) => {
                    if (metric.unit === 'B/hour' || metric.unit === 'B/flow') return `${(value / 1024).toFixed(1)} KB${metric.unit === 'B/hour' ? '/hour' : '/flow'}`;
                    return `${value.toLocaleString()} ${metric.unit}`;
                  };

                  return (
                    <div key={metric.key} style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 10 }}>{metric.label}</div>
                      <div style={{ display: 'grid', gridTemplateColumns: '76px 1fr auto', gap: 8, alignItems: 'center', fontSize: 12, marginBottom: 6 }}>
                        <span style={{ color: '#94a3b8' }}>Normal</span>
                        <div style={{ height: 7, background: '#0f172a', borderRadius: 4 }}>
                          <div style={{ width: `${metric.normal / maximum * 100}%`, height: '100%', background: '#64748b', borderRadius: 4 }} />
                        </div>
                        <span className="mono">{formatValue(metric.normal)}</span>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '76px 1fr auto', gap: 8, alignItems: 'center', fontSize: 12 }}>
                        <span style={{ color: '#94a3b8' }}>Observed</span>
                        <div style={{ height: 7, background: '#0f172a', borderRadius: 4 }}>
                          <div style={{ width: `${metric.observed / maximum * 100}%`, height: '100%', background: observedColor, borderRadius: 4 }} />
                        </div>
                        <span className="mono">{formatValue(metric.observed)}</span>
                      </div>
                      <div style={{ color: observedColor, fontSize: 11, marginTop: 8 }}>
                        {metric.change_percent === null
                          ? 'No baseline activity for comparison'
                          : `${metric.change_percent >= 0 ? '+' : ''}${metric.change_percent}% vs baseline`}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Grid: Destinations & Ports */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20, marginBottom: 24 }}>
            {/* Top Destinations */}
            <div className="card">
              <div className="card-title">Top Contacted Destinations</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Destination IP</th>
                      <th>Connection Flows</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostDetails.top_destinations?.map((d, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: '#38bdf8' }}>{d.destination}</td>
                        <td>{d.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <div className="card-title">Top Incoming Sources</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Source IP</th>
                      <th>Incoming Flows</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostDetails.top_sources?.map((source) => (
                      <tr key={source.source}>
                        <td className="mono" style={{ color: '#38bdf8' }}>{source.source}</td>
                        <td>{source.count}</td>
                      </tr>
                    ))}
                    {!hostDetails.top_sources?.length && (
                      <tr><td colSpan={2} style={{ color: '#64748b' }}>No incoming flows</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Top Ports */}
            <div className="card">
              <div className="card-title">Top Destination Ports Contacted</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Connection Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hostDetails.top_ports?.map((p, i) => (
                      <tr key={i}>
                        <td className="mono" style={{ color: '#fbbf24' }}>{p.port}</td>
                        <td>{p.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Incidents on this Host */}
          {hostDetails.incidents && hostDetails.incidents.length > 0 && (
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="card-title" style={{ color: '#ef4444' }}>
                <span>Associated Security Incidents</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {hostDetails.incidents.map((inc) => (
                  <div
                    key={inc.incident_id}
                    style={{
                      background: 'rgba(30, 41, 59, 0.4)',
                      border: '1px solid #1e293b',
                      borderRadius: 8,
                      padding: 12,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      cursor: 'pointer',
                    }}
                    onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                  >
                    <div>
                      <span className="mono" style={{ fontWeight: 700, color: '#f8fafc', marginRight: 10 }}>
                        {inc.incident_id}
                      </span>
                      <span style={{ color: '#cbd5e1' }}>{inc.title}</span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span className="badge badge-high">{inc.severity}</span>
                      <span style={{ fontSize: 16, fontWeight: 800, color: '#38bdf8' }}>
                        Score: {inc.score}
                      </span>
                      <ExternalLink size={14} color="#64748b" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Supporting Evidence Flow Records */}
          <div className="card">
            <div className="card-title">
              <span>Observed Flow Evidence Records (Sample of {hostDetails.evidence_flows?.length})</span>
            </div>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Record ID</th>
                    <th>Timestamp</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Dst Port</th>
                    <th>Protocol</th>
                    <th>Bytes Sent</th>
                    <th>Bytes Recv</th>
                    <th>Action</th>
                    <th>DNS Query</th>
                  </tr>
                </thead>
                <tbody>
                  {hostDetails.evidence_flows?.map((flow, i) => (
                    <tr key={i}>
                      <td className="mono">{flow.record_id}</td>
                      <td className="mono" style={{ fontSize: 12 }}>{flow.timestamp}</td>
                      <td className="mono" style={{ color: '#94a3b8' }}>{flow.src_ip}</td>
                      <td className="mono" style={{ color: '#38bdf8' }}>{flow.dst_ip}</td>
                      <td className="mono">{flow.dst_port ?? 'N/A'}</td>
                      <td>{flow.protocol}</td>
                      <td>{flow.bytes_sent}</td>
                      <td>{flow.bytes_received}</td>
                      <td>
                        <span className={`badge ${flow.action === 'DENY' || flow.action === 'DROP' ? 'badge-critical' : 'badge-low'}`}>
                          {flow.action || 'ALLOW'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontSize: 11, color: '#94a3b8' }}>
                        {flow.dns_query || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
