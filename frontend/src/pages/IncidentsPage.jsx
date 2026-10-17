import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle,
  ShieldAlert,
  ArrowRight,
  Download
} from 'lucide-react';
import { api } from '../services/api';

export default function IncidentsPage({ canManageIncidents = false, dataRevision }) {
  const navigate = useNavigate();
  const [incidents, setIncidents] = useState([]);
  const [severityFilter, setSeverityFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [updatingIncident, setUpdatingIncident] = useState('');
  const [error, setError] = useState('');

  const fetchIncidents = useCallback(async () => {
    try {
      const res = await api.getIncidents(severityFilter);
      setIncidents(res.incidents || []);
      setError('');
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [severityFilter]);

  const handleStatusChange = async (incidentId, status) => {
    setError('');
    try {
      setUpdatingIncident(incidentId);
      await api.updateIncidentStatus(incidentId, status);
      setIncidents((currentIncidents) => currentIncidents.map((incident) => (
        incident.incident_id === incidentId ? { ...incident, status } : incident
      )));
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setUpdatingIncident('');
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents, dataRevision]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <AlertTriangle color="#ef4444" /> Security Incidents Triage Queue
          </h1>
          <p className="page-subtitle">
            Correlated multi-finding security incidents prioritized by deterministic evidence scoring (0–100).
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select
            className="form-control"
            style={{ width: 150, padding: '6px 12px', fontSize: 13 }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <a
            href={api.getExportUrl('incidents')}
            className="btn btn-secondary btn-sm"
            download="netwatch_incidents.csv"
          >
            <Download size={14} /> Export Incidents CSV
          </a>
        </div>
      </div>

      {error && <div className="alert alert-danger"><AlertTriangle size={18} /><div>{error}</div></div>}

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
          <div className="spinner" style={{ width: 36, height: 36 }} />
        </div>
      ) : incidents.length === 0 ? (
        <div className="card empty-state">
          <ShieldAlert className="empty-icon" />
          <h2 className="empty-title">No Incidents Detected</h2>
          <p className="empty-text">
            No security incidents match the current filter or baseline evaluation has not been executed yet.
          </p>
          <button className="btn btn-primary" onClick={() => navigate('/baseline')}>
            Run Baseline & Detection
          </button>
        </div>
      ) : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Incident ID</th>
                <th>Target Host</th>
                <th>Severity</th>
                <th>Priority Score</th>
                <th>Correlated Rules</th>
                <th>Findings</th>
                <th>Active Window</th>
                {canManageIncidents && <th>Status</th>}
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {incidents.map((inc) => {
                const sevBadge =
                  inc.severity === 'Critical'
                    ? 'badge-critical'
                    : inc.severity === 'High'
                    ? 'badge-high'
                    : inc.severity === 'Medium'
                    ? 'badge-medium'
                    : 'badge-low';

                const scoreColor =
                  inc.score >= 85
                    ? '#ef4444'
                    : inc.score >= 65
                    ? '#f97316'
                    : inc.score >= 35
                    ? '#fbbf24'
                    : '#38bdf8';

                return (
                  <tr
                    key={inc.incident_id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/incidents/${inc.incident_id}`)}
                  >
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className="mono" style={{ fontWeight: 700, color: '#f8fafc' }}>
                          {inc.incident_id}
                        </span>
                        {inc.is_approved_activity && (
                          <span className="badge badge-approved" style={{ fontSize: 10 }}>
                            Approved
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="mono" style={{ color: '#38bdf8', fontWeight: 600 }}>
                      {inc.affected_hosts?.join(', ')}
                    </td>

                    <td>
                      <span className={`badge ${sevBadge}`}>{inc.severity}</span>
                    </td>

                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{ width: 60, height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                          <div style={{ width: `${inc.score}%`, height: '100%', backgroundColor: scoreColor }} />
                        </div>
                        <span style={{ fontWeight: 700, color: scoreColor, fontSize: 13 }}>
                          {inc.score}
                        </span>
                      </div>
                    </td>

                    <td style={{ fontSize: 12, color: '#cbd5e1' }}>
                      {inc.related_rules?.join(', ')}
                    </td>

                    <td>
                      <span className="badge badge-low">{inc.findings_count}</span>
                    </td>

                    <td style={{ fontSize: 12, color: '#94a3b8' }}>
                      {inc.first_seen?.split(' ')[1] || inc.first_seen} &rarr;{' '}
                      {inc.last_seen?.split(' ')[1] || inc.last_seen}
                    </td>

                    {canManageIncidents && (
                      <td>
                        <select
                          className="form-control"
                          aria-label={`Status for ${inc.incident_id}`}
                          value={inc.status || 'open'}
                          disabled={updatingIncident === inc.incident_id}
                          onClick={(event) => event.stopPropagation()}
                          onChange={(event) => handleStatusChange(inc.incident_id, event.target.value)}
                        >
                          <option value="open">Open</option>
                          <option value="acknowledged">Acknowledged</option>
                          <option value="resolved">Resolved</option>
                        </select>
                      </td>
                    )}

                    <td>
                      <button
                        className="btn btn-outline-cyan btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/incidents/${inc.incident_id}`);
                        }}
                      >
                        Investigate <ArrowRight size={13} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
