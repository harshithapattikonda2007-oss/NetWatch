import React, { useState, useEffect } from 'react';
import {
  Sliders,
  Save,
  CheckCircle,
  AlertTriangle,
  RotateCcw,
  ShieldCheck,
  Plus,
  Trash2
} from 'lucide-react';
import { api } from '../services/api';

export default function SettingsPage() {
  const [config, setConfig] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [statusMessage, setStatusMessage] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  useEffect(() => {
    api.getConfig()
      .then((data) => setConfig(data))
      .catch((err) => setErrorMessage(err.message))
      .finally(() => setLoading(false));
  }, []);

  const handleRuleToggle = (ruleKey) => {
    setConfig((prev) => ({
      ...prev,
      rules: {
        ...prev.rules,
        [ruleKey]: {
          ...prev.rules[ruleKey],
          enabled: !prev.rules[ruleKey].enabled,
        },
      },
    }));
  };

  const handleRuleParamChange = (ruleKey, paramKey, val) => {
    const num = isNaN(Number(val)) ? val : Number(val);
    setConfig((prev) => ({
      ...prev,
      rules: {
        ...prev.rules,
        [ruleKey]: {
          ...prev.rules[ruleKey],
          [paramKey]: num,
        },
      },
    }));
  };

  const handleWeightChange = (key, val) => {
    const num = parseFloat(val);
    setConfig((prev) => ({
      ...prev,
      scoring: {
        ...prev.scoring,
        weights: {
          ...prev.scoring.weights,
          [key]: num,
        },
      },
    }));
  };

  const handleRuleWeightChange = (ruleId, val) => {
    const num = parseFloat(val);
    setConfig((prev) => ({
      ...prev,
      scoring: {
        ...prev.scoring,
        rule_weights: {
          ...prev.scoring.rule_weights,
          [ruleId]: num,
        },
      },
    }));
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      setStatusMessage(null);
      setErrorMessage(null);

      // Client-side quick check
      if (config.scoring && config.scoring.weights) {
        const totalW = Object.values(config.scoring.weights).reduce((a, b) => a + Number(b), 0);
        if (Math.abs(totalW - 1.0) > 0.05) {
          throw new Error(`Scoring weights must sum to 1.0 (current sum: ${totalW.toFixed(2)})`);
        }
      }

      const res = await api.updateConfig(config);
      setStatusMessage('Configuration successfully validated and saved to config/settings.yaml!');
    } catch (err) {
      setErrorMessage(err.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }

  if (!config) return null;

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Sliders color="#38bdf8" /> Anomaly Detection & Scoring Settings
          </h1>
          <p className="page-subtitle">
            Configure threshold multipliers, time-window intervals, scoring weights, and approved maintenance lists.
          </p>
        </div>

        <button
          className="btn btn-primary"
          onClick={handleSave}
          disabled={saving}
        >
          {saving ? <span className="spinner" style={{ width: 14, height: 14 }} /> : <Save size={16} />}
          <span>{saving ? 'Saving Changes...' : 'Save Configuration'}</span>
        </button>
      </div>

      {statusMessage && (
        <div className="alert alert-success">
          <CheckCircle size={18} />
          <div>{statusMessage}</div>
        </div>
      )}

      {errorMessage && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} />
          <div>{errorMessage}</div>
        </div>
      )}

      {/* Rules Configuration */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title">
          <span>7 Rule-Based Anomaly Detection Engines</span>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Rule A: Data Transfer */}
          {config.rules?.unusual_data_transfer && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule A: Unusual Data Transfer</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.unusual_data_transfer.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.unusual_data_transfer.enabled}
                    onChange={() => handleRuleToggle('unusual_data_transfer')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Baseline Multiplier</label>
                  <input
                    type="number"
                    step="0.5"
                    className="form-control"
                    value={config.rules.unusual_data_transfer.baseline_multiplier}
                    onChange={(e) => handleRuleParamChange('unusual_data_transfer', 'baseline_multiplier', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min Bytes Threshold</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.unusual_data_transfer.min_bytes_threshold}
                    onChange={(e) => handleRuleParamChange('unusual_data_transfer', 'min_bytes_threshold', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule B: Port Probing */}
          {config.rules?.port_probing && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule B: Port Probing</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.port_probing.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.port_probing.enabled}
                    onChange={() => handleRuleToggle('port_probing')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Distinct Port Threshold</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.port_probing.distinct_port_threshold}
                    onChange={(e) => handleRuleParamChange('port_probing', 'distinct_port_threshold', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Window Size (Seconds)</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.port_probing.time_window_seconds}
                    onChange={(e) => handleRuleParamChange('port_probing', 'time_window_seconds', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule C: Destination Diversity */}
          {config.rules?.destination_diversity && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule C: Destination Diversity</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.destination_diversity.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.destination_diversity.enabled}
                    onChange={() => handleRuleToggle('destination_diversity')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min Distinct Targets Threshold</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.destination_diversity.min_dest_threshold}
                    onChange={(e) => handleRuleParamChange('destination_diversity', 'min_dest_threshold', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Window Size (Seconds)</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.destination_diversity.time_window_seconds}
                    onChange={(e) => handleRuleParamChange('destination_diversity', 'time_window_seconds', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule D: Periodic Beaconing */}
          {config.rules?.periodic_connections && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule D: Periodic Connections (Beaconing)</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.periodic_connections.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.periodic_connections.enabled}
                    onChange={() => handleRuleToggle('periodic_connections')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min Occurrences</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.periodic_connections.min_occurrences}
                    onChange={(e) => handleRuleParamChange('periodic_connections', 'min_occurrences', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Coefficient of Variation Max (CV)</label>
                  <input
                    type="number"
                    step="0.05"
                    className="form-control"
                    value={config.rules.periodic_connections.cv_threshold}
                    onChange={(e) => handleRuleParamChange('periodic_connections', 'cv_threshold', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule E: Unexpected Communication */}
          {config.rules?.unexpected_host_communication && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule E: Unexpected Host Communication</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.unexpected_host_communication.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.unexpected_host_communication.enabled}
                    onChange={() => handleRuleToggle('unexpected_host_communication')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min Baseline Flows to Qualify</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.unexpected_host_communication.min_baseline_flows}
                    onChange={(e) => handleRuleParamChange('unexpected_host_communication', 'min_baseline_flows', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule F: DNS Behaviour */}
          {config.rules?.dns_behaviour && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule F: DNS Behaviour Analysis</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.dns_behaviour.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.dns_behaviour.enabled}
                    onChange={() => handleRuleToggle('dns_behaviour')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min DNS Queries</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.dns_behaviour.min_query_volume}
                    onChange={(e) => handleRuleParamChange('dns_behaviour', 'min_query_volume', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Unique Domain Ratio Threshold</label>
                  <input
                    type="number"
                    step="0.05"
                    className="form-control"
                    value={config.rules.dns_behaviour.unique_query_ratio_threshold}
                    onChange={(e) => handleRuleParamChange('dns_behaviour', 'unique_query_ratio_threshold', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          {/* Rule G: Blocked Connections */}
          {config.rules?.blocked_failed_connections && (
            <div style={{ background: 'rgba(30, 41, 59, 0.4)', padding: 16, borderRadius: 8 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div>
                  <strong style={{ fontSize: 14, color: '#fff' }}>Rule G: Blocked or Failed Connections</strong>
                  <div style={{ fontSize: 12, color: '#94a3b8' }}>{config.rules.blocked_failed_connections.description}</div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={config.rules.blocked_failed_connections.enabled}
                    onChange={() => handleRuleToggle('blocked_failed_connections')}
                  />
                  <span style={{ fontSize: 13 }}>Enabled</span>
                </label>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Min Failed Events Count</label>
                  <input
                    type="number"
                    className="form-control"
                    value={config.rules.blocked_failed_connections.min_failed_count}
                    onChange={(e) => handleRuleParamChange('blocked_failed_connections', 'min_failed_count', e.target.value)}
                  />
                </div>
                <div>
                  <label className="form-label" style={{ fontSize: 11 }}>Failure Rate Threshold (e.g. 0.35)</label>
                  <input
                    type="number"
                    step="0.05"
                    className="form-control"
                    value={config.rules.blocked_failed_connections.failure_rate_threshold}
                    onChange={(e) => handleRuleParamChange('blocked_failed_connections', 'failure_rate_threshold', e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Incident Scoring Weights */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title">
          <span>Incident Risk Scoring Weights (Must Sum to 1.0)</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14 }}>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Severity Weight</label>
            <input
              type="number"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.severity || 0.35}
              onChange={(e) => handleWeightChange('severity', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Deviation Weight</label>
            <input
              type="number"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.deviation || 0.25}
              onChange={(e) => handleWeightChange('deviation', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Persistence Weight</label>
            <input
              type="number"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.persistence || 0.20}
              onChange={(e) => handleWeightChange('persistence', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Category Diversity Weight</label>
            <input
              type="number"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.category_diversity || 0.20}
              onChange={(e) => handleWeightChange('category_diversity', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Rule Priority Weight</label>
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.rule_priority ?? 0.10}
              onChange={(e) => handleWeightChange('rule_priority', e.target.value)}
            />
          </div>
          <div>
            <label className="form-label" style={{ fontSize: 12 }}>Correlation Weight</label>
            <input
              type="number"
              min="0"
              max="1"
              step="0.05"
              className="form-control"
              value={config.scoring?.weights?.correlation ?? 0.10}
              onChange={(e) => handleWeightChange('correlation', e.target.value)}
            />
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title"><span>Detection Rule Priority Weights (0-100)</span></div>
        <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
          Rule priorities affect the rule-priority component of each incident score. Changes apply on the next analysis run.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 14 }}>
          {Object.entries(config.scoring?.rule_weights || {}).map(([ruleId, weight]) => (
            <div key={ruleId}>
              <label className="form-label" style={{ fontSize: 12 }}>{ruleId.replace('RULE_', '').replaceAll('_', ' ')}</label>
              <input
                type="number"
                min="0"
                max="100"
                step="1"
                className="form-control"
                value={weight}
                onChange={(e) => handleRuleWeightChange(ruleId, e.target.value)}
              />
            </div>
          ))}
        </div>
      </div>

      {/* Approved Activities List */}
      <div className="card">
        <div className="card-title">
          <span>Explicitly Approved Activities & Scheduled Maintenance</span>
        </div>
        <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
          Approved activities are tagged and contextualized in reports, but findings and evidence are{' '}
          <strong>never silently deleted</strong>.
        </p>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Activity ID</th>
                <th>Name</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Ports</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {config.approved_activities?.map((act, i) => (
                <tr key={i}>
                  <td className="mono" style={{ color: '#38bdf8' }}>{act.id}</td>
                  <td style={{ fontWeight: 600 }}>{act.name}</td>
                  <td className="mono">{act.source_ip}</td>
                  <td className="mono">{act.destination_ip || 'Any'}</td>
                  <td className="mono">{act.ports?.length > 0 ? act.ports.join(', ') : 'Any'}</td>
                  <td style={{ fontSize: 12, color: '#94a3b8' }}>{act.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
