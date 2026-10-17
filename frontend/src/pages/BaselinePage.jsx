import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  GitBranch,
  Calendar,
  ShieldCheck,
  AlertTriangle,
  Play,
  CheckCircle,
  Database,
  ArrowRight,
  TrendingUp,
  Server
} from 'lucide-react';
import { api } from '../services/api';

export default function BaselinePage({ canManageBaseline = false, onBaselineOrAnalysisChanged }) {
  const navigate = useNavigate();
  const [timeRange, setTimeRange] = useState(null);
  const [learningStart, setLearningStart] = useState('');
  const [learningEnd, setLearningEnd] = useState('');
  const [evalStart, setEvalStart] = useState('');
  const [evalEnd, setEvalEnd] = useState('');
  const [minRecords, setMinRecords] = useState(10);

  const [buildingBaseline, setBuildingBaseline] = useState(false);
  const [baselineSummary, setBaselineSummary] = useState(null);
  const [runningAnalysis, setRunningAnalysis] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setTimeRange(null);
    api.getBaseline()
      .then((data) => setBaselineSummary(data.baseline_summary || null))
      .catch((err) => setError(`Failed to load baseline: ${err.message}`));
    api.getTimeRange()
      .then((data) => {
        if (data.available) {
          setTimeRange(data);

          // Default initial suggestions based on time range
          const minTs = data.min_timestamp;
          const maxTs = data.max_timestamp;

          if (minTs && maxTs) {
            // If sample dataset (starts with 2026-03-01):
            if (minTs.startsWith('2026-03-01')) {
              setLearningStart('2026-03-01 08:00:00');
              setLearningEnd('2026-03-01 18:00:00');
              setEvalStart('2026-03-02 08:00:00');
              setEvalEnd('2026-03-02 18:00:00');
            } else {
              setLearningStart(minTs);
              setLearningEnd(data.suggested_learning_end || '');
              setEvalStart(data.suggested_evaluation_start || '');
              setEvalEnd(maxTs);
            }
          }
        }
      })
      .catch((err) => setError(`Failed to load dataset time range: ${err.message}`));
  }, []);

  const handleBuildBaseline = async () => {
    try {
      setBuildingBaseline(true);
      setError(null);
      const res = await api.buildBaseline(learningStart, learningEnd, parseInt(minRecords, 10));
      setBaselineSummary(res.baseline_summary);
      if (onBaselineOrAnalysisChanged) onBaselineOrAnalysisChanged();
    } catch (err) {
      setError(`Failed to build baseline: ${err.message}`);
    } finally {
      setBuildingBaseline(false);
    }
  };

  const handleRunAnalysis = async () => {
    try {
      setRunningAnalysis(true);
      setError(null);
      const res = await api.runAnalysis(evalStart, evalEnd);
      setAnalysisResult(res);
      if (onBaselineOrAnalysisChanged) onBaselineOrAnalysisChanged();
    } catch (err) {
      setError(`Detection failed: ${err.message}`);
    } finally {
      setRunningAnalysis(false);
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <GitBranch color="#38bdf8" /> Learning Period & Behavioral Baseline
          </h1>
          <p className="page-subtitle">
            Train per-host statistical profiles on historical traffic with strict temporal separation to prevent leakage.
          </p>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger">
          <AlertTriangle size={18} />
          <div>{error}</div>
        </div>
      )}

      {/* Dataset Range Context */}
      {timeRange && (
        <div className="alert alert-info">
          <Calendar size={18} />
          <div>
            <strong>Available Dataset Timespan:</strong> {timeRange.min_timestamp} to {timeRange.max_timestamp}{' '}
            ({timeRange.total_records?.toLocaleString()} records available)
          </div>
        </div>
      )}

      {timeRange && !timeRange.split_available && (
        <div className="alert alert-warning">
          <AlertTriangle size={18} />
          <div>A leakage-safe baseline and evaluation split requires at least two distinct timestamps. This dataset has only one.</div>
        </div>
      )}

      {/* Period Selection Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 24 }}>
        {canManageBaseline && <div className="card" style={{ borderTop: '3px solid #38bdf8' }}>
          <div className="card-title">
            <span>1. Historical Learning Period</span>
            <span className="badge badge-low">Baseline Training</span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
            Captures normal host behavior: average volumes, destination sets, service ports, and failure rates.
          </p>

          <div className="form-group">
            <label className="form-label">Learning Start (YYYY-MM-DD HH:MM:SS)</label>
            <input
              type="text"
              className="form-control mono"
              value={learningStart}
              onChange={(e) => setLearningStart(e.target.value)}
              placeholder="2026-03-01 08:00:00"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Learning End (YYYY-MM-DD HH:MM:SS)</label>
            <input
              type="text"
              className="form-control mono"
              value={learningEnd}
              onChange={(e) => setLearningEnd(e.target.value)}
              placeholder="2026-03-01 18:00:00"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Min Records per Baseline Threshold</label>
            <input
              type="number"
              className="form-control"
              value={minRecords}
              onChange={(e) => setMinRecords(e.target.value)}
              min={1}
            />
          </div>

          <button
            className="btn btn-outline-cyan"
            style={{ width: '100%', marginTop: 8 }}
            onClick={handleBuildBaseline}
            disabled={buildingBaseline}
          >
            {buildingBaseline ? (
              <span className="spinner" style={{ width: 14, height: 14 }} />
            ) : (
              <Server size={16} />
            )}
            <span>{buildingBaseline ? 'Training Baseline Model...' : 'Build Historical Baseline'}</span>
          </button>
        </div>}

        {/* Phase 2: Evaluation Period */}
        <div className="card" style={{ borderTop: '3px solid #6366f1' }}>
          <div className="card-title">
            <span>2. Evaluation Period</span>
            <span className="badge badge-medium">Anomaly Evaluation</span>
          </div>
          <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
            Period to analyze for anomalies against the trained baseline. Overlapping with learning period is rejected.
          </p>

          <div className="form-group">
            <label className="form-label">Evaluation Start (YYYY-MM-DD HH:MM:SS)</label>
            <input
              type="text"
              className="form-control mono"
              value={evalStart}
              onChange={(e) => setEvalStart(e.target.value)}
              placeholder="2026-03-02 08:00:00"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Evaluation End (YYYY-MM-DD HH:MM:SS)</label>
            <input
              type="text"
              className="form-control mono"
              value={evalEnd}
              onChange={(e) => setEvalEnd(e.target.value)}
              placeholder="2026-03-02 18:00:00"
            />
          </div>

          <div style={{ marginTop: 46 }}>
            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={handleRunAnalysis}
              disabled={runningAnalysis}
            >
              {runningAnalysis ? (
                <span className="spinner" style={{ width: 14, height: 14 }} />
              ) : (
                <Play size={16} />
              )}
              <span>{runningAnalysis ? 'Executing Detection Engines...' : 'Execute Anomaly Detectors'}</span>
            </button>
          </div>
        </div>
      </div>

      {baselineSummary ? (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-title" style={{ color: '#10b981' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <CheckCircle size={18} /> Active Behavioral Baseline
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
            <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Profiled Hosts</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#38bdf8', marginTop: 4 }}>
                {baselineSummary.hosts_profiled_count}
              </div>
            </div>
            <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Learning Records Used</div>
              <div style={{ fontSize: 20, fontWeight: 700, color: '#f8fafc', marginTop: 4 }}>
                {baselineSummary.learning_records_count?.toLocaleString()}
              </div>
            </div>
            <div style={{ padding: 12, background: 'rgba(30, 41, 59, 0.4)', borderRadius: 8 }}>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Learning Time Window</div>
              <div style={{ fontSize: 13, color: '#cbd5e1', marginTop: 6 }} className="mono">
                {baselineSummary.learning_start} &rarr; {baselineSummary.learning_end}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="alert alert-info">
          <ShieldCheck size={18} />
          <div>No baseline has been established for the active dataset yet.</div>
        </div>
      )}

      {/* Detection Result Summary Banner */}
      {analysisResult && (
        <div className="card" style={{ border: '1px solid rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.05)' }}>
          <div className="card-title" style={{ color: '#f87171' }}>
            <span>Detection Analysis Completed</span>
            <button className="btn btn-primary btn-sm" onClick={() => navigate('/incidents')}>
              View Incidents ({analysisResult.total_incidents}) <ArrowRight size={14} />
            </button>
          </div>
          <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap', marginTop: 8 }}>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Evaluation Records Analyzed:</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#fff' }}>
                {analysisResult.evaluation_records?.toLocaleString()}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Total Rule Findings:</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#f59e0b' }}>
                {analysisResult.total_findings}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: '#94a3b8' }}>Correlated Incidents:</div>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#ef4444' }}>
                {analysisResult.total_incidents}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
