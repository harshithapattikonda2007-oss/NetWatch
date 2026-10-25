import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Database, Play, Sparkles, RefreshCw, LogOut } from 'lucide-react';
import { api } from '../services/api';

export default function TopBar({ healthData, onRefresh, onLogout, user }) {
  const navigate = useNavigate();
  const [loadingSample, setLoadingSample] = useState(false);

  const handleLoadSample = async () => {
    try {
      setLoadingSample(true);
      await api.loadSampleDataset();
      await onRefresh();
      navigate('/upload');
    } catch (err) {
      alert(`Error loading sample dataset: ${err.message}`);
    } finally {
      setLoadingSample(false);
    }
  };

  return (
    <header className="top-bar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div className="dataset-pill">
          <Database size={15} color="#38bdf8" />
          <span>
            Target: <strong>{healthData?.dataset_loaded ? 'Active Flow Dataset' : 'No Dataset Selected'}</strong>
          </span>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{ color: '#94a3b8', fontSize: 12 }}>
          {user?.email} · {user?.role === 'admin' ? 'Admin' : 'Security Analyst'}
        </span>
        <button
          className="btn btn-secondary btn-sm"
          onClick={handleLoadSample}
          disabled={loadingSample}
          title="Load pre-built synthetic dataset with 7 anomaly scenarios"
        >
          {loadingSample ? (
            <span className="spinner" style={{ width: 14, height: 14 }} />
          ) : (
            <Sparkles size={14} color="#38bdf8" />
          )}
          <span>Load Synthetic Sample</span>
        </button>

        <button
          className="btn btn-primary btn-sm"
          onClick={() => navigate('/baseline')}
        >
          <Play size={14} />
          <span>Baseline & Detection</span>
        </button>

        <button
          className="btn btn-secondary btn-sm"
          onClick={onRefresh}
          title="Refresh system state"
          style={{ padding: '6px 8px' }}
        >
          <RefreshCw size={14} />
        </button>
        <button
          className="btn btn-secondary btn-sm"
          onClick={onLogout}
          title="Sign out"
          aria-label="Sign out"
          style={{ padding: '6px 8px' }}
        >
          <LogOut size={14} />
        </button>
      </div>
    </header>
  );
}
