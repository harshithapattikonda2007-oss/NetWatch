import React, { useState, useEffect } from 'react';
import {
  Activity,
  ArrowUpDown,
  PieChart as PieIcon,
  BarChart2,
  Filter,
  Server
} from 'lucide-react';
import {
  AreaChart,
  Area,
  LineChart,
  Line,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ReferenceDot,
  ResponsiveContainer
} from 'recharts';
import { api } from '../services/api';

export default function TrafficAnalyticsPage({ dataRevision }) {
  const [interval, setInterval] = useState(5);
  const [trafficData, setTrafficData] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchTraffic = async (intVal) => {
    try {
      setLoading(true);
      const res = await api.getTrafficAnalytics(intVal);
      setTrafficData(res);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTraffic(interval);
  }, [interval, dataRevision]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <Activity color="#38bdf8" /> Network Traffic Analytics
          </h1>
          <p className="page-subtitle">
            Temporal flow aggregation, volume fluctuations, protocol composition, and endpoint talkers.
          </p>
        </div>

        {/* Interval Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 13, color: '#94a3b8' }}>Binning Window:</span>
          {[1, 5, 60].map((mins) => (
            <button
              key={mins}
              className={`btn btn-sm ${interval === mins ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setInterval(mins)}
            >
              {mins === 60 ? '1 Hour' : `${mins} Min`}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
          <div className="spinner" style={{ width: 36, height: 36 }} />
        </div>
      ) : !trafficData || !trafficData.time_series || trafficData.time_series.length === 0 ? (
        <div className="card empty-state">
          <Activity className="empty-icon" />
          <h2 className="empty-title">No Traffic Data Available</h2>
          <p className="empty-text">Upload network flow data to analyze bandwidth and protocols.</p>
        </div>
      ) : (
        <>
          {/* Chart 1: Bandwidth Sent vs Received */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div className="card-title">
              <span>Bandwidth Over Time (Bytes Sent vs Received)</span>
              <span className="badge badge-low">{interval}-minute buckets</span>
            </div>
            <div style={{ height: 300, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trafficData.time_series}>
                  <defs>
                    <linearGradient id="areaSent" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.7} />
                      <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0} />
                    </linearGradient>
                    <linearGradient id="areaRecv" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#818cf8" stopOpacity={0.7} />
                      <stop offset="95%" stopColor="#818cf8" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="timestamp"
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    tickFormatter={(val) => (val ? val.split(' ')[1] || val : '')}
                  />
                  <YAxis
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    tickFormatter={(b) =>
                      b > 1048576 ? `${(b / 1048576).toFixed(1)} MB` : `${(b / 1024).toFixed(0)} KB`
                    }
                  />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }}
                    formatter={(v) => [`${(v / 1024).toFixed(1)} KB`, '']}
                  />
                  <Legend wrapperStyle={{ paddingTop: 10 }} />
                  <Area type="monotone" dataKey="bytes_sent" name="Bytes Sent" stroke="#38bdf8" fill="url(#areaSent)" />
                  <Area type="monotone" dataKey="bytes_received" name="Bytes Received" stroke="#818cf8" fill="url(#areaRecv)" />
                  {trafficData.time_series.filter((bucket) => bucket.anomaly_count > 0 || bucket.approved_activity_count > 0).map((bucket) => (
                    <ReferenceDot
                      key={`anomaly-${bucket.timestamp}`}
                      x={bucket.timestamp}
                      y={Math.max(bucket.bytes_sent, bucket.bytes_received)}
                      r={6}
                      fill={bucket.anomaly_count > 0 ? '#ef4444' : '#10b981'}
                      stroke="#fff"
                      ifOverflow="visible"
                    />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {(trafficData.anomaly_markers || []).length > 0 && (
            <div className="card" style={{ marginBottom: 24 }}>
              <div className="card-title">Traffic Deviations & Trigger Measurements ({trafficData.anomaly_markers.length})</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr><th>Time</th><th>Host</th><th>Rule</th><th>Observed</th><th>Trigger Threshold</th><th>Explanation</th></tr>
                  </thead>
                  <tbody>
                    {trafficData.anomaly_markers.map((finding) => (
                      <tr key={finding.finding_id}>
                        <td className="mono">{finding.timestamp}</td>
                        <td className="mono">{finding.affected_host}</td>
                        <td>{finding.rule_name}{finding.is_suppressed && <span className="badge badge-approved" style={{ marginLeft: 6 }}>Approved</span>}</td>
                        <td>{finding.observed_value}</td>
                        <td>{finding.baseline_threshold}</td>
                        <td>{finding.is_suppressed ? finding.suppression_reason : finding.explanation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Chart 2: Connections & Packet Velocity */}
          <div className="card" style={{ marginBottom: 24 }}>
            <div className="card-title">Connection Counts & Packet Velocity</div>
            <div style={{ height: 240, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trafficData.time_series}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="timestamp"
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    tickFormatter={(val) => (val ? val.split(' ')[1] || val : '')}
                  />
                  <YAxis stroke="#64748b" tick={{ fontSize: 11 }} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: 8 }}
                  />
                  <Legend wrapperStyle={{ paddingTop: 10 }} />
                  <Line type="monotone" dataKey="connections" name="Connections" stroke="#10b981" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="packets" name="Packets" stroke="#f59e0b" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Grid: Protocols & Top Talkers */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 20 }}>
            {/* Protocol Distribution */}
            <div className="card">
              <div className="card-title">Protocol Distribution</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Flows Count</th>
                      <th>Total Volume</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trafficData.protocols?.map((p, idx) => (
                      <tr key={idx}>
                        <td className="mono" style={{ fontWeight: 600, color: '#38bdf8' }}>{p.protocol}</td>
                        <td>{p.count?.toLocaleString()}</td>
                        <td>{(p.total_bytes / 1024).toFixed(1)} KB</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Top Talkers */}
            <div className="card">
              <div className="card-title">Top Volume Talkers</div>
              <div className="table-container">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Host IP</th>
                      <th>Total Bytes</th>
                      <th>Destinations</th>
                      <th>Connections</th>
                    </tr>
                  </thead>
                  <tbody>
                    {trafficData.top_talkers?.map((talker, idx) => (
                      <tr key={idx}>
                        <td className="mono" style={{ color: '#38bdf8', fontWeight: 600 }}>{talker.host}</td>
                        <td>{(talker.total_bytes / 1024).toFixed(1)} KB</td>
                        <td>{talker.distinct_destinations}</td>
                        <td>{talker.connections}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
