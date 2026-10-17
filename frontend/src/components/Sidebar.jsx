import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Upload,
  ShieldCheck,
  GitBranch,
  Activity,
  Server,
  Network,
  Globe,
  Share2,
  AlertTriangle,
  Sliders,
  FileText,
  ShieldAlert,
  UsersRound
} from 'lucide-react';

export default function Sidebar({ healthData, user }) {
  const isAdmin = user?.role === 'admin';
  const navSections = [
    {
      title: 'Operations',
      items: [
        { path: '/', label: 'Dashboard', icon: LayoutDashboard },
        { path: '/upload', label: 'Upload Dataset', icon: Upload },
        { path: '/data-quality', label: 'Data Quality', icon: ShieldCheck },
        { path: '/baseline', label: 'Learning & Baseline', icon: GitBranch },
      ],
    },
    {
      title: 'Analytics',
      items: [
        { path: '/traffic', label: 'Traffic Analytics', icon: Activity },
        { path: '/hosts', label: 'Host Analysis', icon: Server },
        { path: '/ports', label: 'Port Analysis', icon: Network },
        { path: '/dns', label: 'DNS Analysis', icon: Globe },
        { path: '/graph', label: 'Network Graph', icon: Share2 },
      ],
    },
    {
      title: 'Investigation',
      items: [
        { path: '/incidents', label: 'Incidents', icon: AlertTriangle },
        ...(isAdmin ? [
          { path: '/settings', label: 'Detection Settings', icon: Sliders },
          { path: '/admin', label: 'Admin & Access', icon: UsersRound },
        ] : []),
        { path: '/reports', label: 'Reports & Exports', icon: FileText },
      ],
    },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="logo-icon">
          <ShieldAlert size={20} color="#fff" />
        </div>
        <div>
          <div className="logo-text">NETWATCH</div>
          <div className="logo-tag">Traffic Anomaly SOC</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navSections.map((sec, idx) => (
          <div key={idx}>
            <div className="nav-section-title">{sec.title}</div>
            {sec.items.map((item) => {
              const Icon = item.icon;
              return (
                <NavLink
                  key={item.path}
                  to={item.path}
                  className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
                  end={item.path === '/'}
                >
                  <Icon size={17} />
                  <span>{item.label}</span>
                </NavLink>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div className="status-badge" style={{ background: 'rgba(30, 41, 59, 0.6)', color: '#94a3b8' }}>
            <span
              className="status-indicator"
              style={{
                backgroundColor: healthData?.dataset_loaded ? '#10b981' : '#64748b',
                color: healthData?.dataset_loaded ? '#10b981' : '#64748b',
              }}
            />
            <span>Data: {healthData?.dataset_loaded ? 'Loaded' : 'None'}</span>
          </div>

          <div className="status-badge" style={{ background: 'rgba(30, 41, 59, 0.6)', color: '#94a3b8' }}>
            <span
              className="status-indicator"
              style={{
                backgroundColor: healthData?.baseline_ready ? '#38bdf8' : '#64748b',
                color: healthData?.baseline_ready ? '#38bdf8' : '#64748b',
              }}
            />
            <span>Baseline: {healthData?.baseline_ready ? 'Trained' : 'Pending'}</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
