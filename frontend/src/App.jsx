import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom';

import Sidebar from './components/Sidebar';
import TopBar from './components/TopBar';

import DashboardPage from './pages/DashboardPage';
import UploadPage from './pages/UploadPage';
import DataQualityPage from './pages/DataQualityPage';
import BaselinePage from './pages/BaselinePage';
import TrafficAnalyticsPage from './pages/TrafficAnalyticsPage';
import HostAnalysisPage from './pages/HostAnalysisPage';
import PortAnalysisPage from './pages/PortAnalysisPage';
import DnsAnalysisPage from './pages/DnsAnalysisPage';
import NetworkGraphPage from './pages/NetworkGraphPage';
import IncidentsPage from './pages/IncidentsPage';
import IncidentDetailPage from './pages/IncidentDetailPage';
import SettingsPage from './pages/SettingsPage';
import ReportsPage from './pages/ReportsPage';
import AuthPage from './pages/AuthPage';
import AdminPage from './pages/AdminPage';

import { api } from './services/api';

function DatasetRequired({ healthData, children }) {
  if (!healthData) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }
  return healthData.dataset_loaded ? children : <Navigate to="/upload" replace />;
}

function RequirePermission({ user, permission, children }) {
  const permissions = user?.permissions || [];
  return permissions.includes('*') || permissions.includes(permission)
    ? children
    : <Navigate to="/" replace />;
}

export default function App() {
  return (
    <Router>
      <Application />
    </Router>
  );
}

function Application() {
  const location = useLocation();
  const navigate = useNavigate();
  const [healthData, setHealthData] = useState(null);
  const [dataRevision, setDataRevision] = useState(0);
  const [authUser, setAuthUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  const refreshHealth = async () => {
    try {
      const data = await api.getHealth();
      setHealthData(data);
    } catch (err) {
      console.warn('API Health Check failed:', err);
    }
  };

  const refreshData = async () => {
    await refreshHealth();
    setDataRevision((revision) => revision + 1);
  };

  useEffect(() => {
    api.getAuthSession()
      .then((session) => {
        setAuthUser(session.user || null);
        if (session.authenticated) return refreshHealth();
      })
      .catch(() => setAuthUser(null))
      .finally(() => setAuthLoading(false));
  }, []);

  const handleAuthenticated = async (user) => {
    setAuthUser(user);
    await refreshData();
    navigate(user.role === 'admin' ? '/admin' : '/', { replace: true });
  };

  const handleLogout = async () => {
    await api.logout();
    setAuthUser(null);
    setHealthData(null);
    navigate('/login', { replace: true });
  };

  if (authLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '100vh' }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }

  if (!authUser) {
    return (
      <Routes>
        <Route path="/signup" element={<AuthPage mode="signup" />} />
        <Route path="/login" element={<AuthPage mode="login" onAuthenticated={handleAuthenticated} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  if (location.pathname === '/signup' || location.pathname === '/login') {
    return <Navigate to={authUser.role === 'admin' ? '/admin' : '/'} replace />;
  }

  return (
      <div className="app-container">
        <Sidebar healthData={healthData} user={authUser} />
        <div className="main-wrapper">
          <TopBar healthData={healthData} onRefresh={refreshData} onLogout={handleLogout} user={authUser} />
          <main className="content-viewport">
            <Routes>
              <Route path="/" element={<DatasetRequired healthData={healthData}><DashboardPage dataRevision={dataRevision} onDatasetChanged={refreshData} /></DatasetRequired>} />
              <Route path="/upload" element={<UploadPage onDatasetChanged={refreshData} />} />
              <Route path="/data-quality" element={<DatasetRequired healthData={healthData}><DataQualityPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/baseline" element={<RequirePermission user={authUser} permission="baseline:view"><DatasetRequired healthData={healthData}><BaselinePage canManageBaseline={authUser.role === 'admin'} onBaselineOrAnalysisChanged={refreshData} /></DatasetRequired></RequirePermission>} />
              <Route path="/traffic" element={<DatasetRequired healthData={healthData}><TrafficAnalyticsPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/hosts" element={<DatasetRequired healthData={healthData}><HostAnalysisPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/ports" element={<DatasetRequired healthData={healthData}><PortAnalysisPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/dns" element={<DatasetRequired healthData={healthData}><DnsAnalysisPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/graph" element={<DatasetRequired healthData={healthData}><NetworkGraphPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/incidents" element={<DatasetRequired healthData={healthData}><IncidentsPage canManageIncidents={authUser.permissions?.includes('*') || authUser.permissions?.includes('incidents:manage')} dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/incidents/:id" element={<DatasetRequired healthData={healthData}><IncidentDetailPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/settings" element={<RequirePermission user={authUser} permission="admin:settings"><SettingsPage /></RequirePermission>} />
              <Route path="/admin" element={<RequirePermission user={authUser} permission="admin:manage"><AdminPage /></RequirePermission>} />
              <Route path="/reports" element={<DatasetRequired healthData={healthData}><ReportsPage dataRevision={dataRevision} /></DatasetRequired>} />
              <Route path="/login" element={<Navigate to="/" replace />} />
              <Route path="/signup" element={<Navigate to="/" replace />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </div>
  );
}
