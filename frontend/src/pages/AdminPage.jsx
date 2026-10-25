import React, { useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle, ShieldCheck, UserPlus, Users } from 'lucide-react';
import { api } from '../services/api';

const ROLE_LABELS = {
  admin: 'Admin',
  security_analyst: 'Security Analyst',
};

export default function AdminPage() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState({});
  const [auditEvents, setAuditEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [updatingUser, setUpdatingUser] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('security_analyst');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  const loadAdminData = async () => {
    try {
      const [userData, roleData, auditData] = await Promise.all([
        api.getAdminUsers(),
        api.getRolePermissions(),
        api.getAuditEvents(),
      ]);
      setUsers(userData.users);
      setRoles(roleData.roles);
      setAuditEvents(auditData.events);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAdminData();
  }, []);

  const handleCreateUser = async (event) => {
    event.preventDefault();
    setError('');
    setNotice('');
    try {
      setSaving(true);
      const result = await api.createAdminUser(email, password, role);
      setUsers((currentUsers) => [...currentUsers, result.user]);
      setEmail('');
      setPassword('');
      setNotice(`Created ${ROLE_LABELS[result.user.role]} account for ${result.user.email}.`);
      await loadAdminData();
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setSaving(false);
    }
  };

  const handleRoleChange = async (user, nextRole) => {
    if (user.role === nextRole) return;
    setError('');
    setNotice('');
    try {
      setUpdatingUser(user.id);
      const result = await api.updateUserRole(user.id, nextRole);
      setUsers((currentUsers) => currentUsers.map((item) => (
        item.id === user.id ? result.user : item
      )));
      setNotice(`Updated ${user.email} to ${ROLE_LABELS[result.user.role]}.`);
      const auditData = await api.getAuditEvents();
      setAuditEvents(auditData.events);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setUpdatingUser('');
    }
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '60vh' }}>
        <div className="spinner" style={{ width: 36, height: 36 }} />
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title"><ShieldCheck color="#38bdf8" /> Administration & Access Control</h1>
          <p className="page-subtitle">Manage accounts, assign fixed role permissions, and review security audit events.</p>
        </div>
      </div>

      {error && <div className="alert alert-danger"><AlertTriangle size={18} /><div>{error}</div></div>}
      {notice && <div className="alert alert-success"><CheckCircle size={18} /><div>{notice}</div></div>}

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title"><span><UserPlus size={17} /> Create account</span></div>
        <form onSubmit={handleCreateUser} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(190px, 1fr))', gap: 14, alignItems: 'end' }}>
          <div className="form-group">
            <label className="form-label" htmlFor="admin-user-email">Email address</label>
            <input id="admin-user-email" className="form-control" type="email" value={email} onChange={(event) => setEmail(event.target.value)} maxLength={254} required />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="admin-user-password">Account password</label>
            <input id="admin-user-password" className="form-control" type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={12} maxLength={1024} autoComplete="new-password" required />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="admin-user-role">Role</label>
            <select id="admin-user-role" className="form-control" value={role} onChange={(event) => setRole(event.target.value)}>
              {Object.entries(ROLE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </div>
          <button className="btn btn-primary" type="submit" disabled={saving}>
            <UserPlus size={15} /> {saving ? 'Creating...' : 'Create account'}
          </button>
        </form>
        <p style={{ color: '#94a3b8', fontSize: 11, marginTop: 12 }}>Passwords must contain at least 12 characters. They are stored as salted PBKDF2 hashes.</p>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title"><span><Users size={17} /> Users & roles</span><span className="badge badge-low">{users.length} accounts</span></div>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>Email</th><th>Created</th><th>Role</th></tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id}>
                  <td>{user.email}</td>
                  <td>{new Date(user.created_at * 1000).toLocaleString()}</td>
                  <td>
                    <select
                      className="form-control"
                      aria-label={`Role for ${user.email}`}
                      value={user.role}
                      disabled={updatingUser === user.id}
                      onChange={(event) => handleRoleChange(user, event.target.value)}
                    >
                      {Object.entries(ROLE_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title"><span><ShieldCheck size={17} /> Role permissions</span></div>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>Capability</th>{Object.keys(roles).map((roleName) => <th key={roleName}>{ROLE_LABELS[roleName] || roleName}</th>)}</tr>
            </thead>
            <tbody>
              {Array.from(new Set(Object.values(roles).flat())).map((permission) => (
                <tr key={permission}>
                  <td>{permission === '*' ? 'All application permissions' : permission}</td>
                  {Object.entries(roles).map(([roleName, permissions]) => (
                    <td key={roleName}>{permissions.includes('*') || permissions.includes(permission) ? 'Allowed' : '—'}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ color: '#94a3b8', fontSize: 11, marginTop: 12 }}>Permissions are assigned by the server-side role policy and cannot be overridden by the browser.</p>
      </div>

      <div className="card">
        <div className="card-title"><span>Security audit log</span><span className="badge badge-low">{auditEvents.length} events</span></div>
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr>
            </thead>
            <tbody>
              {auditEvents.map((event) => (
                <tr key={event.id}>
                  <td>{new Date(event.created_at * 1000).toLocaleString()}</td>
                  <td>{event.actor_email || 'System'}</td>
                  <td>{event.action}</td>
                  <td>{event.target || '—'}</td>
                  <td><code>{JSON.stringify(event.details)}</code></td>
                </tr>
              ))}
              {auditEvents.length === 0 && <tr><td colSpan="5">No audit events recorded.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
