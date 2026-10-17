import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowRight, LockKeyhole, Mail } from 'lucide-react';
import { api } from '../services/api';
import './AuthPage.css';

export default function AuthPage({ mode, onAuthenticated }) {
  const isSignup = mode === 'signup';
  const location = useLocation();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [demoAccounts, setDemoAccounts] = useState([]);
  const [selectedDemo, setSelectedDemo] = useState('');

  useEffect(() => {
    if (isSignup) return;
    api.getDemoAccounts()
      .then((result) => setDemoAccounts(Array.isArray(result.accounts) ? result.accounts : []))
      .catch(() => setDemoAccounts([]));
  }, [isSignup]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    if (isSignup && password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    try {
      setSubmitting(true);
      if (isSignup) {
        await api.signUp(email, password);
        navigate('/login', { replace: true, state: { registered: true } });
      } else {
        const result = await api.login(email, password);
        await onAuthenticated(result.user);
      }
    } catch (requestError) {
      setError(requestError.message || 'Authentication failed. Please try again.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-screen">
      <section className="auth-brand" aria-label="NetWatch">
        <div className="auth-mark"><Activity size={24} /></div>
        <div className="auth-wordmark">NETWATCH</div>
        <p>Network Traffic Anomaly Detection</p>
        <div className="auth-rule-line" />
        <span>SECURE INVESTIGATION WORKSPACE</span>
      </section>

      <section className="auth-panel">
        <div className="auth-panel-heading">
          <span className="auth-kicker">{isSignup ? 'CREATE ACCOUNT' : 'SECURE ACCESS'}</span>
          <h1>{isSignup ? 'Create your account' : 'Sign in to NetWatch'}</h1>
          <p>{isSignup ? 'Set up an account to access the investigation workspace.' : 'Continue to your network investigation workspace.'}</p>
        </div>

        {!isSignup && location.state?.registered && (
          <div className="auth-success" role="status">Account created. Sign in to continue.</div>
        )}

        {error && (
          <div className="auth-error" role="alert"><AlertTriangle size={16} />{error}</div>
        )}

        {!isSignup && demoAccounts.length > 0 && (
          <section className="auth-demos" aria-label="Demo accounts">
            <h2>Demo accounts</h2>
            <p>Select a role to fill in its demo credentials. Click Sign in to authenticate.</p>
            <div className="auth-demo-list">
              {demoAccounts.map((account) => (
                <button
                  className={`auth-demo ${selectedDemo === account.role ? 'selected' : ''}`}
                  type="button"
                  key={account.role}
                  onClick={() => {
                    setEmail(account.email);
                    setPassword(account.password);
                    setSelectedDemo(account.role);
                    setError('');
                  }}
                >
                  <span>{account.label}</span>
                  <small>{account.role === 'admin' ? 'Full administration access' : 'Security investigation access'}</small>
                </button>
              ))}
            </div>
            {selectedDemo && <p className="auth-demo-selected" role="status">Credentials filled. Click Sign in to continue.</p>}
          </section>
        )}

        <form className="auth-form" onSubmit={handleSubmit}>
          <label htmlFor="auth-email">Email address</label>
          <div className="auth-input-wrap">
            <Mail size={17} aria-hidden="true" />
            <input
              id="auth-email"
              type="email"
              value={email}
              onChange={(event) => {
                setEmail(event.target.value);
                setSelectedDemo('');
              }}
              autoComplete="email"
              required
              maxLength={254}
            />
          </div>

          <label htmlFor="auth-password">Password</label>
          <div className="auth-input-wrap">
            <LockKeyhole size={17} aria-hidden="true" />
            <input
              id="auth-password"
              type="password"
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
                setSelectedDemo('');
              }}
              autoComplete={isSignup ? 'new-password' : 'current-password'}
              minLength={12}
              maxLength={1024}
              required
            />
          </div>

          {isSignup && (
            <>
              <label htmlFor="auth-confirm-password">Confirm password</label>
              <div className="auth-input-wrap">
                <LockKeyhole size={17} aria-hidden="true" />
                <input
                  id="auth-confirm-password"
                  type="password"
                  value={confirmPassword}
                  onChange={(event) => setConfirmPassword(event.target.value)}
                  autoComplete="new-password"
                  minLength={12}
                  maxLength={1024}
                  required
                />
              </div>
              <p className="auth-help">Use at least 12 characters.</p>
            </>
          )}

          <button className="auth-submit" type="submit" disabled={submitting}>
            <span>{submitting ? 'Please wait…' : isSignup ? 'Create account' : 'Sign in'}</span>
            {!submitting && <ArrowRight size={17} />}
          </button>
        </form>

        <div className="auth-switch">
          {isSignup ? 'Already registered?' : 'New to NetWatch?'}{' '}
          <Link to={isSignup ? '/login' : '/signup'}>{isSignup ? 'Sign in' : 'Create account'}</Link>
        </div>
        <p className="auth-footnote">Your password is stored as a salted PBKDF2 hash and is never sent back to the browser.</p>
      </section>
    </main>
  );
}
