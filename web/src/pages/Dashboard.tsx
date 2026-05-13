import { Activity, AlertTriangle, Play } from "lucide-react";

export function Dashboard() {
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Engagement Dashboard</h1>
          <p>Start scoped scans, monitor findings, and review attack paths.</p>
        </div>
        <button className="primary"><Play size={16} />New Scan</button>
      </header>
      <div className="metric-grid">
        <article><Activity /><span>Active Sessions</span><strong>0</strong></article>
        <article><AlertTriangle /><span>Critical Findings</span><strong>0</strong></article>
        <article><Activity /><span>Registered Tools</span><strong>0</strong></article>
      </div>
      <form className="scan-form">
        <label>
          Target
          <input placeholder="https://example.com" />
        </label>
        <label>
          Mode
          <select defaultValue="active">
            <option value="passive">Passive</option>
            <option value="active">Active</option>
            <option value="stealth">Stealth</option>
          </select>
        </label>
        <button type="button" className="primary">Start Scoped Scan</button>
      </form>
    </section>
  );
}

