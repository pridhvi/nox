import { useQuery } from "@tanstack/react-query";
import { effectiveConfig } from "../api/client";

export function Settings() {
  const configQuery = useQuery({ queryKey: ["effective-config"], queryFn: effectiveConfig });
  const cfg = configQuery.data;
  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Settings</h1>
          <p>Read-only effective configuration and environment health.</p>
        </div>
      </header>
      <div className="settings-grid">
        <section className="panel">
          <h2>Runtime</h2>
          <dl><dt>Session Dir</dt><dd>{cfg?.database.session_dir}</dd><dt>Platform</dt><dd>{cfg?.runtime.goos}/{cfg?.runtime.goarch}</dd><dt>Auth</dt><dd>{cfg?.server.auth_enabled ? "enabled" : "disabled"}</dd></dl>
        </section>
        <section className="panel">
          <h2>LLM</h2>
          <dl><dt>Enabled</dt><dd>{cfg?.llm.enabled ? "yes" : "no"}</dd><dt>Configured</dt><dd>{cfg?.llm.configured ? "yes" : "no"}</dd><dt>Model</dt><dd>{cfg?.llm.model}</dd><dt>API Key</dt><dd>{cfg?.llm.api_key_set ? "set" : "not set"}</dd></dl>
        </section>
        <section className="panel">
          <h2>CVE</h2>
          <pre>{JSON.stringify(cfg?.cve ?? {}, null, 2)}</pre>
        </section>
        <section className="panel">
          <h2>Tool Paths</h2>
          <pre>{JSON.stringify(cfg?.tools ?? {}, null, 2)}</pre>
        </section>
      </div>
    </section>
  );
}
