import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { listFindings, listSessions, updateFinding, type Finding } from "../api/client";

export function Findings() {
  const params = useParams();
  const queryClient = useQueryClient();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
  const [severity, setSeverity] = useState("");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [editSeverity, setEditSeverity] = useState("");
  const [editRemediation, setEditRemediation] = useState("");
  const findingsQuery = useQuery({
    queryKey: ["findings-page", selected, severity],
    queryFn: () => listFindings(selected, severity ? { severity } : {}),
    enabled: selected !== "",
  });
  const findings = findingsQuery.data ?? [];
  const updateMutation = useMutation({
    mutationFn: () => updateFinding(selected, selectedFinding?.id ?? "", { severity: editSeverity, remediation: editRemediation }),
    onSuccess: (finding) => {
      setSelectedFinding(finding);
      queryClient.invalidateQueries({ queryKey: ["findings-page", selected] });
      queryClient.invalidateQueries({ queryKey: ["findings", selected] });
      queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
    },
  });

  function openFinding(finding: Finding) {
    setSelectedFinding(finding);
    setEditSeverity(finding.severity);
    setEditRemediation(finding.remediation ?? "");
  }

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Findings</h1>
          <p>Review normalized findings, CVEs, remediation, and persisted evidence.</p>
        </div>
        <label className="compact-control">
          Severity
          <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
            <option value="">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </label>
      </header>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Severity</th><th>Type</th><th>Tool</th><th>Title</th><th>CVEs</th><th>Evidence</th></tr>
            </thead>
            <tbody>
              {findings.map((finding) => (
                <tr key={finding.id} className={selectedFinding?.id === finding.id ? "selected-row" : ""} onClick={() => openFinding(finding)}>
                  <td><span className={`severity ${finding.severity}`}>{finding.severity}</span></td>
                  <td>{finding.type}</td>
                  <td>{finding.tool_id}</td>
                  <td>{finding.title}<small>{finding.url}</small></td>
                  <td>{(finding.cve_matches ?? []).map((cve) => cve.cve_id).join(", ") || "-"}</td>
                  <td><code>{finding.evidence_normalized || finding.evidence_raw || "-"}</code></td>
                </tr>
              ))}
              {findings.length === 0 ? <tr><td colSpan={6}>No findings for the selected filters.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
      {selectedFinding ? (
        <section className="panel finding-detail-panel">
          <div className="detail-header">
            <div>
              <h2>{selectedFinding.title}</h2>
              <p>{selectedFinding.tool_id} · {selectedFinding.type} · {selectedFinding.url || "no URL"}</p>
            </div>
            <button className="secondary" onClick={() => setSelectedFinding(null)}>Close</button>
          </div>
          <div className="finding-editor">
            <label className="compact-control">
              Severity
              <select value={editSeverity} onChange={(event) => setEditSeverity(event.target.value)}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </label>
            <label>
              Remediation
              <textarea value={editRemediation} onChange={(event) => setEditRemediation(event.target.value)} rows={4} />
            </label>
            <button className="primary" onClick={() => updateMutation.mutate()} disabled={updateMutation.isPending}>
              {updateMutation.isPending ? "Saving" : "Save Changes"}
            </button>
          </div>
          {updateMutation.error ? <p className="error-text">{updateMutation.error.message}</p> : null}
          <div className="evidence-grid">
            <article>
              <h3>Normalized Evidence</h3>
              <pre>{selectedFinding.evidence_normalized || "-"}</pre>
            </article>
            <article>
              <h3>Raw Evidence</h3>
              <pre>{selectedFinding.evidence_raw || "-"}</pre>
            </article>
            <article>
              <h3>HTTP Request</h3>
              <pre>{selectedFinding.http_evidence?.request_raw || "-"}</pre>
            </article>
            <article>
              <h3>HTTP Response</h3>
              <pre>{selectedFinding.http_evidence?.response_raw || "-"}</pre>
            </article>
          </div>
        </section>
      ) : null}
    </section>
  );
}
