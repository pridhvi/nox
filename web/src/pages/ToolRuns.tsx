import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listToolRuns, type ToolRun } from "../api/client";
import { useSessionContext } from "../session";

export function ToolRuns() {
  const { selectedSessionID } = useSessionContext();
  const [selectedRun, setSelectedRun] = useState<ToolRun | null>(null);
  const runsQuery = useQuery({ queryKey: ["tool-runs", selectedSessionID], queryFn: () => listToolRuns(selectedSessionID), enabled: selectedSessionID !== "" });
  const runs = runsQuery.data ?? [];
  return (
    <section className="page wide-page">
      <header className="page-header"><div><h1>Tool Runs</h1><p>Arguments, status, stdout, stderr, duration, and finding counts.</p></div></header>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Duration</th><th>Args</th><th>Started</th></tr></thead>
            <tbody>
              {runs.map((run) => (
                <tr key={run.id} onClick={() => setSelectedRun(run)} className={selectedRun?.id === run.id ? "selected-row" : ""}>
                  <td>{run.tool_id}</td><td>{run.exit_code}</td><td>{run.finding_count}</td><td>{run.duration_ms}ms</td><td><code>{run.args.join(" ")}</code></td><td>{new Date(run.started_at).toLocaleString()}</td>
                </tr>
              ))}
              {runs.length === 0 ? <tr><td colSpan={6}>No tool runs for the selected session.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
      {selectedRun ? <section className="panel finding-detail-panel"><h2>{selectedRun.tool_id}</h2><div className="evidence-grid"><article><h3>stdout</h3><pre>{selectedRun.stdout_raw || "-"}</pre></article><article><h3>stderr</h3><pre>{selectedRun.stderr_raw || "-"}</pre></article></div></section> : null}
    </section>
  );
}
