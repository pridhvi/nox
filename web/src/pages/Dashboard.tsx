import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, AlertTriangle, Pause, Play, RefreshCw, Square, TerminalSquare, Trash2 } from "lucide-react";
import { Link } from "react-router-dom";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { deleteSession, getSessionStats, listFindings, listTargets, listToolRuns, pauseScan, resumeScan, scanEventsURL, stopScan, type ScanEvent } from "../api/client";
import { useSessionContext } from "../session";

const severityColors: Record<string, string> = {
  critical: "#991b1b",
  high: "#dc2626",
  medium: "#d97706",
  low: "#2563eb",
  info: "#64748b",
};

export function Dashboard() {
  const queryClient = useQueryClient();
  const { sessions, selectedSessionID, setSelectedSessionID, refreshSessions } = useSessionContext();
  const [scanEvents, setScanEvents] = useState<ScanEvent[]>([]);
  const selected = selectedSessionID;
  const selectedRecord = sessions.find((record) => record.session.id === selected)?.session;
  const statsQuery = useQuery({
    queryKey: ["session-stats", selected],
    queryFn: () => getSessionStats(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const findingsQuery = useQuery({
    queryKey: ["findings", selected],
    queryFn: () => listFindings(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const targetsQuery = useQuery({
    queryKey: ["targets", selected],
    queryFn: () => listTargets(selected),
    enabled: selected !== "",
    refetchInterval: 3500,
  });
  const toolRunsQuery = useQuery({
    queryKey: ["tool-runs", selected],
    queryFn: () => listToolRuns(selected),
    enabled: selected !== "",
    refetchInterval: 2500,
  });
  const pauseMutation = useMutation({ mutationFn: () => pauseScan(selected), onSuccess: refreshSessions });
  const resumeMutation = useMutation({ mutationFn: () => resumeScan(selected), onSuccess: refreshSessions });
  const cancelMutation = useMutation({
    mutationFn: () => stopScan(selected),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      refreshSessions();
    },
  });
  const deleteMutation = useMutation({
    mutationFn: () => deleteSession(selected),
    onSuccess: () => {
      setSelectedSessionID("");
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      refreshSessions();
    },
  });
  const totals = useMemo(() => {
    return sessions.reduce(
      (acc, record) => {
        if (record.session.status === "running" || record.session.status === "pending" || record.session.status === "paused") {
          acc.active += 1;
        }
        acc.findings += record.session.finding_count;
        return acc;
      },
      { active: 0, findings: 0 },
    );
  }, [sessions]);
  const severityData = useMemo(() => {
    const counts = statsQuery.data?.severity_counts ?? {};
    return ["critical", "high", "medium", "low", "info"].map((severity) => ({
      severity,
      value: counts[severity] ?? 0,
    })).filter((item) => item.value > 0);
  }, [statsQuery.data]);

  useEffect(() => {
    if (!selected) {
      setScanEvents([]);
      return;
    }
    setScanEvents([]);
    const socket = new WebSocket(scanEventsURL(selected));
    socket.onmessage = (message) => {
      const event = JSON.parse(message.data) as ScanEvent;
      setScanEvents((current) => [event, ...current.filter((item) => item.at !== event.at || item.type !== event.type)].slice(0, 12));
      if (event.type === "finding_found" || event.type === "tool_completed" || event.type === "tool_error" || event.type === "completed" || event.type === "failed" || event.type === "cancelled" || event.status === "paused") {
        queryClient.invalidateQueries({ queryKey: ["sessions"] });
        queryClient.invalidateQueries({ queryKey: ["session-stats", selected] });
        queryClient.invalidateQueries({ queryKey: ["findings", selected] });
        queryClient.invalidateQueries({ queryKey: ["tool-runs", selected] });
      }
    };
    return () => socket.close();
  }, [queryClient, selected]);

  const highLevelEvents = useMemo(() => scanEvents.filter((event) => {
    return ["phase_started", "phase_completed", "tool_completed", "tool_error", "completed", "failed", "cancelled"].includes(event.type) || event.status === "paused" || event.type === "finding_found";
  }).slice(0, 10), [scanEvents]);
  const terminalLines = useMemo(() => {
    const lines = scanEvents.map((event) => event.message ?? event.finding_title ?? `${event.type}${event.tool_id ? ` ${event.tool_id}` : ""}`);
    for (const run of (toolRunsQuery.data ?? []).slice(0, 8)) {
      lines.push(`${run.tool_id}: exit=${run.exit_code} findings=${run.finding_count}`);
    }
    return lines.slice(0, 18);
  }, [scanEvents, toolRunsQuery.data]);
  const status = selectedRecord?.status ?? "";

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Engagement Dashboard</h1>
          <p>{selectedRecord ? `${selectedRecord.name || "Untitled engagement"} · ${selectedRecord.target_count} target${selectedRecord.target_count === 1 ? "" : "s"}` : "Start scoped scans, monitor findings, and review attack paths."}</p>
        </div>
        <div className="action-row">
          <Link className="primary link-button" to="/scan"><TerminalSquare size={16} />New Scan</Link>
          {selected ? (
            <>
              {status === "running" ? <button className="secondary" onClick={() => pauseMutation.mutate()}><Pause size={16} />Pause</button> : null}
              {status === "running" || status === "pending" ? <button className="secondary danger" onClick={() => window.confirm("Cancel this scan?") && cancelMutation.mutate()}><Square size={16} />Cancel</button> : null}
              {status === "paused" ? <button className="secondary" onClick={() => resumeMutation.mutate()}><Play size={16} />Resume</button> : null}
              <button className="secondary danger" onClick={() => window.confirm("Delete this session and its database?") && deleteMutation.mutate()}><Trash2 size={16} />Delete</button>
            </>
          ) : null}
          <button className="secondary" onClick={refreshSessions}><RefreshCw size={16} />Refresh</button>
        </div>
      </header>
      <div className="metric-grid">
        <article><Activity /><span>Active Sessions</span><strong>{totals.active}</strong></article>
        <article><AlertTriangle /><span>Total Findings</span><strong>{totals.findings}</strong></article>
        <article><Activity /><span>Tool Runs</span><strong>{statsQuery.data?.tool_run_count ?? 0}</strong></article>
      </div>
      <div className="data-grid">
        <section className="panel">
          <h2>Sessions</h2>
          <div className="table-wrap scroll-panel">
            <table>
              <thead>
                <tr><th>Engagement</th><th>Status</th><th>Targets</th><th>Findings</th><th>Created</th></tr>
              </thead>
              <tbody>
                {sessions.map((record) => (
                  <tr
                    key={record.session.id}
                    className={record.session.id === selected ? "selected-row" : ""}
                    onClick={() => setSelectedSessionID(record.session.id)}
                  >
                    <td><strong>{record.session.name || record.session.target_input}</strong><small>{record.session.target_input}</small></td>
                    <td><span className={`status ${record.session.status}`}>{record.session.status}</span></td>
                    <td>{record.session.target_count}</td>
                    <td>{record.session.finding_count}</td>
                    <td>{new Date(record.session.created_at).toLocaleString()}</td>
                  </tr>
                ))}
                {sessions.length === 0 ? <tr><td colSpan={5}>No sessions yet.</td></tr> : null}
              </tbody>
            </table>
          </div>
        </section>
        <section className="panel">
          <h2>Findings</h2>
          <div className="chart-panel" aria-label="Findings by severity">
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie data={severityData} dataKey="value" nameKey="severity" innerRadius={46} outerRadius={72} paddingAngle={2}>
                    {severityData.map((entry) => <Cell key={entry.severity} fill={severityColors[entry.severity]} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : <div className="empty-line">No severity data yet.</div>}
          </div>
          <div className="severity-strip">
            {["critical", "high", "medium", "low", "info"].map((severity) => (
              <span key={severity}>{severity}: {statsQuery.data?.severity_counts?.[severity] ?? 0}</span>
            ))}
          </div>
          <div className="target-strip">
            {(targetsQuery.data ?? []).slice(0, 6).map((target) => <span key={target.id}>{target.protocol}://{target.host}{target.port ? `:${target.port}` : ""}</span>)}
          </div>
          <div className="finding-list scroll-panel">
            {(findingsQuery.data ?? []).slice(0, 8).map((finding) => (
              <article key={finding.id} className="finding-item">
                <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                <strong>{finding.title}</strong>
                <small>{finding.tool_id} · {finding.url}</small>
              </article>
            ))}
            {(findingsQuery.data ?? []).length === 0 ? <div className="empty-line">No findings for the selected session.</div> : null}
          </div>
        </section>
      </div>
      <section className="panel event-panel">
        <h2>Live Progress</h2>
        <div className="event-list">
          {highLevelEvents.map((event) => (
            <article key={`${event.type}-${event.at}-${event.tool_id ?? ""}-${event.finding_id ?? ""}`} className={`event-item ${eventTone(event)}`}>
              <span className={`event-type ${event.type}`}>{event.status === "paused" ? "paused" : event.type.replace("_", " ")}</span>
              <strong>{event.message ?? event.finding_title ?? event.tool_id ?? event.status ?? "Scan event"}</strong>
              <small>{new Date(event.at).toLocaleTimeString()}{event.tool_id ? ` · ${event.tool_id}` : ""}</small>
            </article>
          ))}
          {highLevelEvents.length === 0 ? <div className="empty-line">No live events for the selected session.</div> : null}
        </div>
      </section>
      <section className="panel terminal-feed">
        <h2>Live Terminal Feed</h2>
        <pre>{terminalLines.length > 0 ? terminalLines.join("\n") : "No terminal output for the selected session yet."}</pre>
      </section>
    </section>
  );
}

function eventTone(event: ScanEvent) {
  if (event.type === "failed" || event.type === "tool_error" || event.type === "cancelled") return "error";
  if (event.type === "completed" || event.type === "tool_completed" || event.type === "phase_completed") return "success";
  if (event.type === "finding_found" || event.status === "paused") return "warning";
  return "running";
}
