import { type FormEvent, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, PackagePlus, RefreshCw, XCircle } from "lucide-react";
import { createPlugin, listPlugins, listTools, updatePlugin, type ToolRecord } from "../api/client";
import { useSessionContext } from "../session";

export function Tools() {
  const queryClient = useQueryClient();
  const { selectedSessionID } = useSessionContext();
  const toolsQuery = useQuery({ queryKey: ["tools", selectedSessionID], queryFn: () => listTools(selectedSessionID), enabled: selectedSessionID !== "" });
  const pluginsQuery = useQuery({ queryKey: ["plugins", selectedSessionID], queryFn: () => listPlugins(selectedSessionID), enabled: selectedSessionID !== "" });
  const [pluginName, setPluginName] = useState("");
  const [pluginBinary, setPluginBinary] = useState("");
  const createMutation = useMutation({
    mutationFn: () => createPlugin(selectedSessionID, { name: pluginName, binary: pluginBinary, enabled: true }),
    onSuccess: () => {
      setPluginName("");
      setPluginBinary("");
      queryClient.invalidateQueries({ queryKey: ["plugins", selectedSessionID] });
      queryClient.invalidateQueries({ queryKey: ["tools", selectedSessionID] });
    },
  });

  function submitPlugin(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selectedSessionID && pluginBinary.trim()) {
      createMutation.mutate();
    }
  }

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Tools</h1>
          <p>Inventory, install status, last run state, and session plugins.</p>
        </div>
        <button className="primary" onClick={() => toolsQuery.refetch()}><RefreshCw size={16} />Refresh</button>
      </header>
      <section className="panel">
        <h2>Registered Tools</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Status</th><th>Tool</th><th>Phase</th><th>Kind</th><th>Binary</th><th>Version</th><th>Last Run</th></tr></thead>
            <tbody>
              {(toolsQuery.data ?? []).map((tool) => (
                <tr key={tool.id}>
                  <td><span className={`status ${tool.installed ? "completed" : "failed"} icon-status`}>{tool.installed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}{tool.installed ? "ready" : "missing"}</span></td>
                  <td><strong>{tool.id}</strong><small>{tool.name}</small><small>{tool.depends_on.length ? `depends: ${tool.depends_on.join(", ")}` : tool.install_hint}</small></td>
                  <td>{tool.phase}</td>
                  <td>{kindLabel(tool)}</td>
                  <td><code>{tool.binary_path || "-"}</code></td>
                  <td>{tool.version || "-"}</td>
                  <td>{tool.last_run ? <span className={`status ${tool.last_run.exit_code === 0 ? "completed" : "failed"}`}>{tool.last_run.exit_code === 0 ? "ok" : `exit ${tool.last_run.exit_code}`}</span> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel">
        <h2>Session Plugins</h2>
        <form className="scan-form plugin-form" onSubmit={submitPlugin}>
          <label>Name<input value={pluginName} onChange={(event) => setPluginName(event.target.value)} placeholder="optional" /></label>
          <label>Binary<input value={pluginBinary} onChange={(event) => setPluginBinary(event.target.value)} placeholder="/path/to/plugin" /></label>
          <button className="primary" disabled={!selectedSessionID || createMutation.isPending}><PackagePlus size={16} />Register</button>
        </form>
        {createMutation.error ? <p className="error-text">{createMutation.error.message}</p> : null}
        {!selectedSessionID ? <p className="warning-text">Select a session before registering plugins.</p> : null}
        <div className="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Binary</th><th>Status</th><th>Action</th></tr></thead>
            <tbody>
              {(pluginsQuery.data ?? []).map((plugin) => (
                <tr key={plugin.id}>
                  <td>{plugin.name}</td>
                  <td><code>{plugin.binary}</code></td>
                  <td>{plugin.enabled ? "enabled" : "disabled"}</td>
                  <td><button className="secondary" onClick={() => updatePlugin(selectedSessionID, plugin.id, { enabled: !plugin.enabled }).then(() => queryClient.invalidateQueries({ queryKey: ["plugins", selectedSessionID] }))}>{plugin.enabled ? "Disable" : "Enable"}</button></td>
                </tr>
              ))}
              {(pluginsQuery.data ?? []).length === 0 ? <tr><td colSpan={4}>No plugins registered for the selected session.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

function kindLabel(tool: ToolRecord) {
  if (tool.kind === "builtin_http") {
    return "built in";
  }
  if (tool.kind === "subprocess") {
    return "subprocess";
  }
  return "plugin";
}
