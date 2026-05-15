import { type FormEvent, type ReactNode, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, CircleHelp, Play, Save, ShieldCheck, Trash2, XCircle } from "lucide-react";
import { createScanProfile, deleteScanProfile, listLLMModels, listScanProfiles, listTools, startScan, type StartScanRequest, type ToolRecord } from "../api/client";
import { allProfiles, buildCustomProfileRequest, cleanToolParameters, splitArgs, splitLines, type ScanProfile } from "../scanProfiles";
import { useSessionContext } from "../session";

const phases = [
  { id: "recon", label: "Recon", description: "Discover hosts, services, and reachable HTTP surfaces." },
  { id: "fingerprint", label: "Fingerprint", description: "Identify technologies, frameworks, TLS posture, and API surfaces." },
  { id: "enumerate", label: "Enumerate", description: "Find paths, parameters, scripts, secrets, CORS behavior, and storage exposure." },
  { id: "vuln_scan", label: "Vulnerability Scan", description: "Run active checks for injection, XSS, SSRF, JWT, OAuth, SSTI, XXE, and known CVEs." },
];

const modeDescriptions: Record<string, string> = {
  passive: "Passive avoids active fuzzing and favors low-noise discovery.",
  active: "Active enables scanners and probes that may send more requests.",
  stealth: "Stealth keeps the selected scope but uses conservative pacing where adapters support it.",
};

const runtimeHelp: Record<string, string> = {
  concurrency: "Maximum number of adapter tasks Nox may run at once.",
  perToolConcurrency: "Maximum concurrent runs of the same tool across targets.",
  timeout: "Per-tool timeout passed to adapters that support runtime overrides.",
  delay: "Delay before each tool execution, useful for pacing active scans.",
  rateLimit: "Operator label persisted with the run; adapters can use it as a policy hint.",
};

export function ScanBuilder() {
  const queryClient = useQueryClient();
  const { setSelectedSessionID } = useSessionContext();
  const toolsQuery = useQuery({ queryKey: ["tools"], queryFn: () => listTools() });
  const profilesQuery = useQuery({ queryKey: ["scan-profiles"], queryFn: listScanProfiles });
  const tools = toolsQuery.data ?? [];
  const [target, setTarget] = useState("");
  const [name, setName] = useState("");
  const [mode, setMode] = useState("active");
  const [outOfScope, setOutOfScope] = useState("");
  const [selectedPhases, setSelectedPhases] = useState<string[]>([]);
  const [selectedTools, setSelectedTools] = useState<string[]>([]);
  const [llmBaseURL, setLLMBaseURL] = useState("");
  const [llmModel, setLLMModel] = useState("");
  const [concurrency, setConcurrency] = useState(4);
  const [perToolConcurrency, setPerToolConcurrency] = useState(1);
  const [timeout, setTimeout] = useState(60);
  const [delay, setDelay] = useState(0);
  const [rateLimit, setRateLimit] = useState("");
  const [params, setParams] = useState<Record<string, Record<string, unknown>>>({});
  const [selectedProfileID, setSelectedProfileID] = useState("");
  const [profileName, setProfileName] = useState("");
  const [llmStatus, setLLMStatus] = useState("");

  const selectedToolRecords = useMemo(() => tools.filter((tool) => selectedTools.includes(tool.id)), [selectedTools, tools]);
  const toolByID = useMemo(() => new Map(tools.map((tool) => [tool.id, tool])), [tools]);
  const dependencyWarnings = useMemo(() => {
    const selected = new Set(selectedTools);
    return selectedToolRecords.flatMap((tool) => tool.depends_on.filter((dep) => !selected.has(dep)).map((dep) => `${tool.id} depends on ${dep}; Nox will include it automatically.`));
  }, [selectedToolRecords, selectedTools]);
  const installedSelectedTools = selectedToolRecords.filter((tool) => tool.installed);
  const selectedEnabledPhaseCount = selectedPhases.length;
  const canStartBase = target.trim() !== "" && selectedEnabledPhaseCount > 0 && installedSelectedTools.length > 0;

  const mutation = useMutation({
    mutationFn: startScan,
    onSuccess: (record) => {
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      setSelectedSessionID(record.session.id);
    },
  });
  const createProfileMutation = useMutation({
    mutationFn: () => createScanProfile(buildCustomProfileRequest(profileName, currentRequest())),
    onSuccess: () => {
      setProfileName("");
      queryClient.invalidateQueries({ queryKey: ["scan-profiles"] });
    },
  });
  const deleteProfileMutation = useMutation({
    mutationFn: (profileID: string) => deleteScanProfile(profileID),
    onSuccess: () => {
      setSelectedProfileID("");
      queryClient.invalidateQueries({ queryKey: ["scan-profiles"] });
    },
  });
  const modelsMutation = useMutation({
    mutationFn: () => listLLMModels(llmBaseURL),
    onSuccess: (result) => {
      setLLMStatus(`Connected. ${result.models.length} model${result.models.length === 1 ? "" : "s"} available.`);
      if (!llmModel && result.models.length > 0) {
        setLLMModel(result.models[0]);
      }
    },
    onError: (error) => {
      setLLMStatus(error instanceof Error ? error.message : "Unable to connect.");
    },
  });

  function togglePhase(phase: string) {
    setSelectedPhases((current) => {
      if (current.includes(phase)) {
        setSelectedTools((tools) => tools.filter((toolID) => toolByID.get(toolID)?.phase !== phase));
        return current.filter((item) => item !== phase);
      }
      return [...current, phase];
    });
  }

  function toggleTool(tool: ToolRecord) {
    if (!selectedPhases.includes(tool.phase)) {
      return;
    }
    setSelectedTools((current) => {
      if (current.includes(tool.id)) {
        return current.filter((item) => item !== tool.id);
      }
      const next = collectToolWithDependencies(tool.id, new Set(current));
      const neededPhases = [...next].map((toolID) => toolByID.get(toolID)?.phase).filter(Boolean) as string[];
      setSelectedPhases((phases) => [...new Set([...phases, ...neededPhases])]);
      return [...next];
    });
  }

  function collectToolWithDependencies(toolID: string, next: Set<string>) {
    const tool = toolByID.get(toolID);
    if (!tool || next.has(toolID)) {
      return next;
    }
    next.add(toolID);
    for (const depID of tool.depends_on) {
      collectToolWithDependencies(depID, next);
    }
    return next;
  }

  function setToolParam(toolID: string, name: string, value: unknown) {
    setParams((current) => ({ ...current, [toolID]: { ...(current[toolID] ?? {}), [name]: value } }));
  }

  function currentRequest(): StartScanRequest {
    return {
      target,
      name,
      mode,
      out_of_scope: splitLines(outOfScope),
      enabled_phases: selectedPhases,
      tools: selectedTools,
      tool_parameters: cleanToolParameters(params),
      concurrency,
      per_tool_concurrency: perToolConcurrency,
      tool_timeout_seconds: timeout,
      tool_delay_ms: delay,
      rate_limit: rateLimit,
      llm_base_url: llmBaseURL,
      llm_model: llmModel,
    };
  }

  function applyProfile(profile: ScanProfile) {
    const request = profile.request;
    if (request.mode) {
      setMode(request.mode);
    }
    setSelectedPhases(request.enabled_phases ?? []);
    setSelectedTools(request.tools ?? []);
    setParams(request.tool_parameters ?? {});
    setConcurrency(request.concurrency ?? 4);
    setPerToolConcurrency(request.per_tool_concurrency ?? 1);
    setTimeout(request.tool_timeout_seconds ?? 60);
    setDelay(request.tool_delay_ms ?? 0);
    setRateLimit(request.rate_limit ?? "");
    setLLMBaseURL(request.llm_base_url ?? "");
    setLLMModel(request.llm_model ?? "");
  }

  function saveProfile() {
    if (!profileName.trim()) {
      return;
    }
    createProfileMutation.mutate();
  }

  function deleteSelectedProfile() {
    if (selectedProfile && !selectedProfile.builtIn) {
      deleteProfileMutation.mutate(selectedProfile.id);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    mutation.mutate(currentRequest());
  }

  const profiles = allProfiles(profilesQuery.data ?? []);
  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileID);
  const canStart = canStartBase && !mutation.isPending;
  const llmModels = modelsMutation.data?.models ?? [];

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>Scan Builder</h1>
          <p>Configure scope, phases, tools, runtime options, and per-scan parameters.</p>
        </div>
      </header>
      <form className="operator-grid" onSubmit={submit}>
        <section className="panel span-2">
          <h2>Profiles</h2>
          <div className="profile-bar">
            <label>Preset
              <select value={selectedProfileID} onChange={(event) => setSelectedProfileID(event.target.value)}>
                <option value="">Choose a profile</option>
                {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
              </select>
            </label>
            <button className="secondary" type="button" disabled={!selectedProfile} onClick={() => selectedProfile && applyProfile(selectedProfile)}>Apply</button>
            <label>Save Current As
              <input value={profileName} onChange={(event) => setProfileName(event.target.value)} placeholder="Profile name" />
            </label>
            <button className="secondary" type="button" disabled={!profileName.trim() || createProfileMutation.isPending} onClick={saveProfile}><Save size={16} />Save</button>
            <button className="secondary" type="button" disabled={!selectedProfile || selectedProfile.builtIn || deleteProfileMutation.isPending} onClick={deleteSelectedProfile}><Trash2 size={16} />Delete</button>
          </div>
          {createProfileMutation.error ? <p className="error-text">{createProfileMutation.error.message}</p> : null}
          {selectedProfile ? <p className="profile-description">{selectedProfile.description}</p> : null}
        </section>
        <section className="panel">
          <h2>Scope</h2>
          <div className="form-grid">
            <label>Target<input value={target} onChange={(event) => setTarget(event.target.value)} placeholder="https://example.com" required /></label>
            <label>Name<input value={name} onChange={(event) => setName(event.target.value)} placeholder="Engagement name" /></label>
            <label>Mode
              <span className="inline-help-control">
                <select value={mode} onChange={(event) => setMode(event.target.value)}><option value="passive">Passive</option><option value="active">Active</option><option value="stealth">Stealth</option></select>
                <InfoTip text={modeDescriptions[mode]} />
              </span>
            </label>
            <label>Out of Scope<textarea value={outOfScope} onChange={(event) => setOutOfScope(event.target.value)} rows={3} placeholder="one host or CIDR per line" /></label>
          </div>
        </section>
        <section className="panel">
          <h2>Runtime</h2>
          <div className="form-grid compact">
            <HelpLabel label="Concurrency" help={runtimeHelp.concurrency}><input type="number" min={1} value={concurrency} onChange={(event) => setConcurrency(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Per Tool" help={runtimeHelp.perToolConcurrency}><input type="number" min={1} value={perToolConcurrency} onChange={(event) => setPerToolConcurrency(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Timeout Seconds" help={runtimeHelp.timeout}><input type="number" min={0} value={timeout} onChange={(event) => setTimeout(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Delay MS" help={runtimeHelp.delay}><input type="number" min={0} value={delay} onChange={(event) => setDelay(Number(event.target.value))} /></HelpLabel>
            <HelpLabel label="Rate Limit" help={runtimeHelp.rateLimit}><input value={rateLimit} onChange={(event) => setRateLimit(event.target.value)} placeholder="optional label" /></HelpLabel>
          </div>
        </section>
        <section className="panel">
          <h2>LLM</h2>
          <div className="form-grid">
            <label>Base URL<input value={llmBaseURL} onChange={(event) => setLLMBaseURL(event.target.value)} placeholder="http://localhost:11434/v1" /></label>
            <label>Model
              {llmModels.length > 0 ? <select value={llmModel} onChange={(event) => setLLMModel(event.target.value)}>{llmModels.map((model) => <option key={model} value={model}>{model}</option>)}</select>
                : <input value={llmModel} onChange={(event) => setLLMModel(event.target.value)} placeholder="llama3:8b" />}
            </label>
          </div>
          <div className="llm-actions">
            <button className="secondary" type="button" disabled={!llmBaseURL.trim() || modelsMutation.isPending} onClick={() => modelsMutation.mutate()}>{modelsMutation.isPending ? "Checking" : "Check Connection"}</button>
            {llmStatus ? <span className={modelsMutation.isError ? "error-text inline-status" : "success-text inline-status"}>{llmStatus}</span> : null}
          </div>
        </section>
        <section className="panel span-2">
          <h2>Phases</h2>
          <div className="phase-grid">
            {phases.map((phase) => (
              <label key={phase.id} className={`phase-option ${selectedPhases.includes(phase.id) ? "selected" : ""}`}>
                <input type="checkbox" checked={selectedPhases.includes(phase.id)} onChange={() => togglePhase(phase.id)} />
                <span><strong>{phase.label}</strong><small>{phase.description}</small></span>
              </label>
            ))}
          </div>
        </section>
        <section className="panel span-2">
          <h2>Tools</h2>
          <div className="tool-phase-grid">
            {phases.map((phase) => (
              <article key={phase.id} className={!selectedPhases.includes(phase.id) ? "disabled-tool-phase" : ""}>
                <h3>{phase.label}</h3>
                {tools.filter((tool) => tool.phase === phase.id).map((tool) => (
                  <label key={tool.id} className={`tool-check ${tool.installed ? tool.kind : "missing"} ${selectedTools.includes(tool.id) ? "selected" : ""}`}>
                    <input type="checkbox" disabled={!selectedPhases.includes(phase.id)} checked={selectedTools.includes(tool.id)} onChange={() => toggleTool(tool)} />
                    {tool.installed ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
                    <span><strong>{tool.id}</strong><small>{toolStatus(tool)} · {tool.name}</small></span>
                  </label>
                ))}
              </article>
            ))}
          </div>
          {dependencyWarnings.map((warning) => <p key={warning} className="warning-text">{warning}</p>)}
          <p className="profile-description">Selecting a tool also selects its dependencies when those dependency phases are enabled.</p>
        </section>
        {selectedToolRecords.length > 0 ? (
          <section className="panel span-2">
            <h2>Tool Parameters</h2>
            <div className="parameter-grid">
              {selectedToolRecords.map((tool) => <ToolParameters key={tool.id} tool={tool} values={params[tool.id] ?? {}} onChange={(name, value) => setToolParam(tool.id, name, value)} />)}
            </div>
          </section>
        ) : null}
        <section className="panel span-2 action-panel">
          {mutation.error ? <p className="error-text">{mutation.error.message}</p> : null}
          {!canStartBase ? <p className="warning-text">Select at least one phase and one installed tool before starting a scan.</p> : null}
          <button className="primary" type="submit" disabled={!canStart}><Play size={16} />{mutation.isPending ? "Starting" : "Start Scan"}</button>
          <span><ShieldCheck size={16} /> Scope validation is enforced before adapters run.</span>
        </section>
      </form>
    </section>
  );
}

function ToolParameters({ tool, values, onChange }: { tool: ToolRecord; values: Record<string, unknown>; onChange: (name: string, value: unknown) => void }) {
  return (
    <article className="parameter-card">
      <h3>{tool.id}</h3>
      {tool.parameters.map((param) => (
        <label key={param.name}>{param.label}
          {param.type === "enum" ? <select value={String(values[param.name] ?? "")} onChange={(event) => onChange(param.name, event.target.value)}><option value="">Default</option>{(param.options ?? []).map((option) => <option key={option} value={option}>{option}</option>)}</select>
            : param.type === "boolean" ? <input type="checkbox" checked={Boolean(values[param.name])} onChange={(event) => onChange(param.name, event.target.checked)} />
              : <input value={Array.isArray(values[param.name]) ? (values[param.name] as string[]).join(" ") : String(values[param.name] ?? "")} type={param.type === "number" ? "number" : "text"} onChange={(event) => onChange(param.name, param.type === "number" ? Number(event.target.value) : param.type === "list" ? splitArgs(event.target.value) : event.target.value)} />}
        </label>
      ))}
      {tool.parameters.length === 0 ? <p className="empty-line">No configurable parameters for this tool.</p> : null}
    </article>
  );
}

function HelpLabel({ label, help, children }: { label: string; help: string; children: ReactNode }) {
  return (
    <label>{label}
      <span className="inline-help-control">
        {children}
        <InfoTip text={help} />
      </span>
    </label>
  );
}

function InfoTip({ text }: { text: string }) {
  return <span className="info-tip" title={text} aria-label={text}><CircleHelp size={16} /></span>;
}

function toolStatus(tool: ToolRecord) {
  if (!tool.installed) {
    return "missing";
  }
  if (tool.kind === "builtin_http") {
    return "built in";
  }
  if (tool.kind === "subprocess") {
    return "installed subprocess";
  }
  return "plugin";
}
