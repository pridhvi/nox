import { useState } from "react";
import type React from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FlaskConical, KeyRound, Network, Radar, ShieldAlert, Sparkles } from "lucide-react";
import { generatePayloads, listADEntities, listADRelationships, listBlockEvents, listCredentials, listFindings, listOSINT, listPayloads, listPoCResults, runOSINT, runPoC, testCredentials } from "../api/client";
import { useSessionContext } from "../session";

const tabs = ["payloads", "credentials", "osint", "ad", "poc", "evasion"] as const;

export function PowerFeatures() {
  const queryClient = useQueryClient();
  const { selectedSessionID } = useSessionContext();
  const [tab, setTab] = useState<(typeof tabs)[number]>("payloads");
  const [findingID, setFindingID] = useState("");
  const enabled = Boolean(selectedSessionID);
  const findingsQuery = useQuery({ queryKey: ["findings", selectedSessionID], queryFn: () => listFindings(selectedSessionID), enabled });
  const payloadsQuery = useQuery({ queryKey: ["payloads", selectedSessionID], queryFn: () => listPayloads(selectedSessionID), enabled });
  const credentialsQuery = useQuery({ queryKey: ["credentials", selectedSessionID], queryFn: () => listCredentials(selectedSessionID), enabled });
  const osintQuery = useQuery({ queryKey: ["osint", selectedSessionID], queryFn: () => listOSINT(selectedSessionID), enabled });
  const adQuery = useQuery({ queryKey: ["ad-entities", selectedSessionID], queryFn: () => listADEntities(selectedSessionID), enabled });
  const adRelationshipsQuery = useQuery({ queryKey: ["ad-relationships", selectedSessionID], queryFn: () => listADRelationships(selectedSessionID), enabled });
  const pocQuery = useQuery({ queryKey: ["poc-results", selectedSessionID], queryFn: () => listPoCResults(selectedSessionID), enabled });
  const blockQuery = useQuery({ queryKey: ["block-events", selectedSessionID], queryFn: () => listBlockEvents(selectedSessionID), enabled });
  const generateMutation = useMutation({
    mutationFn: () => generatePayloads(selectedSessionID, findingID || findingsQuery.data?.[0]?.id || ""),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["payloads", selectedSessionID] }),
  });
  const credMutation = useMutation({
    mutationFn: () => testCredentials(selectedSessionID, { mode: "correlate" }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["credentials", selectedSessionID] }),
  });
  const osintMutation = useMutation({
    mutationFn: () => runOSINT(selectedSessionID),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["osint", selectedSessionID] }),
  });
  const pocMutation = useMutation({
    mutationFn: () => runPoC(selectedSessionID, findingID || findingsQuery.data?.[0]?.id || "", true),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["poc-results", selectedSessionID] }),
  });

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Power Features</h1>
          <p>Operator-triggered advanced modules. Active actions stay explicit and API-key protected.</p>
        </div>
      </header>
      {!selectedSessionID ? <section className="empty-state">Select a session to inspect power-feature records.</section> : null}
      <div className="target-strip">
        {tabs.map((item) => <button key={item} className={tab === item ? "primary" : "secondary"} onClick={() => setTab(item)}>{item.replace("-", " ")}</button>)}
      </div>
      <section className="panel">
        {tab === "payloads" ? (
          <FeatureSection icon={<Sparkles size={17} />} title="AI Payload Generation" action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => generateMutation.mutate()} label="Generate" disabled={!enabled || generateMutation.isPending} />}>
            <RecordTable rows={(payloadsQuery.data ?? []).map((item) => [item.payload_type, item.payload, item.bypass_technique || "-", `${Math.round(item.confidence * 100)}%`])} headers={["Type", "Payload", "Bypass", "Confidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "credentials" ? (
          <FeatureSection icon={<KeyRound size={17} />} title="Credential Testing" action={<button className="primary" onClick={() => credMutation.mutate()} disabled={!enabled || credMutation.isPending}>Record Test</button>}>
            <RecordTable rows={(credentialsQuery.data ?? []).map((item) => [item.credential_type, item.username, item.password, item.valid ? "valid" : "unconfirmed", item.evidence])} headers={["Type", "Username", "Password", "Status", "Evidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "osint" ? (
          <FeatureSection icon={<Radar size={17} />} title="OSINT Expansion" action={<button className="primary" onClick={() => osintMutation.mutate()} disabled={!enabled || osintMutation.isPending}>Run Local OSINT</button>}>
            <RecordTable rows={(osintQuery.data ?? []).map((item) => [item.kind, item.value, item.source, `${Math.round(item.confidence * 100)}%`])} headers={["Kind", "Value", "Source", "Confidence"]} />
          </FeatureSection>
        ) : null}
        {tab === "ad" ? (
          <FeatureSection icon={<Network size={17} />} title="AD / Internal Network">
            <RecordTable rows={(adQuery.data ?? []).map((item) => [item.entity_type, item.name, item.domain, item.sid || "-"])} headers={["Type", "Name", "Domain", "SID"]} />
            <p className="empty-line">{adRelationshipsQuery.data?.length ?? 0} AD relationship records</p>
          </FeatureSection>
        ) : null}
        {tab === "poc" ? (
          <FeatureSection icon={<FlaskConical size={17} />} title="PoC / Impact" action={<ActionControls value={findingID} onChange={setFindingID} onRun={() => pocMutation.mutate()} label="Record PoC" disabled={!enabled || pocMutation.isPending} />}>
            <RecordTable rows={(pocQuery.data ?? []).map((item) => [item.poc_type, item.status, item.evidence, item.impact_narrative])} headers={["Type", "Status", "Evidence", "Impact"]} />
          </FeatureSection>
        ) : null}
        {tab === "evasion" ? (
          <FeatureSection icon={<ShieldAlert size={17} />} title="Evasion / Request Behavior">
            <RecordTable rows={(blockQuery.data ?? []).map((item) => [item.tool_id || "-", item.status_code.toString(), item.signal, item.backoff_ms.toString()])} headers={["Tool", "Status", "Signal", "Backoff ms"]} />
          </FeatureSection>
        ) : null}
      </section>
    </section>
  );
}

function FeatureSection({ icon, title, action, children }: { icon: React.ReactNode; title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="pipeline">
      <div className="action-panel">
        <h2>{icon}{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

function ActionControls({ value, onChange, onRun, label, disabled }: { value: string; onChange: (value: string) => void; onRun: () => void; label: string; disabled?: boolean }) {
  return (
    <div className="action-row">
      <input value={value} onChange={(event) => onChange(event.target.value)} placeholder="Finding ID (defaults to first)" />
      <button className="primary" onClick={onRun} disabled={disabled}>{label}</button>
    </div>
  );
}

function RecordTable({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead>
        <tbody>
          {rows.map((row, index) => <tr key={index}>{row.map((cell, cellIndex) => <td key={cellIndex}><code>{cell}</code></td>)}</tr>)}
        </tbody>
      </table>
      {rows.length === 0 ? <p className="empty-line">No records yet</p> : null}
    </div>
  );
}
