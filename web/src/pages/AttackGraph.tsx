import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import cytoscape from "cytoscape";
import { listFindings, listSessions, listTargets, listVectors, type AttackVector, type Finding, type Target } from "../api/client";

export function AttackGraph() {
  const params = useParams();
  const sessionsQuery = useQuery({ queryKey: ["sessions"], queryFn: listSessions });
  const selected = params.sessionID ?? sessionsQuery.data?.[0]?.session.id ?? "";
  const [severity, setSeverity] = useState("");
  const targetsQuery = useQuery({ queryKey: ["targets", selected], queryFn: () => listTargets(selected), enabled: selected !== "" });
  const findingsQuery = useQuery({ queryKey: ["findings", selected], queryFn: () => listFindings(selected), enabled: selected !== "" });
  const vectorsQuery = useQuery({ queryKey: ["vectors", selected], queryFn: () => listVectors(selected), enabled: selected !== "" });

  const nodes = useMemo(() => {
    const targets = targetsQuery.data ?? [];
    const findings = (findingsQuery.data ?? []).filter((finding) => !severity || finding.severity === severity);
    const vectors = vectorsQuery.data ?? [];
    return { targets, findings, vectors };
  }, [findingsQuery.data, severity, targetsQuery.data, vectorsQuery.data]);
  const graphRef = useRef<HTMLDivElement | null>(null);
  const [selectedNode, setSelectedNode] = useState<{ label: string; detail: string } | null>(null);

  useEffect(() => {
    if (!graphRef.current) {
      return;
    }
    const elements = graphElements(nodes.targets, nodes.findings, nodes.vectors);
    const graph = cytoscape({
      container: graphRef.current,
      elements,
      layout: { name: "breadthfirst", directed: true, padding: 20, spacingFactor: 1.2 },
      style: [
        { selector: "node", style: { label: "data(label)", "font-size": "10px", color: "#111827", "text-valign": "center", "text-halign": "center", width: "72px", height: "72px", "text-wrap": "wrap", "text-max-width": "96px", "border-width": "2px", "border-color": "#d1d5db", "background-color": "#e5e7eb" } },
        { selector: "node[type='target']", style: { "background-color": "#dbeafe", shape: "round-rectangle" } },
        { selector: "node[type='finding']", style: { "background-color": "data(color)", color: "#ffffff", "border-color": "#111827" } },
        { selector: "node[type='vector']", style: { "background-color": "#111827", color: "#ffffff", shape: "hexagon" } },
        { selector: "edge", style: { width: "2px", "line-color": "#94a3b8", "target-arrow-color": "#94a3b8", "target-arrow-shape": "triangle", "curve-style": "bezier" } },
      ],
    });
    graph.on("tap", "node", (event) => {
      const node = event.target;
      setSelectedNode({ label: node.data("label"), detail: node.data("detail") });
    });
    return () => graph.destroy();
  }, [nodes]);

  return (
    <section className="page">
      <header className="page-header">
        <div>
          <h1>Attack Graph</h1>
          <p>Targets, findings, technologies, and deterministic attack chains.</p>
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
        <h2>Interactive Graph</h2>
        <div className="cy-graph" ref={graphRef} />
        {selectedNode ? (
          <div className="graph-detail">
            <strong>{selectedNode.label}</strong>
            <p>{selectedNode.detail}</p>
          </div>
        ) : null}
      </section>
      <div className="graph-layout">
        <section className="graph-column">
          <h2>Targets</h2>
          {nodes.targets.map((target) => (
            <article key={target.id} className="graph-node target-node">
              <strong>{target.host}</strong>
              <span>{target.protocol}:{target.port} · {target.discovered_by}</span>
              {(target.technologies ?? []).map((tech) => (
                <small key={tech.id}>{tech.name} {tech.version}</small>
              ))}
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Findings</h2>
          {nodes.findings.map((finding) => (
            <article key={finding.id} className={`graph-node finding-node ${finding.severity}`}>
              <span className={`severity ${finding.severity}`}>{finding.severity}</span>
              <strong>{finding.title}</strong>
              <small>{finding.tool_id} · {finding.type}</small>
            </article>
          ))}
        </section>
        <section className="graph-column">
          <h2>Attack Vectors</h2>
          {nodes.vectors.map((vector) => (
            <article key={vector.id} className={`graph-node vector-node ${vector.severity}`}>
              <span className={`severity ${vector.severity}`}>{vector.severity}</span>
              <strong>{vector.title}</strong>
              <small>{vector.owasp_category || "uncategorized"} · confidence {Math.round(vector.confidence * 100)}%</small>
              {vector.steps.slice(0, 3).map((step) => <small key={step.order}>{step.order}. {step.description}</small>)}
            </article>
          ))}
        </section>
      </div>
    </section>
  );
}

function graphElements(targets: Target[], findings: Finding[], vectors: AttackVector[]) {
  const elements: cytoscape.ElementDefinition[] = [];
  for (const target of targets) {
    elements.push({ data: { id: `target:${target.id}`, label: target.host, type: "target", detail: `${target.protocol}:${target.port} discovered by ${target.discovered_by}` } });
    for (const tech of target.technologies ?? []) {
      const techID = `tech:${tech.id}`;
      elements.push({ data: { id: techID, label: `${tech.name} ${tech.version}`.trim(), type: "target", detail: `${tech.category || "technology"} confidence ${Math.round(tech.confidence * 100)}%` } });
      elements.push({ data: { id: `edge:${target.id}:${tech.id}`, source: `target:${target.id}`, target: techID } });
    }
  }
  for (const finding of findings) {
    elements.push({ data: { id: `finding:${finding.id}`, label: finding.title, type: "finding", color: severityColor(finding.severity), detail: `${finding.severity} ${finding.type} from ${finding.tool_id}. ${finding.url}` } });
    if (finding.target_id) {
      elements.push({ data: { id: `edge:${finding.target_id}:${finding.id}`, source: `target:${finding.target_id}`, target: `finding:${finding.id}` } });
    }
  }
  for (const vector of vectors) {
    elements.push({ data: { id: `vector:${vector.id}`, label: vector.title, type: "vector", detail: `${vector.severity} confidence ${Math.round(vector.confidence * 100)}%. ${vector.narrative}` } });
    for (const findingID of vector.prereq_finding_ids ?? []) {
      elements.push({ data: { id: `edge:${findingID}:${vector.id}`, source: `finding:${findingID}`, target: `vector:${vector.id}` } });
    }
  }
  return elements;
}

function severityColor(severity: string) {
  switch (severity) {
    case "critical": return "#991b1b";
    case "high": return "#dc2626";
    case "medium": return "#d97706";
    case "low": return "#2563eb";
    default: return "#64748b";
  }
}
