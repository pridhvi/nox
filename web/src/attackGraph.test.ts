import { describe, expect, it } from "vitest";
import { graphElements } from "./pages/AttackGraph";
import type { AttackGraphEdge, AttackVector, Finding, SourceFinding, Target } from "./api/client";
import { findingOrigin } from "./pages/Findings";

describe("graphElements", () => {
  it("skips edges whose source or target nodes are missing", () => {
    const targets: Target[] = [{ id: "t1", host: "example.com", port: 443, protocol: "https", is_alive: true, discovered_by: "seed" }];
    const findings: Finding[] = [{
      id: "f1",
      session_id: "s1",
      target_id: "missing-target",
      tool_id: "test",
      type: "exposure",
      severity: "medium",
      confidence: 0.8,
      cvss_score: 5,
      title: "Finding",
      description: "",
      remediation: "",
      url: "",
      created_at: "",
    }];
    const vectors: AttackVector[] = [{
      id: "v1",
      title: "Vector",
      description: "",
      narrative: "",
      owasp_category: "",
      severity: "medium",
      confidence: 0.7,
      steps: [],
      prereq_finding_ids: ["f1", "missing-finding"],
    }];

    const graph = graphElements(targets, findings, vectors);
    expect(graph.skippedEdges).toBe(2);
    expect(graph.elements.some((element) => element.data.id === "edge:missing-target:f1")).toBe(false);
    expect(graph.elements.some((element) => element.data.id === "edge:f1:v1")).toBe(true);
  });

  it("adds source nodes and labelled graph edges", () => {
    const findings: Finding[] = [{
      id: "f1",
      session_id: "s1",
      target_id: "",
      tool_id: "audit/semgrep",
      type: "vulnerability",
      severity: "high",
      confidence: 0.8,
      cvss_score: 8,
      title: "Static Finding",
      description: "",
      remediation: "",
      url: "file://app.py#L1",
      created_at: "",
    }];
    const sourceFindings: SourceFinding[] = [{
      id: "sf1",
      session_id: "s1",
      kind: "route",
      language: "python",
      framework: "flask",
      file_path: "app.py",
      line_number: 1,
      value: "/admin",
      confirmed_dynamic: true,
      created_at: "",
    }];
    const edges: AttackGraphEdge[] = [{ id: "e1", session_id: "s1", from_id: "source:sf1", to_id: "finding:f1", relation: "confirms", confidence: 0.9, created_at: "" }];
    const graph = graphElements([], findings, [], sourceFindings, edges);
    expect(graph.elements.some((element) => element.data.id === "source:sf1")).toBe(true);
    expect(graph.elements.some((element) => element.data.id === "graph:e1" && element.data.label === "confirms")).toBe(true);
    expect(findingOrigin(findings[0])).toBe("static");
  });
});
