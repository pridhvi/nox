import { describe, expect, it } from "vitest";
import { graphElements } from "./pages/AttackGraph";
import type { AttackVector, Finding, Target } from "./api/client";

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
});
