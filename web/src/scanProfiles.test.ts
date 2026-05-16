import { describe, expect, it } from "vitest";
import { allProfiles, apiProfiles, buildCustomProfileRequest, cleanToolParameters, splitArgs, splitLines } from "./scanProfiles";

describe("scan profile helpers", () => {
  it("combines built-in and API-backed profiles", () => {
    const profiles = allProfiles([{ id: "custom", name: "Custom", description: "", request: { target: "", mode: "active" }, created_at: "", updated_at: "" }]);
    expect(profiles.some((profile) => profile.builtIn)).toBe(true);
    expect(profiles.some((profile) => profile.id === "custom")).toBe(true);
  });

  it("builds reusable profiles without target-specific fields", () => {
    const profile = buildCustomProfileRequest("Active Web", {
      target: "https://example.com",
      source_path: "/repo",
      name: "One-off",
      mode: "active",
      out_of_scope: ["admin.example.com"],
      tools: ["ffuf"],
      tool_parameters: { ffuf: { wordlist: "/tmp/words" } },
    });
    expect(profile.name).toBe("Active Web");
    expect(profile.request).toMatchObject({ mode: "active", tools: ["ffuf"], tool_parameters: { ffuf: { wordlist: "/tmp/words" } } });
    expect(profile.request.target).toBe("");
    expect(profile.request.source_path).toBe("/repo");
    expect(profile.request).not.toHaveProperty("name");
  });

  it("maps API profile records to UI profiles", () => {
    expect(apiProfiles([{ id: "p1", name: "P1", description: "", request: { target: "", mode: "active" }, created_at: "", updated_at: "" }])[0]).toMatchObject({ id: "p1", name: "P1" });
  });

  it("cleans empty parameters and splits operators inputs", () => {
    expect(cleanToolParameters({ ffuf: { wordlist: "", extra_args: [], timeout_seconds: 30 } })).toEqual({ ffuf: { timeout_seconds: 30 } });
    expect(splitLines("a.example.com, b.example.com\nc.example.com")).toEqual(["a.example.com", "b.example.com", "c.example.com"]);
    expect(splitArgs("--rate 10  --json")).toEqual(["--rate", "10", "--json"]);
  });
});
