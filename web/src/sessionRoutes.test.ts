import { describe, expect, it } from "vitest";
import { scopedSessionPath } from "./sessionRoutes";

describe("scopedSessionPath", () => {
  it("routes to the root dashboard when no session is selected", () => {
    expect(scopedSessionPath("", "")).toBe("/");
  });

  it("routes unscoped pages when no session is selected", () => {
    expect(scopedSessionPath("", "/findings")).toBe("/findings");
  });

  it("routes selected-session pages when a session is selected", () => {
    expect(scopedSessionPath("sess-1", "/tools")).toBe("/sessions/sess-1/tools");
  });
});
