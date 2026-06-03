import { describe, it, expect } from "vitest";
import { nearMiss } from "../src/scanners/typosquat";

describe("typosquat nearMiss", () => {
  it("catches deletion, insertion, substitution and transposition", () => {
    expect(nearMiss("expres", "express")).toBe(true);
    expect(nearMiss("reactt", "react")).toBe(true);
    expect(nearMiss("lodahs", "lodash")).toBe(true);
    expect(nearMiss("loadsh", "lodash")).toBe(true);
    expect(nearMiss("axois", "axios")).toBe(true);
  });

  it("does not match identical names", () => {
    expect(nearMiss("react", "react")).toBe(false);
  });

  it("does not match distant names", () => {
    expect(nearMiss("lodash", "express")).toBe(false);
    expect(nearMiss("react", "redux")).toBe(false);
    expect(nearMiss("a", "abc")).toBe(false);
  });

  it("flags legit near-neighbours too (gating handles them later)", () => {
    expect(nearMiss("preact", "react")).toBe(true);
  });
});
