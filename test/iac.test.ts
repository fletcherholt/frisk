import { describe, it, expect } from "vitest";
import { scanIacText } from "../src/scanners/iac";

const has = (fs: { title: string }[], t: string) =>
  fs.some((f) => f.title.includes(t));

describe("iac scanner", () => {
  it("flags a Dockerfile with no USER as running as root", () => {
    const f = scanIacText("Dockerfile", "FROM node:20\nRUN npm ci\n");
    expect(has(f, "runs as root")).toBe(true);
  });

  it("does not flag a Dockerfile that sets USER", () => {
    const f = scanIacText("Dockerfile", "FROM node:20\nUSER app\nRUN npm ci\n");
    expect(has(f, "runs as root")).toBe(false);
  });

  it("flags secrets baked into image layers", () => {
    const f = scanIacText("Dockerfile", "FROM x\nENV API_KEY=abc123\n");
    expect(has(f, "Secret baked")).toBe(true);
  });

  it("flags privileged containers and docker socket mounts in yaml", () => {
    const f = scanIacText(
      "docker-compose.yml",
      "services:\n  app:\n    privileged: true\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
    );
    expect(has(f, "Privileged container")).toBe(true);
    expect(has(f, "Docker socket")).toBe(true);
  });

  it("flags 0.0.0.0/0 ingress in terraform", () => {
    const f = scanIacText("main.tf", 'ingress {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n');
    expect(has(f, "0.0.0.0/0")).toBe(true);
    expect(f[0].severity).toBe("high");
  });

  it("flags pull_request_target and script injection in a workflow", () => {
    const wf =
      "on: pull_request_target\njobs:\n  x:\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n";
    const f = scanIacText(".github/workflows/ci.yml", wf);
    expect(has(f, "pull_request_target")).toBe(true);
    expect(has(f, "script injection")).toBe(true);
  });

  it("ignores non-infra files", () => {
    expect(scanIacText("src/app.js", "const x = 1;").length).toBe(0);
  });
});
