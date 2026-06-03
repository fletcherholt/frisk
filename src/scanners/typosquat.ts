import type { Finding } from "../types";
import type { Dep } from "./deps";

const POPULAR: Record<string, Set<string>> = {
  npm: new Set([
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander",
    "debug", "request", "moment", "async", "bluebird", "underscore", "jquery",
    "vue", "webpack", "typescript", "eslint", "prettier", "jest", "mocha",
    "chai", "dotenv", "body-parser", "cors", "mongoose", "ws", "uuid", "semver",
    "glob", "rimraf", "mkdirp", "yargs", "inquirer", "colors", "ora",
    "node-fetch", "cross-env", "nodemon", "ts-node", "esbuild", "vite", "next",
    "nuxt", "svelte", "redux", "react-redux", "styled-components", "tailwindcss",
    "postcss", "autoprefixer", "sass", "classnames", "prop-types", "immer",
    "zustand", "formik", "yup", "joi", "zod", "dayjs", "date-fns", "ramda",
    "rxjs", "graphql", "sequelize", "pg", "mysql2", "redis", "ioredis",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet", "morgan",
    "winston", "pino", "nanoid", "qs", "minimist", "fs-extra", "execa",
    "chokidar", "sharp", "puppeteer", "playwright", "cheerio", "ejs",
    "handlebars", "pug", "marked", "dotenv-cli", "babel-core", "core-js",
    "regenerator-runtime", "tslib", "rollup", "browserify", "gulp", "grunt",
    "socket.io", "socket.io-client", "ethers", "web3", "bignumber.js",
  ]),
  PyPI: new Set([
    "requests", "numpy", "pandas", "scipy", "matplotlib", "flask", "django",
    "fastapi", "pytest", "setuptools", "pip", "wheel", "urllib3", "certifi",
    "boto3", "botocore", "pyyaml", "click", "jinja2", "werkzeug", "sqlalchemy",
    "psycopg2", "pymongo", "redis", "celery", "pillow", "opencv-python",
    "scikit-learn", "tensorflow", "torch", "keras", "transformers",
    "beautifulsoup4", "lxml", "selenium", "scrapy", "aiohttp", "httpx",
    "pydantic", "typer", "rich", "tqdm", "colorama", "python-dotenv",
    "cryptography", "paramiko", "pyjwt", "bcrypt", "passlib", "gunicorn",
    "uvicorn", "starlette", "attrs", "six", "python-dateutil", "pytz",
    "openpyxl", "pyarrow", "protobuf", "grpcio", "websockets", "discord.py",
    "openai", "anthropic", "langchain", "tenacity", "loguru", "rich-click",
  ]),
  "crates.io": new Set([
    "serde", "serde_json", "tokio", "rand", "clap", "log", "regex", "reqwest",
    "anyhow", "thiserror", "libc", "syn", "quote", "proc-macro2", "chrono",
    "futures", "hyper", "async-trait", "lazy_static", "once_cell", "itertools",
    "base64", "bytes", "uuid", "num", "tracing", "axum", "actix-web", "rayon",
    "crossbeam", "parking_lot", "indexmap", "toml", "url", "time", "nom",
  ]),
};

export function nearMiss(a: string, b: string): boolean {
  if (a === b) return false;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > 1) return false;
  if (la === lb) {
    const idx: number[] = [];
    for (let i = 0; i < la; i++) {
      if (a[i] !== b[i]) {
        idx.push(i);
        if (idx.length > 2) return false;
      }
    }
    if (idx.length === 1) return true;
    return (
      idx.length === 2 &&
      idx[1] === idx[0] + 1 &&
      a[idx[0]] === b[idx[1]] &&
      a[idx[1]] === b[idx[0]]
    );
  }
  const s = la < lb ? a : b;
  const l = la < lb ? b : a;
  let i = 0;
  let j = 0;
  let skips = 0;
  while (i < s.length && j < l.length) {
    if (s[i] === l[j]) {
      i++;
      j++;
    } else {
      skips++;
      j++;
      if (skips > 1) return false;
    }
  }
  return true;
}

async function monthlyDownloads(
  ecosystem: string,
  name: string,
): Promise<number | null> {
  const registry: Record<string, string> = {
    npm: "npmjs.org",
    PyPI: "pypi.org",
    "crates.io": "crates.io",
  };
  const reg = registry[ecosystem];
  if (!reg) return null;
  try {
    const r = await fetch(
      `https://packages.ecosyste.ms/api/v1/registries/${reg}/packages/${encodeURIComponent(name)}`,
      { signal: AbortSignal.timeout(8000) },
    );
    if (r.status === 404) return 0;
    if (!r.ok) return null;
    const j = (await r.json()) as { downloads?: number | null };
    return typeof j.downloads === "number" ? j.downloads : null;
  } catch {
    return null;
  }
}

const POPULAR_THRESHOLD = 100_000;

export async function scanTyposquat(deps: Dep[]): Promise<Finding[]> {
  const seen = new Set<string>();
  const candidates: { dep: Dep; target: string }[] = [];
  for (const d of deps) {
    const popular = POPULAR[d.ecosystem];
    if (!popular || popular.has(d.name)) continue;
    const key = `${d.ecosystem}:${d.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    for (const target of popular) {
      if (nearMiss(d.name, target)) {
        candidates.push({ dep: d, target });
        break;
      }
    }
  }

  const checked = await Promise.all(
    candidates.slice(0, 30).map(async ({ dep, target }) => {
      const dl = await monthlyDownloads(dep.ecosystem, dep.name);
      if (dl !== null && dl > POPULAR_THRESHOLD) return null;
      const usage = dl === null ? "unknown usage" : `${dl} downloads/month`;
      const finding: Finding = {
        severity: "high",
        category: "dependency",
        title: `Possible typosquat: ${dep.name}`,
        file: dep.file,
        detail: `'${dep.name}' is one character from the popular package '${target}' (${dep.ecosystem}) and has ${usage}. Confirm this is the package you meant.`,
      };
      return finding;
    }),
  );
  return checked.filter((f): f is Finding => f !== null);
}
