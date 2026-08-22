#!/usr/bin/env node
const { spawnSync } = require("child_process");
const { existsSync } = require("fs");
const { join } = require("path");

const ext = process.platform === "win32" ? ".exe" : "";
const candidates = [
  join(__dirname, `skyport-${process.platform}-${process.arch}${ext}`),
  join(__dirname, `skyport${ext}`),
];

let bin = null;
for (const p of candidates) {
  if (existsSync(p)) { bin = p; break; }
}

if (!bin) {
  console.error(`[skyport] binary not found for ${process.platform}-${process.arch}`);
  console.error(`[skyport] tried: ${candidates.join(", ")}`);
  console.error(`[skyport] reinstall with: npm install -g skyport --force`);
  console.error(`[skyport] or download from https://github.com/skyhighbg22-jpg/skyport/releases`);
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), { stdio: "inherit" });
process.exit(result.status ?? 1);
