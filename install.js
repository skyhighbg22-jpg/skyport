const { createWriteStream, existsSync, chmodSync, unlinkSync } = require("fs");
const { join } = require("path");
const { get } = require("https");
const { spawnSync } = require("child_process");

const PKG_VERSION = require("./package.json").version;
const REPO = "skyhighbg22-jpg/skyport";
const BASE_URL = `https://github.com/${REPO}/releases/download/v${PKG_VERSION}`;

const ext = process.platform === "win32" ? ".exe" : "";
const binName = `skyport${ext}`;
const platformBin = `skyport-${process.platform}-${process.arch}${ext}`;
const destPlatform = join(__dirname, "bin", platformBin);
const destGeneric = join(__dirname, "bin", binName);

function platformAsset() {
  const map = {
    "win32-x64": `skyport-x86_64-pc-windows-msvc.exe`,
    "darwin-x64": `skyport-x86_64-apple-darwin`,
    "darwin-arm64": `skyport-aarch64-apple-darwin`,
    "linux-x64": `skyport-x86_64-unknown-linux-gnu`,
    "linux-arm64": `skyport-aarch64-unknown-linux-gnu`,
  };
  return map[`${process.platform}-${process.arch}`] || null;
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = createWriteStream(dest);
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        file.close();
        try { unlinkSync(dest); } catch {}
        download(res.headers.location, dest).then(resolve, reject);
        return;
      }
      if (res.statusCode !== 200) {
        file.close();
        try { unlinkSync(dest); } catch {}
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      res.pipe(file);
      file.on("finish", () => file.close(resolve));
      file.on("error", reject);
    }).on("error", reject);
  });
}

async function main() {
  if (process.env.SKYPORT_SKIP_DOWNLOAD === "1") {
    console.log("[skyport] SKIP_DOWNLOAD set, skipping binary download");
    return;
  }

  if (existsSync(destPlatform) || existsSync(destGeneric)) {
    return;
  }

  const localBin = join(__dirname, "..", "target", "release", binName);
  if (existsSync(localBin) && !process.env.npm_config_global) {
    return;
  }

  const asset = platformAsset();
  if (!asset) {
    console.warn(`[skyport] unsupported platform ${process.platform}-${process.arch}, will try cargo build`);
    const hasCargo = spawnSync("cargo", ["--version"], { stdio: "ignore" }).status === 0;
    if (hasCargo) {
      console.log("[skyport] building from source with cargo...");
      const r = spawnSync("cargo", ["build", "--release"], { stdio: "inherit", cwd: __dirname });
      if (r.status === 0 && existsSync(localBin)) {
        console.log("[skyport] built from source");
        return;
      }
    }
    console.warn(`[skyport] no binary for this platform. Install Rust and run: cargo install skyport`);
    return;
  }

  const url = `${BASE_URL}/${asset}`;
  console.log(`[skyport] downloading ${asset} v${PKG_VERSION} ...`);
  try {
    await download(url, destPlatform);
    if (process.platform !== "win32") chmodSync(destPlatform, 0o755);
    try {
      const { copyFileSync } = require("fs");
      copyFileSync(destPlatform, destGeneric);
      if (process.platform !== "win32") chmodSync(destGeneric, 0o755);
    } catch {}
    console.log(`[skyport] installed to ${destPlatform}`);
  } catch (err) {
    try { unlinkSync(destPlatform); } catch {}
    console.warn(`[skyport] download failed: ${err.message}`);
    console.warn(`[skyport] release may not exist yet. Build locally:`);
    console.warn(`[skyport]   cargo install --git https://github.com/${REPO}.git`);
    console.warn(`[skyport] or cargo build --release`);
  }
}

main();
