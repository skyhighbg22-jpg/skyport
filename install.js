const { createWriteStream, existsSync, chmodSync, unlinkSync, readFileSync, copyFileSync } = require("fs");
const { join } = require("path");
const { get } = require("https");
const { spawnSync } = require("child_process");
const { createHash } = require("crypto");

const PKG_VERSION = require("./package.json").version;
const REPO = "skyhighbg22-jpg/skyport";
const BASE_URL = `https://github.com/${REPO}/releases/download/v${PKG_VERSION}`;

const ext = process.platform === "win32" ? ".exe" : "";
const binName = `skyport${ext}`;
const platformBin = `skyport-${process.platform}-${process.arch}${ext}`;
const destPlatform = join(__dirname, "bin", platformBin);
const destGeneric = join(__dirname, "bin", binName);

function platformAsset(platform = process.platform, arch = process.arch, environment = process.env) {
  const isAndroid = platform === "android"
    || (platform === "linux" && Boolean(environment.ANDROID_ROOT || environment.ANDROID_DATA));
  const effectivePlatform = isAndroid ? "android" : platform;
  const map = {
    "win32-x64": `skyport-x86_64-pc-windows-msvc.exe`,
    "darwin-x64": `skyport-x86_64-apple-darwin`,
    "darwin-arm64": `skyport-aarch64-apple-darwin`,
    "linux-x64": `skyport-x86_64-unknown-linux-gnu`,
    "linux-arm64": `skyport-aarch64-unknown-linux-gnu`,
    "android-arm64": `skyport-aarch64-linux-android`,
  };
  return map[`${effectivePlatform}-${arch}`] || null;
}

function download(url, dest, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new Error(`Too many redirects for ${url}`));
      return;
    }
    const file = createWriteStream(dest);
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        file.close();
        try { unlinkSync(dest); } catch {}
        download(res.headers.location, dest, redirects + 1).then(resolve, reject);
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

function checksumFor(manifest, asset) {
  const line = String(manifest)
    .split(/\r?\n/)
    .find((entry) => {
      const parts = entry.trim().split(/\s+/);
      return parts.length >= 2 && parts.at(-1).replace(/^\*/, "") === asset;
    });
  const checksum = line?.trim().split(/\s+/)[0]?.toLowerCase();
  return /^[a-f0-9]{64}$/.test(checksum || "") ? checksum : null;
}

function verifyChecksum(binaryPath, manifestPath, asset) {
  const expected = checksumFor(readFileSync(manifestPath, "utf8"), asset);
  if (!expected) throw new Error(`No SHA-256 checksum published for ${asset}`);
  const actual = createHash("sha256").update(readFileSync(binaryPath)).digest("hex");
  if (actual !== expected) {
    throw new Error(`SHA-256 mismatch for ${asset}`);
  }
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
    console.warn(`[skyport] unsupported platform ${process.platform}-${process.arch}, checking for a source build`);
    const hasCargo = spawnSync("cargo", ["--version"], { stdio: "ignore" }).status === 0;
    if (hasCargo) {
      console.log("[skyport] building from source with cargo...");
      const r = spawnSync("cargo", ["build", "--release"], { stdio: "inherit", cwd: __dirname });
      if (r.status === 0 && existsSync(localBin)) {
        console.log("[skyport] built from source");
        return;
      }
    }
    throw new Error(`No Skyport binary is available for ${process.platform}-${process.arch}. Install with: cargo install skyport`);
  }

  const url = `${BASE_URL}/${asset}`;
  const checksumPath = `${destPlatform}.SHA256SUMS`;
  console.log(`[skyport] downloading ${asset} v${PKG_VERSION} ...`);
  try {
    await download(url, destPlatform);
    await download(`${BASE_URL}/SHA256SUMS`, checksumPath);
    verifyChecksum(destPlatform, checksumPath, asset);
    unlinkSync(checksumPath);
    if (process.platform !== "win32") chmodSync(destPlatform, 0o755);
    copyFileSync(destPlatform, destGeneric);
    if (process.platform !== "win32") chmodSync(destGeneric, 0o755);
    console.log(`[skyport] installed to ${destPlatform}`);
  } catch (err) {
    try { unlinkSync(destPlatform); } catch {}
    try { unlinkSync(checksumPath); } catch {}
    console.warn(`[skyport] download failed: ${err.message}`);
    console.warn(`[skyport] release may not exist yet. Build locally:`);
    console.warn(`[skyport]   cargo install --git https://github.com/${REPO}.git`);
    console.warn(`[skyport] or cargo build --release`);
    throw err;
  }
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`[skyport] installation failed: ${error.message}`);
    process.exitCode = 1;
  });
}

module.exports = { checksumFor, platformAsset, verifyChecksum };
