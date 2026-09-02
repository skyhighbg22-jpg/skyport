const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const { mkdtempSync, rmSync, writeFileSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");

const { checksumFor, platformAsset, verifyChecksum } = require("../install.js");

test("maps every published target to its release asset", () => {
  assert.equal(platformAsset("win32", "x64"), "skyport-x86_64-pc-windows-msvc.exe");
  assert.equal(platformAsset("darwin", "x64"), "skyport-x86_64-apple-darwin");
  assert.equal(platformAsset("darwin", "arm64"), "skyport-aarch64-apple-darwin");
  assert.equal(platformAsset("linux", "x64", {}), "skyport-x86_64-unknown-linux-gnu");
  assert.equal(platformAsset("linux", "arm64", {}), "skyport-aarch64-unknown-linux-gnu");
  assert.equal(platformAsset("android", "arm64"), "skyport-aarch64-linux-android");
  assert.equal(
    platformAsset("linux", "arm64", { ANDROID_ROOT: "/system" }),
    "skyport-aarch64-linux-android",
  );
  assert.equal(platformAsset("android", "x64"), null);
  assert.equal(platformAsset("win32", "arm64"), null);
});

test("selects an exact asset checksum and rejects malformed entries", () => {
  const digest = "a".repeat(64);
  const manifest = `${"b".repeat(64)}  skyport-other\n${digest} *skyport-linux-x64\n`;
  assert.equal(checksumFor(manifest, "skyport-linux-x64"), digest);
  assert.equal(checksumFor(manifest, "skyport-linux"), null);
  assert.equal(checksumFor("not-a-digest  skyport-linux-x64", "skyport-linux-x64"), null);
});

test("verifies downloaded bytes and rejects a mismatch", () => {
  const directory = mkdtempSync(join(tmpdir(), "skyport-installer-"));
  const binary = join(directory, "skyport-test");
  const manifest = join(directory, "SHA256SUMS");
  try {
    const bytes = Buffer.from("verified release bytes");
    const digest = createHash("sha256").update(bytes).digest("hex");
    writeFileSync(binary, bytes);
    writeFileSync(manifest, `${digest}  skyport-test\n`);
    assert.doesNotThrow(() => verifyChecksum(binary, manifest, "skyport-test"));
    writeFileSync(binary, "tampered bytes");
    assert.throws(() => verifyChecksum(binary, manifest, "skyport-test"), /SHA-256 mismatch/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
