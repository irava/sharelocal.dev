const assert = require("node:assert");
const { spawnSync } = require("node:child_process");
const { platformBinaryName, vendorBinaryPath } = require("./platform");

function main() {
  assert.ok(vendorBinaryPath().includes("vendor"));
  platformBinaryName("darwin", "arm64");
  platformBinaryName("darwin", "x64");
  platformBinaryName("linux", "arm64");
  platformBinaryName("linux", "x64");
  platformBinaryName("win32", "x64");

  const dryRun = spawnSync(process.execPath, [require.resolve("./postinstall"), "--dry-run"], {
    stdio: ["ignore", "pipe", "pipe"],
    encoding: "utf8"
  });
  assert.strictEqual(dryRun.status, 0);
  const out = dryRun.stdout.trim().split("\n");
  assert.ok(out[0].includes("/releases/download/v"));
  assert.ok(out[0].endsWith(platformBinaryName()));
  assert.ok(out[1].endsWith(vendorBinaryPath()));
  assert.ok(out[2].endsWith("/sha256sums.txt"));
  console.log("ok");
}

main();
