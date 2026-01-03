const fs = require("node:fs");
const path = require("node:path");
const { chmodSync } = require("node:fs");
const crypto = require("node:crypto");
const { platformBinaryName, vendorBinaryPath } = require("./platform");

function readPackageJson() {
  const pkgPath = path.join(__dirname, "..", "package.json");
  return JSON.parse(fs.readFileSync(pkgPath, "utf8"));
}

function repositoryBaseURL(pkg) {
  const repo = pkg.repository;
  if (typeof repo === "string") {
    return repo.replace(/\.git$/, "");
  }
  if (repo && typeof repo.url === "string") {
    return repo.url.replace(/\.git$/, "");
  }
  return "https://github.com/sharelocaldev/sharelocal";
}

function assetURL(pkg, assetName) {
  const base = repositoryBaseURL(pkg).replace(/\/+$/, "");
  const tag = `v${pkg.version}`;
  return `${base}/releases/download/${tag}/${assetName}`;
}

async function downloadToFile(url, destPath) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) {
    throw new Error(`download failed: ${res.status} ${res.statusText}`);
  }

  const arrayBuffer = await res.arrayBuffer();
  const buf = Buffer.from(arrayBuffer);
  if (buf.length === 0) {
    throw new Error("downloaded file is empty");
  }

  fs.mkdirSync(path.dirname(destPath), { recursive: true });
  fs.writeFileSync(destPath, buf);
}

async function downloadText(url) {
  const res = await fetch(url, { redirect: "follow" });
  if (!res.ok) {
    throw new Error(`download failed: ${res.status} ${res.statusText}`);
  }
  return await res.text();
}

function sha256FileHex(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function expectedSha256FromSums(contents, assetName) {
  for (const line of contents.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const [sum, name] = parts;
    if (name === assetName) {
      return sum.toLowerCase();
    }
  }
  return null;
}

async function main() {
  const pkg = readPackageJson();
  const assetName = platformBinaryName();
  const url = assetURL(pkg, assetName);

  const outPath = vendorBinaryPath();
  const sumsURL = assetURL(pkg, "sha256sums.txt");

  if (process.argv.includes("--dry-run")) {
    process.stdout.write(`${url}\n${outPath}\n${sumsURL}\n`);
    return;
  }

  try {
    await downloadToFile(url, outPath);

    const sums = await downloadText(sumsURL);
    const expected = expectedSha256FromSums(sums, assetName);
    if (expected) {
      const actual = sha256FileHex(outPath);
      if (actual !== expected) {
        throw new Error(`checksum mismatch for ${assetName}`);
      }
    }
  } catch (err) {
    const message = err && err.message ? err.message : String(err);
    process.stderr.write(`sharelocal: ${message}\n`);
    process.stderr.write(`sharelocal: failed to download ${assetName}\n`);
    process.stderr.write(`sharelocal: url: ${url}\n`);
    process.exit(1);
  }

  if (process.platform !== "win32") {
    chmodSync(outPath, 0o755);
  }
}

main();
