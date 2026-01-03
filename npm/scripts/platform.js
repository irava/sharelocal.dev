const path = require("node:path");

function platformBinaryName(platform = process.platform, arch = process.arch) {
  const isWindows = platform === "win32";

  if (platform === "darwin" && arch === "arm64") return "sharelocal-darwin-arm64";
  if (platform === "darwin" && arch === "x64") return "sharelocal-darwin-amd64";
  if (platform === "linux" && arch === "arm64") return "sharelocal-linux-arm64";
  if (platform === "linux" && arch === "x64") return "sharelocal-linux-amd64";
  if (platform === "win32" && arch === "x64") return "sharelocal-windows-amd64.exe";

  const suffix = isWindows ? ".exe" : "";
  throw new Error(`unsupported platform: ${platform}/${arch}${suffix}`);
}

function vendorBinaryPath(platform = process.platform) {
  const isWindows = platform === "win32";
  const filename = isWindows ? "sharelocal.exe" : "sharelocal";
  return path.join(__dirname, "..", "vendor", filename);
}

module.exports = { platformBinaryName, vendorBinaryPath };

