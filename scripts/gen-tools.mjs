import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const appCandidates = [
  ["attestd-app", "mcp-server", "src", "tools.ts"],
  ["Attestd-App", "mcp-server", "src", "tools.ts"],
];
const sourcePath = appCandidates
  .map((parts) => path.join(__dirname, "..", "..", ...parts))
  .find((p) => fs.existsSync(p));
if (!sourcePath) {
  console.warn(
    "gen-tools: sibling attestd-app/mcp-server/src/tools.ts not found, skipping (using committed src/tools.ts)",
  );
  process.exit(0);
}

const destPath = path.join(__dirname, "..", "src", "tools.ts");
fs.mkdirSync(path.dirname(destPath), { recursive: true });
fs.copyFileSync(sourcePath, destPath);
console.log("Copied tools.ts from", sourcePath);
