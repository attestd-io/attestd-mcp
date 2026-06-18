import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const sourcePath = path.join(
  __dirname,
  "..",
  "..",
  "Attestd-App",
  "mcp-server",
  "src",
  "tools.ts",
);
if (!fs.existsSync(sourcePath)) {
  console.warn(
    "gen-tools: %s not found, skipping (using committed src/tools.ts)",
    sourcePath,
  );
  process.exit(0);
}

const destPath = path.join(__dirname, "..", "src", "tools.ts");
fs.mkdirSync(path.dirname(destPath), { recursive: true });
fs.copyFileSync(sourcePath, destPath);
console.log("Copied tools.ts from Attestd-App/mcp-server");
