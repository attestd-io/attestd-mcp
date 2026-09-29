import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const appCandidates = [
  ["attestd-app", "mcp-server", "src", "tools.ts"],
  ["Attestd-App", "mcp-server", "src", "tools.ts"],
];

export function extractServerVersion(source) {
  const match = source.match(/export const SERVER_VERSION = "([^"]+)"/);
  return match ? match[1] : null;
}

/**
 * Return a skip reason when copying sibling App tools.ts would clobber the
 * committed mcp schema. Null means the copy is allowed.
 */
export function skipCopyReason({ destExists, sourceText, destText }) {
  if (!destExists) return null;
  const sourceVersion = extractServerVersion(sourceText);
  const destVersion = extractServerVersion(destText);
  if (!sourceVersion || !destVersion) {
    return "could not parse SERVER_VERSION in sibling or committed tools.ts";
  }
  if (sourceVersion !== destVersion) {
    return `sibling SERVER_VERSION ${sourceVersion} != committed ${destVersion}`;
  }
  const sourceHasLikely = sourceText.includes("likely_intended");
  const destHasLikely = destText.includes("likely_intended");
  if (sourceHasLikely && !destHasLikely) {
    return "sibling tools.ts still advertises likely_intended; committed mcp schema dropped it";
  }
  return null;
}

export function copyToolsFromSibling({
  sourcePath,
  destPath,
  mkdirSync = (dir) => fs.mkdirSync(dir, { recursive: true }),
  copyFileSync = (src, dest) => fs.copyFileSync(src, dest),
  readFileSync = (p) => fs.readFileSync(p, "utf8"),
  existsSync = (p) => fs.existsSync(p),
  log = console,
} = {}) {
  if (!sourcePath) {
    log.warn(
      "gen-tools: sibling attestd-app/mcp-server/src/tools.ts not found, skipping (using committed src/tools.ts)",
    );
    return { copied: false, skipped: true };
  }

  const destExists = existsSync(destPath);
  const sourceText = readFileSync(sourcePath);
  const destText = destExists ? readFileSync(destPath) : "";
  const reason = skipCopyReason({ destExists, sourceText, destText });
  if (reason) {
    log.warn(`gen-tools: skip copy; ${reason}. Using committed src/tools.ts.`);
    return { copied: false, skipped: true, reason };
  }

  mkdirSync(path.dirname(destPath));
  copyFileSync(sourcePath, destPath);
  log.log("Copied tools.ts from", sourcePath);
  return { copied: true, skipped: false };
}

function main() {
  const sourcePath = appCandidates
    .map((parts) => path.join(__dirname, "..", "..", ...parts))
    .find((p) => fs.existsSync(p));
  const destPath = path.join(__dirname, "..", "src", "tools.ts");
  copyToolsFromSibling({ sourcePath, destPath });
}

const isMain =
  Boolean(process.argv[1]) &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main();
}
