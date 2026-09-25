import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const websiteCandidates = [
  ["attestd-website", "lib", "products.ts"],
  ["Attestd-website", "lib", "products.ts"],
];
const websitePath = websiteCandidates
  .map((parts) => path.join(__dirname, "..", "..", ...parts))
  .find((p) => fs.existsSync(p));
if (!websitePath) {
  console.warn(
    "gen-products: sibling attestd-website/lib/products.ts not found, skipping (using committed src/products.ts)",
  );
  process.exit(0);
}
const s = fs.readFileSync(websitePath, "utf8");
const re =
  /\{\s*slug:\s*"([^"]+)",\s*display:\s*"([^"]+)"/g;
const items = [];
let m;
while ((m = re.exec(s))) {
  items.push({ slug: m[1], display: m[2] });
}
if (items.length < 50) {
  console.error("Unexpected product count:", items.length);
  process.exit(1);
}
const lines = [
  "/**",
  " * Covered infrastructure products (CVE risk via /v1/check).",
  " * Keep in sync with attestd-website/lib/products.ts when adding products.",
  " */",
  "export const COVERED_PRODUCTS: ReadonlyArray<{ slug: string; display: string }> = [",
];
for (const { slug, display } of items) {
  lines.push(`  { slug: ${JSON.stringify(slug)}, display: ${JSON.stringify(display)} },`);
}
lines.push("];");
lines.push(`export const COVERED_PRODUCT_COUNT = ${items.length} as const;`);
const outDir = path.join(__dirname, "..", "src");
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, "products.ts"), lines.join("\n") + "\n");
console.log("Wrote src/products.ts with", items.length, "products");
