# For Claude Code and contributors

## Build

```bash
npm install
npm run build
```

`prebuild` runs two generators:

- `scripts/gen-products.mjs` regenerates `src/products.ts` from `../attestd-website/lib/products.ts` (also accepts `../Attestd-website/...`).
- `scripts/gen-tools.mjs` copies `src/tools.ts` from `../attestd-app/mcp-server/src/tools.ts` (also accepts `../Attestd-App/...`) when that sibling exists.

Run from a checkout that has **attestd-mcp** plus the website (and optionally attestd-app) under the same parent directory, or edit the generated files manually.

## Local MCP smoke test (stdio)

Unix:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | ATTESTD_API_KEY=atst_... node dist/index.js
```

Windows (PowerShell), pipe a here-string or use `cmd /c`.

## Implementation notes

- **Shebang**: Injected into `dist/index.js` by `tsup` (`banner` in `tsup.config.ts`), not duplicated in `src/index.ts`.
- **SDK**: Uses `@modelcontextprotocol/sdk` v1 `Server` + `ListToolsRequestSchema` / `CallToolRequestSchema`, not the newer `McpServer` helper from pre-release docs.
- **Four tools**: `check_package_vulnerability`, `check_batch_vulnerabilities` (both need `ATTESTD_API_KEY`), `get_cve_details` (needs key), and `list_covered_products` (static list without key; live data from `GET /v1/products` when keyed).
- **Product list**: Must stay aligned with marketing/docs catalog in `attestd-website/lib/products.ts`.
