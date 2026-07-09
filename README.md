# @attestd/mcp

[![npm version](https://img.shields.io/npm/v/@attestd/mcp)](https://www.npmjs.com/package/@attestd/mcp)
[![smithery badge](https://smithery.ai/badge/@attestd/mcp)](https://smithery.ai/server/@attestd/mcp)

> Attestd checks whether a dependency version has exploitable CVEs or a confirmed supply-chain compromise. One API call returns a structured risk response.

Official [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for [Attestd](https://attestd.io). Exposes CVE risk and supply-chain checks as tools for Claude Code, Claude Desktop, and any MCP-compatible client.

[Get a free API key](https://api.attestd.io/portal/login) · [Full docs](https://attestd.io/docs/integrations/mcp)

- **stdio transport**: run via `npx -y @attestd/mcp` with no global install.
- **`check_package_vulnerability`**: wraps [`GET /v1/check`](https://attestd.io/docs/api-reference) using [`@attestd/sdk`](https://www.npmjs.com/package/@attestd/sdk).
- **`check_batch_vulnerabilities`**: checks up to 100 packages in one call. Use for lockfile and manifest audits.
- **`list_covered_products`**: returns Attestd-covered products. With an API key, returns live data from `GET /v1/products`. Without a key, returns the static bundled infrastructure list.
- **`get_cve_details`**: returns CVSS, EPSS, KEV status, and affected products for a single CVE id.

## Prerequisites

- Node.js 18+
- An Attestd API key from the [portal](https://api.attestd.io/portal/login). Required for `check_package_vulnerability`, `check_batch_vulnerabilities`, `get_cve_details`, and live `list_covered_products`.

## Claude Code / MCP config

Add to `~/.claude/mcp.json` or project `.mcp.json`:

```json
{
  "mcpServers": {
    "attestd": {
      "command": "npx",
      "args": ["-y", "@attestd/mcp"],
      "env": {
        "ATTESTD_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

Optional: override the API base URL (e.g. dev):

```json
"env": {
  "ATTESTD_API_KEY": "your-api-key-here",
  "ATTESTD_BASE_URL": "https://dev.api.attestd.io"
}
```

## Tools

### `check_package_vulnerability`

| Argument  | Type   | Description |
| --------- | ------ | ----------- |
| `product` | string | Product slug (`nginx`, `postgresql`, `litellm`, …) |
| `version` | string | Exact version (`1.20.0`) |

Returns JSON with:

| Field | Meaning |
| ----- | ------- |
| `outsideCoverage` | `true` if the product is not covered. Unknown risk, not safe. |
| `riskState` | `critical` \| `high` \| `elevated` \| `low` \| `none` \| `null` when outside coverage |
| `activelyExploited` | CISA KEV signal |
| `remoteExploitable` | `true` if any matching CVE is remotely exploitable |
| `authenticationRequired` | `true` only when all matching CVEs require authentication |
| `patchAvailable` / `fixedVersion` | Patch guidance |
| `confidence` | Synthesis confidence 0.0–1.0 |
| `cveIds` | CVE IDs contributing to the risk assessment |
| `typosquat` | Package name integrity: typosquat or AI-hallucinated name (`kind`, `resembles`, `likely_intended`) |
| `message` | Explanation when `outsideCoverage` is true |
| `supplyChainCompromised` / `supplyChainDescription` | PyPI/npm supply-chain signal |

On invalid/missing API key or rate limit, returns `isError: true` with a JSON `error` string.

### `check_batch_vulnerabilities`

| Argument | Type  | Description |
| -------- | ----- | ----------- |
| `items`  | array | Array of `{ product, version }` objects. Maximum 100 per call. Each item costs one API call. |

Quota is checked upfront. If the batch would exceed your monthly quota, a 429 is returned before any calls are billed.

Returns JSON with `count` and `results`. Supported items include the same fields as `check_package_vulnerability` minus `typosquat`. Outside-coverage items return only `product`, `version`, `outsideCoverage: true`, and `riskState: null`.

### `list_covered_products`

No arguments. With an API key, returns live JSON from `GET /v1/products`:

| Field | Meaning |
| ----- | ------- |
| `source` | `"live"` when fetched from the API |
| `total` | Combined count of CVE products and supply chain packages |
| `cveProducts` | CVE infrastructure slugs with display names |
| `supplyChainPackages` | Monitored PyPI/npm packages |

Without an API key, returns the static bundled list:

| Field | Meaning |
| ----- | ------- |
| `source` | `"static"` |
| `count` | Number of bundled infrastructure products |
| `products` | Array of `{ slug, display }` entries |

### `get_cve_details`

| Argument | Type   | Description |
| -------- | ------ | ----------- |
| `cve_id` | string | CVE identifier, e.g. `CVE-2021-44228` |

Returns JSON with:

| Field | Meaning |
| ----- | ------- |
| `found` | `true` when the CVE is in Attestd's database; `false` on 404 (not an error) |
| `cveId` | CVE identifier |
| `description` | NVD description text |
| `cvssScore` / `cvssVector` | CVSS base score and vector |
| `activelyExploited` | CISA KEV signal |
| `remoteExploitable` | Remotely exploitable |
| `authenticationRequired` | Authentication required for exploitation |
| `affectedProducts` | Attestd product slugs affected by this CVE |
| `epssScore` / `epssPercentile` | EPSS probability and percentile |
| `sourcePublishedAt` / `lastCheckedAt` | ISO timestamps |

When the CVE is not found, returns `{ "found": false, "cveId": "..." }` without `isError`. On invalid/missing API key or rate limit, returns `isError: true` with a JSON `error` string.

## Verify locally

```bash
npm run build
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

## License

MIT. See [LICENSE](./LICENSE).
