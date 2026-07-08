# @attestd/mcp

[![npm version](https://img.shields.io/npm/v/@attestd/mcp)](https://www.npmjs.com/package/@attestd/mcp)
[![smithery badge](https://smithery.ai/badge/@attestd/mcp)](https://smithery.ai/server/@attestd/mcp)

> Attestd checks whether a dependency version has exploitable CVEs or a confirmed supply-chain compromise. One API call returns a structured risk response.

Official [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for [Attestd](https://attestd.io). Exposes CVE risk and supply-chain checks as tools for Claude Code, Claude Desktop, and any MCP-compatible client.

[Get a free API key](https://api.attestd.io/portal/login) · [Full docs](https://attestd.io/docs/integrations/mcp)

- **stdio transport**: run via `npx -y @attestd/mcp` with no global install.
- **`check_package_vulnerability`**: wraps [`GET /v1/check`](https://attestd.io/docs/api-reference) using [`@attestd/sdk`](https://www.npmjs.com/package/@attestd/sdk).
- **`check_batch_vulnerabilities`**: checks up to 100 packages in one call. Use for lockfile and manifest audits.
- **`list_covered_products`**: returns supported infrastructure product slugs (static list). No API key required.

## Prerequisites

- Node.js 18+
- An Attestd API key from the [portal](https://api.attestd.io/portal/login). Required for `check_package_vulnerability` and `check_batch_vulnerabilities`.

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
| `typosquat` | Present when the package name resembles a known product |
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

No arguments. Returns JSON with `count` and `products` (`slug` + `display` for each covered infrastructure product).

## Verify locally

```bash
npm run build
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

## License

MIT. See [LICENSE](./LICENSE).
