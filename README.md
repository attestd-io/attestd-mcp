# @attestd/mcp

[![smithery badge](https://smithery.ai/badge/@attestd/mcp)](https://smithery.ai/server/@attestd/mcp)

Official [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for **[Attestd](https://attestd.io)**. Exposes deterministic CVE risk and supply-chain integrity checks as tools for **Claude Code**, Claude Desktop, and any MCP-compatible client.

- **stdio transport** — run via `npx -y @attestd/mcp` with no global install.
- **`check_package_vulnerability`** — wraps [`GET /v1/check`](https://attestd.io/docs/api-reference) using [`@attestd/sdk`](https://www.npmjs.com/package/@attestd/sdk).
- **`list_covered_products`** — returns supported infrastructure product slugs (static list); **no API key required**.

Full docs: [attestd.io/docs/integrations/mcp](https://attestd.io/docs/integrations/mcp)

## Prerequisites

- **Node.js 18+**
- An Attestd API key (`atst_...`) from the [portal](https://api.attestd.io/portal) — required only for `check_package_vulnerability`.

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

Returns JSON (text content) with:

| Field | Meaning |
| ----- | ------- |
| `outsideCoverage` | `true` if the product is not covered — **unknown risk, not safe** |
| `riskState` | `critical` \| `high` \| `elevated` \| `low` \| `none` \| `null` when outside coverage |
| `activelyExploited` | CISA KEV signal |
| `patchAvailable` / `fixedVersion` | Patch guidance |
| `supplyChainCompromised` / `supplyChainDescription` | PyPI/npm supply-chain signal |

On invalid/missing API key or rate limit, returns `isError: true` with a JSON `error` string.

### `list_covered_products`

No arguments. Returns JSON with `count` and `products` (`slug` + `display` for each covered infrastructure product).

## Verify locally

```bash
npm run build
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | node dist/index.js
```

## License

MIT — see [LICENSE](./LICENSE).
