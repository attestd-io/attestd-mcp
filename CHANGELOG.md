# Changelog

## 0.3.2 - 2026-10-08

Unpublished work on `main` since npm `@attestd/mcp@0.3.1` (git `28041a9`, tag `v0.3.1`). Patch release. Additive tools and client-compat fixes. No breaking public MCP shape.

### Added

- `get_usage` tool wrapping `GET /v1/usage` so agents can inspect remaining quota before a 429 (#7).

### Fixed

- Return `structuredContent` on success paths for tools that advertise `outputSchema`, so official MCP SDK clients no longer throw. Schemas allow the nulls the runtime emits (#8).
- Trim `product` and `version` on `check_package_vulnerability`. Whitespace-only values are rejected the same way empty strings are (#6).
- Skip `gen-tools` copy when a sibling `attestd-app` checkout is behind (`SERVER_VERSION` mismatch or leftover `likely_intended`) (#5).
- Shorten `server.json` description to the MCP registry 100-character limit.

### Docs

- Document `gen-tools` in `CLAUDE.md` and accept the lowercase `attestd-website` sibling path (#4).
