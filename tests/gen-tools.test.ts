import { describe, expect, it, vi } from "vitest";
import {
  copyToolsFromSibling,
  extractServerVersion,
  skipCopyReason,
} from "../scripts/gen-tools.mjs";

const MCP_TOOLS = `export const SERVER_VERSION = "0.3.1";
const CHECK_OUTPUT_SCHEMA = {
  typosquat: { properties: { detected: { type: "boolean" } } },
};
`;

const APP_OLDER = `export const SERVER_VERSION = "0.3.0";
const CHECK_OUTPUT_SCHEMA = {
  typosquat: { properties: { likely_intended: { type: "array" } } },
};
`;

describe("extractServerVersion", () => {
  it("reads the exported SERVER_VERSION string", () => {
    expect(extractServerVersion(MCP_TOOLS)).toBe("0.3.1");
    expect(extractServerVersion("no version here")).toBeNull();
  });
});

describe("skipCopyReason", () => {
  it("allows copy when dest is missing", () => {
    expect(
      skipCopyReason({
        destExists: false,
        sourceText: APP_OLDER,
        destText: "",
      }),
    ).toBeNull();
  });

  it("skips when sibling SERVER_VERSION differs from committed mcp", () => {
    expect(
      skipCopyReason({
        destExists: true,
        sourceText: APP_OLDER,
        destText: MCP_TOOLS,
      }),
    ).toMatch(/0\.3\.0 != committed 0\.3\.1/);
  });

  it("skips when sibling still advertises likely_intended after mcp dropped it", () => {
    const sameVersionApp = APP_OLDER.replace("0.3.0", "0.3.1");
    expect(
      skipCopyReason({
        destExists: true,
        sourceText: sameVersionApp,
        destText: MCP_TOOLS,
      }),
    ).toMatch(/likely_intended/);
  });

  it("allows copy when versions match and schema markers align", () => {
    expect(
      skipCopyReason({
        destExists: true,
        sourceText: MCP_TOOLS,
        destText: MCP_TOOLS,
      }),
    ).toBeNull();
  });
});

describe("copyToolsFromSibling", () => {
  it("does not overwrite dest when the App sibling is behind", () => {
    const copyFileSync = vi.fn();
    const result = copyToolsFromSibling({
      sourcePath: "/tmp/app-tools.ts",
      destPath: "/tmp/mcp-tools.ts",
      existsSync: (p) => p === "/tmp/mcp-tools.ts",
      readFileSync: (p) => (p.includes("app") ? APP_OLDER : MCP_TOOLS),
      copyFileSync,
      mkdirSync: vi.fn(),
      log: { warn: vi.fn(), log: vi.fn() },
    });
    expect(result.copied).toBe(false);
    expect(result.skipped).toBe(true);
    expect(copyFileSync).not.toHaveBeenCalled();
  });
});
