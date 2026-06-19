import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  AttestdAPIError,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  Client,
} from "@attestd/sdk";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { COVERED_PRODUCT_COUNT, COVERED_PRODUCTS } from "./products.js";

export const SERVER_VERSION = "0.1.2";

const CHECK_DESCRIPTION =
  "Check whether a software package version has known CVE vulnerabilities or supply chain compromise. " +
  "Use before deploying or recommending any software dependency. " +
  "outsideCoverage=true means Attestd has no data. Treat as unknown risk, not safe. " +
  "Covers infrastructure products (nginx, PostgreSQL, Redis, Docker, Kubernetes, etc.) and " +
  "PyPI/npm packages for supply chain integrity.";

const LIST_DESCRIPTION =
  "Returns infrastructure product slugs covered by Attestd for CVE checks. " +
  "PyPI and npm packages also work with check_package_vulnerability even when absent from this list. " +
  "Call this first if you are unsure whether an infrastructure slug is supported. " +
  "Uses a static bundled list. No /v1/check API call for this tool.";

const CHECK_OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: {
    outsideCoverage: {
      type: "boolean",
      description: "True when Attestd has no CVE data for this product. Unknown risk, not safe.",
    },
    riskState: {
      type: "string",
      description:
        'Risk band: "critical", "high", "elevated", "low", "none", or null when outside coverage.',
    },
    activelyExploited: {
      type: "boolean",
      description: "True when the version appears in the CISA KEV catalog.",
    },
    patchAvailable: {
      type: "boolean",
      description: "True when a fixed version with no critical/high CVEs is known.",
    },
    fixedVersion: {
      type: "string",
      description: "Earliest clean version to recommend. Omitted or null when unknown.",
    },
    cveIds: {
      type: "array",
      items: { type: "string" },
      description: "CVE IDs contributing to the risk assessment.",
    },
    confidence: {
      type: "number",
      description: "Synthesis confidence from 0.0 to 1.0.",
    },
    remoteExploitable: {
      type: "boolean",
      description: "True when any matching CVE is remotely exploitable.",
    },
    authenticationRequired: {
      type: "boolean",
      description: "True only when all matching CVEs require authentication.",
    },
    typosquat: {
      type: "object",
      description: "Typosquat warning when the package name resembles a known product.",
      properties: {
        detected: { type: "boolean" },
        resembles: { type: "string" },
        confidence: { type: "number" },
        ecosystem: { type: "string" },
      },
    },
    supplyChainCompromised: {
      type: "boolean",
      description: "True when a malicious PyPI or npm publish was detected.",
    },
    supplyChainDescription: {
      type: "string",
      description: "Human-readable supply-chain event description when present.",
    },
    message: {
      type: "string",
      description: "Explanation when outsideCoverage is true.",
    },
    error: {
      type: "string",
      description: "Error message when the tool returns isError.",
    },
  },
};

const LIST_OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: {
    count: {
      type: "integer",
      description: "Number of covered infrastructure products.",
    },
    products: {
      type: "array",
      description: "Covered products with slug and display name.",
      items: {
        type: "object",
        properties: {
          slug: { type: "string", description: "Product slug for check_package_vulnerability." },
          display: { type: "string", description: "Human-readable product name." },
        },
        required: ["slug", "display"],
      },
    },
  },
  required: ["count", "products"],
};

const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: true,
};

const LIST_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
};

export const TOOL_DEFINITIONS = [
  {
    name: "check_package_vulnerability",
    description: CHECK_DESCRIPTION,
    inputSchema: {
      type: "object" as const,
      properties: {
        product: {
          type: "string",
          description:
            'Package or product slug, e.g. "nginx", "runc", "@bitwarden/cli", "litellm"',
        },
        version: {
          type: "string",
          description: 'Exact version string, e.g. "1.20.0"',
        },
      },
      required: ["product", "version"],
    },
    outputSchema: CHECK_OUTPUT_SCHEMA,
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "list_covered_products",
    description: LIST_DESCRIPTION,
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
    outputSchema: LIST_OUTPUT_SCHEMA,
    annotations: LIST_ANNOTATIONS,
  },
];

function getClient(apiKey: string | undefined, baseUrl?: string): Client | null {
  const key = apiKey?.trim();
  if (!key) return null;
  const url = baseUrl?.trim();
  return new Client({
    apiKey: key,
    ...(url ? { baseUrl: url } : {}),
  });
}

/**
 * Registers ListTools and CallTool handlers on an MCP Server instance.
 * Used by both stdio (attestd-mcp) and HTTP (this service); HTTP passes apiKey from Authorization.
 */
export function registerTools(
  server: Server,
  apiKey: string | undefined,
  baseUrl?: string,
): void {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const args = request.params.arguments ?? {};

    if (toolName === "list_covered_products") {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                count: COVERED_PRODUCT_COUNT,
                products: COVERED_PRODUCTS,
              },
              null,
              2,
            ),
          },
        ],
      };
    }

    if (toolName === "check_package_vulnerability") {
      const product = typeof args.product === "string" ? args.product : "";
      const version = typeof args.version === "string" ? args.version : "";
      if (!product || !version) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  error: "Both product and version are required.",
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      const attestd = getClient(apiKey, baseUrl);
      if (!attestd) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  error:
                    "A valid Attestd API key is required. Set ATTESTD_API_KEY (stdio) or pass Authorization: Bearer (HTTP).",
                },
                null,
                2,
              ),
            },
          ],
        };
      }

      try {
        const result = await attestd.check(product, version);
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  outsideCoverage: false,
                  riskState: result.riskState,
                  activelyExploited: result.activelyExploited,
                  remoteExploitable: result.remoteExploitable,
                  authenticationRequired: result.authenticationRequired,
                  patchAvailable: result.patchAvailable,
                  fixedVersion: result.fixedVersion,
                  cveIds: result.cveIds,
                  confidence: result.confidence,
                  typosquat: result.typosquat,
                  supplyChainCompromised: result.supplyChain?.compromised ?? false,
                  supplyChainDescription: result.supplyChain?.description ?? null,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
        if (err instanceof AttestdUnsupportedProductError) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    outsideCoverage: true,
                    riskState: null,
                    typosquat: err.typosquat,
                    message: `No Attestd coverage for '${product}'. Treat as unknown risk, not safe.`,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        const isUnsupported =
          err instanceof AttestdAPIError &&
          err.message.includes("missing 'risk_state'");

        if (isUnsupported) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    outsideCoverage: true,
                    riskState: null,
                    message: `No Attestd coverage for '${product}'. Treat as unknown risk, not safe.`,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        if (err instanceof AttestdAuthError) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error:
                      "Invalid API key. Use a valid atst_... key from https://api.attestd.io/portal",
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        if (err instanceof AttestdRateLimitError) {
          const ra = err.retryAfter;
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: `Rate limit exceeded.${ra != null ? ` Retry after ${ra}s.` : ""}`,
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        const message =
          err instanceof Error ? err.message : "An unexpected error occurred.";
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: message }, null, 2),
            },
          ],
        };
      }
    }

    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: `Unknown tool: ${toolName}` }, null, 2),
        },
      ],
    };
  });
}
