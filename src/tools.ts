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

export const SERVER_VERSION = "0.3.0";

const CHECK_DESCRIPTION =
  "Check whether a software package or infrastructure product version has known CVE vulnerabilities or a confirmed supply chain compromise. " +
  "Call this before adding, updating, or recommending any npm, PyPI, or infrastructure dependency, including mid-conversation when a developer asks about installing or upgrading a package. " +
  "outsideCoverage=true means Attestd has no data for that product; treat as unknown risk, not safe. " +
  "Covers infrastructure products (nginx, PostgreSQL, Redis, Docker, Kubernetes, etc.) and PyPI/npm packages.";

const LIST_DESCRIPTION =
  "Returns Attestd-covered products for CVE checks. With an API key, returns live data from GET /v1/products (CVE infrastructure slugs plus monitored supply chain packages). Without a key, returns the static bundled infrastructure list. PyPI and npm packages also work with check_package_vulnerability even when absent from this list.";

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
    riskFactors: {
      type: "array",
      items: { type: "string" },
      description: "Risk factor vocabulary driving riskState.",
    },
    maxEpss: {
      type: "number",
      description: "Highest EPSS probability across matching CVEs. Omitted or null when unavailable.",
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
    source: {
      type: "string",
      enum: ["static", "live"],
      description:
        "static when no API key is provided; live when fetched from GET /v1/products.",
    },
    count: {
      type: "integer",
      description: "Number of covered infrastructure products (static source only).",
    },
    products: {
      type: "array",
      description: "Covered CVE infrastructure products (static source only).",
      items: {
        type: "object",
        properties: {
          slug: { type: "string", description: "Product slug for check_package_vulnerability." },
          display: { type: "string", description: "Human-readable product name." },
        },
        required: ["slug", "display"],
      },
    },
    total: {
      type: "integer",
      description: "Total covered CVE products plus supply chain packages (live source only).",
    },
    cveProducts: {
      type: "array",
      description: "CVE infrastructure products from GET /v1/products (live source only).",
      items: {
        type: "object",
        properties: {
          slug: { type: "string" },
          displayName: { type: "string" },
        },
      },
    },
    supplyChainPackages: {
      type: "array",
      description: "Monitored PyPI and npm packages from GET /v1/products (live source only).",
      items: {
        type: "object",
        properties: {
          package: { type: "string" },
          ecosystem: { type: "string" },
          displayName: { type: ["string", "null"] },
        },
      },
    },
  },
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
  openWorldHint: true,
};

const GET_CVE_DESCRIPTION =
  "Return full details for a single CVE id (CVSS, EPSS, KEV status, affected products). " +
  "Use when you need context on a specific CVE before recommending a patch or explaining risk to a developer.";

const CVE_DETAIL_OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: {
    found: { type: "boolean", description: "False when the CVE id is not in Attestd's database." },
    cveId: { type: "string" },
    description: { type: "string" },
    cvssScore: { type: "number" },
    cvssVector: { type: "string" },
    activelyExploited: { type: "boolean" },
    remoteExploitable: { type: "boolean" },
    authenticationRequired: { type: "boolean" },
    affectedProducts: { type: "array", items: { type: "string" } },
    epssScore: { type: "number" },
    epssPercentile: { type: "number" },
    sourcePublishedAt: { type: "string" },
    lastCheckedAt: { type: "string" },
    error: { type: "string" },
  },
};

const BATCH_DESCRIPTION =
  "Check up to 100 software packages or infrastructure products in a single request. " +
  "Each item is billed as one API call. Use this instead of multiple check_package_vulnerability calls when you need to audit a lockfile, manifest, or dependency list. " +
  "Items outside Attestd coverage return outsideCoverage=true and should be treated as unknown risk, not safe. " +
  "A 429 is returned before any results are delivered if the batch would exceed your monthly quota; no calls are billed in that case.";

const BATCH_OUTPUT_SCHEMA = {
  type: "object" as const,
  properties: {
    count: {
      type: "integer",
      description: "Number of items returned.",
    },
    results: {
      type: "array",
      items: {
        type: "object",
        properties: {
          product: { type: "string" },
          version: { type: "string" },
          outsideCoverage: {
            type: "boolean",
            description: "True when Attestd has no CVE data for this product. Unknown risk, not safe.",
          },
          riskState: {
            type: "string",
            description: 'Risk band: "critical", "high", "elevated", "low", "none", or null when outside coverage.',
          },
          riskFactors: { type: "array", items: { type: "string" } },
          maxEpss: { type: "number" },
          activelyExploited: { type: "boolean" },
          remoteExploitable: { type: "boolean" },
          authenticationRequired: { type: "boolean" },
          patchAvailable: { type: "boolean" },
          fixedVersion: { type: "string" },
          cveIds: { type: "array", items: { type: "string" } },
          confidence: { type: "number" },
          supplyChainCompromised: { type: "boolean" },
          supplyChainDescription: { type: "string" },
        },
      },
    },
  },
  required: ["count", "results"],
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
  {
    name: "check_batch_vulnerabilities",
    description: BATCH_DESCRIPTION,
    inputSchema: {
      type: "object" as const,
      properties: {
        items: {
          type: "array",
          description: "Products to check. Maximum 100 per call. Each item costs one API call.",
          items: {
            type: "object",
            properties: {
              product: {
                type: "string",
                description: 'Package or product slug, e.g. "nginx", "litellm"',
              },
              version: {
                type: "string",
                description: 'Exact version string, e.g. "1.20.0"',
              },
            },
            required: ["product", "version"],
          },
          minItems: 1,
          maxItems: 100,
        },
      },
      required: ["items"],
    },
    outputSchema: BATCH_OUTPUT_SCHEMA,
    annotations: READ_ONLY_ANNOTATIONS,
  },
  {
    name: "get_cve_details",
    description: GET_CVE_DESCRIPTION,
    inputSchema: {
      type: "object" as const,
      properties: {
        cve_id: {
          type: "string",
          description: 'CVE identifier, e.g. "CVE-2021-44228"',
        },
      },
      required: ["cve_id"],
    },
    outputSchema: CVE_DETAIL_OUTPUT_SCHEMA,
    annotations: READ_ONLY_ANNOTATIONS,
  },
];

function getClient(
  apiKey: string | undefined,
  baseUrl?: string,
  fetchImpl?: typeof fetch,
): Client | null {
  const key = apiKey?.trim();
  if (!key) return null;
  const url = baseUrl?.trim();
  return new Client({
    apiKey: key,
    ...(url ? { baseUrl: url } : {}),
    ...(fetchImpl ? { fetch: fetchImpl } : {}),
  });
}

export type ToolCallResult = {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
};

/**
 * Dispatches a single MCP tool call. Exported for unit tests.
 */
export async function handleToolCall(
  toolName: string,
  args: Record<string, unknown>,
  apiKey: string | undefined,
  baseUrl?: string,
  fetchImpl?: typeof fetch,
): Promise<ToolCallResult> {
  if (toolName === "list_covered_products") {
    const attestd = getClient(apiKey, baseUrl, fetchImpl);
    if (attestd) {
      try {
        const result = await attestd.products();
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  source: "live",
                  total: result.total,
                  cveProducts: result.cveProducts,
                  supplyChainPackages: result.supplyChainPackages,
                },
                null,
                2,
              ),
            },
          ],
        };
      } catch (err) {
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
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              source: "static",
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

      const attestd = getClient(apiKey, baseUrl, fetchImpl);
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
                  riskFactors: result.riskFactors,
                  maxEpss: result.maxEpss,
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
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error:
                      "Attestd API returned an invalid response (missing risk_state). Retry or check API status.",
                    product,
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

    if (toolName === "check_batch_vulnerabilities") {
      const rawItems = args.items;
      if (!Array.isArray(rawItems) || rawItems.length === 0) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "items must be a non-empty array." }, null, 2),
            },
          ],
        };
      }
      if (rawItems.length > 100) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: "items exceeds maximum of 100 per call." }, null, 2),
            },
          ],
        };
      }

      const items: Array<{ product: string; version: string }> = [];
      for (const item of rawItems) {
        if (typeof item !== "object" || item === null) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  { error: "Each item must be an object with product and version." },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        const product =
          typeof (item as Record<string, unknown>).product === "string"
            ? ((item as Record<string, unknown>).product as string).trim()
            : "";
        const version =
          typeof (item as Record<string, unknown>).version === "string"
            ? ((item as Record<string, unknown>).version as string).trim()
            : "";
        if (!product || !version) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  { error: "Each item must have a non-empty product and version." },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        items.push({ product, version });
      }

      const attestd = getClient(apiKey, baseUrl, fetchImpl);
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
        const results = await attestd.checkBatch(items);
        const output = results.map((result, i) => {
          if (result === null) {
            return {
              product: items[i].product,
              version: items[i].version,
              outsideCoverage: true,
              riskState: null,
            };
          }
          return {
            product: items[i].product,
            version: items[i].version,
            outsideCoverage: false,
            riskState: result.riskState,
            riskFactors: result.riskFactors,
            maxEpss: result.maxEpss,
            activelyExploited: result.activelyExploited,
            remoteExploitable: result.remoteExploitable,
            authenticationRequired: result.authenticationRequired,
            patchAvailable: result.patchAvailable,
            fixedVersion: result.fixedVersion ?? null,
            cveIds: result.cveIds,
            confidence: result.confidence,
            supplyChainCompromised: result.supplyChain?.compromised ?? false,
            supplyChainDescription: result.supplyChain?.description ?? null,
          };
        });
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ count: output.length, results: output }, null, 2),
            },
          ],
        };
      } catch (err) {
        if (err instanceof AttestdAuthError) {
          return {
            isError: true,
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  { error: "Invalid API key. Use a valid atst_... key from https://api.attestd.io/portal" },
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
                  { error: `Rate limit exceeded.${ra != null ? ` Retry after ${ra}s.` : ""}` },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        const message = err instanceof Error ? err.message : "An unexpected error occurred.";
        return {
          isError: true,
          content: [{ type: "text", text: JSON.stringify({ error: message }, null, 2) }],
        };
      }
    }

  if (toolName === "get_cve_details") {
    const cveId = typeof args.cve_id === "string" ? args.cve_id.trim() : "";
    if (!cveId) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: "cve_id is required." }, null, 2),
          },
        ],
      };
    }

    const attestd = getClient(apiKey, baseUrl, fetchImpl);
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
      const detail = await attestd.cve(cveId);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(
              {
                found: true,
                cveId: detail.cveId,
                description: detail.description,
                cvssScore: detail.cvssScore,
                cvssVector: detail.cvssVector,
                activelyExploited: detail.activelyExploited,
                remoteExploitable: detail.remoteExploitable,
                authenticationRequired: detail.authenticationRequired,
                affectedProducts: detail.affectedProducts,
                epssScore: detail.epssScore,
                epssPercentile: detail.epssPercentile,
                sourcePublishedAt: detail.sourcePublishedAt?.toISOString() ?? null,
                lastCheckedAt: detail.lastCheckedAt?.toISOString() ?? null,
              },
              null,
              2,
            ),
          },
        ],
      };
    } catch (err) {
      if (err instanceof AttestdAPIError && err.statusCode === 404) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ found: false, cveId }, null, 2),
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
}

/**
 * Registers ListTools and CallTool handlers on an MCP Server instance.
 * Used by both stdio (attestd-mcp) and HTTP (this service); HTTP passes apiKey from Authorization.
 */
export function registerTools(
  server: Server,
  apiKey: string | undefined,
  baseUrl?: string,
  fetchImpl?: typeof fetch,
): void {
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOL_DEFINITIONS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    return handleToolCall(toolName, args, apiKey, baseUrl, fetchImpl);
  });
}
