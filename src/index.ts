import {
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  Client,
} from "@attestd/sdk";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

import { COVERED_PRODUCTS, COVERED_PRODUCT_COUNT } from "./products.js";

const SERVER_VERSION = "0.1.1";

const CHECK_DESCRIPTION =
  "Check whether a software package version has known CVE vulnerabilities or supply chain compromise. " +
  "Use before deploying or recommending any software dependency. " +
  "outsideCoverage=true means Attestd has no data — treat as unknown risk, not safe. " +
  "Covers infrastructure products (nginx, PostgreSQL, Redis, Docker, Kubernetes, etc.) and " +
  "PyPI/npm packages for supply chain integrity.";

const LIST_DESCRIPTION =
  "Returns all product slugs and human-readable names covered by Attestd for CVE risk checks. " +
  "Call this first if you are unsure whether a product slug is supported. " +
  "Does not require an API key.";

const TOOL_DEFINITIONS = [
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
  },
  {
    name: "list_covered_products",
    description: LIST_DESCRIPTION,
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
];

function getClient(): Client | null {
  const apiKey = process.env.ATTESTD_API_KEY?.trim();
  if (!apiKey) return null;
  const baseUrl = process.env.ATTESTD_BASE_URL?.trim();
  return new Client({
    apiKey,
    ...(baseUrl ? { baseUrl } : {}),
  });
}

async function main(): Promise<void> {
  const server = new Server(
    { name: "attestd", version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

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

      const attestd = getClient();
      if (!attestd) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  error:
                    "ATTESTD_API_KEY is not set. Add it to the MCP server env block in mcp.json.",
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
                  patchAvailable: result.patchAvailable,
                  fixedVersion: result.fixedVersion,
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
                      "Invalid API key. Set ATTESTD_API_KEY to a valid atst_... key from https://api.attestd.io/portal",
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

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
