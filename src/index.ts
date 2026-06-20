import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { registerTools, SERVER_VERSION } from "./tools.js";

async function main(): Promise<void> {
  const server = new Server(
    { name: "attestd", version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  const apiKey = process.env.ATTESTD_API_KEY?.trim();
  const baseUrl = process.env.ATTESTD_BASE_URL?.trim();
  registerTools(server, apiKey, baseUrl);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
