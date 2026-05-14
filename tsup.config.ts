import { defineConfig } from "tsup";

export default defineConfig({
    entry: ["src/index.ts"],
    format: ["esm"],
    platform: "node",
    target: "node18",
    dts: false,
    clean: true,
    bundle: true,
    sourcemap: true,
    banner: {
      js: "#!/usr/bin/env node",
    },
    noExternal: ["@attestd/sdk", "@modelcontextprotocol/sdk"],
  });
