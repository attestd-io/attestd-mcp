import { describe, it, expect } from "vitest";
import { handleToolCall } from "../src/tools.js";
import { COVERED_PRODUCT_COUNT } from "../src/products.js";

describe("handleToolCall", () => {
  it("list_covered_products returns static list without key", async () => {
    const result = await handleToolCall("list_covered_products", {}, undefined);
    expect(result.isError).toBeUndefined();
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.source).toBe("static");
    expect(payload.count).toBe(COVERED_PRODUCT_COUNT);
    expect(payload.products[0]?.slug).toBeTruthy();
  });

  it("get_cve_details happy path", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(
        JSON.stringify({
          cve_id: "CVE-2021-44228",
          description: "Log4Shell",
          cvss_score: 10.0,
          cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
          actively_exploited: true,
          remote_exploitable: true,
          authentication_required: false,
          affected_products: ["log4j"],
          epss_score: 0.97568,
          epss_percentile: 0.99976,
          source_published_at: "2021-12-10T00:00:00Z",
          last_checked_at: "2026-07-08T04:00:00Z",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );

    const result = await handleToolCall(
      "get_cve_details",
      { cve_id: "CVE-2021-44228" },
      "atst_test",
      undefined,
      fetchImpl,
    );
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.found).toBe(true);
    expect(payload.cveId).toBe("CVE-2021-44228");
    expect(payload.cvssScore).toBe(10);
    expect(payload.epssScore).toBeCloseTo(0.97568);
  });

  it("get_cve_details 404 returns not found", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response(JSON.stringify({ detail: "CVE not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });

    const result = await handleToolCall(
      "get_cve_details",
      { cve_id: "CVE-9999-99999" },
      "atst_test",
      undefined,
      fetchImpl,
    );
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.found).toBe(false);
    expect(payload.cveId).toBe("CVE-9999-99999");
  });

  it("check_package_vulnerability missing key returns error", async () => {
    const result = await handleToolCall(
      "check_package_vulnerability",
      { product: "nginx", version: "1.25.3" },
      undefined,
    );
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.error).toContain("API key");
  });
});
