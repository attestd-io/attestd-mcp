import { describe, it, expect } from "vitest";
import { handleToolCall } from "../src/tools.js";
import { COVERED_PRODUCT_COUNT } from "../src/products.js";

function expectSuccessStructured(result: Awaited<ReturnType<typeof handleToolCall>>) {
  expect(result.isError).toBeUndefined();
  expect(result.structuredContent).toBeDefined();
  expect(result.structuredContent).toEqual(JSON.parse(result.content[0]?.text ?? "{}"));
}

describe("handleToolCall", () => {
  it("list_covered_products returns static list without key", async () => {
    const result = await handleToolCall("list_covered_products", {}, undefined);
    expectSuccessStructured(result);
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
    expectSuccessStructured(result);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.found).toBe(true);
    expect(payload.cveId).toBe("CVE-2021-44228");
    expect(payload.cvssScore).toBe(10);
    expect(payload.epssScore).toBeCloseTo(0.97568);
  });

  it("get_usage happy path", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const href =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input instanceof Request
              ? input.url
              : String(input);
      expect(href).toContain("/v1/usage");
      return new Response(
        JSON.stringify({
          tier: "solo",
          key_calls_this_month: 1200,
          account_calls_this_month: 1200,
          included_calls: 10000,
          billing_period_start: "2026-07-01T00:00:00Z",
          billing_period_end: "2026-08-01T00:00:00Z",
          overage_calls: 0,
          estimated_overage_usd: 0.0,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    };

    const result = await handleToolCall(
      "get_usage",
      {},
      "atst_test",
      undefined,
      fetchImpl,
    );
    expectSuccessStructured(result);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.tier).toBe("solo");
    expect(payload.keyCallsThisMonth).toBe(1200);
    expect(payload.includedCalls).toBe(10000);
    expect(payload.billingPeriodStart).toBe("2026-07-01T00:00:00.000Z");
  });

  it("get_usage missing key returns error", async () => {
    const result = await handleToolCall("get_usage", {}, undefined);
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.error).toContain("API key");
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
    expectSuccessStructured(result);
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

  it("check_package_vulnerability rejects whitespace-only product and version", async () => {
    let called = false;
    const fetchImpl: typeof fetch = async () => {
      called = true;
      return jsonResponse({ error: "should not be called" }, 500);
    };
    const result = await handleToolCall(
      "check_package_vulnerability",
      { product: "   ", version: "\t" },
      "atst_test",
      undefined,
      fetchImpl,
    );
    expect(called).toBe(false);
    expect(result.isError).toBe(true);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.error).toContain("product and version are required");
  });
});

const NGINX_CHECK_BODY = {
  product: "nginx",
  version: "1.20.0",
  supported: true,
  risk_state: "high",
  risk_factors: ["remote_code_execution", "no_authentication_required"],
  actively_exploited: false,
  remote_exploitable: true,
  authentication_required: false,
  patch_available: true,
  fixed_version: "1.21.0",
  confidence: 0.91,
  cve_ids: ["CVE-2021-23017"],
  max_epss: 0.12,
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: null,
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("handleToolCall check and batch", () => {
  it("check_package_vulnerability returns risk fields including maxEpss", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const href =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input instanceof Request
              ? input.url
              : String(input);
      const url = new URL(href);
      expect(url.searchParams.get("product")).toBe("nginx");
      expect(url.searchParams.get("version")).toBe("1.20.0");
      return jsonResponse(NGINX_CHECK_BODY);
    };
    const result = await handleToolCall(
      "check_package_vulnerability",
      { product: "  nginx  ", version: "  1.20.0  " },
      "atst_test",
      undefined,
      fetchImpl,
    );
    expectSuccessStructured(result);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.outsideCoverage).toBe(false);
    expect(payload.riskState).toBe("high");
    expect(payload.riskFactors).toContain("remote_code_execution");
    expect(payload.maxEpss).toBeCloseTo(0.12);
    expect(payload.cveIds).toEqual(["CVE-2021-23017"]);
    expect(payload.typosquat).toBeNull();
  });

  it("check_batch_vulnerabilities returns count and per-item fields", async () => {
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.includes("/v1/check/batch")) {
        return jsonResponse({
          results: [
            {
              product: "nginx",
              version: "1.20.0",
              result: NGINX_CHECK_BODY,
            },
          ],
        });
      }
      return jsonResponse({ error: "unexpected url" }, 500);
    };
    const result = await handleToolCall(
      "check_batch_vulnerabilities",
      { items: [{ product: "nginx", version: "1.20.0" }] },
      "atst_test",
      undefined,
      fetchImpl,
    );
    expectSuccessStructured(result);
    const payload = JSON.parse(result.content[0]?.text ?? "{}");
    expect(payload.count).toBe(1);
    expect(payload.results[0].product).toBe("nginx");
    expect(payload.results[0].riskState).toBe("high");
    expect(payload.results[0].maxEpss).toBeCloseTo(0.12);
    expect(payload.results[0].cveIds).toEqual(["CVE-2021-23017"]);
  });

  it("check_package_vulnerability outside coverage includes structuredContent with null riskState", async () => {
    const fetchImpl: typeof fetch = async () => jsonResponse({ detail: "not found" }, 404);
    const result = await handleToolCall(
      "check_package_vulnerability",
      { product: "unknown-lib", version: "1.0.0" },
      "atst_test",
      undefined,
      fetchImpl,
    );
    expectSuccessStructured(result);
    expect(result.structuredContent?.outsideCoverage).toBe(true);
    expect(result.structuredContent?.riskState).toBeNull();
    expect(result.structuredContent?.typosquat).toBeNull();
  });
});
