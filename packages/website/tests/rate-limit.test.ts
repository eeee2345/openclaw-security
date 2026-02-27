import { describe, it, expect } from "vitest";
import { checkRateLimit, getClientIP } from "../src/lib/rate-limit";

/* ─── checkRateLimit ─── */

describe("checkRateLimit", () => {
  // Each test uses a unique IP to avoid cross-test interference
  // since the module-level store persists across tests

  it("allows the first request", () => {
    expect(checkRateLimit("10.0.0.1")).toBe(true);
  });

  it("allows up to 5 requests per window", () => {
    const ip = "10.0.0.2";
    for (let i = 0; i < 5; i++) {
      expect(checkRateLimit(ip)).toBe(true);
    }
  });

  it("blocks the 6th request within the window", () => {
    const ip = "10.0.0.3";
    for (let i = 0; i < 5; i++) {
      checkRateLimit(ip);
    }
    expect(checkRateLimit(ip)).toBe(false);
  });

  it("different IPs have independent limits", () => {
    const ip1 = "10.0.0.4";
    const ip2 = "10.0.0.5";
    for (let i = 0; i < 5; i++) {
      checkRateLimit(ip1);
    }
    // ip1 is exhausted, but ip2 should still be allowed
    expect(checkRateLimit(ip1)).toBe(false);
    expect(checkRateLimit(ip2)).toBe(true);
  });
});

/* ─── getClientIP ─── */

describe("getClientIP", () => {
  function makeRequest(headers: Record<string, string>): Request {
    return new Request("https://example.com", {
      headers: new Headers(headers),
    });
  }

  it("prefers x-real-ip header", () => {
    const req = makeRequest({
      "x-real-ip": "1.2.3.4",
      "x-forwarded-for": "5.6.7.8, 9.10.11.12",
    });
    expect(getClientIP(req)).toBe("1.2.3.4");
  });

  it("takes the FIRST IP from x-forwarded-for", () => {
    const req = makeRequest({
      "x-forwarded-for": "1.1.1.1, 2.2.2.2, 3.3.3.3",
    });
    expect(getClientIP(req)).toBe("1.1.1.1");
  });

  it("trims whitespace from forwarded IPs", () => {
    const req = makeRequest({
      "x-forwarded-for": "  4.4.4.4 , 5.5.5.5",
    });
    expect(getClientIP(req)).toBe("4.4.4.4");
  });

  it("returns 'unknown' when no IP headers present", () => {
    const req = makeRequest({});
    expect(getClientIP(req)).toBe("unknown");
  });

  it("returns x-forwarded-for single value", () => {
    const req = makeRequest({
      "x-forwarded-for": "9.9.9.9",
    });
    expect(getClientIP(req)).toBe("9.9.9.9");
  });
});
