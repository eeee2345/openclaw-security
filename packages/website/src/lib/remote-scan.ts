/**
 * Remote security scanner — lightweight checks using Node.js native modules.
 * DNS resolution, TCP port checks, TLS/SSL inspection, HTTP header analysis.
 */

import dns from "dns/promises";
import net from "net";
import tls from "tls";

/* ─── Types ─── */

export interface ScanFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  detail: string;
}

export interface ScanResult {
  target: string;
  scanDuration: number;
  score: number;
  grade: string;
  findings: ScanFinding[];
  openPorts: number[];
  ssl: { valid: boolean; expiresIn: number; protocol: string } | null;
}

/* ─── Constants ─── */

const COMMON_PORTS = [22, 80, 443, 3306, 5432, 6379, 8080, 8443];
const TCP_TIMEOUT = 3000;
const TOTAL_TIMEOUT = 15000;

/* ─── Private IP check (SSRF protection) ─── */

const PRIVATE_RANGES = [
  /^127\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^fd/i,
  /^localhost$/i,
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some((re) => re.test(ip));
}

function isPrivateTarget(target: string): boolean {
  return PRIVATE_RANGES.some((re) => re.test(target));
}

/* ─── Domain/IP validation ─── */

const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

export function isValidTarget(target: string): boolean {
  return DOMAIN_RE.test(target) || IPV4_RE.test(target);
}

/* ─── Individual checks ─── */

async function resolveDNS(target: string): Promise<{ ips: string[]; findings: ScanFinding[] }> {
  const findings: ScanFinding[] = [];
  try {
    const ips = await dns.resolve4(target);
    for (const ip of ips) {
      if (isPrivateIP(ip)) {
        throw new Error("Target resolves to private IP");
      }
    }
    return { ips, findings };
  } catch (err) {
    if (err instanceof Error && err.message.includes("private")) {
      throw err;
    }
    // If it's an IP address, return it directly
    if (IPV4_RE.test(target)) {
      if (isPrivateIP(target)) throw new Error("Target is a private IP");
      return { ips: [target], findings };
    }
    findings.push({
      severity: "high",
      title: "DNS Resolution Failed",
      detail: `Could not resolve ${target} to an IP address.`,
    });
    return { ips: [], findings };
  }
}

async function checkPort(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(TCP_TIMEOUT);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

async function checkPorts(host: string): Promise<{ openPorts: number[]; findings: ScanFinding[] }> {
  const findings: ScanFinding[] = [];
  const results = await Promise.all(
    COMMON_PORTS.map(async (port) => ({
      port,
      open: await checkPort(host, port),
    }))
  );

  const openPorts = results.filter((r) => r.open).map((r) => r.port);

  // Findings for risky open ports
  const riskyPorts: Record<number, string> = {
    3306: "MySQL database port is publicly accessible",
    5432: "PostgreSQL database port is publicly accessible",
    6379: "Redis port is publicly accessible (common attack vector)",
  };

  for (const port of openPorts) {
    if (riskyPorts[port]) {
      findings.push({
        severity: port === 6379 ? "critical" : "high",
        title: `Port ${port} Open`,
        detail: riskyPorts[port],
      });
    }
  }

  return { openPorts, findings };
}

async function checkSSL(
  host: string
): Promise<{ ssl: ScanResult["ssl"]; findings: ScanFinding[] }> {
  const findings: ScanFinding[] = [];

  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: 443,
        servername: host,
        timeout: TCP_TIMEOUT,
        // Intentionally false: we connect regardless of cert validity
        // in order to inspect and report on certificate issues as findings.
        rejectUnauthorized: false,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol() || "unknown";
        const authorized = socket.authorized;

        let expiresIn = 0;
        if (cert.valid_to) {
          const expiry = new Date(cert.valid_to).getTime();
          expiresIn = Math.floor((expiry - Date.now()) / (1000 * 60 * 60 * 24));
        }

        if (!authorized) {
          findings.push({
            severity: "high",
            title: "SSL Certificate Invalid",
            detail: String(socket.authorizationError || "Certificate validation failed"),
          });
        } else if (expiresIn < 0) {
          findings.push({
            severity: "critical",
            title: "SSL Certificate Expired",
            detail: `Certificate expired ${Math.abs(expiresIn)} days ago.`,
          });
        } else if (expiresIn < 30) {
          findings.push({
            severity: "medium",
            title: "SSL Certificate Expiring Soon",
            detail: `Certificate expires in ${expiresIn} days.`,
          });
        }

        if (protocol === "TLSv1" || protocol === "TLSv1.1") {
          findings.push({
            severity: "high",
            title: "Outdated TLS Version",
            detail: `Server uses ${protocol}. Upgrade to TLS 1.2 or 1.3.`,
          });
        }

        socket.destroy();
        resolve({
          ssl: { valid: authorized && expiresIn > 0, expiresIn, protocol },
          findings,
        });
      }
    );

    socket.once("timeout", () => {
      socket.destroy();
      resolve({ ssl: null, findings });
    });

    socket.once("error", () => {
      socket.destroy();
      findings.push({
        severity: "medium",
        title: "No SSL/TLS",
        detail: "Could not establish TLS connection on port 443.",
      });
      resolve({ ssl: null, findings });
    });
  });
}

async function checkHTTPHeaders(target: string): Promise<ScanFinding[]> {
  const findings: ScanFinding[] = [];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TCP_TIMEOUT);

    const res = await fetch(`https://${target}`, {
      method: "HEAD",
      signal: controller.signal,
      redirect: "follow",
    });
    clearTimeout(timeout);

    const headers = res.headers;

    if (!headers.get("strict-transport-security")) {
      findings.push({
        severity: "medium",
        title: "Missing HSTS Header",
        detail: "Strict-Transport-Security header not set. Browsers may connect over HTTP.",
      });
    }

    if (!headers.get("x-frame-options") && !headers.get("content-security-policy")?.includes("frame-ancestors")) {
      findings.push({
        severity: "medium",
        title: "Missing Clickjacking Protection",
        detail: "Neither X-Frame-Options nor CSP frame-ancestors is set.",
      });
    }

    if (!headers.get("x-content-type-options")) {
      findings.push({
        severity: "low",
        title: "Missing X-Content-Type-Options",
        detail: "X-Content-Type-Options: nosniff header not set.",
      });
    }

    const server = headers.get("server");
    if (server && /nginx|apache|iis/i.test(server)) {
      findings.push({
        severity: "info",
        title: "Server Version Disclosed",
        detail: `Server header reveals: ${server}`,
      });
    }
  } catch {
    // HTTP check failure is non-critical — SSL check already covers connectivity
  }

  return findings;
}

/* ─── Score calculation ─── */

function calculateScore(findings: ScanFinding[]): { score: number; grade: string } {
  let score = 100;

  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        score -= 25;
        break;
      case "high":
        score -= 15;
        break;
      case "medium":
        score -= 8;
        break;
      case "low":
        score -= 3;
        break;
      case "info":
        score -= 1;
        break;
    }
  }

  score = Math.max(0, Math.min(100, score));

  let grade: string;
  if (score >= 90) grade = "A";
  else if (score >= 80) grade = "B";
  else if (score >= 70) grade = "C";
  else if (score >= 60) grade = "D";
  else grade = "F";

  return { score, grade };
}

/* ─── Main scan function ─── */

export async function runRemoteScan(target: string): Promise<ScanResult> {
  const start = Date.now();

  // Validate target
  if (!isValidTarget(target)) {
    throw new Error("Invalid target format");
  }

  if (isPrivateTarget(target)) {
    throw new Error("Scanning private/internal addresses is not allowed");
  }

  // DNS resolution
  const { ips, findings: dnsFindings } = await resolveDNS(target);
  const allFindings: ScanFinding[] = [...dnsFindings];

  if (ips.length === 0) {
    const { score, grade } = calculateScore(allFindings);
    return {
      target,
      scanDuration: Date.now() - start,
      score,
      grade,
      findings: allFindings,
      openPorts: [],
      ssl: null,
    };
  }

  const host = ips[0];

  // Run port check, SSL check, and HTTP headers in parallel with total timeout
  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("Scan timeout")), TOTAL_TIMEOUT)
  );

  try {
    const [portResult, sslResult, headerFindings] = await Promise.race([
      Promise.all([
        checkPorts(host),
        checkSSL(target),
        checkHTTPHeaders(target),
      ]),
      timeoutPromise,
    ]) as [
      Awaited<ReturnType<typeof checkPorts>>,
      Awaited<ReturnType<typeof checkSSL>>,
      ScanFinding[]
    ];

    allFindings.push(...portResult.findings, ...sslResult.findings, ...headerFindings);
    const { score, grade } = calculateScore(allFindings);

    return {
      target,
      scanDuration: Date.now() - start,
      score,
      grade,
      findings: allFindings,
      openPorts: portResult.openPorts,
      ssl: sslResult.ssl,
    };
  } catch {
    const { score, grade } = calculateScore(allFindings);
    return {
      target,
      scanDuration: Date.now() - start,
      score,
      grade,
      findings: allFindings,
      openPorts: [],
      ssl: null,
    };
  }
}
