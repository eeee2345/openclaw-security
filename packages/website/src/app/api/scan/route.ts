import { NextResponse } from "next/server";
import { checkRateLimit, getClientIP } from "@/lib/rate-limit";
import { runRemoteScan, isValidTarget } from "@/lib/remote-scan";

const ALLOWED_ORIGINS = [
  "https://panguard.ai",
  "https://www.panguard.ai",
];

function isAllowedOrigin(req: Request): boolean {
  // Allow all requests in development
  if (process.env.NODE_ENV === "development") return true;

  const origin = req.headers.get("origin");
  if (origin && ALLOWED_ORIGINS.includes(origin)) return true;

  // Fallback: check referer for same-site requests (some browsers omit origin)
  const referer = req.headers.get("referer");
  if (referer && ALLOWED_ORIGINS.some((o) => referer.startsWith(o))) return true;

  return false;
}

export async function POST(req: Request) {
  // Origin check — reject cross-origin abuse
  if (!isAllowedOrigin(req)) {
    return NextResponse.json(
      { error: "Forbidden" },
      { status: 403 }
    );
  }

  // Rate limiting
  const ip = getClientIP(req);
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Too many requests. Please wait a minute." },
      { status: 429 }
    );
  }

  // Parse body
  let body: { target?: string };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json(
      { error: "Invalid request body" },
      { status: 400 }
    );
  }

  const target = (body.target || "").trim().toLowerCase();

  // Validate
  if (!target) {
    return NextResponse.json(
      { error: "Target is required" },
      { status: 400 }
    );
  }

  if (!isValidTarget(target)) {
    return NextResponse.json(
      { error: "Invalid target. Please enter a valid domain or IP address." },
      { status: 400 }
    );
  }

  // Run scan
  try {
    const result = await runRemoteScan(target);
    return NextResponse.json(result);
  } catch (err) {
    const message =
      err instanceof Error ? err.message : "Scan failed";

    // Don't expose internal error details
    const safeMessages = [
      "Invalid target format",
      "Scanning private/internal addresses is not allowed",
      "Target resolves to private IP",
      "Target is a private IP",
      "Scan timeout",
    ];

    const status = safeMessages.includes(message) ? 400 : 500;
    const responseMessage = safeMessages.includes(message)
      ? message
      : "Scan failed. Please try again later.";

    return NextResponse.json(
      { error: responseMessage },
      { status }
    );
  }
}
