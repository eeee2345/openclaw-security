import { promises as fs } from "fs";
import path from "path";

/**
 * Append a row to a lead-capture store.
 *
 * Storage priority:
 * 1. LEAD_WEBHOOK_URL env var -> POST JSON to external webhook (Zapier, Make, etc.)
 * 2. Local data/<sheet>.json file (development / self-hosted)
 * 3. /tmp/<sheet>.json fallback (Vercel serverless, ephemeral)
 */
export async function appendToSheet(sheet: string, row: string[]) {
  // If a webhook URL is configured, send data there
  const webhookUrl = process.env.LEAD_WEBHOOK_URL;
  if (webhookUrl) {
    await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sheet, row, timestamp: row[0] }),
    });
    return;
  }

  // Try local data/ directory first, fall back to /tmp for serverless
  const dirs = [
    path.join(process.cwd(), "data"),
    path.join("/tmp", "panguard-leads"),
  ];

  for (const dataDir of dirs) {
    try {
      await fs.mkdir(dataDir, { recursive: true });
      const filePath = path.join(dataDir, `${sheet}.json`);

      let existing: string[][] = [];
      try {
        const raw = await fs.readFile(filePath, "utf-8");
        existing = JSON.parse(raw);
      } catch {
        // File doesn't exist yet
      }

      existing.push(row);
      await fs.writeFile(filePath, JSON.stringify(existing, null, 2), "utf-8");
      return;
    } catch {
      // Directory not writable, try next
    }
  }
}
