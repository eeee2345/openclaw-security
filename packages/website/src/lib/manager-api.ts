/**
 * Manager server API client for admin dashboard
 *
 * Connects to the panguard-manager SSE stream and REST endpoints
 * to provide real-time guard status data. Falls back gracefully
 * when the manager server is not available.
 */

const MANAGER_URL = process.env.NEXT_PUBLIC_MANAGER_URL || 'http://localhost:3100';

export interface ManagerAgent {
  agentId: string;
  hostname: string;
  os: string;
  version: string;
  status: 'online' | 'offline' | 'warning';
  lastSeen: string;
  threatCount: number;
}

export interface ManagerStatus {
  agents: ManagerAgent[];
  totalThreats: number;
  totalBlocked: number;
  eventsProcessed: number;
}

/**
 * Fetch all registered agents from the manager
 */
export async function fetchAgents(): Promise<ManagerAgent[] | null> {
  try {
    const res = await fetch(`${MANAGER_URL}/api/agents`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { agents?: ManagerAgent[] };
    return data.agents ?? null;
  } catch {
    return null;
  }
}

/**
 * Fetch aggregated dashboard status from the manager
 */
export async function fetchDashboardStatus(): Promise<ManagerStatus | null> {
  try {
    const res = await fetch(`${MANAGER_URL}/api/dashboard/status`, {
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return null;
    return (await res.json()) as ManagerStatus;
  } catch {
    return null;
  }
}

/**
 * Create an SSE connection to the manager event stream.
 * Returns a cleanup function.
 */
export function connectManagerSSE(
  onEvent: (type: string, data: unknown) => void
): () => void {
  let es: EventSource | null = null;

  try {
    es = new EventSource(`${MANAGER_URL}/api/events/stream`);

    es.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data as string) as {
          type: string;
          data: unknown;
        };
        onEvent(parsed.type, parsed.data);
      } catch {
        // Ignore malformed SSE data
      }
    };

    es.onerror = () => {
      // SSE will auto-reconnect
    };
  } catch {
    // EventSource not available or URL invalid
  }

  return () => {
    es?.close();
  };
}
