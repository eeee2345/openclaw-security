/**
 * Wazuh REST API adapter
 * Wazuh REST API 對接器
 *
 * Integrates with Wazuh SIEM/XDR platform via its REST API for
 * alert retrieval and security event correlation.
 * Handles authentication, connection failures, and alert normalization.
 * 透過 REST API 與 Wazuh SIEM/XDR 平台整合，進行告警取得和安全事件關聯。
 * 處理認證、連線失敗和告警正規化。
 *
 * @module @openclaw/core/adapters/wazuh-adapter
 */

import { randomUUID } from 'node:crypto';

import type { AdapterConfig, AdapterAlert } from './types.js';
import { BaseAdapter } from './base-adapter.js';

/**
 * Default configuration for the Wazuh adapter
 * Wazuh 對接器的預設配置
 */
const DEFAULT_WAZUH_CONFIG: AdapterConfig = {
  enabled: true,
  endpoint: process.env['WAZUH_API_URL'] ?? 'https://localhost:55000',
  username: process.env['WAZUH_API_USER'] ?? '',
  password: process.env['WAZUH_API_PASS'] ?? '',
  pollInterval: 30000,
};

/**
 * Raw Wazuh alert structure from the REST API
 * 來自 REST API 的原始 Wazuh 告警結構
 */
interface WazuhRawAlert {
  /** Alert ID / 告警 ID */
  id?: string;
  /** Alert timestamp / 告警時間戳 */
  timestamp?: string;
  /** Rule information / 規則資訊 */
  rule?: {
    /** Rule ID / 規則 ID */
    id?: string;
    /** Rule description / 規則描述 */
    description?: string;
    /** Rule level (0-15) / 規則等級 (0-15) */
    level?: number;
    /** MITRE ATT&CK groups / MITRE ATT&CK 群組 */
    groups?: string[];
  };
  /** Agent information / 代理程式資訊 */
  agent?: {
    /** Agent ID / 代理程式 ID */
    id?: string;
    /** Agent name / 代理程式名稱 */
    name?: string;
  };
  /** Full log message / 完整日誌訊息 */
  full_log?: string;
  /** Decoder information / 解碼器資訊 */
  decoder?: {
    /** Decoder name / 解碼器名稱 */
    name?: string;
  };
}

/**
 * Wazuh API response envelope
 * Wazuh API 回應封裝
 */
interface WazuhApiResponse {
  /** Response data / 回應資料 */
  data?: {
    /** Affected items / 受影響的項目 */
    affected_items?: WazuhRawAlert[];
    /** Total affected items / 受影響項目總數 */
    total_affected_items?: number;
  };
  /** Error code / 錯誤碼 */
  error?: number;
  /** Error message / 錯誤訊息 */
  message?: string;
}

/**
 * Map Wazuh rule level (0-15) to severity string
 * 將 Wazuh 規則等級 (0-15) 映射為嚴重等級字串
 *
 * Wazuh levels: 0-3 info, 4-7 low, 8-11 medium, 12-14 high, 15 critical
 * Wazuh 等級：0-3 資訊，4-7 低，8-11 中，12-14 高，15 重大
 *
 * @param level - Wazuh rule level / Wazuh 規則等級
 * @returns Severity string / 嚴重等級字串
 */
function mapWazuhLevel(level: number): string {
  if (level >= 15) return 'critical';
  if (level >= 12) return 'high';
  if (level >= 8) return 'medium';
  if (level >= 4) return 'low';
  return 'info';
}

/**
 * Wazuh REST API security adapter
 * Wazuh REST API 安全對接器
 *
 * Connects to a Wazuh manager instance via its REST API to:
 * - Authenticate using basic credentials or API key
 * - Retrieve security alerts with optional time filtering
 * - Convert Wazuh alerts to the standardized SecurityEvent format
 *
 * 連接到 Wazuh 管理器實例的 REST API 以：
 * - 使用基本憑證或 API 金鑰進行認證
 * - 取得安全告警（可選時間過濾）
 * - 將 Wazuh 告警轉換為標準化的 SecurityEvent 格式
 *
 * @example
 * ```typescript
 * const adapter = new WazuhAdapter({
 *   enabled: true,
 *   endpoint: 'https://wazuh-manager:55000',
 *   username: 'wazuh-wui',
 *   password: 'wazuh-wui',
 * });
 *
 * if (await adapter.isAvailable()) {
 *   const alerts = await adapter.getAlerts(new Date(Date.now() - 3600000));
 *   const events = adapter.toSecurityEvents(alerts);
 * }
 * ```
 */
export class WazuhAdapter extends BaseAdapter {
  /** @inheritdoc */
  readonly name = 'Wazuh';

  /** @inheritdoc */
  readonly type = 'siem';

  /**
   * Cached JWT token from Wazuh authentication
   * 從 Wazuh 認證快取的 JWT 令牌
   */
  private authToken: string | null = null;

  /**
   * Token expiration timestamp
   * 令牌到期時間戳
   */
  private tokenExpiry: number = 0;

  /**
   * Create a new WazuhAdapter instance
   * 建立新的 WazuhAdapter 實例
   *
   * @param config - Adapter configuration (merged with defaults) / 對接器配置（與預設值合併）
   */
  constructor(config: Partial<AdapterConfig> = {}) {
    const merged: AdapterConfig = { ...DEFAULT_WAZUH_CONFIG, ...config };
    super('adapter-wazuh', merged);
  }

  /**
   * Get the configured Wazuh API endpoint
   * 取得已配置的 Wazuh API 端點
   *
   * @returns Endpoint URL without trailing slash / 不含末尾斜線的端點 URL
   */
  private get endpoint(): string {
    return (this.config.endpoint ?? DEFAULT_WAZUH_CONFIG.endpoint!).replace(/\/+$/, '');
  }

  /**
   * Authenticate with the Wazuh API and obtain a JWT token
   * 與 Wazuh API 認證並取得 JWT 令牌
   *
   * Uses basic authentication (username:password) to obtain a bearer token
   * from the /security/user/authenticate endpoint.
   * 使用基本認證（使用者名稱:密碼）從 /security/user/authenticate 端點取得 bearer 令牌。
   *
   * @returns JWT token string / JWT 令牌字串
   * @throws Error if authentication fails / 認證失敗時拋出錯誤
   */
  private async authenticate(): Promise<string> {
    // Return cached token if still valid (with 60s buffer)
    // 若快取令牌仍有效（含 60 秒緩衝），則回傳快取令牌
    if (this.authToken && Date.now() < this.tokenExpiry - 60000) {
      return this.authToken;
    }

    const username = this.config.username ?? '';
    const password = this.config.password ?? '';
    const credentials = Buffer.from(`${username}:${password}`).toString('base64');

    const url = `${this.endpoint}/security/user/authenticate`;

    this.logger.debug('Authenticating with Wazuh API', { url });

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(
        `Wazuh authentication failed: ${response.status} ${response.statusText}`,
      );
    }

    const body = (await response.json()) as { data?: { token?: string } };
    const token = body.data?.token;

    if (!token) {
      throw new Error('Wazuh authentication response did not contain a token');
    }

    this.authToken = token;
    // Wazuh tokens typically expire in 900s (15 min)
    // Wazuh 令牌通常在 900 秒（15 分鐘）後到期
    this.tokenExpiry = Date.now() + 900000;

    this.logger.info('Successfully authenticated with Wazuh API');
    return token;
  }

  /**
   * Make an authenticated request to the Wazuh API
   * 向 Wazuh API 發送已認證的請求
   *
   * @param path - API path (appended to endpoint) / API 路徑（附加到端點）
   * @param params - Optional URL search parameters / 可選的 URL 搜尋參數
   * @returns Parsed JSON response / 解析後的 JSON 回應
   */
  private async apiRequest<T>(path: string, params?: Record<string, string>): Promise<T> {
    const token = await this.authenticate();

    const url = new URL(`${this.endpoint}${path}`);
    if (params) {
      for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
      }
    }

    const response = await fetch(url.toString(), {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      throw new Error(
        `Wazuh API request failed: ${response.status} ${response.statusText} for ${path}`,
      );
    }

    return (await response.json()) as T;
  }

  /**
   * Check if the Wazuh API is available and reachable
   * 檢查 Wazuh API 是否可用且可連線
   *
   * Attempts to authenticate with the configured endpoint.
   * Returns false if authentication fails or endpoint is unreachable.
   * 嘗試與已配置的端點進行認證。
   * 若認證失敗或端點不可連線，則回傳 false。
   *
   * @returns True if Wazuh is available / 若 Wazuh 可用則回傳 true
   */
  async isAvailable(): Promise<boolean> {
    try {
      await this.authenticate();
      return true;
    } catch (err) {
      this.logger.warn('Wazuh API is not available', {
        endpoint: this.endpoint,
        error: err instanceof Error ? err.message : String(err),
      });
      return false;
    }
  }

  /**
   * Retrieve alerts from the Wazuh API
   * 從 Wazuh API 取得告警
   *
   * Fetches up to 500 alerts from the /alerts endpoint, optionally
   * filtered by timestamp. Handles connection errors gracefully.
   * 從 /alerts 端點取得最多 500 筆告警，可選依時間戳過濾。
   * 優雅地處理連線錯誤。
   *
   * @param since - Optional cutoff date; only return alerts after this time / 可選截止日期，僅回傳此時間之後的告警
   * @returns Array of normalized adapter alerts / 正規化對接器告警陣列
   */
  async getAlerts(since?: Date): Promise<AdapterAlert[]> {
    try {
      const params: Record<string, string> = {
        offset: '0',
        limit: '500',
      };

      if (since) {
        // Wazuh API query filter format: timestamp>ISO_DATE
        // Wazuh API 查詢過濾格式：timestamp>ISO_DATE
        params['q'] = `timestamp>${since.toISOString()}`;
      }

      const response = await this.apiRequest<WazuhApiResponse>('/alerts', params);

      const items = response.data?.affected_items ?? [];

      if (items.length === 0) {
        this.logger.debug('No alerts returned from Wazuh');
        return [];
      }

      const alerts: AdapterAlert[] = items.map((item) => ({
        id: item.id ?? item.rule?.id ?? randomUUID(),
        timestamp: item.timestamp ?? new Date().toISOString(),
        severity: mapWazuhLevel(item.rule?.level ?? 0),
        title: item.rule?.description ?? 'Wazuh Alert',
        description: [
          item.rule?.description ?? '',
          item.full_log ? `Log: ${item.full_log}` : '',
          item.agent?.name ? `Agent: ${item.agent.name}` : '',
          item.rule?.groups?.length ? `Groups: ${item.rule.groups.join(', ')}` : '',
        ]
          .filter(Boolean)
          .join(' | '),
        source: 'wazuh',
        raw: item,
      }));

      this.logger.info(`Retrieved ${alerts.length} alerts from Wazuh`, {
        total: response.data?.total_affected_items ?? alerts.length,
        returned: alerts.length,
      });

      return alerts;
    } catch (err) {
      this.logger.warn('Failed to retrieve alerts from Wazuh', {
        endpoint: this.endpoint,
        error: err instanceof Error ? err.message : String(err),
      });
      return [];
    }
  }
}
