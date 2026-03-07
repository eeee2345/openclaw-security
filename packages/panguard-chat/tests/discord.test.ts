/**
 * Discord Channel Tests
 * Discord 管道測試
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { DiscordChannel } from '../src/channels/discord.js';
import type { ThreatAlert, FormattedMessage } from '../src/types.js';

// ---------------------------------------------------------------------------
// Mock https module
// 模擬 https 模組
// ---------------------------------------------------------------------------

const mockWrite = vi.fn();
const mockEnd = vi.fn();
const mockOn = vi.fn();
const mockDestroy = vi.fn();

let capturedRequestOptions: Record<string, unknown> = {};
let capturedRequestCallback: ((res: unknown) => void) | null = null;
let writtenData: string | Buffer = '';

function createMockResponse(statusCode: number, body: string) {
  return {
    statusCode,
    on: (event: string, handler: (chunk?: Buffer) => void) => {
      if (event === 'data') {
        handler(Buffer.from(body));
      }
      if (event === 'end') {
        handler();
      }
    },
  };
}

vi.mock('node:https', () => ({
  request: (options: Record<string, unknown>, callback: (res: unknown) => void) => {
    capturedRequestOptions = { ...options };
    capturedRequestCallback = callback;
    return {
      write: (data: string | Buffer) => {
        writtenData = data;
        mockWrite(data);
      },
      end: () => {
        mockEnd();
        // Auto-respond with success by default
        if (capturedRequestCallback) {
          capturedRequestCallback(createMockResponse(204, ''));
        }
      },
      on: mockOn,
      destroy: mockDestroy,
    };
  },
}));

// ---------------------------------------------------------------------------
// Test Data
// 測試資料
// ---------------------------------------------------------------------------

const TEST_WEBHOOK_URL = 'https://discord.com/api/webhooks/1234567890/abcdefghijklmnop';

const TEST_CONFIG = {
  webhookUrl: TEST_WEBHOOK_URL,
  username: 'Panguard Test',
};

const TEST_ALERT: ThreatAlert = {
  conclusion: 'malicious',
  confidence: 0.95,
  humanSummary: 'SQL injection attempt detected',
  reasoning: 'Detected malicious SQL payload in POST body targeting /api/users endpoint.',
  recommendedAction: 'Block source IP and review WAF rules.',
  mitreTechnique: 'T1190 - Exploit Public-Facing Application',
  severity: 'critical',
  eventDescription: 'POST /api/users with SQL injection payload from 192.168.1.100',
  actionsTaken: ['Blocked IP 192.168.1.100', 'Notified security team'],
  timestamp: '2025-01-15T10:30:00Z',
};

const TEST_MESSAGE: FormattedMessage = {
  text: 'All systems operational. No threats detected in the last 24 hours.',
  severity: 'info',
};

// ---------------------------------------------------------------------------
// Tests
// 測試
// ---------------------------------------------------------------------------

describe('DiscordChannel', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedRequestOptions = {};
    capturedRequestCallback = null;
    writtenData = '';
  });

  // -----------------------------------------------------------------------
  // Initialization
  // 初始化
  // -----------------------------------------------------------------------

  it('should initialize with config', () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    expect(channel.channelType).toBe('discord');
  });

  it('should initialize with minimal config (no username)', () => {
    const channel = new DiscordChannel({ webhookUrl: TEST_WEBHOOK_URL });
    expect(channel.channelType).toBe('discord');
  });

  // -----------------------------------------------------------------------
  // URL Parsing
  // URL 解析
  // -----------------------------------------------------------------------

  it('should parse webhook URL correctly', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);

    // Verify by sending a message and checking the request options
    await channel.sendMessage('', TEST_MESSAGE);

    // The request should go to discord.com
    expect(capturedRequestOptions.hostname).toBe('discord.com');
    expect(capturedRequestOptions.path).toBe('/api/webhooks/1234567890/abcdefghijklmnop');
  });

  it('should throw on invalid webhook URL', () => {
    expect(() => {
      new DiscordChannel({ webhookUrl: 'not-a-url' });
    }).toThrow();
  });

  // -----------------------------------------------------------------------
  // sendMessage
  // 發送訊息
  // -----------------------------------------------------------------------

  it('should send message with correct payload', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const result = await channel.sendMessage('user-1', TEST_MESSAGE);

    expect(result.success).toBe(true);
    expect(result.channel).toBe('discord');

    // Verify request options
    expect(capturedRequestOptions.method).toBe('POST');
    expect(capturedRequestOptions.hostname).toBe('discord.com');

    // Verify payload
    const payload = JSON.parse(writtenData as string);
    expect(payload.username).toBe('Panguard Test');
    expect(payload.embeds).toHaveLength(1);
    expect(payload.embeds[0].description).toBe(TEST_MESSAGE.text);
    expect(payload.embeds[0].title).toBe('Panguard Notification');
    expect(payload.embeds[0].color).toBe(0x3498db); // info = blue
  });

  it('should use default username when not configured', async () => {
    const channel = new DiscordChannel({ webhookUrl: TEST_WEBHOOK_URL });
    await channel.sendMessage('', TEST_MESSAGE);

    const payload = JSON.parse(writtenData as string);
    expect(payload.username).toBe('Panguard AI');
  });

  it('should map warning severity to orange color', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const warningMessage: FormattedMessage = {
      text: 'Warning: unusual activity detected.',
      severity: 'warning',
    };

    await channel.sendMessage('', warningMessage);

    const payload = JSON.parse(writtenData as string);
    expect(payload.embeds[0].color).toBe(0xff8c00);
  });

  it('should map critical severity to red color', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const criticalMessage: FormattedMessage = {
      text: 'Critical: system compromised.',
      severity: 'critical',
    };

    await channel.sendMessage('', criticalMessage);

    const payload = JSON.parse(writtenData as string);
    expect(payload.embeds[0].color).toBe(0xff0000);
  });

  // -----------------------------------------------------------------------
  // sendAlert
  // 發送告警
  // -----------------------------------------------------------------------

  it('should send alert as embed with correct color mapping', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const result = await channel.sendAlert('user-1', TEST_ALERT);

    expect(result.success).toBe(true);
    expect(result.channel).toBe('discord');

    const payload = JSON.parse(writtenData as string);
    const embed = payload.embeds[0];

    // Verify embed structure
    expect(embed.title).toContain('SQL injection attempt detected');
    expect(embed.description).toBe(TEST_ALERT.reasoning);
    expect(embed.color).toBe(0xff0000); // critical = red
    expect(embed.timestamp).toBe(TEST_ALERT.timestamp);
    expect(embed.footer.text).toBe('Panguard AI Security');
  });

  it('should include MITRE ATT&CK technique in alert fields', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    await channel.sendAlert('', TEST_ALERT);

    const payload = JSON.parse(writtenData as string);
    const fields = payload.embeds[0].fields;

    const mitreField = fields.find(
      (f: { name: string; value: string }) => f.name === 'MITRE ATT&CK'
    );
    expect(mitreField).toBeDefined();
    expect(mitreField.value).toBe('T1190 - Exploit Public-Facing Application');
  });

  it('should include severity, conclusion, and confidence fields', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    await channel.sendAlert('', TEST_ALERT);

    const payload = JSON.parse(writtenData as string);
    const fields = payload.embeds[0].fields;

    const severityField = fields.find(
      (f: { name: string; value: string }) => f.name === 'Severity'
    );
    expect(severityField).toBeDefined();
    expect(severityField.value).toBe('CRITICAL');

    const conclusionField = fields.find(
      (f: { name: string; value: string }) => f.name === 'Conclusion'
    );
    expect(conclusionField).toBeDefined();
    expect(conclusionField.value).toBe('malicious');

    const confidenceField = fields.find(
      (f: { name: string; value: string }) => f.name === 'Confidence'
    );
    expect(confidenceField).toBeDefined();
    expect(confidenceField.value).toBe('95%');
  });

  it('should include actions taken when available', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    await channel.sendAlert('', TEST_ALERT);

    const payload = JSON.parse(writtenData as string);
    const fields = payload.embeds[0].fields;

    const actionsField = fields.find(
      (f: { name: string; value: string }) => f.name === 'Actions Taken'
    );
    expect(actionsField).toBeDefined();
    expect(actionsField.value).toContain('Blocked IP 192.168.1.100');
    expect(actionsField.value).toContain('Notified security team');
  });

  it('should omit MITRE field when not provided', async () => {
    const alertWithoutMitre: ThreatAlert = {
      ...TEST_ALERT,
      mitreTechnique: undefined,
    };

    const channel = new DiscordChannel(TEST_CONFIG);
    await channel.sendAlert('', alertWithoutMitre);

    const payload = JSON.parse(writtenData as string);
    const fields = payload.embeds[0].fields;

    const mitreField = fields.find(
      (f: { name: string; value: string }) => f.name === 'MITRE ATT&CK'
    );
    expect(mitreField).toBeUndefined();
  });

  it('should map alert severity colors correctly', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);

    const severityColorMap: Array<{ severity: ThreatAlert['severity']; color: number }> = [
      { severity: 'critical', color: 0xff0000 },
      { severity: 'high', color: 0xff8c00 },
      { severity: 'medium', color: 0xffd700 },
      { severity: 'low', color: 0x3498db },
      { severity: 'info', color: 0x95a5a6 },
    ];

    for (const { severity, color } of severityColorMap) {
      const alert: ThreatAlert = { ...TEST_ALERT, severity };
      await channel.sendAlert('', alert);

      const payload = JSON.parse(writtenData as string);
      expect(payload.embeds[0].color).toBe(color);
    }
  });

  // -----------------------------------------------------------------------
  // sendFile
  // 發送檔案
  // -----------------------------------------------------------------------

  it('should send file as multipart/form-data', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const fileContent = Buffer.from('report content here');
    const result = await channel.sendFile('user-1', fileContent, 'report.pdf');

    expect(result.success).toBe(true);
    expect(result.channel).toBe('discord');

    // Verify the written data is a Buffer (multipart)
    expect(Buffer.isBuffer(writtenData)).toBe(true);

    // Verify the multipart body contains the filename and payload_json
    const bodyStr = (writtenData as Buffer).toString();
    expect(bodyStr).toContain('files[0]');
    expect(bodyStr).toContain('report.pdf');
    expect(bodyStr).toContain('payload_json');
    expect(bodyStr).toContain('Security report: report.pdf');
  });

  // -----------------------------------------------------------------------
  // Error Handling
  // 錯誤處理
  // -----------------------------------------------------------------------

  it('should handle sendMessage errors gracefully', async () => {
    // Override the mock to simulate an error
    const originalEnd = mockEnd.getMockImplementation();
    mockEnd.mockImplementationOnce(() => {
      if (capturedRequestCallback) {
        capturedRequestCallback(createMockResponse(429, '{"message":"Rate limited"}'));
      }
    });

    const channel = new DiscordChannel(TEST_CONFIG);
    const result = await channel.sendMessage('', { text: 'test' });

    expect(result.success).toBe(false);
    expect(result.channel).toBe('discord');
    expect(result.error).toContain('Discord API error 429');

    mockEnd.mockImplementation(originalEnd ?? (() => {}));
  });

  it('should handle sendAlert errors gracefully', async () => {
    mockEnd.mockImplementationOnce(() => {
      if (capturedRequestCallback) {
        capturedRequestCallback(createMockResponse(500, 'Internal Server Error'));
      }
    });

    const channel = new DiscordChannel(TEST_CONFIG);
    const result = await channel.sendAlert('', TEST_ALERT);

    expect(result.success).toBe(false);
    expect(result.channel).toBe('discord');
    expect(result.error).toContain('Discord API error 500');
  });

  it('should handle sendFile errors gracefully', async () => {
    mockEnd.mockImplementationOnce(() => {
      if (capturedRequestCallback) {
        capturedRequestCallback(createMockResponse(413, 'Payload Too Large'));
      }
    });

    const channel = new DiscordChannel(TEST_CONFIG);
    const result = await channel.sendFile('', Buffer.from('big file'), 'huge.zip');

    expect(result.success).toBe(false);
    expect(result.channel).toBe('discord');
    expect(result.error).toContain('Discord API error 413');
  });

  // -----------------------------------------------------------------------
  // Reply Handler & Interaction Processing
  // 回覆處理器和互動處理
  // -----------------------------------------------------------------------

  it('should register reply handler', () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    const handler = async (_userId: string, _text: string) => 'ok';
    channel.onReply(handler);
  });

  it('should process interaction with registered handler', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);

    let receivedUserId = '';
    let receivedText = '';
    channel.onReply(async (userId, text) => {
      receivedUserId = userId;
      receivedText = text;
      return 'processed';
    });

    const result = await channel.processInteraction({
      type: 'APPLICATION_COMMAND',
      userId: 'discord-user-123',
      data: { name: 'status', value: 'check_status' },
    });

    expect(result).toBe('processed');
    expect(receivedUserId).toBe('discord-user-123');
    expect(receivedText).toBe('check_status');
  });

  it('should return null when no interaction handler registered', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);

    const result = await channel.processInteraction({
      type: 'APPLICATION_COMMAND',
      userId: 'user-1',
      data: { name: 'status' },
    });

    expect(result).toBeNull();
  });

  it('should return null for interaction with empty data', async () => {
    const channel = new DiscordChannel(TEST_CONFIG);
    channel.onReply(async () => 'ok');

    const result = await channel.processInteraction({
      type: 'APPLICATION_COMMAND',
      userId: 'user-1',
      data: {},
    });

    expect(result).toBeNull();
  });
});
