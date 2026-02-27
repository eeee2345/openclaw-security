/**
 * ChatAgent tests
 * ChatAgent 測試
 */

import { describe, it, expect, beforeEach } from 'vitest';
import type {
  ChatConfig,
  ThreatAlert,
  SummaryReport,
  LearningProgress,
  ConfirmationRequest,
  FormattedMessage,
  ChannelResult,
  MessagingChannel,
  ReplyHandler,
} from '../src/types.js';
import { ChatAgent } from '../src/agent/chat-agent.js';

// ---------------------------------------------------------------------------
// Mock Channel
// ---------------------------------------------------------------------------

class MockChannel implements MessagingChannel {
  readonly channelType = 'line' as const;
  readonly sentMessages: { userId: string; message: FormattedMessage }[] = [];
  readonly sentAlerts: { userId: string; alert: ThreatAlert }[] = [];
  readonly sentFiles: { userId: string; filename: string }[] = [];
  replyHandler: ReplyHandler | null = null;

  async sendMessage(userId: string, message: FormattedMessage): Promise<ChannelResult> {
    this.sentMessages.push({ userId, message });
    return { success: true, channel: 'line', messageId: `msg-${this.sentMessages.length}` };
  }

  async sendAlert(userId: string, alert: ThreatAlert): Promise<ChannelResult> {
    this.sentAlerts.push({ userId, alert });
    return { success: true, channel: 'line' };
  }

  async sendFile(userId: string, _file: Buffer, filename: string): Promise<ChannelResult> {
    this.sentFiles.push({ userId, filename });
    return { success: true, channel: 'line' };
  }

  onReply(handler: ReplyHandler): void {
    this.replyHandler = handler;
  }
}

// ---------------------------------------------------------------------------
// Test Data
// ---------------------------------------------------------------------------

function makeConfig(overrides: Partial<ChatConfig> = {}): ChatConfig {
  return {
    userProfile: {
      type: 'developer',
      language: 'en',
      notificationChannel: 'line',
      preferences: {
        criticalAlerts: true,
        dailySummary: true,
        weeklySummary: true,
        peacefulReport: true,
      },
    },
    channels: {},
    maxFollowUpTokens: 2000,
    ...overrides,
  };
}

function makeAlert(overrides: Partial<ThreatAlert> = {}): ThreatAlert {
  return {
    conclusion: 'malicious',
    confidence: 0.92,
    humanSummary: 'SSH brute force detected and blocked.',
    reasoning: 'Multiple failed SSH login attempts from same IP.',
    recommendedAction: 'Enable two-factor authentication.',
    severity: 'high',
    eventDescription: 'SSH brute force from 103.0.0.1',
    actionsTaken: ['Blocked IP 103.0.0.1'],
    timestamp: '2025-01-15T10:30:00Z',
    ...overrides,
  };
}

function makeSummary(): SummaryReport {
  return {
    period: 'daily',
    startDate: '2025-01-15',
    endDate: '2025-01-15',
    totalEvents: 1500,
    threatsBlocked: 12,
    suspiciousEvents: 3,
    topAttackSources: [{ ip: '103.0.0.1', count: 50, country: 'China' }],
    actionsTaken: [{ action: 'block_ip', count: 8 }],
  };
}

function makeLearning(): LearningProgress {
  return {
    day: 3,
    totalDays: 7,
    patternsRecorded: 150,
    eventsAnalyzed: 4200,
    notableFindings: 2,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('ChatAgent', () => {
  let agent: ChatAgent;
  let channel: MockChannel;

  beforeEach(() => {
    agent = new ChatAgent(makeConfig());
    channel = new MockChannel();
    agent.registerChannel(channel);
  });

  describe('initialization', () => {
    it('should initialize with correct user profile', () => {
      expect(agent.getUserProfile().type).toBe('developer');
      expect(agent.getUserProfile().language).toBe('en');
    });

    it('should register channels', () => {
      expect(agent.getRegisteredChannels()).toContain('line');
    });

    it('should generate system prompt', () => {
      const prompt = agent.getSystemPrompt();
      expect(prompt).toContain('Panguard AI');
      expect(prompt).toContain('bodyguard');
    });

    it('should use custom system prompt when provided', () => {
      const custom = new ChatAgent(makeConfig({ systemPromptOverride: 'Custom prompt' }));
      expect(custom.getSystemPrompt()).toBe('Custom prompt');
    });
  });

  describe('sendAlert', () => {
    it('should send alert via the registered channel', async () => {
      const result = await agent.sendAlert('user-001', makeAlert());
      expect(result.success).toBe(true);
      expect(channel.sentMessages.length).toBe(1);
    });

    it('should format the message based on user type', async () => {
      await agent.sendAlert('user-001', makeAlert({ mitreTechnique: 'T1110' }));
      const msg = channel.sentMessages[0]!.message;
      expect(msg.text).toContain('T1110'); // developer gets technical details
    });

    it('should store follow-up context', async () => {
      await agent.sendAlert('user-001', makeAlert());
      expect(agent.getActiveContextCount()).toBe(1);
    });

    it('should return error when no channel is registered', async () => {
      const bare = new ChatAgent(makeConfig());
      const result = await bare.sendAlert('user-001', makeAlert());
      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  describe('sendSummary', () => {
    it('should send summary via channel', async () => {
      const result = await agent.sendSummary('user-001', makeSummary());
      expect(result.success).toBe(true);
      expect(channel.sentMessages.length).toBe(1);
      expect(channel.sentMessages[0]!.message.text).toContain('12');
    });
  });

  describe('sendLearningUpdate', () => {
    it('should send learning progress', async () => {
      const result = await agent.sendLearningUpdate('user-001', makeLearning());
      expect(result.success).toBe(true);
      expect(channel.sentMessages[0]!.message.text).toContain('43%');
    });
  });

  describe('sendPeacefulReport', () => {
    it('should send all-clear report', async () => {
      const result = await agent.sendPeacefulReport('user-001');
      expect(result.success).toBe(true);
      expect(channel.sentMessages[0]!.message.text).toContain('Everything is normal');
    });
  });

  describe('confirmation flow', () => {
    it('should send confirmation request', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-001',
        conclusion: 'suspicious',
        confidence: 0.75,
        humanSummary: 'Unusual connection detected.',
        proposedAction: 'Block connection',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      const result = await agent.requestConfirmation('user-001', request);
      expect(result.success).toBe(true);
      expect(agent.getPendingConfirmationCount()).toBe(1);
    });

    it('should process confirmation (approve)', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-002',
        conclusion: 'malicious',
        confidence: 0.9,
        humanSummary: 'Malware detected.',
        proposedAction: 'Quarantine file',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      await agent.requestConfirmation('user-001', request);
      const response = agent.processConfirmation('v-002', true);

      expect(response).not.toBeNull();
      expect(response!.confirmed).toBe(true);
      expect(agent.getPendingConfirmationCount()).toBe(0);
    });

    it('should process confirmation (reject)', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-003',
        conclusion: 'suspicious',
        confidence: 0.6,
        humanSummary: 'Possible false positive.',
        proposedAction: 'Block IP',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      await agent.requestConfirmation('user-001', request);
      const response = agent.processConfirmation('v-003', false, 'Known safe IP');

      expect(response).not.toBeNull();
      expect(response!.confirmed).toBe(false);
      expect(response!.reason).toBe('Known safe IP');
    });

    it('should return null for expired confirmation', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-004',
        conclusion: 'suspicious',
        confidence: 0.7,
        humanSummary: 'Test.',
        proposedAction: 'Test action',
        expiresAt: new Date(Date.now() - 1000).toISOString(), // already expired
      };

      await agent.requestConfirmation('user-001', request);
      const response = agent.processConfirmation('v-004', true);
      expect(response).toBeNull();
    });

    it('should return null for unknown verdict', () => {
      const response = agent.processConfirmation('v-unknown', true);
      expect(response).toBeNull();
    });
  });

  describe('follow-up handling', () => {
    it('should answer follow-up questions from existing context', async () => {
      await agent.sendAlert('user-001', makeAlert());

      const answer = await agent.handleReply('user-001', 'What is this?');
      expect(answer).toBeTruthy();
      expect(answer.length).toBeGreaterThan(10);
    });

    it('should handle "how serious" questions', async () => {
      await agent.sendAlert('user-001', makeAlert());

      const answer = await agent.handleReply('user-001', 'How serious is this?');
      expect(answer).toContain('92%');
    });

    it('should handle "what did you do" questions', async () => {
      await agent.sendAlert('user-001', makeAlert());

      const answer = await agent.handleReply('user-001', 'What did you do?');
      expect(answer).toContain('Blocked IP 103.0.0.1');
    });

    it('should handle recommendation questions', async () => {
      await agent.sendAlert('user-001', makeAlert());

      const answer = await agent.handleReply('user-001', 'What should I do?');
      expect(answer).toContain('two-factor authentication');
    });

    it('should return no-context message when no alerts exist', async () => {
      const answer = await agent.handleReply('user-001', 'What happened?');
      expect(answer).toContain('No recent alerts');
    });

    it('should handle confirmation actions via reply', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-010',
        conclusion: 'suspicious',
        confidence: 0.75,
        humanSummary: 'Test.',
        proposedAction: 'Block',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      await agent.requestConfirmation('user-001', request);

      const answer = await agent.handleReply('user-001', 'confirm:v-010');
      expect(answer).toContain('Confirmed');
    });

    it('should handle rejection via reply', async () => {
      const request: ConfirmationRequest = {
        verdictId: 'v-011',
        conclusion: 'suspicious',
        confidence: 0.75,
        humanSummary: 'Test.',
        proposedAction: 'Block',
        expiresAt: new Date(Date.now() + 3600000).toISOString(),
      };

      await agent.requestConfirmation('user-001', request);

      const answer = await agent.handleReply('user-001', 'reject:v-011');
      expect(answer).toContain('Cancelled');
    });
  });

  describe('boss user type', () => {
    it('should not include technical terms', async () => {
      const bossAgent = new ChatAgent(
        makeConfig({
          userProfile: {
            type: 'boss',
            language: 'zh-TW',
            notificationChannel: 'line',
            preferences: {
              criticalAlerts: true,
              dailySummary: true,
              weeklySummary: true,
              peacefulReport: true,
            },
          },
        })
      );
      const bossChannel = new MockChannel();
      bossAgent.registerChannel(bossChannel);

      await bossAgent.sendAlert('user-001', makeAlert({ mitreTechnique: 'T1110' }));
      const msg = bossChannel.sentMessages[0]!.message;

      expect(msg.text).not.toContain('MITRE');
      expect(msg.text).not.toContain('T1110');
      expect(msg.text).not.toContain('malicious');
    });
  });
});
