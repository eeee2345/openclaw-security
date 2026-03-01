/**
 * Channel tests
 * 管道測試
 */

import { describe, it, expect } from 'vitest';
import { TelegramChannel } from '../src/channels/telegram.js';
import { SlackChannel } from '../src/channels/slack.js';
import { EmailChannel } from '../src/channels/email.js';
import { WebhookChannel } from '../src/channels/webhook.js';
import { LINEChannel } from '../src/channels/line.js';

// Note: These are unit tests that verify channel construction and interface compliance.
// Actual API calls require real credentials and are tested in integration tests.
// 注意：這些是驗證管道建構和介面合規的單元測試。
// 實際 API 呼叫需要真實憑證，在整合測試中測試。

describe('TelegramChannel', () => {
  it('should initialize with config', () => {
    const channel = new TelegramChannel({
      botToken: 'test-bot-token',
      chatId: '12345',
    });
    expect(channel.channelType).toBe('telegram');
  });

  it('should register reply handler', () => {
    const channel = new TelegramChannel({
      botToken: 'test-bot-token',
      chatId: '12345',
    });
    const handler = async (_userId: string, _text: string) => 'ok';
    channel.onReply(handler);
  });

  it('should handle sendMessage errors gracefully', async () => {
    const channel = new TelegramChannel({
      botToken: 'invalid-token',
      chatId: '12345',
    });
    const result = await channel.sendMessage('user-1', { text: 'test' });
    expect(result.success).toBe(false);
    expect(result.channel).toBe('telegram');
  });

  it('should process text message update', async () => {
    const channel = new TelegramChannel({
      botToken: 'test-token',
      chatId: '12345',
    });

    let receivedUserId = '';
    let receivedText = '';
    channel.onReply(async (userId, text) => {
      receivedUserId = userId;
      receivedText = text;
      return 'response';
    });

    const result = await channel.processUpdate({
      message: {
        chat: { id: 12345 },
        text: 'Hello',
      },
    });

    expect(result).toBe('response');
    expect(receivedUserId).toBe('12345');
    expect(receivedText).toBe('Hello');
  });

  it('should return null when no handler registered', async () => {
    const channel = new TelegramChannel({
      botToken: 'test-token',
      chatId: '12345',
    });

    const result = await channel.processUpdate({
      message: { chat: { id: 12345 }, text: 'Hello' },
    });
    expect(result).toBeNull();
  });
});

describe('LINEChannel', () => {
  it('should initialize with config', () => {
    const channel = new LINEChannel({
      channelAccessToken: 'test-access-token',
      destinationUserId: 'U1234567890abcdef',
    });
    expect(channel.channelType).toBe('line');
  });

  it('should register reply handler', () => {
    const channel = new LINEChannel({
      channelAccessToken: 'test-access-token',
      destinationUserId: 'U1234567890abcdef',
    });
    const handler = async (_userId: string, _text: string) => 'ok';
    channel.onReply(handler);
  });

  it('should handle sendMessage errors gracefully', async () => {
    const channel = new LINEChannel({
      channelAccessToken: 'invalid-token',
      destinationUserId: 'U1234567890abcdef',
    });
    const result = await channel.sendMessage('user-1', { text: 'test' });
    expect(result.success).toBe(false);
    expect(result.channel).toBe('line');
  });

  it('should process text message webhook event', async () => {
    const channel = new LINEChannel({
      channelAccessToken: 'test-token',
      destinationUserId: 'U1234567890abcdef',
    });

    let receivedUserId = '';
    let receivedText = '';
    channel.onReply(async (userId, text) => {
      receivedUserId = userId;
      receivedText = text;
      return 'response';
    });

    const result = await channel.processWebhook({
      type: 'message',
      source: { userId: 'U9876543210' },
      message: { type: 'text', text: 'Hello' },
    });

    expect(result).toBe('response');
    expect(receivedUserId).toBe('U9876543210');
    expect(receivedText).toBe('Hello');
  });

  it('should process postback webhook event', async () => {
    const channel = new LINEChannel({
      channelAccessToken: 'test-token',
      destinationUserId: 'U1234567890abcdef',
    });

    let receivedAction = '';
    channel.onReply(async (_userId, text) => {
      receivedAction = text;
      return 'done';
    });

    const result = await channel.processWebhook({
      type: 'postback',
      source: { userId: 'U9876543210' },
      postback: { data: 'action=block_source' },
    });

    expect(result).toBe('done');
    expect(receivedAction).toBe('action=block_source');
  });

  it('should return null when no handler registered', async () => {
    const channel = new LINEChannel({
      channelAccessToken: 'test-token',
      destinationUserId: 'U1234567890abcdef',
    });

    const result = await channel.processWebhook({
      type: 'message',
      source: { userId: 'U9876543210' },
      message: { type: 'text', text: 'Hello' },
    });
    expect(result).toBeNull();
  });
});

describe('SlackChannel', () => {
  it('should initialize with config', () => {
    const channel = new SlackChannel({
      botToken: 'xoxb-test',
      signingSecret: 'test-secret',
      defaultChannel: '#security',
    });
    expect(channel.channelType).toBe('slack');
  });

  it('should handle sendMessage errors gracefully', async () => {
    const channel = new SlackChannel({
      botToken: 'invalid-token',
      signingSecret: 'test-secret',
      defaultChannel: '#security',
    });
    const result = await channel.sendMessage('', { text: 'test' });
    expect(result.success).toBe(false);
    expect(result.channel).toBe('slack');
  });

  it('should process message events', async () => {
    const channel = new SlackChannel({
      botToken: 'xoxb-test',
      signingSecret: 'test-secret',
      defaultChannel: '#security',
    });

    let receivedText = '';
    channel.onReply(async (_userId, text) => {
      receivedText = text;
      return 'ok';
    });

    const result = await channel.processEvent({
      type: 'message',
      text: 'What happened?',
      user: 'U123',
      channel: '#security',
    });

    expect(result).toBe('ok');
    expect(receivedText).toBe('What happened?');
  });

  it('should process block_actions events', async () => {
    const channel = new SlackChannel({
      botToken: 'xoxb-test',
      signingSecret: 'test-secret',
      defaultChannel: '#security',
    });

    let receivedAction = '';
    channel.onReply(async (_userId, text) => {
      receivedAction = text;
      return 'done';
    });

    const result = await channel.processEvent({
      type: 'block_actions',
      channel: '#security',
      actions: [{ action_id: 'block_source', value: 'block_source' }],
    });

    expect(result).toBe('done');
    expect(receivedAction).toBe('block_source');
  });
});

describe('EmailChannel', () => {
  it('should initialize with config', () => {
    const channel = new EmailChannel({
      host: 'smtp.test.com',
      port: 587,
      secure: false,
      auth: { user: 'test', pass: 'test' },
      from: 'alert@test.com',
      to: ['admin@test.com'],
    });
    expect(channel.channelType).toBe('email');
  });
});

describe('WebhookChannel', () => {
  it('should initialize with bearer_token auth', () => {
    const channel = new WebhookChannel({
      endpoint: 'https://hooks.test.com/webhook',
      authMethod: 'bearer_token',
      secret: 'test-bearer-token',
    });
    expect(channel.channelType).toBe('webhook');
  });

  it('should initialize with hmac_signature auth', () => {
    const channel = new WebhookChannel({
      endpoint: 'https://hooks.test.com/webhook',
      authMethod: 'hmac_signature',
      secret: 'hmac-secret',
    });
    expect(channel.channelType).toBe('webhook');
  });

  it('should initialize with mtls auth', () => {
    const channel = new WebhookChannel({
      endpoint: 'https://hooks.test.com/webhook',
      authMethod: 'mtls',
      secret: '',
    });
    expect(channel.channelType).toBe('webhook');
  });

  it('should process callback', async () => {
    const channel = new WebhookChannel({
      endpoint: 'https://hooks.test.com/webhook',
      authMethod: 'bearer_token',
      secret: 'test',
    });

    let receivedText = '';
    channel.onReply(async (_userId, text) => {
      receivedText = text;
      return 'ok';
    });

    const result = await channel.processCallback({
      userId: 'user-1',
      text: 'confirm:v-001',
    });

    expect(result).toBe('ok');
    expect(receivedText).toBe('confirm:v-001');
  });

  it('should return null when no handler registered', async () => {
    const channel = new WebhookChannel({
      endpoint: 'https://hooks.test.com/webhook',
      authMethod: 'bearer_token',
      secret: 'test',
    });

    const result = await channel.processCallback({ text: 'test' });
    expect(result).toBeNull();
  });

  it('should handle sendMessage errors gracefully', async () => {
    const channel = new WebhookChannel({
      endpoint: 'https://invalid.test.com/webhook',
      authMethod: 'bearer_token',
      secret: 'test',
    });

    const result = await channel.sendMessage('', { text: 'test' });
    expect(result.success).toBe(false);
    expect(result.channel).toBe('webhook');
  });
});
