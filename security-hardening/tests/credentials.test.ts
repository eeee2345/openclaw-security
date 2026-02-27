import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdirSync, writeFileSync, existsSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  InMemoryCredentialStore,
  EncryptedFileCredentialStore,
} from '../src/credentials/credential-store.js';
import { scanPlaintextCredentials, migrateCredentials } from '../src/credentials/migration.js';

describe('InMemoryCredentialStore', () => {
  let store: InMemoryCredentialStore;

  beforeEach(() => {
    store = new InMemoryCredentialStore();
  });

  it('should store and retrieve credentials', async () => {
    await store.set('telegram', 'bot', 'my-secret-token');
    const result = await store.get('telegram', 'bot');
    expect(result).toBe('my-secret-token');
  });

  it('should return null for non-existent credentials', async () => {
    const result = await store.get('nonexistent', 'account');
    expect(result).toBeNull();
  });

  it('should delete credentials', async () => {
    await store.set('slack', 'default', 'slack-token');
    expect(await store.delete('slack', 'default')).toBe(true);
    expect(await store.get('slack', 'default')).toBeNull();
  });

  it('should list accounts for a service', async () => {
    await store.set('openai', 'key1', 'value1');
    await store.set('openai', 'key2', 'value2');
    await store.set('claude', 'key1', 'value3');
    const accounts = await store.list('openai');
    expect(accounts).toHaveLength(2);
    expect(accounts).toContain('key1');
    expect(accounts).toContain('key2');
  });
});

describe('EncryptedFileCredentialStore', () => {
  let storePath: string;
  let store: EncryptedFileCredentialStore;

  beforeEach(() => {
    storePath = join(tmpdir(), `panguard-test-creds-${Date.now()}`);
    store = new EncryptedFileCredentialStore(storePath);
  });

  afterEach(() => {
    if (existsSync(storePath)) {
      rmSync(storePath, { recursive: true });
    }
  });

  it('should store and retrieve encrypted credentials', async () => {
    await store.set('telegram', 'bot', 'encrypted-secret');
    const result = await store.get('telegram', 'bot');
    expect(result).toBe('encrypted-secret');
  });

  it('should create encrypted files (not plaintext)', async () => {
    await store.set('openai', 'default', 'sk-1234567890');
    const { readdirSync } = await import('fs');
    const files = readdirSync(storePath) as string[];
    expect(files.some((f: string) => f.endsWith('.enc'))).toBe(true);
  });

  it('should handle multiple accounts per service', async () => {
    await store.set('api', 'prod', 'prod-key');
    await store.set('api', 'dev', 'dev-key');
    expect(await store.get('api', 'prod')).toBe('prod-key');
    expect(await store.get('api', 'dev')).toBe('dev-key');
  });

  it('should delete credentials', async () => {
    await store.set('service', 'account', 'value');
    expect(await store.delete('service', 'account')).toBe(true);
    expect(await store.get('service', 'account')).toBeNull();
  });
});

describe('Plaintext Credential Scanner', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(tmpdir(), `panguard-test-scan-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  it('should detect plaintext credential files', () => {
    writeFileSync(join(testDir, 'telegram.token'), 'bot-token-123');
    writeFileSync(join(testDir, 'openai.key'), 'sk-abcdef');
    const found = scanPlaintextCredentials(testDir);
    expect(found.length).toBe(2);
    expect(found.map((c) => c.service)).toContain('telegram');
    expect(found.map((c) => c.service)).toContain('openai');
  });

  it('should return empty array for non-existent directory', () => {
    const found = scanPlaintextCredentials('/nonexistent/path');
    expect(found).toHaveLength(0);
  });

  it('should skip backup and encrypted files', () => {
    writeFileSync(join(testDir, 'telegram.token.backup'), 'old-token');
    writeFileSync(join(testDir, 'slack.enc'), 'encrypted-data');
    const found = scanPlaintextCredentials(testDir);
    expect(found).toHaveLength(0);
  });
});

describe('Credential Migration', () => {
  let testDir: string;
  let store: InMemoryCredentialStore;

  beforeEach(() => {
    testDir = join(tmpdir(), `panguard-test-migrate-${Date.now()}`);
    mkdirSync(testDir, { recursive: true });
    store = new InMemoryCredentialStore();
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  it('should migrate plaintext credentials to secure store', async () => {
    writeFileSync(join(testDir, 'discord.token'), 'discord-bot-token');
    const report = await migrateCredentials(store, testDir);
    expect(report.migrated).toBe(1);
    expect(report.failed).toBe(0);
    expect(await store.get('discord', 'bot')).toBe('discord-bot-token');
  });

  it('should create backup of original files after migration', async () => {
    writeFileSync(join(testDir, 'slack.token'), 'slack-token');
    await migrateCredentials(store, testDir);
    expect(existsSync(join(testDir, 'slack.token.backup'))).toBe(true);
    expect(existsSync(join(testDir, 'slack.token'))).toBe(false);
  });

  it('should handle dry run without migrating', async () => {
    writeFileSync(join(testDir, 'line.token'), 'line-token');
    const report = await migrateCredentials(store, testDir, true);
    expect(report.migrated).toBe(1);
    // In dry run, original file still exists
    expect(existsSync(join(testDir, 'line.token'))).toBe(true);
    // And credential not stored
    expect(await store.get('line', 'default')).toBeNull();
  });
});
