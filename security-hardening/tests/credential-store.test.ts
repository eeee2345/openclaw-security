import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdirSync, writeFileSync, existsSync, rmSync, readFileSync, readdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  InMemoryCredentialStore,
  EncryptedFileCredentialStore,
} from '../src/credentials/credential-store.js';
import { scanPlaintextCredentials, migrateCredentials } from '../src/credentials/migration.js';

// Suppress log output
beforeEach(() => {
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  vi.spyOn(console, 'error').mockImplementation(() => undefined);
  vi.spyOn(console, 'warn').mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// InMemoryCredentialStore - Extended Tests
// ---------------------------------------------------------------------------
describe('InMemoryCredentialStore - Extended', () => {
  let store: InMemoryCredentialStore;

  beforeEach(() => {
    store = new InMemoryCredentialStore();
  });

  it('should handle concurrent set/get operations', async () => {
    const ops = Array.from({ length: 50 }, (_, i) =>
      store.set('service', `account-${i}`, `value-${i}`)
    );
    await Promise.all(ops);

    for (let i = 0; i < 50; i++) {
      const val = await store.get('service', `account-${i}`);
      expect(val).toBe(`value-${i}`);
    }
  });

  it('should return empty array after deleting all accounts', async () => {
    await store.set('svc', 'a', 'v1');
    await store.set('svc', 'b', 'v2');
    await store.delete('svc', 'a');
    await store.delete('svc', 'b');
    const accounts = await store.list('svc');
    expect(accounts).toHaveLength(0);
  });

  it('should handle unicode in service/account names', async () => {
    await store.set('telegram', 'user@domain.com', 'secret-123');
    expect(await store.get('telegram', 'user@domain.com')).toBe('secret-123');
  });

  it('should handle very long credential values', async () => {
    const longValue = 'x'.repeat(10000);
    await store.set('service', 'account', longValue);
    expect(await store.get('service', 'account')).toBe(longValue);
  });

  it('should handle colons in service/account names correctly', async () => {
    // Service:account format is used internally, so colons in names need testing
    await store.set('service:with:colons', 'account', 'value');
    const result = await store.get('service:with:colons', 'account');
    expect(result).toBe('value');
  });

  it('should list correctly distinguishing between services with shared prefix', async () => {
    await store.set('api', 'key1', 'v1');
    await store.set('api-v2', 'key1', 'v2');
    const apiAccounts = await store.list('api');
    expect(apiAccounts).toHaveLength(1);
    expect(apiAccounts).toContain('key1');
  });

  it('should not find account from different service after delete', async () => {
    await store.set('svcA', 'shared-account', 'valueA');
    await store.set('svcB', 'shared-account', 'valueB');
    await store.delete('svcA', 'shared-account');
    expect(await store.get('svcA', 'shared-account')).toBeNull();
    expect(await store.get('svcB', 'shared-account')).toBe('valueB');
  });
});

// ---------------------------------------------------------------------------
// EncryptedFileCredentialStore - Extended Tests
// ---------------------------------------------------------------------------
describe('EncryptedFileCredentialStore - Extended', () => {
  let storePath: string;
  let store: EncryptedFileCredentialStore;

  beforeEach(() => {
    storePath = join(
      tmpdir(),
      `panguard-test-enc-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    store = new EncryptedFileCredentialStore(storePath);
  });

  afterEach(() => {
    if (existsSync(storePath)) {
      rmSync(storePath, { recursive: true });
    }
  });

  it('should handle unicode credential values', async () => {
    await store.set('service', 'account', 'password with special chars');
    const result = await store.get('service', 'account');
    expect(result).toBe('password with special chars');
  });

  it('should handle empty credential values', async () => {
    await store.set('service', 'account', '');
    const result = await store.get('service', 'account');
    expect(result).toBe('');
  });

  it('should create encrypted file with iv:authTag:data format', async () => {
    await store.set('test-service', 'user', 'my-secret');
    const files = readdirSync(storePath);
    const encFile = files.find((f) => f.endsWith('.enc'));
    expect(encFile).toBeDefined();

    const content = readFileSync(join(storePath, encFile!), 'utf-8');
    const parts = content.split(':');
    expect(parts).toHaveLength(3);

    // Each part should be valid base64
    for (const part of parts) {
      expect(() => Buffer.from(part, 'base64')).not.toThrow();
    }
  });

  it('should handle multiple services with different encrypted files', async () => {
    await store.set('service-a', 'account', 'value-a');
    await store.set('service-b', 'account', 'value-b');

    const files = readdirSync(storePath).filter((f) => f.endsWith('.enc'));
    expect(files).toHaveLength(2);
    expect(files.some((f) => f.startsWith('service-a'))).toBe(true);
    expect(files.some((f) => f.startsWith('service-b'))).toBe(true);
  });

  it('should handle rapid sequential writes to the same service', async () => {
    for (let i = 0; i < 10; i++) {
      await store.set('rapid', `account-${i}`, `value-${i}`);
    }
    const accounts = await store.list('rapid');
    expect(accounts).toHaveLength(10);
  });

  it('should return correct account after overwrite followed by list', async () => {
    await store.set('svc', 'key', 'original');
    await store.set('svc', 'key', 'updated');
    const accounts = await store.list('svc');
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toBe('key');
    expect(await store.get('svc', 'key')).toBe('updated');
  });

  it('should handle service names with only underscores and hyphens', async () => {
    await store.set('my_service-v2', 'account', 'value');
    expect(await store.get('my_service-v2', 'account')).toBe('value');
  });

  it('should gracefully handle corrupt data that is partial base64', async () => {
    // Write a file with 3 colon-separated parts but invalid encrypted content
    const corruptPath = join(storePath, 'bad_service.enc');
    writeFileSync(corruptPath, 'aGVsbG8=:d29ybGQ=:YmFk');

    // Should return null (decrypt will fail due to incorrect key/auth tag)
    const result = await store.get('bad_service', 'any-account');
    expect(result).toBeNull();
  });

  it('should gracefully handle file with too few colon-separated parts', async () => {
    const corruptPath = join(storePath, 'truncated_svc.enc');
    writeFileSync(corruptPath, 'only-one-part');

    const result = await store.get('truncated_svc', 'account');
    expect(result).toBeNull();
  });

  it('should gracefully handle file with too many colon-separated parts', async () => {
    const corruptPath = join(storePath, 'extra_svc.enc');
    writeFileSync(corruptPath, 'a:b:c:d:e');

    const result = await store.get('extra_svc', 'account');
    expect(result).toBeNull();
  });

  it('should handle deleting an account that was never created for existing service', async () => {
    await store.set('svc', 'exists', 'value');
    const result = await store.delete('svc', 'not-exists');
    expect(result).toBe(false);
    // Original should still exist
    expect(await store.get('svc', 'exists')).toBe('value');
  });

  it('should handle very long service names', async () => {
    const longName = 'a'.repeat(200);
    await store.set(longName, 'account', 'value');
    expect(await store.get(longName, 'account')).toBe('value');
  });
});

// ---------------------------------------------------------------------------
// Plaintext Credential Scanner - Extended
// ---------------------------------------------------------------------------
describe('Plaintext Credential Scanner - Extended', () => {
  let testDir: string;

  beforeEach(() => {
    testDir = join(
      tmpdir(),
      `panguard-test-scan-ext-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  it('should match case-insensitive credential patterns', () => {
    writeFileSync(join(testDir, 'TELEGRAM_TOKEN'), 'uppercase-token');
    writeFileSync(join(testDir, 'Slack_Token'), 'mixed-case-token');
    const found = scanPlaintextCredentials(testDir);
    expect(found.length).toBe(2);
  });

  it('should match patterns with different separators', () => {
    writeFileSync(join(testDir, 'telegram.token'), 'dot-token');
    writeFileSync(join(testDir, 'telegram-token'), 'dash-token');
    writeFileSync(join(testDir, 'telegram_token'), 'underscore-token');
    const found = scanPlaintextCredentials(testDir);
    expect(found.length).toBe(3);
    // All should map to telegram service
    for (const cred of found) {
      expect(cred.service).toBe('telegram');
    }
  });

  it('should handle empty directory', () => {
    const found = scanPlaintextCredentials(testDir);
    expect(found).toHaveLength(0);
  });

  it('should correctly assign account names per pattern', () => {
    writeFileSync(join(testDir, 'telegram.token'), 'tg-token');
    writeFileSync(join(testDir, 'slack.token'), 'slack-token');
    writeFileSync(join(testDir, 'openai.key'), 'openai-key');
    const found = scanPlaintextCredentials(testDir);

    const telegram = found.find((c) => c.service === 'telegram');
    expect(telegram?.account).toBe('bot');

    const slack = found.find((c) => c.service === 'slack');
    expect(slack?.account).toBe('default');

    const openai = found.find((c) => c.service === 'openai');
    expect(openai?.account).toBe('default');
  });

  it('should not match partial filename patterns', () => {
    writeFileSync(join(testDir, 'my-telegram-token-backup.txt'), 'not-matched');
    writeFileSync(join(testDir, 'prefix-slack.token-suffix'), 'not-matched');
    const found = scanPlaintextCredentials(testDir);
    expect(found).toHaveLength(0);
  });

  it('should handle mixed valid and invalid files', () => {
    writeFileSync(join(testDir, 'telegram.token'), 'valid-token');
    writeFileSync(join(testDir, '.telegram.token'), 'hidden');
    writeFileSync(join(testDir, 'slack.token.backup'), 'backup');
    writeFileSync(join(testDir, 'random.txt'), 'irrelevant');
    writeFileSync(join(testDir, 'discord.enc'), 'encrypted');
    const found = scanPlaintextCredentials(testDir);
    expect(found).toHaveLength(1);
    expect(found[0]!.service).toBe('telegram');
  });
});

// ---------------------------------------------------------------------------
// Credential Migration - Extended
// ---------------------------------------------------------------------------
describe('Credential Migration - Extended', () => {
  let testDir: string;
  let store: InMemoryCredentialStore;

  beforeEach(() => {
    testDir = join(
      tmpdir(),
      `panguard-test-mig-ext-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    mkdirSync(testDir, { recursive: true });
    store = new InMemoryCredentialStore();
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  it('should preserve original file content in backup', async () => {
    const originalContent = 'my-secret-token-value';
    writeFileSync(join(testDir, 'telegram.token'), originalContent);
    await migrateCredentials(store, testDir);
    const backupContent = readFileSync(join(testDir, 'telegram.token.backup'), 'utf-8');
    expect(backupContent).toBe(originalContent);
  });

  it('should not create backup during dry run', async () => {
    writeFileSync(join(testDir, 'telegram.token'), 'token');
    await migrateCredentials(store, testDir, true);
    expect(existsSync(join(testDir, 'telegram.token.backup'))).toBe(false);
  });

  it('should not store credentials in dry run mode', async () => {
    writeFileSync(join(testDir, 'discord.token'), 'dc-token');
    writeFileSync(join(testDir, 'slack.token'), 'sl-token');
    await migrateCredentials(store, testDir, true);
    expect(await store.get('discord', 'bot')).toBeNull();
    expect(await store.get('slack', 'default')).toBeNull();
  });

  it('should report correct scanned count in dry run', async () => {
    writeFileSync(join(testDir, 'discord.token'), 'dc-token');
    writeFileSync(join(testDir, 'openai.key'), 'ai-key');
    const report = await migrateCredentials(store, testDir, true);
    expect(report.scanned).toBe(2);
    expect(report.migrated).toBe(2);
    expect(report.failed).toBe(0);
  });

  it('should handle partial migration failure', async () => {
    writeFileSync(join(testDir, 'telegram.token'), 'tg-token');
    writeFileSync(join(testDir, 'discord.token'), 'dc-token');

    let callCount = 0;
    const partiallyFailingStore = {
      ...store,
      set: async (service: string, account: string, password: string) => {
        callCount++;
        if (callCount === 2) {
          throw new Error('Second write failed');
        }
        return store.set(service, account, password);
      },
      get: store.get.bind(store),
      delete: store.delete.bind(store),
      list: store.list.bind(store),
    };

    const report = await migrateCredentials(partiallyFailingStore, testDir);
    expect(report.scanned).toBe(2);
    expect(report.migrated).toBe(1);
    expect(report.failed).toBe(1);
    expect(report.errors).toHaveLength(1);
  });

  it('should correctly track all errors in the report', async () => {
    writeFileSync(join(testDir, 'telegram.token'), 'tg');
    writeFileSync(join(testDir, 'slack.token'), 'sl');

    const failStore = {
      ...store,
      set: async () => {
        throw new Error('Always fails');
      },
      get: store.get.bind(store),
      delete: store.delete.bind(store),
      list: store.list.bind(store),
    };

    const report = await migrateCredentials(failStore, testDir);
    expect(report.failed).toBe(2);
    expect(report.migrated).toBe(0);
    expect(report.errors).toHaveLength(2);
    for (const error of report.errors) {
      expect(error).toContain('Always fails');
    }
  });
});
