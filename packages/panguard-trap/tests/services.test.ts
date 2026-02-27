/**
 * Trap Services tests
 * 蜜罐服務測試
 */

import { describe, it, expect } from 'vitest';
import {
  createTrapService,
  SSHTrapService,
  HTTPTrapService,
  GenericTrapService,
} from '../src/services/index.js';
import type { TrapServiceConfig } from '../src/types.js';
import { DEFAULT_SERVICE_CONFIGS } from '../src/types.js';

describe('createTrapService', () => {
  it('should create SSHTrapService for ssh type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.ssh, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(SSHTrapService);
    expect(service.serviceType).toBe('ssh');
  });

  it('should create HTTPTrapService for http type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.http, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(HTTPTrapService);
    expect(service.serviceType).toBe('http');
  });

  it('should create GenericTrapService for ftp type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.ftp, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('ftp');
  });

  it('should create GenericTrapService for telnet type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.telnet, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('telnet');
  });

  it('should create GenericTrapService for mysql type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.mysql, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('mysql');
  });

  it('should create GenericTrapService for redis type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.redis, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('redis');
  });

  it('should create GenericTrapService for smb type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.smb, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('smb');
  });

  it('should create GenericTrapService for rdp type', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.rdp, enabled: true };
    const service = createTrapService(config);
    expect(service).toBeInstanceOf(GenericTrapService);
    expect(service.serviceType).toBe('rdp');
  });
});

describe('SSHTrapService', () => {
  it('should initialize in stopped state', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.ssh, enabled: true };
    const service = new SSHTrapService(config);
    expect(service.status).toBe('stopped');
    expect(service.serviceType).toBe('ssh');
    expect(service.getActiveSessions()).toHaveLength(0);
    expect(service.getTotalSessionCount()).toBe(0);
  });

  it('should register session handler', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.ssh, enabled: true };
    const service = new SSHTrapService(config);
    const handler = () => {};
    service.onSession(handler);
    // No error = success
  });
});

describe('HTTPTrapService', () => {
  it('should initialize in stopped state', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.http, enabled: true };
    const service = new HTTPTrapService(config);
    expect(service.status).toBe('stopped');
    expect(service.serviceType).toBe('http');
  });
});

describe('GenericTrapService', () => {
  it('should initialize in stopped state for ftp', () => {
    const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS.ftp, enabled: true };
    const service = new GenericTrapService(config);
    expect(service.status).toBe('stopped');
    expect(service.serviceType).toBe('ftp');
  });

  it('should initialize for all generic types', () => {
    const genericTypes = ['ftp', 'telnet', 'mysql', 'redis', 'smb', 'rdp'] as const;
    for (const type of genericTypes) {
      const config: TrapServiceConfig = { ...DEFAULT_SERVICE_CONFIGS[type], enabled: true };
      const service = new GenericTrapService(config);
      expect(service.serviceType).toBe(type);
    }
  });

  it('should throw for unsupported type', () => {
    expect(() => {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const badType = 'unknown_proto' as any;
      new GenericTrapService({
        type: badType,
        port: 2222,
        enabled: true,
      });
    }).toThrow();
  });
});
