/**
 * Trap Service Factory
 * 蜜罐服務工廠
 *
 * Factory function to create trap services based on service type.
 * SSH and HTTP have dedicated real-protocol handlers.
 * MySQL, Redis, SMB, and RDP now have dedicated binary-protocol handlers.
 * FTP and Telnet use the enhanced generic text-based handler.
 *
 * @module @panguard-ai/panguard-trap/services
 */

import type { TrapServiceConfig, TrapService } from '../types.js';
import { SSHTrapService } from './ssh-trap.js';
import { HTTPTrapService } from './http-trap.js';
import { MySQLTrapService } from './mysql-trap.js';
import { RedisTrapService } from './redis-trap.js';
import { SMBTrapService } from './smb-trap.js';
import { RDPTrapService } from './rdp-trap.js';
import { GenericTrapService } from './generic-trap.js';

/**
 * Create a trap service instance for the given config
 * 根據配置建立蜜罐服務實例
 */
export function createTrapService(config: TrapServiceConfig): TrapService {
  switch (config.type) {
    case 'ssh':
      return new SSHTrapService(config);
    case 'http':
      return new HTTPTrapService(config);
    case 'mysql':
      return new MySQLTrapService(config);
    case 'redis':
      return new RedisTrapService(config);
    case 'smb':
      return new SMBTrapService(config);
    case 'rdp':
      return new RDPTrapService(config);
    case 'ftp':
    case 'telnet':
      return new GenericTrapService(config);
    default:
      throw new Error(`Unknown trap service type: ${config.type}`);
  }
}

export { BaseTrapService } from './base-service.js';
export { SSHTrapService } from './ssh-trap.js';
export { HTTPTrapService } from './http-trap.js';
export { MySQLTrapService } from './mysql-trap.js';
export { RedisTrapService } from './redis-trap.js';
export { SMBTrapService } from './smb-trap.js';
export { RDPTrapService } from './rdp-trap.js';
export { GenericTrapService } from './generic-trap.js';
