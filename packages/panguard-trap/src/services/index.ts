/**
 * Fake Service Simulators
 * 假服務模擬器
 *
 * Factory function to create trap services based on service type.
 * 根據服務類型建立蜜罐服務的工廠函式。
 *
 * @module @panguard-ai/panguard-trap/services
 */

import type { TrapServiceConfig, TrapService, TrapServiceType } from '../types.js';
import { SSHTrapService } from './ssh-trap.js';
import { HTTPTrapService } from './http-trap.js';
import { GenericTrapService } from './generic-trap.js';

/** Service types that use generic handler / 使用通用處理器的服務類型 */
const GENERIC_TYPES: Set<TrapServiceType> = new Set([
  'ftp',
  'telnet',
  'mysql',
  'redis',
  'smb',
  'rdp',
]);

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
    default:
      if (GENERIC_TYPES.has(config.type)) {
        return new GenericTrapService(config);
      }
      throw new Error(`Unknown trap service type: ${config.type}`);
  }
}

export { BaseTrapService } from './base-service.js';
export { SSHTrapService } from './ssh-trap.js';
export { HTTPTrapService } from './http-trap.js';
export { GenericTrapService } from './generic-trap.js';
