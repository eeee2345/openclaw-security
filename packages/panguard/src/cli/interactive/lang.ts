/**
 * Language management for interactive CLI
 * @module @panguard-ai/panguard/cli/interactive/lang
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { Lang } from '../menu.js';

const CONFIG_DIR = join(homedir(), '.panguard');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

let currentLang: Lang = 'en';

export function getLang(): Lang {
  return currentLang;
}

export function setLang(lang: Lang): void {
  currentLang = lang;
}

export function getConfigPath(): string {
  return CONFIG_PATH;
}

export function detectLang(): Lang {
  if (existsSync(CONFIG_PATH)) {
    try {
      const data = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
      if (data.lang === 'zh-TW' || data.lang === 'en') return data.lang;
    } catch {
      /* ignore */
    }
  }
  const sysLang = process.env['LANG'] ?? process.env['LC_ALL'] ?? '';
  if (sysLang.includes('zh')) return 'zh-TW';
  return 'en';
}

export function saveLang(lang: Lang): void {
  try {
    let config: Record<string, unknown> = {};
    if (existsSync(CONFIG_PATH)) {
      config = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    }
    config['lang'] = lang;
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  } catch {
    /* best effort */
  }
}
