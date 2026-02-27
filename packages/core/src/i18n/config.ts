/**
 * i18n configuration and initialization
 * 國際化配置與初始化
 *
 * @module @panguard-ai/core/i18n
 */

import i18next, { type i18n } from 'i18next';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import type { Language } from '../types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let initialized = false;

/**
 * Load translation JSON from filesystem
 * 從檔案系統載入翻譯 JSON
 */
function loadTranslations(lang: string, ns: string): Record<string, unknown> {
  const filePath = resolve(__dirname, `./locales/${lang}/${ns}.json`);
  try {
    const content = readFileSync(filePath, 'utf-8');
    return JSON.parse(content) as Record<string, unknown>;
  } catch {
    console.warn(`[i18n] Failed to load translations: ${filePath}`);
    return {};
  }
}

/**
 * Initialize i18next for bilingual support (zh-TW / en)
 * 初始化 i18next 以支援雙語（繁體中文 / 英文）
 *
 * @param language - Target language / 目標語言
 * @returns Configured i18next instance / 配置好的 i18next 實例
 */
export async function initI18n(language: Language = 'en'): Promise<i18n> {
  if (initialized) {
    await i18next.changeLanguage(language);
    return i18next;
  }

  const resources = {
    en: {
      common: loadTranslations('en', 'common'),
      security: loadTranslations('en', 'security'),
      discovery: loadTranslations('en', 'discovery'),
      'panguard-scan': loadTranslations('en', 'panguard-scan'),
      'panguard-guard': loadTranslations('en', 'panguard-guard'),
      'panguard-chat': loadTranslations('en', 'panguard-chat'),
      'panguard-trap': loadTranslations('en', 'panguard-trap'),
      'panguard-report': loadTranslations('en', 'panguard-report'),
      panguardweb: loadTranslations('en', 'panguardweb'),
    },
    'zh-TW': {
      common: loadTranslations('zh-TW', 'common'),
      security: loadTranslations('zh-TW', 'security'),
      discovery: loadTranslations('zh-TW', 'discovery'),
      'panguard-scan': loadTranslations('zh-TW', 'panguard-scan'),
      'panguard-guard': loadTranslations('zh-TW', 'panguard-guard'),
      'panguard-chat': loadTranslations('zh-TW', 'panguard-chat'),
      'panguard-trap': loadTranslations('zh-TW', 'panguard-trap'),
      'panguard-report': loadTranslations('zh-TW', 'panguard-report'),
      panguardweb: loadTranslations('zh-TW', 'panguardweb'),
    },
  };

  await i18next.init({
    lng: language,
    fallbackLng: 'en',
    supportedLngs: ['zh-TW', 'en'],
    ns: [
      'common',
      'security',
      'discovery',
      'panguard-scan',
      'panguard-guard',
      'panguard-chat',
      'panguard-trap',
      'panguard-report',
      'panguardweb',
    ],
    defaultNS: 'common',
    resources,
    interpolation: {
      escapeValue: false,
    },
    returnNull: false,
  });

  initialized = true;
  return i18next;
}

/**
 * Get the current i18next instance
 * 取得目前的 i18next 實例
 *
 * @returns i18next instance or null if not initialized / i18next 實例，未初始化則為 null
 */
export function getI18n(): i18n | null {
  if (!initialized) {
    return null;
  }
  return i18next;
}

/**
 * Change the active language
 * 切換使用中的語言
 *
 * @param language - Target language / 目標語言
 */
export async function changeLanguage(language: Language): Promise<void> {
  if (!initialized) {
    throw new Error(
      'i18n not initialized. Call initI18n() first. / i18n 尚未初始化，請先呼叫 initI18n()。'
    );
  }
  await i18next.changeLanguage(language);
}

/**
 * Translate a key using the current language
 * 使用目前語言翻譯指定的鍵值
 *
 * @param key - Translation key (e.g., 'common:welcome') / 翻譯鍵值
 * @param options - Interpolation options / 插值選項
 * @returns Translated string / 翻譯後的字串
 */
export function t(key: string, options?: Record<string, unknown>): string {
  if (!initialized) {
    return key;
  }
  return i18next.t(key, options);
}

/**
 * Reset i18n state (primarily for testing)
 * 重設 i18n 狀態（主要用於測試）
 */
export function resetI18n(): void {
  initialized = false;
}
