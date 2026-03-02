const BASE_URL = 'https://panguard.ai';

/**
 * Build per-page alternates with correct canonical URLs and hreflang.
 * Usage: `alternates: buildAlternates('/pricing', locale)`
 */
export function buildAlternates(path: string, locale: string) {
  const enPath = path === '/' ? '' : path;
  const zhPath = `/zh${path === '/' ? '' : path}`;
  return {
    canonical: locale === 'en' ? `${BASE_URL}${enPath}` : `${BASE_URL}${zhPath}`,
    languages: {
      en: `${BASE_URL}${enPath}`,
      'zh-TW': `${BASE_URL}${zhPath}`,
      'x-default': `${BASE_URL}${enPath}`,
    },
  };
}
