import type { MetadataRoute } from 'next';

const locales = ['en', 'zh'] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  const base = 'https://panguard.ai';
  const now = new Date().toISOString();

  const pages = [
    '/',
    '/product',
    '/product/guard',
    '/product/chat',
    '/product/trap',
    '/product/report',
    '/integrations',
    '/pricing',
    '/early-access',
    '/demo',
    '/security',
    '/technology',
    '/company',
    '/contact',
    '/solutions/developers',
    '/solutions/smb',
    '/solutions/enterprise',
    '/blog',
    '/docs',
    '/docs/api',
    '/compliance',
    '/customers',
    '/careers',
    '/changelog',
    '/resources',
    '/partners',
    '/press',
    '/status',
    '/trust',
    '/legal/privacy',
    '/legal/terms',
    '/legal/cookies',
    '/legal/dpa',
    '/legal/sla',
    '/legal/acceptable-use',
    '/legal/responsible-disclosure',
  ];

  const getFrequency = (path: string): 'weekly' | 'monthly' => {
    if (path === '/' || path === '/blog' || path === '/changelog' || path === '/status')
      return 'weekly';
    return 'monthly';
  };

  const getPriority = (path: string): number => {
    if (path === '/') return 1.0;
    if (path.startsWith('/product') || path === '/integrations') return 0.8;
    if (path === '/blog' || path === '/docs' || path === '/pricing') return 0.7;
    return 0.6;
  };

  // English = no prefix (as-needed), Chinese = /zh prefix
  const localeUrl = (locale: string, path: string) => {
    const suffix = path === '/' ? '' : path;
    return locale === 'en' ? `${base}${suffix}` : `${base}/${locale}${suffix}`;
  };

  return locales.flatMap((locale) =>
    pages.map((path) => ({
      url: localeUrl(locale, path),
      lastModified: now,
      changeFrequency: getFrequency(path),
      priority: getPriority(path),
      alternates: {
        languages: Object.fromEntries(
          locales.map((l) => [l === 'zh' ? 'zh-TW' : l, localeUrl(l, path)])
        ),
      },
    }))
  );
}
