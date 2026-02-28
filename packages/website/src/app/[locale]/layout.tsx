import type { Metadata } from 'next';
import { Inter, JetBrains_Mono, Instrument_Serif, Noto_Sans_TC } from 'next/font/google';
import { NextIntlClientProvider } from 'next-intl';
import { getMessages, getTranslations } from 'next-intl/server';
import { notFound } from 'next/navigation';
import { AuthProvider } from '@/lib/auth';

const locales = ['en', 'zh'] as const;

const inter = Inter({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
});

const instrumentSerif = Instrument_Serif({
  subsets: ['latin'],
  weight: '400',
  variable: '--font-display',
  display: 'swap',
});

const notoSansTC = Noto_Sans_TC({
  subsets: ['latin'],
  weight: ['400', '700'],
  variable: '--font-cjk',
  display: 'swap',
});

export async function generateMetadata({
  params: { locale },
}: {
  params: { locale: string };
}): Promise<Metadata> {
  const t = await getTranslations({ locale, namespace: 'metadata.home' });

  return {
    title: {
      default: t('title'),
      template: `%s | Panguard AI`,
    },
    description: t('description'),
    openGraph: {
      type: 'website',
      locale: locale === 'zh' ? 'zh_TW' : 'en_US',
      url: 'https://panguard.ai',
      siteName: 'Panguard AI',
      title: t('title'),
      description: t('description'),
      images: [{ url: '/og-image.png', width: 1200, height: 630 }],
    },
    twitter: {
      card: 'summary_large_image',
      title: t('title'),
      description: t('description'),
      images: ['/og-image.png'],
    },
    robots: { index: true, follow: true },
    icons: {
      icon: [
        { url: '/favicon-32x32.png', sizes: '32x32', type: 'image/png' },
        { url: '/favicon-16x16.png', sizes: '16x16', type: 'image/png' },
        { url: '/favicon.png', sizes: '1024x1024', type: 'image/png' },
      ],
      apple: '/apple-touch-icon.png',
    },
    alternates: {
      canonical: `https://panguard.ai/${locale}`,
      languages: {
        en: 'https://panguard.ai/en',
        'zh-TW': 'https://panguard.ai/zh',
      },
    },
  };
}

const jsonLd = [
  {
    '@context': 'https://schema.org',
    '@type': 'Organization',
    name: 'Panguard AI',
    url: 'https://panguard.ai',
    logo: 'https://panguard.ai/favicon.png',
    sameAs: [
      'https://github.com/panguard-ai/panguard-ai',
      'https://x.com/panguard_ai',
      'https://linkedin.com/company/panguard-ai',
    ],
    contactPoint: {
      '@type': 'ContactPoint',
      contactType: 'sales',
      url: 'https://panguard.ai/contact',
    },
  },
  {
    '@context': 'https://schema.org',
    '@type': 'SoftwareApplication',
    name: 'Panguard AI',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Linux, macOS',
    description:
      'AI-powered endpoint security for developers and SMBs. One command to install. Zero configuration.',
    url: 'https://panguard.ai',
    offers: [
      { '@type': 'Offer', price: '0', priceCurrency: 'USD', name: 'Free Scan' },
      { '@type': 'Offer', price: '9', priceCurrency: 'USD', name: 'Solo' },
      { '@type': 'Offer', price: '19', priceCurrency: 'USD', name: 'Starter' },
      { '@type': 'Offer', price: '14', priceCurrency: 'USD', name: 'Team (per endpoint)' },
      { '@type': 'Offer', price: '10', priceCurrency: 'USD', name: 'Business (per endpoint)' },
    ],
    publisher: {
      '@type': 'Organization',
      name: 'Panguard AI, Inc.',
      url: 'https://panguard.ai',
    },
  },
];

export default async function LocaleLayout({
  children,
  params: { locale },
}: Readonly<{
  children: React.ReactNode;
  params: { locale: string };
}>) {
  if (!locales.includes(locale as (typeof locales)[number])) {
    notFound();
  }

  const messages = await getMessages();

  return (
    <html
      lang={locale === 'zh' ? 'zh-TW' : 'en'}
      className={`${inter.variable} ${jetbrainsMono.variable} ${instrumentSerif.variable} ${notoSansTC.variable}`}
    >
      <head>
        {/* Enable scroll-reveal animations only after JS is ready (prevents FOIC) */}
        <script
          dangerouslySetInnerHTML={{ __html: 'document.documentElement.classList.add("js-ready")' }}
        />
        {/* jsonLd is a static constant — never include user-supplied values */}
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
        {/* Plausible Analytics — privacy-friendly, no cookies, GDPR compliant */}
        {process.env.NEXT_PUBLIC_PLAUSIBLE_DOMAIN && (
          <script
            defer
            data-domain={process.env.NEXT_PUBLIC_PLAUSIBLE_DOMAIN}
            src="https://plausible.io/js/script.js"
          />
        )}
      </head>
      <body className="font-sans antialiased">
        <NextIntlClientProvider messages={messages}>
          <AuthProvider>{children}</AuthProvider>
        </NextIntlClientProvider>
      </body>
    </html>
  );
}
