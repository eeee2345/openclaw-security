import createNextIntlPlugin from 'next-intl/plugin';

const withNextIntl = createNextIntlPlugin();

const isDev = process.env.NODE_ENV === 'development';
const isVercel = !!process.env.VERCEL;

/** @type {import('next').NextConfig} */
const nextConfig = {
  async redirects() {
    return [
      {
        source: '/docs',
        destination: 'https://docs.panguard.ai',
        permanent: true,
      },
      {
        source: '/docs/:path*',
        destination: 'https://docs.panguard.ai/:path*',
        permanent: true,
      },
    ];
  },
  async rewrites() {
    return {
      beforeFiles: [
        {
          source: '/windows',
          has: [{ type: 'host', value: 'get.panguard.ai' }],
          destination: '/api/install/windows',
        },
        {
          source: '/win',
          has: [{ type: 'host', value: 'get.panguard.ai' }],
          destination: '/api/install/windows',
        },
        {
          source: '/install.ps1',
          has: [{ type: 'host', value: 'get.panguard.ai' }],
          destination: '/api/install/windows',
        },
        {
          source: '/:path*',
          has: [{ type: 'host', value: 'get.panguard.ai' }],
          destination: '/api/install',
        },
      ],
    };
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'X-DNS-Prefetch-Control', value: 'on' },
          {
            key: 'Strict-Transport-Security',
            value: 'max-age=31536000; includeSubDomains; preload',
          },
          {
            key: 'Permissions-Policy',
            value: 'camera=(), microphone=(), geolocation=()',
          },
          {
            // SECURITY NOTE: unsafe-inline in script-src is required because layout.tsx
            // uses dangerouslySetInnerHTML for JSON-LD structured data and js-ready
            // class toggle. This weakens XSS protection but is a known Next.js limitation.
            // TODO: Implement nonce-based CSP via Next.js middleware when stable.
            // See: https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
            // style-src unsafe-inline is required by Next.js CSS-in-JS.
            key: 'Content-Security-Policy',
            value: [
              "default-src 'self'",
              `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ''} https://plausible.io`,
              "style-src 'self' 'unsafe-inline'",
              "img-src 'self' data: https:",
              "font-src 'self' data:",
              "connect-src 'self' https://api.panguard.ai https://*.vercel-insights.com https://*.vercel-analytics.com https://plausible.io",
              "frame-ancestors 'none'",
              "base-uri 'self'",
              "form-action 'self'",
              ...(isVercel ? ['upgrade-insecure-requests'] : []),
            ].join('; '),
          },
        ],
      },
    ];
  },
};

export default withNextIntl(nextConfig);
