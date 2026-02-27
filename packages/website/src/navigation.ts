import { createNavigation } from 'next-intl/navigation';
import { defineRouting } from 'next-intl/routing';

export const routing = defineRouting({
  locales: ['en', 'zh'],
  defaultLocale: 'en',
  localePrefix: 'as-needed',
});

export const { Link, redirect, usePathname, useRouter } = createNavigation(routing);

export type Locale = (typeof routing.locales)[number];
