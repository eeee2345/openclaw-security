/**
 * Server component that injects BreadcrumbList JSON-LD structured data.
 *
 * Usage:
 *   <JsonLdBreadcrumb items={[
 *     { name: 'Blog', href: '/blog' },
 *     { name: 'Post Title' },
 *   ]} />
 */

interface BreadcrumbItem {
  name: string;
  href?: string;
}

export default function JsonLdBreadcrumb({ items }: { items: BreadcrumbItem[] }) {
  const breadcrumbJsonLd = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'Home', item: 'https://panguard.ai' },
      ...items.map((item, i) => ({
        '@type': 'ListItem',
        position: i + 2,
        name: item.name,
        ...(item.href ? { item: `https://panguard.ai${item.href}` } : {}),
      })),
    ],
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(breadcrumbJsonLd) }}
    />
  );
}
