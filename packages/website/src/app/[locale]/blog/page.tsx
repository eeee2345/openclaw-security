import { getTranslations } from 'next-intl/server';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import BlogContent from './BlogContent';

export async function generateMetadata({ params }: { params: { locale: string } }) {
  const t = await getTranslations({ locale: params.locale, namespace: 'metadata' });
  return {
    title: t('blog.title'),
    description: t('blog.description'),
  };
}

export default function BlogPage() {
  return (
    <>
      <NavBar />
      <main>
        <BlogContent />
      </main>
      <Footer />
    </>
  );
}
