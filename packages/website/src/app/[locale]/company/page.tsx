import { redirect } from 'next/navigation';

// Company page consolidated into About page to avoid content duplication.
// Brand story, values, and team content all live on /about now.
export default function CompanyPage({ params }: { params: { locale: string } }) {
  redirect(`/${params.locale}/about`);
}
