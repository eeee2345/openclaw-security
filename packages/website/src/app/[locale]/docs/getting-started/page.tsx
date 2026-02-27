import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import GettingStartedContent from './GettingStartedContent';

export default function GettingStartedPage() {
  return (
    <>
      <NavBar />
      <main>
        <GettingStartedContent />
      </main>
      <Footer />
    </>
  );
}
