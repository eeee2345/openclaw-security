import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import ChatDocsContent from './ChatDocsContent';

export const metadata: Metadata = {
  title: 'Panguard Chat — Documentation',
  description: 'AI-powered security notifications via Telegram, Slack, LINE, Email, and Webhook. Natural language threat alerts and daily summaries.',
  openGraph: {
    title: 'Panguard Chat — Panguard AI Docs',
    description: 'Security notifications in plain language. Connect Telegram, Slack, LINE, or Email in minutes.',
  },
};

export default function ChatDocsPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <ChatDocsContent />
      </main>
      <Footer />
    </>
  );
}
