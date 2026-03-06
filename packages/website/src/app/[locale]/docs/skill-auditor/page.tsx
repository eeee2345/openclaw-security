import type { Metadata } from 'next';
import NavBar from '@/components/NavBar';
import Footer from '@/components/Footer';
import SkillAuditorContent from './SkillAuditorContent';

export const metadata: Metadata = {
  title: 'Skill Auditor — Panguard AI Docs',
  description:
    'Automated security scanner for AI agent skills. Detect prompt injection, tool poisoning, hidden Unicode, and credential theft in SKILL.md files.',
  openGraph: {
    title: 'Skill Auditor — Panguard AI',
    description:
      'Scan AI agent skills for security threats in under 1 second. 7 automated checks, 0-100 risk score.',
  },
};

export default function SkillAuditorPage() {
  return (
    <>
      <NavBar />
      <main id="main-content">
        <SkillAuditorContent />
      </main>
      <Footer />
    </>
  );
}
