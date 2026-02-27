import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export async function generateMetadata({
  params: { locale },
}: {
  params: { locale: string };
}): Promise<Metadata> {
  return {
    title: locale === 'zh' ? '隱私權政策' : 'Privacy Policy',
  };
}

export default function PrivacyPolicyPage({ params: { locale } }: { params: { locale: string } }) {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">Privacy Policy</h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
        {locale === 'zh' && (
          <p className="mt-3 text-sm text-text-muted border border-border rounded-lg px-4 py-3 bg-surface-1">
            本隱私權政策目前僅提供英文版本。中文翻譯版本正在準備中，如有任何疑問請聯繫
            <a
              href="mailto:privacy@panguard.ai"
              className="text-brand-sage hover:text-brand-sage-light underline ml-1"
            >
              privacy@panguard.ai
            </a>
          </p>
        )}
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            Panguard AI, Inc. (&quot;Panguard,&quot; &quot;we,&quot; &quot;us,&quot; or
            &quot;our&quot;) is committed to protecting the privacy of individuals who visit our
            website at panguard.ai, use our products and services, or otherwise interact with us.
            This Privacy Policy describes how we collect, use, disclose, and safeguard your
            information.
          </p>
          <p className="mt-3">
            By accessing or using any Panguard service, you acknowledge that you have read,
            understood, and agree to be bound by this Privacy Policy. If you do not agree, you must
            discontinue use of our services immediately.
          </p>
        </section>

        {/* 1. Information We Collect */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            1. Information We Collect
          </h2>

          <h3 className="text-base font-medium text-text-primary mb-2">1.1 Account Information</h3>
          <p>
            When you register for a Panguard account, we collect your name, email address,
            organization name, billing address, and payment information. Payment information is
            processed by our PCI-compliant payment processor and is never stored on our servers.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            1.2 System Telemetry (Anonymized)
          </h3>
          <p>
            Our endpoint protection agent collects anonymized system telemetry data, including
            operating system version, hardware configuration identifiers (hashed), installed
            software inventory, and network configuration metadata. All telemetry data is stripped
            of personally identifiable information before transmission and is used exclusively to
            improve threat detection accuracy.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">1.3 Usage Analytics</h3>
          <p>
            We collect information about how you interact with our platform, including pages
            visited, features used, session duration, and interface interactions. This data helps us
            improve our product experience and is processed in aggregate form.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            1.4 Threat Data (Anonymized)
          </h3>
          <p>
            When our security agent detects potential threats, anonymized indicators of compromise
            (IOCs), file hashes, and behavioral signatures are transmitted to our threat
            intelligence platform. This data does not contain personal files, documents, or
            identifiable user content. Threat data is used to improve detection capabilities across
            all Panguard customers.
          </p>
        </section>

        {/* 2. How We Use Your Information */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            2. How We Use Your Information
          </h2>
          <p>We use the information we collect for the following purposes:</p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>To provide, maintain, and improve our security products and services</li>
            <li>To detect, prevent, and respond to security threats on your behalf</li>
            <li>To process transactions and send related billing communications</li>
            <li>To send you technical alerts, security advisories, and support messages</li>
            <li>To conduct research and analysis to enhance our AI threat detection models</li>
            <li>To comply with legal obligations and enforce our agreements</li>
            <li>To communicate with you about product updates, if you have opted in</li>
          </ul>
        </section>

        {/* 3. Data Sharing */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">3. Data Sharing</h2>
          <p>
            We do not sell, rent, or trade your personal information to third parties. We may share
            your information in the following circumstances:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">Service Providers:</strong> We engage trusted
              third-party service providers who perform services on our behalf, such as cloud
              hosting (infrastructure providers), payment processing, and customer support tools.
              These providers are contractually obligated to protect your data and may only use it
              to perform services for us.
            </li>
            <li>
              <strong className="text-text-primary">Legal Requirements:</strong> We may disclose
              information if required by law, regulation, subpoena, court order, or other
              governmental request.
            </li>
            <li>
              <strong className="text-text-primary">Business Transfers:</strong> In the event of a
              merger, acquisition, or sale of assets, your information may be transferred as part of
              that transaction. We will notify you of any such change in ownership or control.
            </li>
            <li>
              <strong className="text-text-primary">Aggregated or De-identified Data:</strong> We
              may share aggregated, non-identifiable threat intelligence data with industry partners
              and security researchers to advance collective cybersecurity efforts.
            </li>
          </ul>
        </section>

        {/* 4. Data Retention */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">4. Data Retention</h2>
          <p>
            We retain your personal information for as long as your account is active or as needed
            to provide you services. Account information is retained for up to 12 months after
            account closure for legal and audit purposes. Anonymized telemetry and threat data may
            be retained indefinitely as it cannot be linked to individual users. You may request
            deletion of your account data at any time by contacting us at privacy@panguard.ai.
          </p>
        </section>

        {/* 5. Your Rights */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">5. Your Rights</h2>
          <p>
            Depending on your jurisdiction, you may have the following rights regarding your
            personal data under the General Data Protection Regulation (GDPR) and other applicable
            privacy laws:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">Right of Access:</strong> You may request a copy
              of the personal data we hold about you.
            </li>
            <li>
              <strong className="text-text-primary">Right to Rectification:</strong> You may request
              that we correct inaccurate or incomplete personal data.
            </li>
            <li>
              <strong className="text-text-primary">Right to Erasure:</strong> You may request that
              we delete your personal data, subject to certain legal exceptions.
            </li>
            <li>
              <strong className="text-text-primary">Right to Restrict Processing:</strong> You may
              request that we restrict the processing of your personal data in certain
              circumstances.
            </li>
            <li>
              <strong className="text-text-primary">Right to Data Portability:</strong> You may
              request a machine-readable copy of your personal data.
            </li>
            <li>
              <strong className="text-text-primary">Right to Object:</strong> You may object to the
              processing of your personal data for direct marketing purposes.
            </li>
          </ul>
          <p className="mt-3">
            To exercise any of these rights, please contact us at privacy@panguard.ai. We will
            respond to your request within 30 days.
          </p>
        </section>

        {/* 6. Cookies */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">6. Cookies</h2>
          <p>
            We use cookies and similar tracking technologies to operate and improve our website. For
            detailed information about the cookies we use and how to manage them, please refer to
            our{' '}
            <a
              href="/legal/cookies"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Cookie Policy
            </a>
            .
          </p>
        </section>

        {/* 7. International Transfers */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            7. International Data Transfers
          </h2>
          <p>
            Panguard AI, Inc. is headquartered in Taipei, Taiwan. Your information may be
            transferred to, stored, and processed in jurisdictions other than your own. When we
            transfer personal data internationally, we ensure that appropriate safeguards are in
            place, including Standard Contractual Clauses (SCCs) approved by the European
            Commission, adequacy decisions, or other legally recognized transfer mechanisms. Our
            data processing infrastructure is hosted on SOC 2 Type II certified cloud providers with
            data centers in Asia-Pacific, North America, and Europe.
          </p>
        </section>

        {/* 8. Children's Privacy */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            8. Children&apos;s Privacy
          </h2>
          <p>
            Our services are not directed to individuals under the age of 16. We do not knowingly
            collect personal information from children under 16. If we become aware that a child
            under 16 has provided us with personal information, we will take steps to delete such
            information promptly. If you believe that a child under 16 has provided us with personal
            data, please contact us at privacy@panguard.ai.
          </p>
        </section>

        {/* 9. Changes */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            9. Changes to This Policy
          </h2>
          <p>
            We may update this Privacy Policy from time to time to reflect changes in our practices,
            technology, legal requirements, or other factors. We will notify you of any material
            changes by posting the updated policy on our website and updating the &quot;Last
            updated&quot; date. For significant changes, we will provide additional notice via email
            or through our platform. Your continued use of our services after any changes
            constitutes your acceptance of the updated Privacy Policy.
          </p>
        </section>

        {/* 10. Contact */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">10. Contact Us</h2>
          <p>
            If you have any questions, concerns, or requests regarding this Privacy Policy or our
            data practices, please contact us:
          </p>
          <div className="mt-3 p-4 bg-surface-1 border border-border rounded-lg">
            <p className="font-medium text-text-primary">Panguard AI, Inc.</p>
            <p className="mt-1">Privacy Team</p>
            <p>
              Email:{' '}
              <a
                href="mailto:privacy@panguard.ai"
                className="text-brand-sage hover:text-brand-sage-light underline"
              >
                privacy@panguard.ai
              </a>
            </p>
            <p>Taipei, Taiwan</p>
          </div>
        </section>
      </div>
    </article>
  );
}
