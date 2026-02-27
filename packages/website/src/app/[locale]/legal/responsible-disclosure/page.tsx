import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Vulnerability Disclosure Policy',
};

export default function ResponsibleDisclosurePage() {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">
          Vulnerability Disclosure Policy
        </h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            Panguard AI, Inc. (&quot;Panguard&quot;) is committed to the security of our platform
            and the protection of our customers. We welcome and encourage responsible security
            research. This policy outlines the guidelines for reporting vulnerabilities to us and
            describes our commitment to working with security researchers in good faith.
          </p>
        </section>

        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">1. Scope</h2>
          <p>The following assets are in scope for this program:</p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">panguard.ai</strong> -- Our primary marketing
              website and web application
            </li>
            <li>
              <strong className="text-text-primary">app.panguard.ai</strong> -- The Panguard
              dashboard and management console
            </li>
            <li>
              <strong className="text-text-primary">api.panguard.ai</strong> -- The Panguard REST
              API and GraphQL endpoints
            </li>
            <li>
              <strong className="text-text-primary">*.panguard.ai</strong> -- Other first-party
              subdomains operated by Panguard
            </li>
          </ul>
          <p className="mt-3">
            Mobile applications, open-source libraries published by Panguard on GitHub, and the
            Panguard endpoint agent are also in scope.
          </p>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">2. Safe Harbor</h2>
          <p>
            Panguard will not pursue legal action against security researchers who discover and
            report vulnerabilities in good faith and in compliance with this policy. Specifically:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              We consider security research conducted in accordance with this policy to be
              authorized and will not initiate legal action against you
            </li>
            <li>
              We will not pursue claims under the Computer Fraud and Abuse Act (CFAA) or equivalent
              laws for research conducted under this policy
            </li>
            <li>
              If legal action is initiated by a third party against you for activities conducted in
              accordance with this policy, we will take steps to make it known that your actions
              were authorized by us
            </li>
            <li>We will work with you to understand and resolve issues quickly</li>
          </ul>
          <p className="mt-3">
            This safe harbor applies only to legal claims under Panguard&apos;s control and does not
            bind independent third parties.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">3. Reporting Guidelines</h2>
          <p>When you discover a vulnerability, please follow these guidelines:</p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">3.1 How to Report</h3>
          <ul className="list-disc list-inside space-y-1">
            <li>
              Submit vulnerability reports via email to{' '}
              <a
                href="mailto:security@panguard.ai"
                className="text-brand-sage hover:text-brand-sage-light underline"
              >
                security@panguard.ai
              </a>
            </li>
            <li>Encrypt sensitive reports using our PGP key (see Section 6 below)</li>
            <li>
              Include a detailed description of the vulnerability, including steps to reproduce,
              affected systems, and potential impact
            </li>
            <li>
              Provide proof of concept where possible, with minimal impact to production systems
            </li>
          </ul>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            3.2 No Public Disclosure
          </h3>
          <p>
            You must not publicly disclose the vulnerability until Panguard has had a reasonable
            opportunity to investigate and remediate the issue. We request a{' '}
            <strong className="text-text-primary">90-day disclosure window</strong> from the date of
            your initial report. If we require additional time to address the issue, we will
            coordinate with you on an appropriate disclosure timeline.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            3.3 Good Faith Practices
          </h3>
          <ul className="list-disc list-inside space-y-1">
            <li>Do not access, modify, or delete data belonging to other users</li>
            <li>
              Do not perform actions that could degrade the Service for other users (e.g., denial of
              service testing)
            </li>
            <li>
              Do not use automated scanning tools at excessive rates against production systems
            </li>
            <li>
              Do not exploit a vulnerability beyond what is necessary to demonstrate the issue
            </li>
            <li>
              Stop testing and notify us immediately if you encounter any user data during your
              research
            </li>
          </ul>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">4. Out of Scope</h2>
          <p>
            The following vulnerability types and testing methods are out of scope for this program:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              Social engineering attacks (phishing, vishing) against Panguard employees or customers
            </li>
            <li>Physical attacks against Panguard offices or data centers</li>
            <li>Denial of service (DoS/DDoS) attacks against production systems</li>
            <li>Vulnerabilities in third-party software or services not operated by Panguard</li>
            <li>Spam, email spoofing, or SPF/DKIM/DMARC configuration issues</li>
            <li>Clickjacking on pages with no sensitive actions</li>
            <li>Content injection without demonstrable security impact</li>
            <li>Missing HTTP security headers without a demonstrated exploit</li>
            <li>Vulnerabilities requiring physical access to a user&apos;s device</li>
          </ul>
        </section>

        {/* 5 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">5. Contact</h2>
          <div className="p-4 bg-surface-1 border border-border rounded-lg">
            <p className="font-medium text-text-primary">Security Response Team</p>
            <p className="mt-1">
              Email:{' '}
              <a
                href="mailto:security@panguard.ai"
                className="text-brand-sage hover:text-brand-sage-light underline"
              >
                security@panguard.ai
              </a>
            </p>
            <p className="mt-1">
              We aim to acknowledge receipt of your report within 2 business days and provide an
              initial assessment within 5 business days.
            </p>
          </div>
        </section>

        {/* 6 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">6. PGP Key</h2>
          <p>For encrypted communications, please use our PGP public key:</p>
          <div className="mt-3 p-4 bg-surface-1 border border-border rounded-lg font-mono text-xs text-text-tertiary">
            <p>Fingerprint: [PGP key fingerprint will be published here]</p>
            <p className="mt-2">
              The full public key is available at:{' '}
              <span className="text-brand-sage">https://panguard.ai/.well-known/pgp-key.txt</span>
            </p>
          </div>
        </section>

        {/* 7 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">7. Hall of Fame</h2>
          <p>
            We recognize and appreciate the contributions of security researchers who help us keep
            Panguard secure. With your permission, we will acknowledge your contribution on our
            Security Hall of Fame page.
          </p>
          <div className="mt-3 p-4 bg-surface-1 border border-border rounded-lg text-text-tertiary italic">
            The Panguard Security Hall of Fame will be published here once our responsible
            disclosure program is fully operational.
          </div>
        </section>
      </div>
    </article>
  );
}
