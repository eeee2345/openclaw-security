import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Cookie Policy',
};

export default function CookiePolicyPage() {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">Cookie Policy</h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            This Cookie Policy explains how Panguard AI, Inc. (&quot;Panguard,&quot; &quot;we,&quot;
            &quot;us,&quot; or &quot;our&quot;) uses cookies and similar tracking technologies when
            you visit our website at panguard.ai and use our services. This policy should be read
            alongside our{' '}
            <a
              href="/legal/privacy"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Privacy Policy
            </a>
            .
          </p>
        </section>

        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">1. What Are Cookies</h2>
          <p>
            Cookies are small text files that are stored on your device (computer, tablet, or
            mobile) when you visit a website. They are widely used to make websites work more
            efficiently, to provide a better user experience, and to provide information to the
            operators of the website. Cookies may be &quot;session&quot; cookies (deleted when you
            close your browser) or &quot;persistent&quot; cookies (remaining on your device for a
            set period or until you delete them).
          </p>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">2. Essential Cookies</h2>
          <p>
            These cookies are strictly necessary for the operation of our website and services. They
            enable core functionality such as authentication, security, and session management.
            Without these cookies, the services you have requested cannot be provided.
          </p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border">
                  <th className="py-2 pr-4 text-text-primary font-medium">Cookie</th>
                  <th className="py-2 pr-4 text-text-primary font-medium">Purpose</th>
                  <th className="py-2 text-text-primary font-medium">Duration</th>
                </tr>
              </thead>
              <tbody className="text-text-secondary">
                <tr className="border-b border-border/50">
                  <td className="py-2 pr-4 font-mono text-xs">pg_session</td>
                  <td className="py-2 pr-4">Maintains your authenticated session</td>
                  <td className="py-2">Session</td>
                </tr>
                <tr className="border-b border-border/50">
                  <td className="py-2 pr-4 font-mono text-xs">pg_csrf</td>
                  <td className="py-2 pr-4">Prevents cross-site request forgery attacks</td>
                  <td className="py-2">Session</td>
                </tr>
                <tr className="border-b border-border/50">
                  <td className="py-2 pr-4 font-mono text-xs">pg_consent</td>
                  <td className="py-2 pr-4">Stores your cookie consent preferences</td>
                  <td className="py-2">1 year</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="mt-3">
            Essential cookies cannot be disabled as they are required for the website to function
            properly. They do not store any personally identifiable information.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">3. Analytics Cookies</h2>
          <p>
            We use analytics cookies to understand how visitors interact with our website. These
            cookies help us measure traffic patterns, identify popular content, and improve the user
            experience. All analytics data is collected in aggregate form and cannot be used to
            identify individual users.
          </p>
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border">
                  <th className="py-2 pr-4 text-text-primary font-medium">Cookie</th>
                  <th className="py-2 pr-4 text-text-primary font-medium">Purpose</th>
                  <th className="py-2 text-text-primary font-medium">Duration</th>
                </tr>
              </thead>
              <tbody className="text-text-secondary">
                <tr className="border-b border-border/50">
                  <td className="py-2 pr-4 font-mono text-xs">pg_analytics</td>
                  <td className="py-2 pr-4">Privacy-focused analytics (self-hosted)</td>
                  <td className="py-2">30 days</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p className="mt-3">
            We use a self-hosted, privacy-focused analytics solution. We do not use Google Analytics
            or any third-party analytics provider that tracks users across websites.
          </p>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">4. Marketing Cookies</h2>
          <p>
            <strong className="text-text-primary">
              We do not use marketing or advertising cookies.
            </strong>{' '}
            Panguard does not serve third-party advertisements on our website, nor do we use
            tracking cookies to deliver targeted advertising across other websites. We believe your
            security platform should not be tracking you for marketing purposes.
          </p>
        </section>

        {/* 5 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            5. How to Control Cookies
          </h2>
          <p>You can control and manage cookies in several ways:</p>
          <ul className="list-disc list-inside mt-2 space-y-2">
            <li>
              <strong className="text-text-primary">Browser Settings:</strong> Most web browsers
              allow you to control cookies through their settings. You can set your browser to
              refuse cookies, delete existing cookies, or alert you when a cookie is being set.
              Please refer to your browser&apos;s help documentation for instructions.
            </li>
            <li>
              <strong className="text-text-primary">Cookie Banner:</strong> Where required by
              applicable law, our website displays a cookie consent banner that allows you to accept
              or decline non-essential cookies before they are set.
            </li>
            <li>
              <strong className="text-text-primary">Opt-Out:</strong> You may opt out of analytics
              cookies at any time through your account settings or by contacting us at
              privacy@panguard.ai.
            </li>
          </ul>
          <p className="mt-3">
            Please note that disabling essential cookies may prevent you from using certain features
            of our website and services.
          </p>
        </section>

        {/* 6 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            6. Updates to This Policy
          </h2>
          <p>
            We may update this Cookie Policy from time to time to reflect changes in technology,
            legislation, or our data practices. Any changes will be posted on this page with an
            updated &quot;Last updated&quot; date. We encourage you to review this policy
            periodically.
          </p>
          <p className="mt-3">
            If you have any questions about our use of cookies, please contact us at{' '}
            <a
              href="mailto:privacy@panguard.ai"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              privacy@panguard.ai
            </a>
            .
          </p>
        </section>
      </div>
    </article>
  );
}
