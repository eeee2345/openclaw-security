import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Acceptable Use Policy',
};

export default function AcceptableUsePolicyPage() {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">Acceptable Use Policy</h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            This Acceptable Use Policy (&quot;AUP&quot;) governs the use of all products and
            services provided by Panguard AI, Inc. (&quot;Panguard&quot;). This AUP is incorporated
            by reference into our{' '}
            <a
              href="/legal/terms"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Terms of Service
            </a>
            . Violation of this AUP may result in suspension or termination of your account.
          </p>
        </section>

        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">1. Permitted Uses</h2>
          <p>
            Panguard services are designed to help you protect and secure your own systems,
            networks, and digital assets. You may use the Service to:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              Monitor and protect endpoints, servers, and cloud infrastructure that you own or are
              authorized to manage
            </li>
            <li>
              Conduct vulnerability scans on systems and applications for which you have explicit
              authorization
            </li>
            <li>Generate compliance reports for your organization&apos;s security posture</li>
            <li>
              Deploy honeypots within your own network environments with appropriate authorization
            </li>
            <li>Analyze security events and threat intelligence related to your organization</li>
            <li>Integrate Panguard APIs into your authorized security workflows and toolchains</li>
          </ul>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">2. Prohibited Uses</h2>
          <p>
            You may not use the Service for any of the following purposes. This list is not
            exhaustive, and Panguard reserves the right to determine, at its sole discretion,
            whether any use violates this AUP.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.1 No Unauthorized Attacks or Scanning
          </h3>
          <p>
            You shall not use the Service to scan, probe, penetrate, or attack any system, network,
            or application that you do not own or have explicit written authorization to test. This
            includes but is not limited to: unauthorized penetration testing, denial of service
            attacks, port scanning of third-party systems, and exploitation of vulnerabilities in
            systems you do not control.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.2 No Reverse Engineering
          </h3>
          <p>
            You shall not reverse engineer, decompile, disassemble, or otherwise attempt to derive
            the source code, algorithms, or AI models of any Panguard software, service, or
            technology. You shall not attempt to extract, replicate, or reconstruct Panguard&apos;s
            proprietary threat intelligence data, detection models, or training datasets.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.3 No Reselling or Unauthorized Distribution
          </h3>
          <p>
            You shall not resell, sublicense, redistribute, or provide access to the Service to
            third parties without a valid Panguard partner agreement. This includes offering
            Panguard features or functionality as part of your own commercial product or service
            without written authorization.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.4 No Illegal Activity
          </h3>
          <p>
            You shall not use the Service for any purpose that is unlawful or prohibited by
            applicable law. This includes but is not limited to: distributing malware, facilitating
            fraud, engaging in cyberespionage, harassing or threatening individuals, violating
            export control regulations, or processing data in violation of applicable privacy laws.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.5 No Interference with the Service
          </h3>
          <p>
            You shall not attempt to disrupt, degrade, or interfere with the operation of the
            Service or its infrastructure. This includes attempting to bypass rate limits,
            circumvent access controls, or overwhelm Service resources through automated or
            excessive requests.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">3. Resource Limits</h2>
          <p>
            Each subscription plan includes defined resource limits for API calls, scan frequency,
            monitored endpoints, and data storage. These limits are specified in your plan
            documentation and are subject to fair use principles.
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              You shall not exceed the resource limits of your subscription plan without upgrading
              to an appropriate tier
            </li>
            <li>
              Automated scripts or integrations must respect API rate limits as documented in our
              API reference
            </li>
            <li>
              Panguard may throttle or temporarily restrict access if usage patterns indicate
              potential abuse or excessive consumption of shared resources
            </li>
            <li>
              Sustained usage exceeding 200% of plan limits may result in automatic throttling and a
              request to upgrade
            </li>
          </ul>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">4. Enforcement</h2>
          <p>
            4.1 <strong className="text-text-primary">Investigation.</strong> Panguard reserves the
            right to investigate any suspected violation of this AUP. We may review account activity
            and logs to determine whether a violation has occurred.
          </p>
          <p className="mt-2">
            4.2 <strong className="text-text-primary">Notice.</strong> When feasible, Panguard will
            provide notice of a violation and an opportunity to cure before taking enforcement
            action. However, we reserve the right to take immediate action without notice in cases
            of severe violations that pose a threat to other users, our infrastructure, or third
            parties.
          </p>
          <p className="mt-2">
            4.3 <strong className="text-text-primary">Consequences.</strong> Violations of this AUP
            may result in one or more of the following actions, at Panguard&apos;s sole discretion:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>Written warning with a requirement to cease the violation</li>
            <li>Temporary suspension of Service access</li>
            <li>Permanent termination of your account</li>
            <li>
              Referral to law enforcement authorities where violations constitute illegal activity
            </li>
          </ul>
          <p className="mt-3">
            4.4 <strong className="text-text-primary">Reporting.</strong> If you become aware of any
            violation of this AUP by another user, please report it to{' '}
            <a
              href="mailto:abuse@panguard.ai"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              abuse@panguard.ai
            </a>
            .
          </p>
        </section>
      </div>
    </article>
  );
}
