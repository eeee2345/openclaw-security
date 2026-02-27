import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Security Whitepaper',
};

export default function SecurityWhitepaperPage() {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">Security Whitepaper</h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            This document provides a comprehensive overview of the security architecture, practices,
            and compliance standards that underpin the Panguard AI platform. As a security company,
            we hold ourselves to the highest standards and believe in transparency about how we
            protect our customers and their data.
          </p>
        </section>

        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">1. Architecture Overview</h2>
          <p>
            The Panguard platform is built on a cloud-native, microservices architecture designed
            for resilience, scalability, and defense in depth.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">1.1 Infrastructure</h3>
          <p>
            Panguard operates on SOC 2 Type II certified cloud infrastructure with multi-region
            deployment across Asia-Pacific, North America, and Europe. Our infrastructure is
            provisioned using infrastructure as code (IaC) with automated security scanning at every
            deployment stage. All production systems run on hardened, minimal operating system
            images with automatic patching enabled.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            1.2 Network Architecture
          </h3>
          <p>
            Our network architecture employs a zero-trust model with strict network segmentation.
            All services communicate through encrypted channels, and no service is directly exposed
            to the public internet without passing through our application load balancers and web
            application firewall (WAF). Internal service-to-service communication uses mutual TLS
            (mTLS) for authentication and encryption.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">1.3 Data Isolation</h3>
          <p>
            Customer data is logically isolated at the application layer using tenant-aware access
            controls. Each customer&apos;s data is stored in dedicated, encrypted partitions. Our
            architecture ensures that no customer can access another customer&apos;s data, even in
            the event of an application-level vulnerability.
          </p>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">2. Encryption</h2>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">2.1 Data at Rest</h3>
          <p>
            All customer data stored on our platform is encrypted using AES-256 encryption.
            Encryption keys are managed through a dedicated key management service (KMS) with
            hardware security module (HSM) backing. Encryption keys are rotated automatically every
            90 days. Customers on the Business plan may bring their own encryption keys (BYOK) for
            an additional layer of control.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">2.2 Data in Transit</h3>
          <p>
            All data transmitted between client endpoints and Panguard infrastructure is encrypted
            using TLS 1.3 with forward secrecy. We support only modern cipher suites and have
            disabled all legacy protocols (SSLv3, TLS 1.0, TLS 1.1). Our TLS configuration is
            regularly tested and maintains an A+ rating on SSL Labs.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">
            2.3 Agent Communication
          </h3>
          <p>
            The Panguard Guard endpoint agent communicates with our backend using certificate-pinned
            TLS connections with mutual authentication. Each agent receives a unique cryptographic
            identity during enrollment, preventing impersonation and man-in-the-middle attacks.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">3. Access Control</h2>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">3.1 Authentication</h3>
          <p>
            Panguard supports multiple authentication methods: email and password with enforced
            complexity requirements, SAML 2.0 and OIDC for single sign-on (SSO) integration, and
            hardware security key support (WebAuthn/FIDO2). Multi-factor authentication (MFA) is
            available for all accounts and is enforced for all Panguard employees.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">3.2 Authorization</h3>
          <p>
            Our platform implements role-based access control (RBAC) with predefined roles (Owner,
            Admin, Analyst, Viewer) and the ability to create custom roles on the Business plan. All
            API endpoints enforce authorization checks, and access decisions are logged for audit
            purposes.
          </p>

          <h3 className="text-base font-medium text-text-primary mt-4 mb-2">3.3 Internal Access</h3>
          <p>
            Panguard employee access to production systems follows the principle of least privilege.
            Access requires multi-factor authentication, is granted through just-in-time (JIT)
            provisioning, and is automatically revoked after a defined period. All access to
            customer data is logged and subject to regular review.
          </p>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            4. Monitoring and Logging
          </h2>
          <p>
            Panguard maintains comprehensive monitoring and logging across all platform components:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">Infrastructure Monitoring:</strong> Real-time
              monitoring of all servers, networks, and services with automated alerting for
              anomalies
            </li>
            <li>
              <strong className="text-text-primary">Application Logging:</strong> Structured logging
              of all application events, API requests, and authentication events
            </li>
            <li>
              <strong className="text-text-primary">Audit Logs:</strong> Immutable audit logs for
              all administrative actions, configuration changes, and data access events, retained
              for a minimum of one year
            </li>
            <li>
              <strong className="text-text-primary">Threat Detection:</strong> We use our own
              platform to monitor our own infrastructure, providing continuous threat detection and
              automated response
            </li>
            <li>
              <strong className="text-text-primary">SIEM Integration:</strong> All security-relevant
              logs are aggregated in a centralized SIEM platform with correlation rules and
              automated alerting
            </li>
          </ul>
        </section>

        {/* 5 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">5. Incident Response</h2>
          <p>
            Panguard maintains a documented incident response plan that is tested and updated at
            least annually. Our incident response process follows industry best practices:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-2">
            <li>
              <strong className="text-text-primary">Preparation:</strong> Dedicated security
              operations team with 24/7 on-call rotation, pre-defined runbooks for common incident
              types, and regular tabletop exercises
            </li>
            <li>
              <strong className="text-text-primary">Detection:</strong> Automated detection through
              our monitoring systems, supplemented by our responsible disclosure program and bug
              bounty
            </li>
            <li>
              <strong className="text-text-primary">Containment:</strong> Immediate containment
              measures to limit the scope and impact of incidents, including automated isolation
              capabilities
            </li>
            <li>
              <strong className="text-text-primary">Eradication:</strong> Root cause analysis and
              complete removal of threats from affected systems
            </li>
            <li>
              <strong className="text-text-primary">Recovery:</strong> Restoration of affected
              services with verification of integrity before returning to normal operations
            </li>
            <li>
              <strong className="text-text-primary">Post-Incident:</strong> Blameless post-incident
              reviews with published findings and preventive measures. Customers affected by
              security incidents are notified within 72 hours.
            </li>
          </ul>
        </section>

        {/* 6 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">6. Compliance</h2>
          <p>Panguard maintains the following compliance certifications and adherences:</p>
          <div className="mt-3 grid gap-3">
            <div className="p-3 bg-surface-1 border border-border rounded-lg">
              <p className="font-medium text-text-primary">SOC 2 Type II</p>
              <p className="mt-1 text-text-tertiary">
                Annual audit covering security, availability, and confidentiality trust service
                criteria. Reports available to customers under NDA.
              </p>
            </div>
            <div className="p-3 bg-surface-1 border border-border rounded-lg">
              <p className="font-medium text-text-primary">ISO 27001</p>
              <p className="mt-1 text-text-tertiary">
                Certified information security management system (ISMS) with annual surveillance
                audits and triennial recertification.
              </p>
            </div>
            <div className="p-3 bg-surface-1 border border-border rounded-lg">
              <p className="font-medium text-text-primary">GDPR</p>
              <p className="mt-1 text-text-tertiary">
                Full compliance with the EU General Data Protection Regulation, including data
                processing agreements, data subject rights, and cross-border transfer mechanisms.
              </p>
            </div>
            <div className="p-3 bg-surface-1 border border-border rounded-lg">
              <p className="font-medium text-text-primary">Taiwan Cyber Security Act</p>
              <p className="mt-1 text-text-tertiary">
                Compliance with Taiwan&apos;s Cyber Security Management Act, including security
                monitoring, incident reporting, and infrastructure protection requirements.
              </p>
            </div>
          </div>
        </section>

        {/* 7 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">7. Third-Party Audits</h2>
          <p>
            Panguard engages independent, reputable third-party firms to conduct regular security
            assessments:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">Annual Penetration Testing:</strong>{' '}
              Comprehensive penetration tests covering external network, web application, API, and
              mobile application attack surfaces, conducted by certified penetration testing firms
            </li>
            <li>
              <strong className="text-text-primary">SOC 2 Type II Audit:</strong> Annual audit by an
              independent CPA firm validating our security, availability, and confidentiality
              controls
            </li>
            <li>
              <strong className="text-text-primary">ISO 27001 Certification Audit:</strong> Regular
              certification and surveillance audits by an accredited certification body
            </li>
            <li>
              <strong className="text-text-primary">Code Security Review:</strong> Periodic
              third-party code audits of critical platform components, including our AI threat
              detection models and agent software
            </li>
          </ul>
          <p className="mt-3">
            Audit reports and certifications are available to customers and prospective customers
            under NDA. Please contact{' '}
            <a
              href="mailto:security@panguard.ai"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              security@panguard.ai
            </a>{' '}
            to request access.
          </p>
        </section>

        <section>
          <div className="mt-6 p-4 bg-surface-1 border border-border rounded-lg">
            <p className="font-medium text-text-primary">Panguard AI, Inc.</p>
            <p className="mt-1">Security Team</p>
            <p>
              Email:{' '}
              <a
                href="mailto:security@panguard.ai"
                className="text-brand-sage hover:text-brand-sage-light underline"
              >
                security@panguard.ai
              </a>
            </p>
            <p>Taipei, Taiwan</p>
          </div>
        </section>
      </div>
    </article>
  );
}
