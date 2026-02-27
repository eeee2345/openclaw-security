import type { Metadata } from 'next';
import { LEGAL_LAST_UPDATED } from '@/lib/constants';

export const metadata: Metadata = {
  title: 'Data Processing Agreement',
};

export default function DPAPage() {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">Data Processing Agreement</h1>
        <p className="text-sm text-text-tertiary">Last updated: {LEGAL_LAST_UPDATED}</p>
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        <section>
          <p>
            This Data Processing Agreement (&quot;DPA&quot;) forms part of the agreement between
            Panguard AI, Inc. (&quot;Panguard&quot; or &quot;Processor&quot;) and the entity
            agreeing to these terms (&quot;Customer&quot; or &quot;Controller&quot;) for the
            provision of Panguard&apos;s security services (the &quot;Service&quot;). This DPA
            applies to the extent that Panguard processes Personal Data on behalf of the Customer in
            connection with the Service.
          </p>
        </section>

        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">1. Definitions</h2>
          <ul className="list-disc list-inside space-y-2">
            <li>
              <strong className="text-text-primary">&quot;Personal Data&quot;</strong> means any
              information relating to an identified or identifiable natural person that is processed
              by Panguard on behalf of the Customer in connection with the Service.
            </li>
            <li>
              <strong className="text-text-primary">&quot;Processing&quot;</strong> means any
              operation performed on Personal Data, including collection, recording, organization,
              storage, adaptation, retrieval, consultation, use, disclosure, erasure, or
              destruction.
            </li>
            <li>
              <strong className="text-text-primary">&quot;Sub-processor&quot;</strong> means any
              third party engaged by Panguard to process Personal Data on behalf of the Customer.
            </li>
            <li>
              <strong className="text-text-primary">&quot;Data Subject&quot;</strong> means the
              identified or identifiable natural person to whom the Personal Data relates.
            </li>
            <li>
              <strong className="text-text-primary">
                &quot;Applicable Data Protection Law&quot;
              </strong>{' '}
              means all applicable laws and regulations relating to the processing of Personal Data,
              including the GDPR (EU) 2016/679, Taiwan&apos;s Personal Data Protection Act, and any
              other applicable privacy legislation.
            </li>
          </ul>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">2. Scope and Purpose</h2>
          <p>
            2.1 This DPA applies to all processing of Personal Data by Panguard on behalf of the
            Customer in connection with the provision of the Service, including endpoint security
            monitoring, threat detection, vulnerability scanning, and compliance reporting.
          </p>
          <p className="mt-2">
            2.2 The categories of Personal Data processed may include: employee names, email
            addresses, device identifiers, IP addresses, system usernames, and organizational
            metadata. The categories of Data Subjects include: Customer employees, contractors, and
            authorized users of the Service.
          </p>
          <p className="mt-2">
            2.3 The duration of processing shall be for the term of the agreement between Panguard
            and the Customer, plus any retention period required by applicable law.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            3. Customer Responsibilities
          </h2>
          <p>
            3.1 The Customer, as Controller, is responsible for ensuring that the processing of
            Personal Data through the Service complies with Applicable Data Protection Law,
            including obtaining any necessary consents and providing required notices to Data
            Subjects.
          </p>
          <p className="mt-2">
            3.2 The Customer shall ensure that it has a lawful basis for transferring Personal Data
            to Panguard and for instructing Panguard to process such data on its behalf.
          </p>
          <p className="mt-2">
            3.3 The Customer shall promptly notify Panguard of any changes in applicable data
            protection requirements that may affect Panguard&apos;s obligations under this DPA.
          </p>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">4. Panguard Obligations</h2>
          <p>Panguard shall:</p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              Process Personal Data only on documented instructions from the Customer, unless
              required to do so by applicable law
            </li>
            <li>
              Ensure that persons authorized to process Personal Data are bound by confidentiality
              obligations
            </li>
            <li>
              Implement appropriate technical and organizational measures to ensure a level of
              security appropriate to the risk
            </li>
            <li>
              Assist the Customer in fulfilling its obligations to respond to Data Subject requests
            </li>
            <li>
              Assist the Customer in ensuring compliance with its obligations regarding data
              security, breach notification, and data protection impact assessments
            </li>
            <li>
              At the Customer&apos;s election, delete or return all Personal Data upon termination
              of the Service, unless retention is required by applicable law
            </li>
            <li>
              Make available to the Customer all information necessary to demonstrate compliance
              with this DPA
            </li>
          </ul>
        </section>

        {/* 5 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">5. Sub-processors</h2>
          <p>
            5.1 The Customer hereby provides general authorization for Panguard to engage
            Sub-processors to assist in providing the Service. Panguard maintains a current list of
            Sub-processors, available upon request.
          </p>
          <p className="mt-2">
            5.2 Panguard shall notify the Customer of any intended changes to its list of
            Sub-processors at least 30 days before the engagement of a new Sub-processor, providing
            the Customer an opportunity to object.
          </p>
          <p className="mt-2">
            5.3 Panguard shall enter into a written agreement with each Sub-processor imposing data
            protection obligations no less protective than those set out in this DPA. Panguard
            remains fully liable for the acts and omissions of its Sub-processors.
          </p>
        </section>

        {/* 6 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">6. Data Transfers</h2>
          <p>
            6.1 Panguard shall not transfer Personal Data to a country outside the Customer&apos;s
            jurisdiction unless appropriate safeguards are in place, including Standard Contractual
            Clauses (SCCs), adequacy decisions, or Binding Corporate Rules.
          </p>
          <p className="mt-2">
            6.2 Where Personal Data is transferred from the European Economic Area, the United
            Kingdom, or Switzerland, Panguard shall ensure compliance with the applicable Standard
            Contractual Clauses as adopted by the European Commission.
          </p>
        </section>

        {/* 7 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">7. Security Measures</h2>
          <p>
            Panguard implements and maintains the following technical and organizational security
            measures:
          </p>
          <ul className="list-disc list-inside mt-2 space-y-1">
            <li>
              <strong className="text-text-primary">Encryption at Rest:</strong> All Personal Data
              stored by Panguard is encrypted using AES-256 encryption
            </li>
            <li>
              <strong className="text-text-primary">Encryption in Transit:</strong> All data
              transmitted between Customer endpoints and Panguard infrastructure is encrypted using
              TLS 1.3
            </li>
            <li>
              <strong className="text-text-primary">Access Controls:</strong> Role-based access
              controls with multi-factor authentication for all personnel with access to Personal
              Data
            </li>
            <li>
              <strong className="text-text-primary">Monitoring:</strong> Continuous monitoring and
              logging of all access to systems containing Personal Data
            </li>
            <li>
              <strong className="text-text-primary">Infrastructure Security:</strong> SOC 2 Type II
              certified cloud infrastructure with physical security controls, redundancy, and
              disaster recovery
            </li>
            <li>
              <strong className="text-text-primary">Employee Training:</strong> Regular data
              protection and security awareness training for all personnel
            </li>
          </ul>
        </section>

        {/* 8 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">8. Data Subject Requests</h2>
          <p>
            8.1 Panguard shall promptly notify the Customer if it receives a request from a Data
            Subject to exercise their rights under Applicable Data Protection Law, including rights
            of access, rectification, erasure, restriction, portability, or objection.
          </p>
          <p className="mt-2">
            8.2 Panguard shall not respond to such requests directly unless instructed by the
            Customer or required by applicable law. Panguard shall provide reasonable assistance to
            the Customer in responding to such requests.
          </p>
        </section>

        {/* 9 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">9. Breach Notification</h2>
          <p>
            9.1 Panguard shall notify the Customer without undue delay, and in any event within{' '}
            <strong className="text-text-primary">72 hours</strong>, after becoming aware of a
            Personal Data breach that affects Customer Personal Data.
          </p>
          <p className="mt-2">
            9.2 Such notification shall include: (a) a description of the nature of the breach,
            including the categories and approximate number of Data Subjects and records affected;
            (b) the name and contact details of Panguard&apos;s data protection contact; (c) a
            description of the likely consequences of the breach; and (d) a description of the
            measures taken or proposed to be taken to address the breach and mitigate its effects.
          </p>
          <p className="mt-2">
            9.3 Panguard shall cooperate with the Customer and take all reasonable steps to assist
            in the investigation, mitigation, and remediation of any Personal Data breach.
          </p>
        </section>

        {/* 10 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">10. Audit Rights</h2>
          <p>
            10.1 Panguard shall make available to the Customer, on request, all information
            necessary to demonstrate compliance with this DPA and Applicable Data Protection Law.
          </p>
          <p className="mt-2">
            10.2 The Customer (or a qualified third-party auditor appointed by the Customer) may
            conduct an audit of Panguard&apos;s processing activities, provided that: (a) the
            Customer gives at least 30 days&apos; prior written notice; (b) audits are conducted
            during normal business hours; (c) the auditor is bound by confidentiality obligations;
            and (d) audits are limited to once per year unless required by a supervisory authority
            or following a data breach.
          </p>
          <p className="mt-2">
            10.3 Panguard may satisfy audit requests by providing current SOC 2 Type II reports, ISO
            27001 certification documentation, or equivalent third-party audit reports.
          </p>
        </section>

        {/* 11 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">11. Term and Termination</h2>
          <p>
            11.1 This DPA shall remain in effect for the duration of the agreement under which
            Panguard provides the Service to the Customer.
          </p>
          <p className="mt-2">
            11.2 Upon termination of the Service agreement, Panguard shall, at the Customer&apos;s
            election and within 30 days of receiving written instructions, either return all
            Personal Data to the Customer in a commonly used, machine-readable format, or securely
            delete all Personal Data and certify such deletion in writing.
          </p>
          <p className="mt-2">
            11.3 Panguard may retain Personal Data to the extent required by applicable law,
            provided that such data is processed only for the purposes required by law and is
            subject to the confidentiality and security obligations of this DPA.
          </p>
        </section>

        <section>
          <div className="mt-6 p-4 bg-surface-1 border border-border rounded-lg">
            <p className="font-medium text-text-primary">Panguard AI, Inc.</p>
            <p className="mt-1">Data Protection Team</p>
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
