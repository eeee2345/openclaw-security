import type { Metadata } from "next";

export async function generateMetadata({
  params: { locale },
}: {
  params: { locale: string };
}): Promise<Metadata> {
  return {
    title: locale === "zh" ? "服務條款" : "Terms of Service",
  };
}

export default function TermsOfServicePage({
  params: { locale },
}: {
  params: { locale: string };
}) {
  return (
    <article className="prose-legal">
      <header className="mb-10">
        <h1 className="text-2xl font-bold text-text-primary mb-2">
          Terms of Service
        </h1>
        <p className="text-sm text-text-tertiary">
          Last updated: February 2026
        </p>
        {locale === "zh" && (
          <p className="mt-3 text-sm text-text-muted border border-border rounded-lg px-4 py-3 bg-surface-1">
            本服務條款目前僅提供英文版本。中文翻譯版本正在準備中，如有任何疑問請聯繫
            <a href="mailto:legal@panguard.ai" className="text-brand-sage hover:text-brand-sage-light underline ml-1">
              legal@panguard.ai
            </a>
          </p>
        )}
      </header>

      <div className="space-y-8 text-sm text-text-secondary leading-relaxed">
        {/* 1 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            1. Acceptance of Terms
          </h2>
          <p>
            These Terms of Service (&quot;Terms&quot;) constitute a legally
            binding agreement between you (&quot;Customer,&quot;
            &quot;you,&quot; or &quot;your&quot;) and Panguard AI, Inc.
            (&quot;Panguard,&quot; &quot;we,&quot; &quot;us,&quot; or
            &quot;our&quot;), a company incorporated in Taipei, Taiwan. By
            accessing or using our website, products, or services
            (collectively, the &quot;Service&quot;), you agree to be bound by
            these Terms. If you are entering into these Terms on behalf of an
            organization, you represent that you have the authority to bind that
            organization.
          </p>
        </section>

        {/* 2 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            2. Description of Service
          </h2>
          <p>
            Panguard provides an AI-powered endpoint security platform that
            includes, but is not limited to: automated vulnerability scanning
            (Panguard Scan), continuous endpoint protection (Panguard Guard),
            AI-assisted security analysis (Panguard Chat), intelligent
            honeypot deployment (Panguard Trap), and automated compliance
            reporting (Panguard Report). The specific features available to you
            depend on your subscription plan.
          </p>
        </section>

        {/* 3 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            3. Account Registration
          </h2>
          <p>
            To access the Service, you must create an account by providing
            accurate, complete, and current information. You are responsible for
            maintaining the confidentiality of your account credentials and for
            all activity that occurs under your account. You must notify
            Panguard immediately of any unauthorized use of your account. We
            reserve the right to suspend or terminate accounts that contain
            inaccurate information or that violate these Terms.
          </p>
        </section>

        {/* 4 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            4. Subscription and Payment
          </h2>
          <p>
            4.1 <strong className="text-text-primary">Plans.</strong> Panguard
            offers subscription plans as described on our pricing page. Plan
            features, limits, and pricing are subject to change with 30 days
            prior written notice.
          </p>
          <p className="mt-2">
            4.2 <strong className="text-text-primary">Billing.</strong>{" "}
            Subscriptions are billed in advance on a monthly or annual basis,
            depending on the plan selected. All fees are quoted in US Dollars
            and are non-refundable except as expressly set forth herein.
          </p>
          <p className="mt-2">
            4.3 <strong className="text-text-primary">Taxes.</strong> All fees
            are exclusive of applicable taxes. You are responsible for paying
            any taxes, duties, or levies imposed by taxing authorities, except
            for taxes based on Panguard&apos;s net income.
          </p>
          <p className="mt-2">
            4.4 <strong className="text-text-primary">Late Payment.</strong> If
            payment is not received within 15 days of the due date, Panguard
            reserves the right to suspend access to the Service until all
            outstanding amounts are paid.
          </p>
        </section>

        {/* 5 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            5. Free Trial
          </h2>
          <p>
            Panguard offers a 30-day free trial of the Service. During the
            trial period, you will have access to the features of the selected
            plan at no cost. At the end of the trial period, your account will
            be automatically downgraded to the free tier unless you subscribe
            to a paid plan. No credit card is required to initiate a free trial.
            Panguard reserves the right to modify or discontinue the free trial
            offer at any time.
          </p>
        </section>

        {/* 6 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            6. Acceptable Use
          </h2>
          <p>
            Your use of the Service is subject to our{" "}
            <a
              href="/legal/acceptable-use"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Acceptable Use Policy
            </a>
            , which is incorporated into these Terms by reference. You agree
            not to use the Service in any manner that is unlawful, harmful,
            fraudulent, or in violation of any applicable regulations.
          </p>
        </section>

        {/* 7 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            7. Intellectual Property
          </h2>
          <p>
            7.1 <strong className="text-text-primary">Panguard IP.</strong> The
            Service, including all software, algorithms, AI models, user
            interfaces, designs, documentation, and trademarks, is owned by
            Panguard and is protected by intellectual property laws. These Terms
            do not grant you any right, title, or interest in the Service
            except for the limited right to use it in accordance with these
            Terms.
          </p>
          <p className="mt-2">
            7.2 <strong className="text-text-primary">Customer Data.</strong>{" "}
            You retain all rights to the data you submit to the Service
            (&quot;Customer Data&quot;). You grant Panguard a limited,
            non-exclusive license to process Customer Data solely for the
            purpose of providing the Service.
          </p>
          <p className="mt-2">
            7.3 <strong className="text-text-primary">Feedback.</strong> If you
            provide suggestions, ideas, or feedback about the Service, you
            grant Panguard a perpetual, irrevocable, royalty-free license to
            use and incorporate such feedback into our products.
          </p>
        </section>

        {/* 8 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            8. Data Rights
          </h2>
          <p>
            Panguard processes Customer Data in accordance with our{" "}
            <a
              href="/legal/privacy"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Privacy Policy
            </a>{" "}
            and, where applicable, our{" "}
            <a
              href="/legal/dpa"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Data Processing Agreement
            </a>
            . You acknowledge that anonymized and aggregated threat intelligence
            data derived from the Service may be used by Panguard to improve
            its products and contribute to collective cybersecurity efforts.
          </p>
        </section>

        {/* 9 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            9. Service Level Agreement
          </h2>
          <p>
            For Pro and Business plan customers, Panguard provides a Service
            Level Agreement (SLA) guaranteeing 99.9% uptime availability. The
            full terms of the SLA, including service credits and exclusions, are
            set forth in our{" "}
            <a
              href="/legal/sla"
              className="text-brand-sage hover:text-brand-sage-light underline"
            >
              Service Level Agreement
            </a>
            .
          </p>
        </section>

        {/* 10 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            10. Limitation of Liability
          </h2>
          <p>
            TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL
            PANGUARD, ITS AFFILIATES, OFFICERS, DIRECTORS, EMPLOYEES, OR AGENTS
            BE LIABLE FOR ANY INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR
            PUNITIVE DAMAGES, INCLUDING WITHOUT LIMITATION LOSS OF PROFITS,
            DATA, USE, GOODWILL, OR OTHER INTANGIBLE LOSSES, ARISING OUT OF OR
            IN CONNECTION WITH YOUR USE OF THE SERVICE.
          </p>
          <p className="mt-2">
            PANGUARD&apos;S TOTAL AGGREGATE LIABILITY FOR ALL CLAIMS ARISING OUT
            OF OR RELATING TO THESE TERMS OR THE SERVICE SHALL NOT EXCEED THE
            GREATER OF (A) THE AMOUNTS YOU PAID TO PANGUARD IN THE TWELVE (12)
            MONTHS PRECEDING THE CLAIM, OR (B) ONE HUNDRED US DOLLARS (US$100).
          </p>
          <p className="mt-2">
            THE SERVICE IS A SECURITY TOOL DESIGNED TO ASSIST WITH THREAT
            DETECTION AND RESPONSE. PANGUARD DOES NOT GUARANTEE THAT THE SERVICE
            WILL DETECT OR PREVENT ALL SECURITY THREATS. YOU ACKNOWLEDGE THAT NO
            SECURITY SOLUTION CAN PROVIDE ABSOLUTE PROTECTION.
          </p>
        </section>

        {/* 11 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            11. Indemnification
          </h2>
          <p>
            You agree to indemnify, defend, and hold harmless Panguard and its
            affiliates, officers, directors, employees, and agents from and
            against any claims, damages, losses, liabilities, costs, and
            expenses (including reasonable attorneys&apos; fees) arising out of
            or relating to: (a) your use of the Service; (b) your violation of
            these Terms; (c) your violation of any third-party rights; or (d)
            any Customer Data you submit to the Service.
          </p>
        </section>

        {/* 12 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            12. Termination
          </h2>
          <p>
            12.1 <strong className="text-text-primary">By You.</strong> You may
            terminate your account at any time by contacting support or through
            your account settings. Termination does not entitle you to a refund
            of any prepaid fees.
          </p>
          <p className="mt-2">
            12.2 <strong className="text-text-primary">By Panguard.</strong> We
            may suspend or terminate your access to the Service immediately if
            you breach these Terms, fail to pay applicable fees, or if we are
            required to do so by law. We may also discontinue the Service with
            90 days prior notice.
          </p>
          <p className="mt-2">
            12.3{" "}
            <strong className="text-text-primary">Effect of Termination.</strong>{" "}
            Upon termination, your right to access the Service ceases
            immediately. Panguard will make your Customer Data available for
            export for 30 days following termination, after which it may be
            deleted.
          </p>
        </section>

        {/* 13 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            13. Governing Law
          </h2>
          <p>
            These Terms shall be governed by and construed in accordance with
            the laws of the Republic of China (Taiwan), without regard to its
            conflict of law provisions. Any legal action or proceeding arising
            under these Terms shall be brought exclusively in the courts
            located in Taipei, Taiwan, and the parties hereby consent to the
            personal jurisdiction and venue of such courts.
          </p>
        </section>

        {/* 14 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            14. Dispute Resolution
          </h2>
          <p>
            14.1{" "}
            <strong className="text-text-primary">Informal Resolution.</strong>{" "}
            Before initiating any formal dispute resolution proceeding, the
            parties agree to first attempt to resolve any dispute informally by
            contacting each other and negotiating in good faith for a period of
            at least 30 days.
          </p>
          <p className="mt-2">
            14.2 <strong className="text-text-primary">Arbitration.</strong> If
            informal resolution fails, any dispute arising out of or relating to
            these Terms shall be finally resolved by binding arbitration
            administered by the Chinese Arbitration Association, Taipei, in
            accordance with its arbitration rules. The arbitration shall be
            conducted in English, and the arbitral award shall be final and
            binding.
          </p>
          <p className="mt-2">
            14.3{" "}
            <strong className="text-text-primary">
              Class Action Waiver.
            </strong>{" "}
            You agree that any dispute resolution proceeding will be conducted
            only on an individual basis and not in a class, consolidated, or
            representative action.
          </p>
        </section>

        {/* 15 */}
        <section>
          <h2 className="text-lg font-semibold text-text-primary mb-3">
            15. Changes to These Terms
          </h2>
          <p>
            Panguard reserves the right to modify these Terms at any time. We
            will notify you of material changes by posting the updated Terms on
            our website and updating the &quot;Last updated&quot; date. For
            material changes that affect your rights, we will provide at least
            30 days prior notice via email or through the Service. Your
            continued use of the Service after the effective date of any changes
            constitutes your acceptance of the revised Terms.
          </p>
        </section>

        <section>
          <div className="mt-6 p-4 bg-surface-1 border border-border rounded-lg">
            <p className="font-medium text-text-primary">
              Panguard AI, Inc.
            </p>
            <p className="mt-1">
              Email:{" "}
              <a
                href="mailto:legal@panguard.ai"
                className="text-brand-sage hover:text-brand-sage-light underline"
              >
                legal@panguard.ai
              </a>
            </p>
            <p>Taipei, Taiwan</p>
          </div>
        </section>
      </div>
    </article>
  );
}
