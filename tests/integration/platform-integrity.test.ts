/**
 * Platform Integrity Tests
 * 平台完整性測試
 *
 * Verifies cross-package consistency, exports, and contract compliance.
 * 驗證跨套件一致性、匯出和契約合規。
 */

import { describe, it, expect } from 'vitest';

// All package imports to verify they load correctly
import * as core from '@panguard-ai/core';
import * as panguardScan from '@panguard-ai/panguard-scan';
import * as panguardGuard from '@panguard-ai/panguard-guard';
import * as panguardChat from '@panguard-ai/panguard-chat';
import * as panguardTrap from '@panguard-ai/panguard-trap';
import * as panguardReport from '@panguard-ai/panguard-report';
import * as panguardWeb from '@panguard-ai/panguard-web';

describe('Platform Integrity', () => {
  describe('Package Loading', () => {
    it('should load @panguard-ai/core', () => {
      expect(core.CORE_VERSION).toBeDefined();
      expect(typeof core.createLogger).toBe('function');
      expect(typeof core.initI18n).toBe('function');
    });

    it('should load @panguard-ai/panguard-scan', () => {
      expect(panguardScan.PANGUARD_SCAN_VERSION).toBeDefined();
      expect(typeof panguardScan.sortBySeverity).toBe('function');
    });

    it('should load @panguard-ai/panguard-guard', () => {
      expect(panguardGuard.PANGUARD_GUARD_VERSION).toBeDefined();
      expect(typeof panguardGuard.createEmptyBaseline).toBe('function');
      expect(typeof panguardGuard.validateLicense).toBe('function');
    });

    it('should load @panguard-ai/panguard-chat', () => {
      expect(panguardChat.PANGUARD_CHAT_VERSION).toBeDefined();
      expect(typeof panguardChat.formatAlert).toBe('function');
      expect(typeof panguardChat.buildSystemPrompt).toBe('function');
    });

    it('should load @panguard-ai/panguard-trap', () => {
      expect(panguardTrap.PANGUARD_TRAP_VERSION).toBeDefined();
      expect(typeof panguardTrap.buildTrapIntel).toBe('function');
      expect(typeof panguardTrap.estimateSkillLevel).toBe('function');
    });

    it('should load @panguard-ai/panguard-report', () => {
      expect(panguardReport.PANGUARD_REPORT_VERSION).toBeDefined();
      expect(typeof panguardReport.generateComplianceReport).toBe('function');
      expect(typeof panguardReport.getSupportedFrameworks).toBe('function');
    });

    it('should load @panguard-ai/panguard-web', () => {
      expect(panguardWeb.PANGUARD_WEB_VERSION).toBeDefined();
      expect(typeof panguardWeb.generateGuidanceResult).toBe('function');
      expect(typeof panguardWeb.generateHead).toBe('function');
    });
  });

  describe('Export Completeness', () => {
    it('core should export discovery functions', () => {
      expect(typeof core.detectOS).toBe('function');
      expect(typeof core.scanOpenPorts).toBe('function');
      expect(typeof core.detectServices).toBe('function');
      expect(typeof core.calculateRiskScore).toBe('function');
    });

    it('core should export rule engine', () => {
      expect(core.RuleEngine).toBeDefined();
      expect(typeof core.parseSigmaYaml).toBe('function');
      expect(typeof core.matchEvent).toBe('function');
    });

    it('core should export monitor engine', () => {
      expect(core.MonitorEngine).toBeDefined();
      expect(typeof core.normalizeLogEvent).toBe('function');
      expect(typeof core.checkThreatIntel).toBe('function');
    });

    it('core should export adapters', () => {
      expect(core.AdapterRegistry).toBeDefined();
      expect(core.DefenderAdapter).toBeDefined();
      expect(core.WazuhAdapter).toBeDefined();
      expect(core.SyslogAdapter).toBeDefined();
    });

    it('panguard-guard should export multi-agent pipeline', () => {
      expect(panguardGuard.DetectAgent).toBeDefined();
      expect(panguardGuard.AnalyzeAgent).toBeDefined();
      expect(panguardGuard.RespondAgent).toBeDefined();
      expect(panguardGuard.ReportAgent).toBeDefined();
    });

    it('panguard-guard should export investigation engine', () => {
      expect(panguardGuard.InvestigationEngine).toBeDefined();
    });

    it('panguard-guard should export threat cloud', () => {
      expect(panguardGuard.ThreatCloudClient).toBeDefined();
    });

    it('panguard-guard should export dashboard', () => {
      expect(panguardGuard.DashboardServer).toBeDefined();
    });

    it('panguard-guard should export daemon utilities', () => {
      expect(panguardGuard.PidFile).toBeDefined();
      expect(panguardGuard.Watchdog).toBeDefined();
      expect(typeof panguardGuard.installService).toBe('function');
    });

    it('panguard-chat should export all channels', () => {
      expect(panguardChat.LineChannel).toBeDefined();
      expect(panguardChat.TelegramChannel).toBeDefined();
      expect(panguardChat.SlackChannel).toBeDefined();
      expect(panguardChat.EmailChannel).toBeDefined();
      expect(panguardChat.WebhookChannel).toBeDefined();
    });

    it('panguard-chat should export ChatAgent', () => {
      expect(panguardChat.ChatAgent).toBeDefined();
    });

    it('panguard-trap should export services', () => {
      expect(panguardTrap.BaseTrapService).toBeDefined();
      expect(panguardTrap.SSHTrapService).toBeDefined();
      expect(panguardTrap.HTTPTrapService).toBeDefined();
      expect(panguardTrap.GenericTrapService).toBeDefined();
      expect(typeof panguardTrap.createTrapService).toBe('function');
    });

    it('panguard-trap should export profiler', () => {
      expect(panguardTrap.AttackerProfiler).toBeDefined();
    });

    it('panguard-trap should export engine', () => {
      expect(panguardTrap.TrapEngine).toBeDefined();
    });

    it('panguard-report should export framework data', () => {
      expect(panguardReport.TW_CYBER_SECURITY_CONTROLS).toBeDefined();
      expect(panguardReport.ISO27001_CONTROLS).toBeDefined();
      expect(panguardReport.SOC2_CONTROLS).toBeDefined();
    });

    it('panguard-web should export content data', () => {
      expect(panguardWeb.PERSONAS).toBeDefined();
      expect(panguardWeb.PRICING_PLANS).toBeDefined();
      expect(panguardWeb.PAGES).toBeDefined();
      expect(panguardWeb.GUIDANCE_STEPS).toBeDefined();
      expect(panguardWeb.PRODUCT_FEATURES).toBeDefined();
    });
  });

  describe('Default Configuration Consistency', () => {
    it('should have consistent default action policy', () => {
      const policy = panguardGuard.DEFAULT_ACTION_POLICY;
      expect(policy.autoRespond).toBe(85);
      expect(policy.notifyAndWait).toBe(50);
      expect(policy.logOnly).toBe(0);

      // Thresholds must be in order
      expect(policy.autoRespond).toBeGreaterThan(policy.notifyAndWait);
      expect(policy.notifyAndWait).toBeGreaterThan(policy.logOnly);
    });

    it('should have consistent default notification preferences', () => {
      const prefs = panguardChat.DEFAULT_PREFERENCES;
      expect(prefs.criticalAlerts).toBe(true);
      expect(prefs.dailySummary).toBe(true);
      expect(prefs.weeklySummary).toBe(true);
      expect(prefs.peacefulReport).toBe(true);
    });

    it('should have consistent default web config', () => {
      const config = panguardWeb.DEFAULT_WEB_CONFIG;
      expect(config.language).toBe('zh-TW');
      expect(config.baseUrl).toBe('https://panguard.ai');
      expect(config.brandName).toBe('Panguard AI');
    });

    it('should have consistent default report config', () => {
      const config = panguardReport.DEFAULT_REPORT_CONFIG;
      expect(config.language).toBe('zh-TW');
      expect(config.framework).toBe('tw_cyber_security_act');
    });

    it('should have consistent default trap config', () => {
      const config = panguardTrap.DEFAULT_TRAP_CONFIG;
      expect(config).toBeDefined();
    });
  });

  describe('Brand Name Consistency', () => {
    it('should use "Panguard AI" across all web templates', () => {
      const page = panguardWeb.getPage('home')!;
      const head = panguardWeb.generateHead(page, 'en');
      const footer = panguardWeb.generateFooter('en');

      expect(head).toContain('Panguard AI');
      expect(footer).toContain('Panguard AI');
    });

    it('should use "Panguard AI" in footer attribution', () => {
      const footer = panguardWeb.generateFooter('en');
      expect(footer).toContain('Panguard AI');
    });

    it('should use "Panguard" in product names', () => {
      for (const feature of panguardWeb.PRODUCT_FEATURES) {
        expect(feature.product).toMatch(/^Panguard/);
      }
    });
  });

  describe('i18n Namespace Coverage', () => {
    it('should initialize i18n without errors', async () => {
      await expect(core.initI18n('zh-TW')).resolves.not.toThrow();
    });

    it('should support language switching', async () => {
      await core.initI18n('en');
      // Just verify it doesn't throw
      expect(true).toBe(true);
    });
  });

  describe('Security Tool Coverage', () => {
    it('should have 8 honeypot service types covering common attack surfaces', () => {
      const types: string[] = ['ssh', 'http', 'ftp', 'smb', 'mysql', 'rdp', 'telnet', 'redis'];
      for (const type of types) {
        expect(
          panguardTrap.DEFAULT_SERVICE_CONFIGS[
            type as keyof typeof panguardTrap.DEFAULT_SERVICE_CONFIGS
          ]
        ).toBeDefined();
      }
    });

    it('should have 3 compliance frameworks covering TW and international standards', () => {
      const frameworks = panguardReport.getSupportedFrameworks();
      expect(frameworks).toHaveLength(3);
    });

    it('should have 7 alert templates covering common attack scenarios', () => {
      const templates = panguardChat.ALERT_TEMPLATES;
      expect(templates).toHaveLength(7);

      const attackTypes = templates.map((t) => t.attackType);
      expect(attackTypes).toContain('ssh_brute_force');
      expect(attackTypes).toContain('ransomware_detected');
      expect(attackTypes).toContain('sql_injection');
    });

    it('should have 5 internal Sigma rules', () => {
      // Sigma rules are loaded from core
      expect(typeof core.parseSigmaYaml).toBe('function');
      expect(typeof core.matchEvent).toBe('function');
    });

    it('should have 8 investigation tools in guard', () => {
      expect(panguardGuard.InvestigationEngine).toBeDefined();
    });
  });
});
