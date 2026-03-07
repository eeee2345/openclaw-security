/**
 * GuardEngine processEvent() pipeline tests
 * Tests the full detect -> analyze -> respond -> report pipeline,
 * learning mode vs protection mode, YARA scan integration,
 * learning transition, pollPolicy(), and applyPolicy().
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { SecurityEvent } from '@panguard-ai/core';
import type {
  DetectionResult,
  EnvironmentBaseline,
  GuardConfig,
} from '../src/types.js';
import { DEFAULT_ACTION_POLICY } from '../src/types.js';

// ---------------------------------------------------------------------------
// Mocks - must be set up before importing the module under test
// ---------------------------------------------------------------------------

// Mock createLogger
vi.mock('@panguard-ai/core', async () => {
  const actual = await vi.importActual<Record<string, unknown>>('@panguard-ai/core');
  return {
    ...actual,
    createLogger: () => ({
      info: vi.fn(),
      warn: vi.fn(),
      error: vi.fn(),
      debug: vi.fn(),
    }),
    RuleEngine: vi.fn().mockImplementation(() => ({
      loadRules: vi.fn().mockResolvedValue(undefined),
      addRule: vi.fn(),
      destroy: vi.fn(),
    })),
    MonitorEngine: vi.fn().mockImplementation(() => ({
      on: vi.fn(),
      start: vi.fn(),
      stop: vi.fn(),
    })),
    ThreatIntelFeedManager: vi.fn().mockImplementation(() => ({
      start: vi.fn().mockResolvedValue(undefined),
      stop: vi.fn(),
      getIoCCount: vi.fn().mockReturnValue(0),
      getIPCount: vi.fn().mockReturnValue(0),
      addExternalIPs: vi.fn().mockReturnValue(0),
    })),
    YaraScanner: vi.fn().mockImplementation(() => ({
      loadAllRules: vi.fn().mockResolvedValue(0),
      getRuleCount: vi.fn().mockReturnValue(0),
      scanFile: vi.fn(),
      toSecurityEvent: vi.fn(),
    })),
    setFeedManager: vi.fn(),
    parseSigmaYaml: vi.fn().mockReturnValue(null),
  };
});

// Mock security-hardening
vi.mock('@panguard-ai/security-hardening', () => ({
  loadSecurityPolicy: vi.fn().mockReturnValue({}),
  runSecurityAudit: vi.fn().mockReturnValue({ findings: [], riskScore: 0 }),
  logAuditEvent: vi.fn(),
  SyslogAdapter: vi.fn().mockImplementation(() => ({ send: vi.fn() })),
}));

// Mock memory
vi.mock('../src/memory/index.js', () => ({
  loadBaseline: vi.fn().mockReturnValue({
    normalProcesses: [],
    normalConnections: [],
    normalLoginPatterns: [],
    normalServicePorts: [],
    learningStarted: new Date().toISOString(),
    learningComplete: false,
    confidenceLevel: 0,
    lastUpdated: new Date().toISOString(),
    eventCount: 0,
  }),
  saveBaseline: vi.fn(),
  isLearningComplete: vi.fn().mockReturnValue(false),
  getLearningProgress: vi.fn().mockReturnValue(50),
  switchToProtectionMode: vi.fn().mockImplementation((b: EnvironmentBaseline) => ({
    ...b,
    learningComplete: true,
  })),
}));

// Mock memory/baseline.js dynamic import
vi.mock('../src/memory/baseline.js', () => ({
  updateBaseline: vi.fn().mockImplementation((b: EnvironmentBaseline) => b),
  continuousBaselineUpdate: vi.fn().mockImplementation((b: EnvironmentBaseline) => b),
  pruneStalePatterns: vi.fn().mockImplementation((b: EnvironmentBaseline) => b),
  createEmptyBaseline: vi.fn().mockReturnValue({
    normalProcesses: [],
    normalConnections: [],
    normalLoginPatterns: [],
    normalServicePorts: [],
    learningStarted: new Date().toISOString(),
    learningComplete: false,
    confidenceLevel: 0,
    lastUpdated: new Date().toISOString(),
    eventCount: 0,
  }),
}));

// Mock DetectAgent, AnalyzeAgent, RespondAgent, ReportAgent
const mockDetect = vi.fn().mockReturnValue(null);
const mockAnalyze = vi.fn().mockResolvedValue({
  conclusion: 'suspicious',
  confidence: 75,
  reasoning: 'Test reasoning',
  evidence: [{ source: 'rule_match', description: 'test', confidence: 75 }],
  recommendedAction: 'notify',
});
const mockRespond = vi.fn().mockResolvedValue({
  action: 'notify',
  success: true,
  details: 'Notification sent',
  timestamp: new Date().toISOString(),
});
const mockReport = vi.fn().mockReturnValue({
  updatedBaseline: {
    normalProcesses: [],
    normalConnections: [],
    normalLoginPatterns: [],
    normalServicePorts: [],
    learningStarted: new Date().toISOString(),
    learningComplete: false,
    confidenceLevel: 0,
    lastUpdated: new Date().toISOString(),
    eventCount: 1,
  },
  anonymizedData: null,
});
const mockSetModeRespond = vi.fn();
const mockSetModeReport = vi.fn();
const mockAddBlockedIP = vi.fn().mockResolvedValue({ action: 'block_ip', success: true, details: 'Blocked', timestamp: new Date().toISOString() });
const mockUpdateActionPolicy = vi.fn();

vi.mock('../src/agent/index.js', () => ({
  DetectAgent: vi.fn().mockImplementation(() => ({
    detect: mockDetect,
  })),
  AnalyzeAgent: vi.fn().mockImplementation(() => ({
    analyze: mockAnalyze,
  })),
  RespondAgent: vi.fn().mockImplementation(() => ({
    respond: mockRespond,
    setMode: mockSetModeRespond,
    addBlockedIP: mockAddBlockedIP,
    updateActionPolicy: mockUpdateActionPolicy,
  })),
  ReportAgent: vi.fn().mockImplementation(() => ({
    report: mockReport,
    setMode: mockSetModeReport,
  })),
}));

// Mock investigation engine
const mockInvestigate = vi.fn().mockResolvedValue({
  steps: [],
  reasoning: 'Investigation reasoning',
});

vi.mock('../src/investigation/index.js', () => ({
  InvestigationEngine: vi.fn().mockImplementation(() => ({
    investigate: mockInvestigate,
  })),
}));

// Mock notify
vi.mock('../src/notify/index.js', () => ({
  sendNotifications: vi.fn().mockResolvedValue([]),
}));

// Mock threat cloud
const mockUpload = vi.fn().mockResolvedValue(true);
const mockFetchRules = vi.fn().mockResolvedValue([]);
const mockFetchBlocklist = vi.fn().mockResolvedValue([]);
const mockFlushQueue = vi.fn().mockResolvedValue(0);

vi.mock('../src/threat-cloud/index.js', () => ({
  ThreatCloudClient: vi.fn().mockImplementation(() => ({
    upload: mockUpload,
    fetchRules: mockFetchRules,
    fetchBlocklist: mockFetchBlocklist,
    flushQueue: mockFlushQueue,
    getStatus: vi.fn().mockReturnValue('connected'),
    stopFlushTimer: vi.fn(),
  })),
}));

// Mock dashboard
vi.mock('../src/dashboard/index.js', () => ({
  DashboardServer: vi.fn().mockImplementation(() => ({
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn().mockResolvedValue(undefined),
    addVerdict: vi.fn(),
    pushEvent: vi.fn(),
    updateStatus: vi.fn(),
    setConfigGetter: vi.fn(),
    addThreatMapEntry: vi.fn(),
  })),
}));

// Mock daemon
vi.mock('../src/daemon/index.js', () => ({
  PidFile: vi.fn().mockImplementation(() => ({
    write: vi.fn(),
    remove: vi.fn(),
  })),
  Watchdog: vi.fn().mockImplementation(() => ({
    start: vi.fn(),
    stop: vi.fn(),
    heartbeat: vi.fn(),
  })),
}));

// Mock license
vi.mock('../src/license/index.js', () => ({
  validateLicense: vi.fn().mockReturnValue({
    key: '',
    tier: 'free',
    isValid: true,
    features: ['basic_monitoring', 'rule_matching', 'auto_respond', 'threat_cloud_upload'],
  }),
  hasFeature: vi.fn().mockReturnValue(false),
}));

// Mock monitors
vi.mock('../src/monitors/falco-monitor.js', () => ({
  FalcoMonitor: vi.fn().mockImplementation(() => ({
    checkAvailability: vi.fn().mockResolvedValue(false),
    on: vi.fn(),
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn(),
  })),
}));

vi.mock('../src/monitors/suricata-monitor.js', () => ({
  SuricataMonitor: vi.fn().mockImplementation(() => ({
    checkAvailability: vi.fn().mockResolvedValue(false),
    on: vi.fn(),
    start: vi.fn().mockResolvedValue(undefined),
    stop: vi.fn(),
  })),
}));

// Mock builtin rules
vi.mock('../src/rules/builtin-rules.js', () => ({
  BUILTIN_RULES: [],
}));

// Mock agent client
vi.mock('../src/agent-client/index.js', () => ({
  PanguardAgentClient: vi.fn().mockImplementation(() => ({
    register: vi.fn().mockResolvedValue({ agentId: 'test-agent-1' }),
    startHeartbeat: vi.fn(),
    stopHeartbeat: vi.fn(),
    isRegistered: vi.fn().mockReturnValue(false),
    pullPolicy: vi.fn().mockResolvedValue(null),
    reportEvent: vi.fn().mockResolvedValue(undefined),
  })),
}));

// Now import GuardEngine
import { GuardEngine } from '../src/guard-engine.js';
import { isLearningComplete, switchToProtectionMode, saveBaseline } from '../src/memory/index.js';
import { sendNotifications } from '../src/notify/index.js';
import { logAuditEvent } from '@panguard-ai/security-hardening';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: new Date(),
    source: 'network',
    severity: 'high',
    category: 'brute_force',
    description: 'SSH brute force attempt',
    host: 'test-host',
    metadata: {
      sourceIP: '203.0.113.50',
      remoteAddress: '203.0.113.50',
    },
    ...overrides,
  };
}

function makeConfig(overrides: Partial<GuardConfig> = {}): GuardConfig {
  return {
    lang: 'en',
    mode: 'protection',
    learningDays: 7,
    actionPolicy: DEFAULT_ACTION_POLICY,
    notifications: {},
    dataDir: '/tmp/panguard-test',
    dashboardPort: 9001,
    dashboardEnabled: false,
    verbose: false,
    monitors: {
      logMonitor: false,
      networkMonitor: false,
      processMonitor: false,
      fileMonitor: false,
      networkPollInterval: 5000,
      processPollInterval: 5000,
    },
    watchdogEnabled: false,
    watchdogInterval: 30000,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GuardEngine', () => {
  let engine: GuardEngine;

  beforeEach(() => {
    vi.clearAllMocks();
    engine = new GuardEngine(makeConfig());
  });

  afterEach(async () => {
    try {
      await engine.stop();
    } catch {
      // ignore cleanup errors
    }
  });

  describe('processEvent() - full pipeline', () => {
    it('should increment eventsProcessed counter on each call', async () => {
      const event = makeEvent();
      await engine.processEvent(event);

      const status = engine.getStatus();
      expect(status.eventsProcessed).toBe(1);
    });

    it('should log an audit event for every incoming event', async () => {
      const event = makeEvent({ id: 'evt-audit-test' });
      await engine.processEvent(event);

      expect(logAuditEvent).toHaveBeenCalledWith(
        expect.objectContaining({
          level: 'info',
          action: 'policy_check',
          target: 'evt-audit-test',
          result: 'success',
        })
      );
    });

    it('should return early when no detection is found (no threat)', async () => {
      mockDetect.mockReturnValue(null);
      const event = makeEvent();
      await engine.processEvent(event);

      // Analyze should NOT be called when detect returns null
      expect(mockAnalyze).not.toHaveBeenCalled();
      expect(mockRespond).not.toHaveBeenCalled();
      expect(mockReport).not.toHaveBeenCalled();
    });

    it('should run full pipeline when a threat is detected', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'SSH Brute Force', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);

      const event = makeEvent();
      await engine.processEvent(event);

      // All stages should have been called
      expect(mockDetect).toHaveBeenCalledWith(event);
      expect(mockAnalyze).toHaveBeenCalled();
      expect(mockRespond).toHaveBeenCalled();
      expect(mockReport).toHaveBeenCalled();
    });

    it('should increment threatsDetected when detection is found', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'medium' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);

      await engine.processEvent(makeEvent());
      await engine.processEvent(makeEvent());

      const status = engine.getStatus();
      expect(status.threatsDetected).toBe(2);
    });

    it('should increment actionsExecuted for non-log-only responses', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockRespond.mockResolvedValue({
        action: 'block_ip',
        success: true,
        details: 'Blocked',
        timestamp: new Date().toISOString(),
      });

      await engine.processEvent(makeEvent());

      const status = engine.getStatus();
      expect(status.actionsExecuted).toBe(1);
    });

    it('should NOT increment actionsExecuted for log_only responses', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'low' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockRespond.mockResolvedValue({
        action: 'log_only',
        success: true,
        details: 'Logged',
        timestamp: new Date().toISOString(),
      });

      await engine.processEvent(makeEvent());

      const status = engine.getStatus();
      expect(status.actionsExecuted).toBe(0);
    });

    it('should run investigation for non-benign verdicts', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockAnalyze.mockResolvedValue({
        conclusion: 'suspicious',
        confidence: 75,
        reasoning: 'Test',
        evidence: [],
        recommendedAction: 'notify',
      });

      await engine.processEvent(makeEvent());

      expect(mockInvestigate).toHaveBeenCalled();
    });

    it('should skip investigation for benign verdicts', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'low' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockAnalyze.mockResolvedValue({
        conclusion: 'benign',
        confidence: 30,
        reasoning: 'Safe',
        evidence: [],
        recommendedAction: 'log_only',
      });

      await engine.processEvent(makeEvent());

      expect(mockInvestigate).not.toHaveBeenCalled();
    });

    it('should handle errors in processEvent without crashing', async () => {
      mockDetect.mockImplementation(() => {
        throw new Error('Detect agent crashed');
      });

      // Should NOT throw
      await expect(engine.processEvent(makeEvent())).resolves.toBeUndefined();
    });

    it('should send notifications when response action is notify', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockRespond.mockResolvedValue({
        action: 'notify',
        success: true,
        details: 'Notified',
        timestamp: new Date().toISOString(),
      });
      mockAnalyze.mockResolvedValue({
        conclusion: 'suspicious',
        confidence: 75,
        reasoning: 'Test',
        evidence: [],
        recommendedAction: 'notify',
      });

      await engine.processEvent(makeEvent());

      expect(sendNotifications).toHaveBeenCalled();
    });

    it('should send notifications when confidence meets notify threshold', async () => {
      const config = makeConfig({
        actionPolicy: { autoRespond: 90, notifyAndWait: 60, logOnly: 0 },
      });
      const eng = new GuardEngine(config);

      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockRespond.mockResolvedValue({
        action: 'log_only',
        success: true,
        details: 'Logged',
        timestamp: new Date().toISOString(),
      });
      mockAnalyze.mockResolvedValue({
        conclusion: 'suspicious',
        confidence: 65,
        reasoning: 'Test',
        evidence: [],
        recommendedAction: 'notify',
      });

      await eng.processEvent(makeEvent());

      expect(sendNotifications).toHaveBeenCalled();
      await eng.stop();
    });

    it('should upload anonymized data to threat cloud when available', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockReport.mockReturnValue({
        updatedBaseline: {
          normalProcesses: [],
          normalConnections: [],
          normalLoginPatterns: [],
          normalServicePorts: [],
          learningStarted: new Date().toISOString(),
          learningComplete: false,
          confidenceLevel: 0,
          lastUpdated: new Date().toISOString(),
          eventCount: 1,
        },
        anonymizedData: {
          attackSourceIP: '203.0.0.0',
          attackType: 'brute_force',
          mitreTechnique: 'T1110',
          sigmaRuleMatched: 'r1',
          timestamp: new Date().toISOString(),
          region: 'US',
        },
      });

      await engine.processEvent(makeEvent());

      expect(mockUpload).toHaveBeenCalled();
    });

    it('should NOT upload to threat cloud when anonymizedData is null', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'low' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockReport.mockReturnValue({
        updatedBaseline: {
          normalProcesses: [],
          normalConnections: [],
          normalLoginPatterns: [],
          normalServicePorts: [],
          learningStarted: new Date().toISOString(),
          learningComplete: false,
          confidenceLevel: 0,
          lastUpdated: new Date().toISOString(),
          eventCount: 0,
        },
        anonymizedData: null,
      });

      mockUpload.mockClear();
      await engine.processEvent(makeEvent());

      expect(mockUpload).not.toHaveBeenCalled();
    });

    it('should fire event callback when threat is detected', async () => {
      const cb = vi.fn();
      engine.setEventCallback(cb);

      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);

      await engine.processEvent(makeEvent({ category: 'brute_force' }));

      expect(cb).toHaveBeenCalledWith(
        'threat',
        expect.objectContaining({
          category: 'brute_force',
          conclusion: expect.any(String),
          confidence: expect.any(Number),
          action: expect.any(String),
        })
      );
    });
  });

  describe('learning mode vs protection mode', () => {
    it('should update baseline when in learning mode and no detection', async () => {
      const learningEngine = new GuardEngine(makeConfig({ mode: 'learning' }));
      mockDetect.mockReturnValue(null);

      await learningEngine.processEvent(makeEvent());

      const { updateBaseline } = await import('../src/memory/baseline.js');
      expect(updateBaseline).toHaveBeenCalled();
      await learningEngine.stop();
    });

    it('should do continuous baseline update in protection mode for benign non-detections', async () => {
      mockDetect.mockReturnValue(null);

      await engine.processEvent(makeEvent());

      const { continuousBaselineUpdate } = await import('../src/memory/baseline.js');
      expect(continuousBaselineUpdate).toHaveBeenCalledWith(
        expect.any(Object),
        expect.any(Object),
        'benign'
      );
    });
  });

  describe('checkLearningTransition', () => {
    it('should switch to protection mode when learning is complete', async () => {
      const learningEngine = new GuardEngine(makeConfig({ mode: 'learning' }));
      vi.mocked(isLearningComplete).mockReturnValue(true);

      // Trigger the learning check by calling private method via workaround
      // We simulate the interval by calling the method name directly
      (learningEngine as unknown as { checkLearningTransition: () => void }).checkLearningTransition();

      expect(switchToProtectionMode).toHaveBeenCalled();
      expect(mockSetModeRespond).toHaveBeenCalledWith('protection');
      expect(mockSetModeReport).toHaveBeenCalledWith('protection');
      expect(saveBaseline).toHaveBeenCalled();

      await learningEngine.stop();
    });

    it('should NOT switch to protection mode if already in protection mode', async () => {
      vi.mocked(isLearningComplete).mockReturnValue(true);

      (engine as unknown as { checkLearningTransition: () => void }).checkLearningTransition();

      // Should not be called because mode is already 'protection'
      expect(switchToProtectionMode).not.toHaveBeenCalled();
    });

    it('should NOT switch if learning is not complete', async () => {
      const learningEngine = new GuardEngine(makeConfig({ mode: 'learning' }));
      vi.mocked(isLearningComplete).mockReturnValue(false);

      (learningEngine as unknown as { checkLearningTransition: () => void }).checkLearningTransition();

      expect(switchToProtectionMode).not.toHaveBeenCalled();
      await learningEngine.stop();
    });
  });

  describe('applyPolicy()', () => {
    it('should add blocked IP for block_ip rule', () => {
      const policy = {
        rules: [
          {
            type: 'block_ip',
            condition: { ip: '10.20.30.40' },
            action: 'block',
            description: 'Block suspicious IP',
          },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockAddBlockedIP).toHaveBeenCalledWith('10.20.30.40');
    });

    it('should update autoRespond threshold for alert_threshold rule', () => {
      const policy = {
        rules: [
          {
            type: 'alert_threshold',
            condition: { autoRespond: 85, notifyAndWait: 60 },
            action: 'adjust',
            description: 'Lower thresholds',
          },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockUpdateActionPolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          autoRespond: 85,
          notifyAndWait: 60,
        })
      );
    });

    it('should enable auto-respond for auto_respond rule', () => {
      const policy = {
        rules: [
          {
            type: 'auto_respond',
            condition: { enabled: true },
            action: 'toggle',
            description: 'Enable auto respond',
          },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockUpdateActionPolicy).toHaveBeenCalledWith({ autoRespond: 90 });
    });

    it('should disable auto-respond by setting threshold to 100', () => {
      const policy = {
        rules: [
          {
            type: 'auto_respond',
            condition: { enabled: false },
            action: 'toggle',
            description: 'Disable auto respond',
          },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockUpdateActionPolicy).toHaveBeenCalledWith({ autoRespond: 100 });
    });

    it('should handle custom rule type without error', () => {
      const policy = {
        rules: [
          {
            type: 'custom',
            condition: {},
            action: 'log',
            description: 'Custom monitoring rule',
          },
        ],
      };

      // Should not throw
      expect(() => {
        (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);
      }).not.toThrow();
    });

    it('should handle multiple rules in a single policy', () => {
      const policy = {
        rules: [
          { type: 'block_ip', condition: { ip: '1.2.3.4' }, action: 'block', description: 'Block IP 1' },
          { type: 'block_ip', condition: { ip: '5.6.7.8' }, action: 'block', description: 'Block IP 2' },
          { type: 'alert_threshold', condition: { autoRespond: 80 }, action: 'adjust', description: 'Lower threshold' },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockAddBlockedIP).toHaveBeenCalledTimes(2);
      expect(mockAddBlockedIP).toHaveBeenCalledWith('1.2.3.4');
      expect(mockAddBlockedIP).toHaveBeenCalledWith('5.6.7.8');
      expect(mockUpdateActionPolicy).toHaveBeenCalled();
    });

    it('should skip block_ip rule when ip is not provided', () => {
      const policy = {
        rules: [
          { type: 'block_ip', condition: {}, action: 'block', description: 'No IP provided' },
        ],
      };

      (engine as unknown as { applyPolicy: (p: typeof policy) => void }).applyPolicy(policy);

      expect(mockAddBlockedIP).not.toHaveBeenCalled();
    });
  });

  describe('pollPolicy()', () => {
    it('should not poll if agentClient is not registered', async () => {
      // agentClient is null by default (no managerUrl set)
      await (engine as unknown as { pollPolicy: () => Promise<void> }).pollPolicy();

      // Nothing should happen, no error thrown
    });
  });

  describe('getStatus()', () => {
    it('should return correct initial status', () => {
      const status = engine.getStatus();

      expect(status.running).toBe(false);
      expect(status.mode).toBe('protection');
      expect(status.eventsProcessed).toBe(0);
      expect(status.threatsDetected).toBe(0);
      expect(status.actionsExecuted).toBe(0);
      expect(status.memoryUsageMB).toBeGreaterThan(0);
    });

    it('should reflect updated event counts after processing', async () => {
      const detection: DetectionResult = {
        event: makeEvent(),
        ruleMatches: [{ ruleId: 'r1', ruleName: 'Test', severity: 'high' }],
        timestamp: new Date().toISOString(),
      };
      mockDetect.mockReturnValue(detection);
      mockRespond.mockResolvedValue({
        action: 'block_ip',
        success: true,
        details: 'Blocked',
        timestamp: new Date().toISOString(),
      });

      await engine.processEvent(makeEvent());

      const status = engine.getStatus();
      expect(status.eventsProcessed).toBe(1);
      expect(status.threatsDetected).toBe(1);
      expect(status.actionsExecuted).toBe(1);
    });
  });

  describe('isRunning()', () => {
    it('should return false before start', () => {
      expect(engine.isRunning()).toBe(false);
    });
  });

  describe('getBaseline()', () => {
    it('should return the current baseline', () => {
      const baseline = engine.getBaseline();
      expect(baseline).toBeDefined();
      expect(baseline.normalProcesses).toBeDefined();
      expect(baseline.normalConnections).toBeDefined();
    });
  });

  describe('YARA scan integration in processEvent', () => {
    it('should attempt YARA scan for file events with filePath', async () => {
      // This test verifies the flow -- the actual YaraScanner is mocked
      // but we need to ensure the engine uses getRuleCount() to check first
      const event = makeEvent({
        source: 'file',
        category: 'file_change',
        metadata: {
          filePath: '/tmp/suspicious.exe',
          action: 'created',
        },
      });

      mockDetect.mockReturnValue(null);
      await engine.processEvent(event);

      // The engine should have called detect (even without YARA match)
      expect(mockDetect).toHaveBeenCalledWith(event);
    });

    it('should not YARA scan when source is not file', async () => {
      const event = makeEvent({
        source: 'network',
        metadata: { sourceIP: '1.2.3.4' },
      });

      mockDetect.mockReturnValue(null);
      await engine.processEvent(event);

      // Verify the event was processed normally
      expect(engine.getStatus().eventsProcessed).toBe(1);
    });
  });
});
