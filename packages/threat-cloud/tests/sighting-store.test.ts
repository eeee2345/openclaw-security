import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ThreatCloudDB } from '../src/database.js';
import { IoCStore } from '../src/ioc-store.js';
import { SightingStore } from '../src/sighting-store.js';
import { join } from 'node:path';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';

describe('SightingStore', () => {
  let dbWrapper: ThreatCloudDB;
  let iocStore: IoCStore;
  let sightingStore: SightingStore;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sighting-test-'));
    dbWrapper = new ThreatCloudDB(join(tempDir, 'test.db'));
    const db = dbWrapper.getDB();
    iocStore = new IoCStore(db);
    sightingStore = new SightingStore(db);
  });

  afterEach(() => {
    dbWrapper.close();
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      /* ignore */
    }
  });

  function createTestIoC(value = '10.0.0.1') {
    return iocStore.upsertIoC({
      type: 'ip',
      value,
      threatType: 'malicious',
      source: 'test',
      confidence: 50,
    });
  }

  // -------------------------------------------------------------------------
  // Create sightings
  // -------------------------------------------------------------------------

  it('should create a positive sighting', () => {
    const ioc = createTestIoC();
    const sighting = sightingStore.createSighting({
      iocId: ioc.id,
      type: 'positive',
      source: 'analyst',
      confidence: 80,
      details: 'Confirmed via VirusTotal',
    });

    expect(sighting.id).toBeGreaterThan(0);
    expect(sighting.iocId).toBe(ioc.id);
    expect(sighting.type).toBe('positive');
    expect(sighting.source).toBe('analyst');
    expect(sighting.confidence).toBe(80);
  });

  it('should boost IoC confidence on positive sighting', () => {
    const ioc = createTestIoC();
    const originalConf = ioc.confidence;

    sightingStore.createSighting({
      iocId: ioc.id,
      type: 'positive',
      source: 'analyst',
    });

    const updated = iocStore.getIoCById(ioc.id)!;
    expect(updated.confidence).toBeGreaterThan(originalConf);
    expect(updated.sightings).toBe(2); // original + sighting
  });

  it('should reduce IoC confidence on negative sighting', () => {
    const ioc = createTestIoC();
    // First boost to have room to reduce
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'a' });
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'b' });
    const boosted = iocStore.getIoCById(ioc.id)!;

    sightingStore.createSighting({
      iocId: ioc.id,
      type: 'negative',
      source: 'analyst',
    });

    const reduced = iocStore.getIoCById(ioc.id)!;
    expect(reduced.confidence).toBeLessThan(boosted.confidence);
  });

  it('should mark IoC as under_review on false_positive sighting', () => {
    const ioc = createTestIoC();

    sightingStore.createSighting({
      iocId: ioc.id,
      type: 'false_positive',
      source: 'soc-team',
      details: 'Verified as benign CDN IP',
    });

    const updated = iocStore.getIoCById(ioc.id)!;
    expect(updated.status).toBe('under_review');
  });

  // -------------------------------------------------------------------------
  // Agent match (learning)
  // -------------------------------------------------------------------------

  it('should record agent match sighting', () => {
    const ioc = createTestIoC();
    const sighting = sightingStore.recordAgentMatch(ioc.id, 'guard', 'key-hash-123');

    expect(sighting.source).toBe('agent:guard');
    expect(sighting.type).toBe('positive');
    expect(sighting.actorHash).toBe('key-hash-123');
  });

  it('should record trap agent match with higher confidence', () => {
    const ioc = createTestIoC();
    const sighting = sightingStore.recordAgentMatch(ioc.id, 'trap');

    expect(sighting.source).toBe('agent:trap');
    expect(sighting.confidence).toBe(70);
  });

  // -------------------------------------------------------------------------
  // Cross-source correlation
  // -------------------------------------------------------------------------

  it('should record cross-source match when both guard and trap report same IoC', () => {
    const ioc = createTestIoC();

    // Guard reports
    sightingStore.recordAgentMatch(ioc.id, 'guard');
    // No cross-source yet (only 1 source)
    const noMatch = sightingStore.recordCrossSourceMatch(ioc.id);
    expect(noMatch).toBeNull();

    // Trap also reports
    sightingStore.recordAgentMatch(ioc.id, 'trap');
    // Now we have cross-source!
    const match = sightingStore.recordCrossSourceMatch(ioc.id);
    expect(match).not.toBeNull();
    expect(match!.source).toBe('cross-source-correlation');
    expect(match!.confidence).toBe(85);
  });

  it('should not duplicate cross-source sighting within 24h', () => {
    const ioc = createTestIoC();
    sightingStore.recordAgentMatch(ioc.id, 'guard');
    sightingStore.recordAgentMatch(ioc.id, 'trap');
    sightingStore.recordCrossSourceMatch(ioc.id);

    const duplicate = sightingStore.recordCrossSourceMatch(ioc.id);
    expect(duplicate).toBeNull();
  });

  // -------------------------------------------------------------------------
  // Query sightings
  // -------------------------------------------------------------------------

  it('should get sightings for an IoC with pagination', () => {
    const ioc = createTestIoC();
    for (let i = 0; i < 5; i++) {
      sightingStore.createSighting({
        iocId: ioc.id,
        type: 'positive',
        source: `source-${i}`,
      });
    }

    const result = sightingStore.getSightingsForIoC(ioc.id, { page: 1, limit: 3 });
    expect(result.items.length).toBe(3);
    expect(result.total).toBe(5);
    expect(result.hasMore).toBe(true);
  });

  it('should get sighting summary', () => {
    const ioc = createTestIoC();
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'a' });
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'b' });
    sightingStore.createSighting({ iocId: ioc.id, type: 'negative', source: 'c' });

    const summary = sightingStore.getSightingSummary(ioc.id);
    expect(summary.total).toBe(3);
    expect(summary.positive).toBe(2);
    expect(summary.negative).toBe(1);
    expect(summary.falsePositive).toBe(0);
    expect(summary.uniqueSources).toBe(3);
  });

  it('should count recent sightings', () => {
    const ioc = createTestIoC();
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'a' });
    sightingStore.createSighting({ iocId: ioc.id, type: 'positive', source: 'b' });

    const count = sightingStore.getRecentSightingCount(ioc.id, 24);
    expect(count).toBe(2);
  });

  // -------------------------------------------------------------------------
  // Confidence bounds
  // -------------------------------------------------------------------------

  it('should not exceed confidence bounds (0-100)', () => {
    const ioc = createTestIoC();

    // Lots of negative sightings
    for (let i = 0; i < 20; i++) {
      sightingStore.createSighting({ iocId: ioc.id, type: 'negative', source: `neg-${i}` });
    }

    const updated = iocStore.getIoCById(ioc.id)!;
    expect(updated.confidence).toBeGreaterThanOrEqual(0);
    expect(updated.confidence).toBeLessThanOrEqual(100);
  });
});
