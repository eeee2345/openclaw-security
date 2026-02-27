/**
 * YARA Scanner - File scanning using YARA rules
 * YARA 掃描器 - 使用 YARA 規則掃描檔案
 *
 * Provides an abstraction over YARA scanning that:
 * - Loads .yar rule files from a directory
 * - Scans individual files or entire directories
 * - Converts results to SecurityEvent format for unified pipeline
 * - Gracefully degrades when YARA native bindings are not available
 *
 * @module @panguard-ai/core/rules/yara-scanner
 */

import { readdir, stat, readFile } from 'node:fs/promises';
import { join, extname, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { createLogger } from '../utils/logger.js';
import type { SecurityEvent } from '../types.js';

const logger = createLogger('yara-scanner');

/** YARA match result / YARA 比對結果 */
export interface YaraMatch {
  rule: string;
  namespace: string;
  tags: string[];
  meta: Record<string, string>;
  strings: Array<{ identifier: string; offset: number; data: string }>;
}

/** YARA scan result for a single file / 單一檔案的 YARA 掃描結果 */
export interface YaraScanResult {
  filePath: string;
  fileSize: number;
  sha256: string;
  matches: YaraMatch[];
  scannedAt: string;
  durationMs: number;
}

/** YARA rule file info / YARA 規則檔資訊 */
interface YaraRuleFile {
  path: string;
  name: string;
  content: string;
  source?: 'custom' | 'community';
}

/**
 * YARA-based file scanner
 * 基於 YARA 的檔案掃描器
 *
 * Supports two modes:
 * 1. Native YARA via @automattic/yara (requires native bindings)
 * 2. Pattern-based fallback using regex matching on file content
 */
export class YaraScanner {
  private ruleFiles: YaraRuleFile[] = [];
  private compiledPatterns: CompiledPattern[] = [];
  private yaraAvailable = false;

  /** Load YARA rules from a directory (non-recursive) / 從目錄載入 YARA 規則（非遞迴） */
  async loadRules(rulesDir: string): Promise<number> {
    const resolvedDir = resolve(rulesDir);
    this.ruleFiles = [];
    this.compiledPatterns = [];

    try {
      const files = await readdir(resolvedDir);
      const yarFiles = files.filter(f => extname(f) === '.yar' || extname(f) === '.yara');

      for (const file of yarFiles) {
        const filePath = join(resolvedDir, file);
        const content = await readFile(filePath, 'utf-8');
        this.ruleFiles.push({ path: filePath, name: file, content });
      }
    } catch (err) {
      logger.warn(`Failed to load YARA rules from ${rulesDir}: ${err instanceof Error ? err.message : String(err)}`);
      return 0;
    }

    // Try to use native YARA bindings
    this.yaraAvailable = await this.checkNativeYara();

    // Always compile fallback patterns
    this.compiledPatterns = this.compilePatterns();

    logger.info(`Loaded ${this.ruleFiles.length} YARA rule files (native YARA: ${this.yaraAvailable ? 'available' : 'fallback mode'})`);
    return this.ruleFiles.length;
  }

  /**
   * Recursively load YARA rules from a directory tree
   * 從目錄樹遞迴載入 YARA 規則
   *
   * @param rulesDir - Root directory to scan / 要掃描的根目錄
   * @param source - Source tag for loaded rules / 載入規則的來源標記
   * @returns Number of rule files loaded / 載入的規則檔數量
   */
  async loadRulesRecursive(rulesDir: string, source?: 'custom' | 'community'): Promise<number> {
    const resolvedDir = resolve(rulesDir);
    const files: YaraRuleFile[] = [];

    const walk = async (dir: string): Promise<void> => {
      let entries: import('node:fs').Dirent<string>[];
      try {
        entries = await readdir(dir, { withFileTypes: true, encoding: 'utf-8' });
      } catch {
        return;
      }
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();
          if (ext !== '.yar' && ext !== '.yara') continue;
          try {
            const content = await readFile(fullPath, 'utf-8');
            files.push({ path: fullPath, name: entry.name, content, source });
          } catch {
            // Skip unreadable files
          }
        }
      }
    };

    try {
      await walk(resolvedDir);
    } catch (err) {
      logger.warn(`Failed to recursively load YARA rules from ${rulesDir}: ${err instanceof Error ? err.message : String(err)}`);
    }

    logger.info(`Recursively loaded ${files.length} YARA rule files from ${rulesDir} (source: ${source ?? 'unset'})`);
    return files.length;
  }

  /**
   * Load rules from both custom and community directories
   * 從自訂和社群目錄載入規則
   *
   * @param customDir - Custom rules directory / 自訂規則目錄
   * @param communityDir - Optional community rules directory / 可選的社群規則目錄
   * @returns Total number of rule files loaded / 載入的規則檔總數
   */
  async loadAllRules(customDir: string, communityDir?: string): Promise<number> {
    this.ruleFiles = [];
    this.compiledPatterns = [];

    // Load custom rules recursively / 遞迴載入自訂規則
    await this.loadFromDirRecursive(customDir, 'custom');

    // Load community rules if directory exists / 如果目錄存在則載入社群規則
    if (communityDir !== undefined) {
      await this.loadFromDirRecursive(communityDir, 'community');
    }

    // Initialize scanning engine / 初始化掃描引擎
    this.yaraAvailable = await this.checkNativeYara();
    this.compiledPatterns = this.compilePatterns();

    logger.info(`Loaded ${this.ruleFiles.length} total YARA rule files (native YARA: ${this.yaraAvailable ? 'available' : 'fallback mode'})`);
    return this.ruleFiles.length;
  }

  /** Recursively collect .yar/.yara files and append to this.ruleFiles */
  private async loadFromDirRecursive(dir: string, source: 'custom' | 'community'): Promise<void> {
    const resolvedDir = resolve(dir);

    const walk = async (currentDir: string): Promise<void> => {
      let entries: import('node:fs').Dirent<string>[];
      try {
        entries = await readdir(currentDir, { withFileTypes: true, encoding: 'utf-8' });
      } catch {
        return;
      }
      for (const entry of entries) {
        const fullPath = join(currentDir, entry.name);
        if (entry.isDirectory()) {
          await walk(fullPath);
        } else if (entry.isFile()) {
          const ext = extname(entry.name).toLowerCase();
          if (ext !== '.yar' && ext !== '.yara') continue;
          try {
            const content = await readFile(fullPath, 'utf-8');
            this.ruleFiles.push({ path: fullPath, name: entry.name, content, source });
          } catch {
            // Skip unreadable files
          }
        }
      }
    };

    try {
      await walk(resolvedDir);
    } catch (err) {
      logger.warn(`Failed to load YARA rules from ${dir}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /** Get number of loaded rule files / 取得已載入的規則檔數量 */
  getRuleCount(): number {
    return this.ruleFiles.length;
  }

  /** Check if native YARA is available / 檢查原生 YARA 是否可用 */
  isNativeAvailable(): boolean {
    return this.yaraAvailable;
  }

  /**
   * Scan a single file / 掃描單一檔案
   */
  async scanFile(filePath: string): Promise<YaraScanResult> {
    const start = Date.now();
    const resolvedPath = resolve(filePath);
    const fileBuffer = await readFile(resolvedPath);
    const fileStats = await stat(resolvedPath);
    const sha256 = createHash('sha256').update(fileBuffer).digest('hex');

    let matches: YaraMatch[];

    if (this.yaraAvailable) {
      matches = await this.scanWithNativeYara(resolvedPath);
    } else {
      matches = this.scanWithPatterns(fileBuffer.toString('utf-8'), resolvedPath);
    }

    return {
      filePath: resolvedPath,
      fileSize: fileStats.size,
      sha256,
      matches,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - start,
    };
  }

  /**
   * Scan a directory recursively / 遞迴掃描目錄
   */
  async scanDirectory(dirPath: string, options: { maxDepth?: number; extensions?: string[] } = {}): Promise<YaraScanResult[]> {
    const { maxDepth = 5, extensions } = options;
    const results: YaraScanResult[] = [];
    const resolvedDir = resolve(dirPath);

    await this.walkDir(resolvedDir, 0, maxDepth, extensions, results);
    return results;
  }

  /**
   * Convert YARA scan result to SecurityEvent / 轉換 YARA 掃描結果為 SecurityEvent
   */
  toSecurityEvent(result: YaraScanResult): SecurityEvent | null {
    if (result.matches.length === 0) return null;

    const topMatch = result.matches[0]!;
    const severity = this.inferSeverity(topMatch);
    const mitreTechnique = topMatch.meta['mitre'] ?? topMatch.meta['mitre_attack'] ?? undefined;

    // Determine source from the rule file that produced the top match / 從產生最高比對的規則檔判斷來源
    const matchedRuleFile = this.ruleFiles.find(rf => rf.name === topMatch.namespace);
    const ruleSource = matchedRuleFile?.source;

    return {
      id: `yara-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      timestamp: new Date(result.scannedAt),
      source: 'file',
      severity,
      category: 'malware_detection',
      description: `YARA match: ${result.matches.map(m => m.rule).join(', ')} in ${result.filePath}`,
      host: '',
      raw: {
        filePath: result.filePath,
        sha256: result.sha256,
        fileSize: result.fileSize,
        yaraRules: result.matches.map(m => m.rule),
        tags: result.matches.flatMap(m => m.tags),
        mitreTechnique,
        ruleSource,
      },
      metadata: {},
    };
  }

  // -- Private methods --

  private async checkNativeYara(): Promise<boolean> {
    try {
      await import('@automattic/yara' as string);
      return true;
    } catch {
      return false;
    }
  }

  private async scanWithNativeYara(filePath: string): Promise<YaraMatch[]> {
    try {
      const yara = await (import('@automattic/yara' as string) as Promise<Record<string, unknown>>);
      const results: YaraMatch[] = [];

      for (const ruleFile of this.ruleFiles) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const yaraModule = yara as any;
        const scanner = new yaraModule.default.Scanner();
        scanner.addRules(ruleFile.content);
        const scanResult = scanner.scanFile(filePath);

        for (const match of scanResult.rules ?? []) {
          results.push({
            rule: match.id ?? match.rule ?? 'unknown',
            namespace: ruleFile.name,
            tags: match.tags ?? [],
            meta: match.meta ?? {},
            strings: (match.strings ?? []).map((s: { identifier: string; offset: number; data: Buffer }) => ({
              identifier: s.identifier,
              offset: s.offset,
              data: s.data.toString('utf-8').slice(0, 100),
            })),
          });
        }
      }
      return results;
    } catch (err) {
      logger.warn(`Native YARA scan failed, falling back to patterns: ${err instanceof Error ? err.message : String(err)}`);
      const content = await readFile(filePath, 'utf-8').catch(() => '');
      return this.scanWithPatterns(content, filePath);
    }
  }

  /**
   * Fallback pattern-based scanning / 退路：基於模式的掃描
   * Extracts string patterns from YARA rules and matches against file content
   */
  private scanWithPatterns(content: string, filePath: string): YaraMatch[] {
    const matches: YaraMatch[] = [];
    const lowerContent = content.toLowerCase();

    for (const pattern of this.compiledPatterns) {
      const matchedStrings: Array<{ identifier: string; offset: number; data: string }> = [];

      for (const str of pattern.strings) {
        const idx = lowerContent.indexOf(str.value.toLowerCase());
        if (idx !== -1) {
          matchedStrings.push({
            identifier: str.identifier,
            offset: idx,
            data: content.slice(idx, idx + Math.min(str.value.length, 50)),
          });
        }
      }

      // Check if enough strings matched based on condition
      const requiredMatches = pattern.conditionAny ? 1 : pattern.strings.length;
      if (matchedStrings.length >= requiredMatches && matchedStrings.length > 0) {
        matches.push({
          rule: pattern.ruleName,
          namespace: pattern.sourceFile,
          tags: pattern.tags,
          meta: pattern.meta,
          strings: matchedStrings,
        });
      }
    }

    return matches;
  }

  /**
   * Parse YARA rule files into compiled patterns for fallback matching
   * 解析 YARA 規則檔為編譯的模式（退路比對用）
   */
  private compilePatterns(): CompiledPattern[] {
    const patterns: CompiledPattern[] = [];

    for (const ruleFile of this.ruleFiles) {
      const ruleBlocks = ruleFile.content.split(/\brule\s+/);

      for (const block of ruleBlocks) {
        if (!block.trim()) continue;

        const nameMatch = block.match(/^(\w+)\s*(?::\s*([\w\s]+))?\s*\{/);
        if (!nameMatch) continue;

        const ruleName = nameMatch[1] ?? 'unknown';
        const tags = (nameMatch[2] ?? '').trim().split(/\s+/).filter(Boolean);

        // Extract meta
        const meta: Record<string, string> = {};
        const metaBlock = block.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|$)/);
        if (metaBlock?.[1]) {
          const metaLines = metaBlock[1].matchAll(/(\w+)\s*=\s*"([^"]*)"/g);
          for (const m of metaLines) {
            if (m[1] && m[2] !== undefined) {
              meta[m[1]] = m[2];
            }
          }
        }

        // Extract strings
        const strings: Array<{ identifier: string; value: string }> = [];
        const stringsBlock = block.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|$)/);
        if (stringsBlock?.[1]) {
          const stringDefs = stringsBlock[1].matchAll(/(\$\w+)\s*=\s*"([^"]*)"/g);
          for (const s of stringDefs) {
            if (s[1] && s[2] !== undefined) {
              strings.push({ identifier: s[1], value: s[2] });
            }
          }
        }

        // Check condition for "any of them" vs "all of them"
        const conditionBlock = block.match(/condition\s*:\s*([\s\S]*?)(?=\}|$)/);
        const condition = conditionBlock?.[1]?.trim() ?? '';
        const conditionAny = condition.includes('any of') || condition.includes('1 of') || condition.includes(' or ');

        if (strings.length > 0) {
          patterns.push({
            ruleName,
            sourceFile: ruleFile.name,
            tags,
            meta,
            strings,
            conditionAny,
          });
        }
      }
    }

    return patterns;
  }

  private inferSeverity(match: YaraMatch): 'low' | 'medium' | 'high' | 'critical' {
    const severity = match.meta['severity']?.toLowerCase();
    if (severity === 'critical') return 'critical';
    if (severity === 'high') return 'high';
    if (severity === 'medium') return 'medium';
    if (severity === 'low') return 'low';

    // Infer from tags
    const tagStr = match.tags.join(' ').toLowerCase();
    if (tagStr.includes('apt') || tagStr.includes('ransomware')) return 'critical';
    if (tagStr.includes('webshell') || tagStr.includes('malware')) return 'high';
    if (tagStr.includes('suspicious')) return 'medium';
    return 'medium';
  }

  private async walkDir(
    dir: string,
    depth: number,
    maxDepth: number,
    extensions: string[] | undefined,
    results: YaraScanResult[],
  ): Promise<void> {
    if (depth > maxDepth) return;

    try {
      const entries = await readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = join(dir, entry.name);
        if (entry.isDirectory()) {
          // Skip common non-target directories
          if (['node_modules', '.git', '.cache', 'dist', '__pycache__'].includes(entry.name)) continue;
          await this.walkDir(fullPath, depth + 1, maxDepth, extensions, results);
        } else if (entry.isFile()) {
          if (extensions && !extensions.includes(extname(entry.name))) continue;
          try {
            const result = await this.scanFile(fullPath);
            if (result.matches.length > 0) {
              results.push(result);
            }
          } catch {
            // Skip unreadable files
          }
        }
      }
    } catch {
      // Skip unreadable directories
    }
  }
}

/** Internal compiled pattern for fallback matching / 退路比對用的內部編譯模式 */
interface CompiledPattern {
  ruleName: string;
  sourceFile: string;
  tags: string[];
  meta: Record<string, string>;
  strings: Array<{ identifier: string; value: string }>;
  conditionAny: boolean;
}
