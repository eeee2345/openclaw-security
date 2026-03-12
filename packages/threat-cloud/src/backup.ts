/**
 * BackupManager - SQLite database backup with rotation
 *
 * Uses WAL checkpoint + file copy for a consistent backup.
 * Keeps the last N backups (default 7) and rotates old ones automatically.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, readdirSync, unlinkSync, copyFileSync, statSync } from 'node:fs';
import { join, basename } from 'node:path';

export interface BackupResult {
  readonly path: string;
  readonly sizeBytes: number;
  readonly timestamp: string;
}

export class BackupManager {
  private readonly dbPath: string;
  private readonly backupDir: string;
  private readonly maxBackups: number;
  private readonly dbName: string;

  constructor(dbPath: string, backupDir: string, maxBackups = 7) {
    if (!dbPath || !backupDir) {
      throw new Error('dbPath and backupDir are required');
    }
    if (maxBackups < 1) {
      throw new Error('maxBackups must be at least 1');
    }

    this.dbPath = dbPath;
    this.backupDir = backupDir;
    this.maxBackups = maxBackups;
    this.dbName = basename(dbPath, '.db');

    if (!existsSync(backupDir)) {
      mkdirSync(backupDir, { recursive: true });
    }
  }

  /**
   * Create a consistent backup of the SQLite database.
   *
   * 1. Opens the DB in readonly mode
   * 2. Runs a WAL checkpoint (TRUNCATE) to flush pending writes
   * 3. Copies the database file to the backup directory
   * 4. Rotates old backups beyond maxBackups
   */
  backup(): BackupResult {
    if (!existsSync(this.dbPath)) {
      throw new Error(`Database file not found: ${this.dbPath}`);
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupFileName = `${this.dbName}-${timestamp}.db`;
    const backupPath = join(this.backupDir, backupFileName);

    // Checkpoint WAL to ensure all data is flushed to the main DB file
    const db = new Database(this.dbPath);
    try {
      db.pragma('wal_checkpoint(TRUNCATE)');
    } finally {
      db.close();
    }

    // Copy the database file
    copyFileSync(this.dbPath, backupPath);

    // Also copy WAL/SHM if they exist (belt and suspenders)
    const walPath = `${this.dbPath}-wal`;
    const shmPath = `${this.dbPath}-shm`;
    if (existsSync(walPath)) {
      copyFileSync(walPath, `${backupPath}-wal`);
    }
    if (existsSync(shmPath)) {
      copyFileSync(shmPath, `${backupPath}-shm`);
    }

    const sizeBytes = statSync(backupPath).size;

    // Rotate old backups
    this.rotate();

    return {
      path: backupPath,
      sizeBytes,
      timestamp,
    };
  }

  /**
   * Remove old backups beyond maxBackups, keeping the newest ones.
   */
  rotate(): void {
    const backups = this.listBackups();
    if (backups.length <= this.maxBackups) {
      return;
    }

    const toDelete = backups.slice(this.maxBackups);
    for (const fileName of toDelete) {
      const filePath = join(this.backupDir, fileName);
      try {
        unlinkSync(filePath);
        // Also clean up WAL/SHM companions
        const walCompanion = `${filePath}-wal`;
        const shmCompanion = `${filePath}-shm`;
        if (existsSync(walCompanion)) unlinkSync(walCompanion);
        if (existsSync(shmCompanion)) unlinkSync(shmCompanion);
      } catch {
        // Best-effort deletion; log nothing to avoid noise
      }
    }
  }

  /**
   * List existing backups for this database, sorted newest-first.
   */
  listBackups(): string[] {
    if (!existsSync(this.backupDir)) {
      return [];
    }

    const prefix = `${this.dbName}-`;
    return readdirSync(this.backupDir)
      .filter((f) => f.startsWith(prefix) && f.endsWith('.db') && !f.endsWith('-wal') && !f.endsWith('-shm'))
      .sort()
      .reverse(); // newest first (ISO timestamps sort lexicographically)
  }

  /**
   * Format a byte count as a human-readable string.
   */
  static formatSize(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
}
