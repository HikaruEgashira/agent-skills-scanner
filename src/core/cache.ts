/**
 * Caching Layer for Scan Results
 * Provides fast lookups for previously scanned skills
 */

import { createHash } from "crypto";

export interface CacheEntry<T> {
  key: string;
  value: T;
  timestamp: number;
  ttl: number;  // Time to live in milliseconds
}

export class ScanCache<T> {
  private cache: Map<string, CacheEntry<T>> = new Map();
  private defaultTTL: number;
  private maxSize: number;

  constructor(options?: {
    defaultTTL?: number;  // Default: 24 hours
    maxSize?: number;     // Default: 10000 entries
  }) {
    this.defaultTTL = options?.defaultTTL || 24 * 60 * 60 * 1000;  // 24 hours
    this.maxSize = options?.maxSize || 10000;
  }

  /**
   * Generate cache key from content
   */
  generateKey(content: string): string {
    const hash = createHash("sha256");
    hash.update(content);
    return hash.digest("hex");
  }

  /**
   * Get value from cache
   */
  get(key: string): T | null {
    const entry = this.cache.get(key);

    if (!entry) {
      return null;
    }

    // Check if expired
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.value;
  }

  /**
   * Set value in cache
   */
  set(key: string, value: T, ttl?: number): void {
    // Evict oldest entries if cache is full
    if (this.cache.size >= this.maxSize) {
      this.evictOldest();
    }

    this.cache.set(key, {
      key,
      value,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL,
    });
  }

  /**
   * Check if key exists and is valid
   */
  has(key: string): boolean {
    return this.get(key) !== null;
  }

  /**
   * Delete entry
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Clear all entries
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache size
   */
  size(): number {
    return this.cache.size;
  }

  /**
   * Get cache hit rate
   */
  getStatistics(): {
    size: number;
    maxSize: number;
    oldestEntry: number | null;
    newestEntry: number | null;
  } {
    let oldestTimestamp: number | null = null;
    let newestTimestamp: number | null = null;

    for (const entry of this.cache.values()) {
      if (oldestTimestamp === null || entry.timestamp < oldestTimestamp) {
        oldestTimestamp = entry.timestamp;
      }
      if (newestTimestamp === null || entry.timestamp > newestTimestamp) {
        newestTimestamp = entry.timestamp;
      }
    }

    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      oldestEntry: oldestTimestamp,
      newestEntry: newestTimestamp,
    };
  }

  /**
   * Evict oldest entries to make room
   */
  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTimestamp = Infinity;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.timestamp < oldestTimestamp) {
        oldestTimestamp = entry.timestamp;
        oldestKey = key;
      }
    }

    if (oldestKey) {
      this.cache.delete(oldestKey);
    }
  }

  /**
   * Cleanup expired entries
   */
  cleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.cache.entries()) {
      if (now - entry.timestamp > entry.ttl) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.cache.delete(key);
    }
  }

  /**
   * Save cache to file
   */
  async saveToFile(filePath: string): Promise<void> {
    const data = {
      entries: Array.from(this.cache.entries()),
      timestamp: Date.now(),
    };

    await Bun.write(filePath, JSON.stringify(data, null, 2));
  }

  /**
   * Load cache from file
   */
  async loadFromFile(filePath: string): Promise<void> {
    try {
      const content = await Bun.file(filePath).text();
      const data = JSON.parse(content);

      this.cache.clear();

      for (const [key, entry] of data.entries) {
        // Only load non-expired entries
        if (Date.now() - entry.timestamp <= entry.ttl) {
          this.cache.set(key, entry);
        }
      }
    } catch (error) {
      // File doesn't exist or invalid, ignore
    }
  }
}

/**
 * Global cache instance
 */
let globalCache: ScanCache<any> | null = null;

export function getGlobalCache<T>(): ScanCache<T> {
  if (!globalCache) {
    globalCache = new ScanCache<T>();
  }
  return globalCache as ScanCache<T>;
}

export function initGlobalCache<T>(options?: {
  defaultTTL?: number;
  maxSize?: number;
}): ScanCache<T> {
  globalCache = new ScanCache<T>(options);
  return globalCache;
}
