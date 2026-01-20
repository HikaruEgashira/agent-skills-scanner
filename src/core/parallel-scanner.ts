/**
 * Parallel Scanner
 * Enables concurrent scanning of multiple skills
 */

export interface ScanTask<T> {
  id: string;
  input: T;
  priority?: number;
}

export interface ScanResult<T, R> {
  task: ScanTask<T>;
  result: R | null;
  error: Error | null;
  duration: number;
  cached: boolean;
}

export class ParallelScanner<T, R> {
  private concurrency: number;
  private timeout: number;
  private activeTasks: number = 0;
  private queue: ScanTask<T>[] = [];

  constructor(options?: {
    concurrency?: number;  // Default: 10
    timeout?: number;      // Default: 30 seconds per task
  }) {
    this.concurrency = options?.concurrency || 10;
    this.timeout = options?.timeout || 30000;
  }

  /**
   * Scan multiple tasks in parallel
   */
  async scanBatch(
    tasks: ScanTask<T>[],
    scanFn: (input: T) => Promise<R>,
    options?: {
      onProgress?: (completed: number, total: number) => void;
      onError?: (task: ScanTask<T>, error: Error) => void;
    }
  ): Promise<ScanResult<T, R>[]> {
    const results: ScanResult<T, R>[] = [];
    const total = tasks.length;
    let completed = 0;

    // Sort by priority (higher first)
    const sortedTasks = [...tasks].sort((a, b) =>
      (b.priority || 0) - (a.priority || 0)
    );

    // Process tasks in batches
    const batches: ScanTask<T>[][] = [];
    for (let i = 0; i < sortedTasks.length; i += this.concurrency) {
      batches.push(sortedTasks.slice(i, i + this.concurrency));
    }

    for (const batch of batches) {
      const batchResults = await Promise.all(
        batch.map(async (task) => {
          const startTime = Date.now();
          let result: R | null = null;
          let error: Error | null = null;

          try {
            result = await this.executeWithTimeout(
              () => scanFn(task.input),
              this.timeout
            );
          } catch (err) {
            error = err instanceof Error ? err : new Error(String(err));
            if (options?.onError) {
              options.onError(task, error);
            }
          }

          completed++;
          if (options?.onProgress) {
            options.onProgress(completed, total);
          }

          return {
            task,
            result,
            error,
            duration: Date.now() - startTime,
            cached: false,
          };
        })
      );

      results.push(...batchResults);
    }

    return results;
  }

  /**
   * Execute function with timeout
   */
  private async executeWithTimeout<R>(
    fn: () => Promise<R>,
    timeoutMs: number
  ): Promise<R> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Task timeout after ${timeoutMs}ms`));
      }, timeoutMs);

      fn()
        .then((result) => {
          clearTimeout(timer);
          resolve(result);
        })
        .catch((error) => {
          clearTimeout(timer);
          reject(error);
        });
    });
  }

  /**
   * Get statistics
   */
  getStatistics(results: ScanResult<T, R>[]): {
    total: number;
    successful: number;
    failed: number;
    cached: number;
    avgDuration: number;
    maxDuration: number;
    minDuration: number;
  } {
    const successful = results.filter(r => r.error === null).length;
    const failed = results.filter(r => r.error !== null).length;
    const cached = results.filter(r => r.cached).length;
    const durations = results.map(r => r.duration);

    return {
      total: results.length,
      successful,
      failed,
      cached,
      avgDuration: durations.reduce((a, b) => a + b, 0) / durations.length || 0,
      maxDuration: Math.max(...durations, 0),
      minDuration: Math.min(...durations, Infinity) || 0,
    };
  }
}

/**
 * Batch processor with automatic retry
 */
export class BatchProcessor<T, R> {
  private scanner: ParallelScanner<T, R>;
  private maxRetries: number;
  private retryDelay: number;

  constructor(options?: {
    concurrency?: number;
    timeout?: number;
    maxRetries?: number;    // Default: 3
    retryDelay?: number;    // Default: 1000ms
  }) {
    this.scanner = new ParallelScanner<T, R>({
      concurrency: options?.concurrency,
      timeout: options?.timeout,
    });
    this.maxRetries = options?.maxRetries || 3;
    this.retryDelay = options?.retryDelay || 1000;
  }

  /**
   * Process batch with automatic retry on failure
   */
  async process(
    tasks: ScanTask<T>[],
    scanFn: (input: T) => Promise<R>,
    options?: {
      onProgress?: (completed: number, total: number) => void;
      onRetry?: (task: ScanTask<T>, attempt: number) => void;
    }
  ): Promise<ScanResult<T, R>[]> {
    let results = await this.scanner.scanBatch(tasks, scanFn, options);

    // Retry failed tasks
    for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
      const failedTasks = results
        .filter(r => r.error !== null)
        .map(r => r.task);

      if (failedTasks.length === 0) break;

      console.log(`Retrying ${failedTasks.length} failed tasks (attempt ${attempt}/${this.maxRetries})`);

      if (options?.onRetry) {
        failedTasks.forEach(task => options.onRetry!(task, attempt));
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, this.retryDelay * attempt));

      // Retry failed tasks
      const retryResults = await this.scanner.scanBatch(failedTasks, scanFn, options);

      // Update results
      for (const retryResult of retryResults) {
        const index = results.findIndex(r => r.task.id === retryResult.task.id);
        if (index !== -1) {
          results[index] = retryResult;
        }
      }
    }

    return results;
  }
}

/**
 * Progress tracker for long-running scans
 */
export class ProgressTracker {
  private total: number;
  private completed: number = 0;
  private startTime: number;
  private lastUpdate: number;

  constructor(total: number) {
    this.total = total;
    this.startTime = Date.now();
    this.lastUpdate = this.startTime;
  }

  /**
   * Update progress
   */
  update(completed: number): void {
    this.completed = completed;
    this.lastUpdate = Date.now();
  }

  /**
   * Get progress percentage
   */
  getProgress(): number {
    return (this.completed / this.total) * 100;
  }

  /**
   * Get estimated time remaining
   */
  getETA(): number {
    if (this.completed === 0) return 0;

    const elapsed = Date.now() - this.startTime;
    const rate = this.completed / elapsed;
    const remaining = this.total - this.completed;

    return remaining / rate;
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    total: number;
    completed: number;
    progress: number;
    elapsed: number;
    eta: number;
    rate: number;  // items per second
  } {
    const elapsed = Date.now() - this.startTime;
    const rate = (this.completed / elapsed) * 1000;  // per second

    return {
      total: this.total,
      completed: this.completed,
      progress: this.getProgress(),
      elapsed,
      eta: this.getETA(),
      rate,
    };
  }
}
