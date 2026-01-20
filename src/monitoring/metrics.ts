/**
 * Metrics Collector
 * Collects and exports metrics for monitoring (Prometheus-compatible)
 */

export interface Metric {
  name: string;
  type: "counter" | "gauge" | "histogram";
  value: number;
  labels?: Record<string, string>;
  timestamp: number;
}

export class MetricsCollector {
  private metrics: Map<string, Metric> = new Map();

  /**
   * Increment a counter
   */
  incrementCounter(name: string, labels?: Record<string, string>, value: number = 1): void {
    const key = this.getMetricKey(name, labels);
    const existing = this.metrics.get(key);

    if (existing) {
      existing.value += value;
      existing.timestamp = Date.now();
    } else {
      this.metrics.set(key, {
        name,
        type: "counter",
        value,
        labels,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Set a gauge value
   */
  setGauge(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getMetricKey(name, labels);
    this.metrics.set(key, {
      name,
      type: "gauge",
      value,
      labels,
      timestamp: Date.now(),
    });
  }

  /**
   * Record histogram observation
   */
  observeHistogram(name: string, value: number, labels?: Record<string, string>): void {
    const key = this.getMetricKey(name, labels);
    const existing = this.metrics.get(key);

    if (existing && existing.type === "histogram") {
      // Simplified: just update to latest value
      // In real implementation, would maintain buckets
      existing.value = value;
      existing.timestamp = Date.now();
    } else {
      this.metrics.set(key, {
        name,
        type: "histogram",
        value,
        labels,
        timestamp: Date.now(),
      });
    }
  }

  /**
   * Get all metrics
   */
  getAllMetrics(): Metric[] {
    return Array.from(this.metrics.values());
  }

  /**
   * Export metrics in Prometheus format
   */
  exportPrometheus(): string {
    let output = "";
    const metricsByName = new Map<string, Metric[]>();

    // Group metrics by name
    for (const metric of this.metrics.values()) {
      const existing = metricsByName.get(metric.name) || [];
      existing.push(metric);
      metricsByName.set(metric.name, existing);
    }

    // Format each metric group
    for (const [name, metrics] of metricsByName) {
      const firstMetric = metrics[0];
      output += `# TYPE ${name} ${firstMetric.type}\n`;

      for (const metric of metrics) {
        const labels = this.formatLabels(metric.labels);
        output += `${name}${labels} ${metric.value}\n`;
      }
      output += "\n";
    }

    return output;
  }

  /**
   * Export metrics as JSON
   */
  exportJSON(): string {
    return JSON.stringify(this.getAllMetrics(), null, 2);
  }

  /**
   * Reset all metrics
   */
  reset(): void {
    this.metrics.clear();
  }

  /**
   * Get metric key
   */
  private getMetricKey(name: string, labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) {
      return name;
    }

    const sortedLabels = Object.keys(labels)
      .sort()
      .map(k => `${k}="${labels[k]}"`)
      .join(",");

    return `${name}{${sortedLabels}}`;
  }

  /**
   * Format labels for Prometheus
   */
  private formatLabels(labels?: Record<string, string>): string {
    if (!labels || Object.keys(labels).length === 0) {
      return "";
    }

    const formatted = Object.keys(labels)
      .sort()
      .map(k => `${k}="${labels[k]}"`)
      .join(",");

    return `{${formatted}}`;
  }
}

/**
 * Common metrics for skill scanning
 */
export class ScanMetrics {
  private collector: MetricsCollector;

  constructor(collector: MetricsCollector) {
    this.collector = collector;
  }

  /**
   * Record scan started
   */
  scanStarted(): void {
    this.collector.incrementCounter("scans_total");
  }

  /**
   * Record scan completed
   */
  scanCompleted(durationMs: number): void {
    this.collector.incrementCounter("scans_completed_total");
    this.collector.observeHistogram("scan_duration_ms", durationMs);
  }

  /**
   * Record scan failed
   */
  scanFailed(reason: string): void {
    this.collector.incrementCounter("scans_failed_total", { reason });
  }

  /**
   * Record finding detected
   */
  findingDetected(severity: string, category: string): void {
    this.collector.incrementCounter("findings_total", { severity, category });
  }

  /**
   * Record files scanned
   */
  filesScanned(count: number, fileType: string): void {
    this.collector.incrementCounter("files_scanned_total", { type: fileType }, count);
  }

  /**
   * Set current active scans
   */
  setActiveScans(count: number): void {
    this.collector.setGauge("active_scans", count);
  }
}

/**
 * Global metrics collector
 */
let globalCollector: MetricsCollector | null = null;
let globalScanMetrics: ScanMetrics | null = null;

export function initGlobalMetrics(): { collector: MetricsCollector; scanMetrics: ScanMetrics } {
  globalCollector = new MetricsCollector();
  globalScanMetrics = new ScanMetrics(globalCollector);
  return { collector: globalCollector, scanMetrics: globalScanMetrics };
}

export function getMetricsCollector(): MetricsCollector {
  if (!globalCollector) {
    initGlobalMetrics();
  }
  return globalCollector!;
}

export function getScanMetrics(): ScanMetrics {
  if (!globalScanMetrics) {
    initGlobalMetrics();
  }
  return globalScanMetrics!;
}
