/**
 * Structured Logger for Agent Skills Scanner
 * Provides JSON logging with different severity levels
 */

export type LogLevel = "debug" | "info" | "warn" | "error" | "critical";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  event: string;
  message: string;
  metadata?: Record<string, unknown>;
  sessionId?: string;
  userId?: string;
}

export interface ScanEventMetadata {
  skillId?: string;
  skillName?: string;
  findingsCount?: number;
  severity?: string;
  categories?: string[];
  scanDuration?: number;
  fileCount?: number;
  scriptFiles?: number;
}

export class StructuredLogger {
  private minLevel: LogLevel;
  private sessionId?: string;
  private userId?: string;
  private outputStream: WritableStreamDefaultWriter<string> | null = null;

  private levelPriority: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    critical: 4,
  };

  constructor(options?: {
    minLevel?: LogLevel;
    sessionId?: string;
    userId?: string;
    outputFile?: string;
  }) {
    this.minLevel = options?.minLevel || "info";
    this.sessionId = options?.sessionId;
    this.userId = options?.userId;

    if (options?.outputFile) {
      this.initFileOutput(options.outputFile);
    }
  }

  /**
   * Initialize file output
   */
  private async initFileOutput(filePath: string): Promise<void> {
    const file = Bun.file(filePath);
    const writer = file.writer();
    this.outputStream = writer as unknown as WritableStreamDefaultWriter<string>;
  }

  /**
   * Log a message
   */
  private log(level: LogLevel, event: string, message: string, metadata?: Record<string, unknown>): void {
    if (this.levelPriority[level] < this.levelPriority[this.minLevel]) {
      return;
    }

    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      event,
      message,
      metadata,
      sessionId: this.sessionId,
      userId: this.userId,
    };

    const logLine = JSON.stringify(entry);

    // Console output with color
    this.outputToConsole(entry);

    // File output
    if (this.outputStream) {
      this.outputStream.write(logLine + "\n");
    }
  }

  /**
   * Output to console with colors
   */
  private outputToConsole(entry: LogEntry): void {
    const colors = {
      debug: "\x1b[36m",    // Cyan
      info: "\x1b[32m",     // Green
      warn: "\x1b[33m",     // Yellow
      error: "\x1b[31m",    // Red
      critical: "\x1b[35m", // Magenta
    };

    const reset = "\x1b[0m";
    const color = colors[entry.level];

    console.log(`${color}[${entry.level.toUpperCase()}]${reset} ${entry.timestamp} ${entry.event}: ${entry.message}`);
    if (entry.metadata && Object.keys(entry.metadata).length > 0) {
      console.log(`  Metadata: ${JSON.stringify(entry.metadata, null, 2)}`);
    }
  }

  /**
   * Debug level log
   */
  debug(event: string, message: string, metadata?: Record<string, unknown>): void {
    this.log("debug", event, message, metadata);
  }

  /**
   * Info level log
   */
  info(event: string, message: string, metadata?: Record<string, unknown>): void {
    this.log("info", event, message, metadata);
  }

  /**
   * Warning level log
   */
  warn(event: string, message: string, metadata?: Record<string, unknown>): void {
    this.log("warn", event, message, metadata);
  }

  /**
   * Error level log
   */
  error(event: string, message: string, metadata?: Record<string, unknown>): void {
    this.log("error", event, message, metadata);
  }

  /**
   * Critical level log
   */
  critical(event: string, message: string, metadata?: Record<string, unknown>): void {
    this.log("critical", event, message, metadata);
  }

  /**
   * Log skill scan start
   */
  scanStart(skillId: string, skillName: string): void {
    this.info("scan_start", `Starting scan for skill: ${skillName}`, {
      skillId,
      skillName,
    });
  }

  /**
   * Log skill scan complete
   */
  scanComplete(skillId: string, findings: number, duration: number, metadata?: ScanEventMetadata): void {
    const level = findings > 0 ? "warn" : "info";
    this.log(
      level,
      "scan_complete",
      `Scan completed for skill ${skillId}: ${findings} findings in ${duration}ms`,
      {
        skillId,
        findingsCount: findings,
        scanDuration: duration,
        ...metadata,
      }
    );
  }

  /**
   * Log vulnerability found
   */
  vulnerabilityFound(
    skillId: string,
    severity: string,
    category: string,
    patternId: string,
    message: string
  ): void {
    const level = severity === "critical" ? "critical" : severity === "high" ? "error" : "warn";
    this.log(
      level,
      "vulnerability_found",
      `[${severity.toUpperCase()}] ${category}: ${message}`,
      {
        skillId,
        severity,
        category,
        patternId,
      }
    );
  }

  /**
   * Log resource access
   */
  resourceAccess(
    resourceType: "file" | "network" | "env" | "command",
    resource: string,
    action: "read" | "write" | "execute",
    allowed: boolean
  ): void {
    this.log(
      allowed ? "info" : "warn",
      "resource_access",
      `${action.toUpperCase()} ${resourceType}: ${resource} - ${allowed ? "ALLOWED" : "DENIED"}`,
      {
        resourceType,
        resource,
        action,
        allowed,
      }
    );
  }

  /**
   * Log error
   */
  logError(event: string, error: Error, metadata?: Record<string, unknown>): void {
    this.error(event, error.message, {
      ...metadata,
      stack: error.stack,
      name: error.name,
    });
  }

  /**
   * Close file output stream
   */
  async close(): Promise<void> {
    if (this.outputStream) {
      await this.outputStream.close();
    }
  }
}

/**
 * Global logger instance
 */
let globalLogger: StructuredLogger | null = null;

export function initGlobalLogger(options?: {
  minLevel?: LogLevel;
  sessionId?: string;
  userId?: string;
  outputFile?: string;
}): StructuredLogger {
  globalLogger = new StructuredLogger(options);
  return globalLogger;
}

export function getLogger(): StructuredLogger {
  if (!globalLogger) {
    globalLogger = new StructuredLogger();
  }
  return globalLogger;
}
