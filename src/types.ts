export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  filePath: string;
  line: number;
  snippet: string;
  description: string;
}

export interface Rule {
  id: string;
  name: string;
  severity: Severity;
  description: string;
  check(fileContent: string, filePath: string): Finding[];
}

export interface ScanResult {
  scannedFiles: number;
  findings: Finding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}
