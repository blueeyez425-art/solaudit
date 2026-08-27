"use client";

import type { Finding, ScanResult, Severity } from "@solaudit/core";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEVERITY_STYLES: Record<Severity, { badge: string; text: string; border: string }> = {
  CRITICAL: { badge: "bg-red-500/15 text-red-400 border-red-500/30", text: "text-red-400", border: "border-red-500/20" },
  HIGH: { badge: "bg-orange-500/15 text-orange-400 border-orange-500/30", text: "text-orange-400", border: "border-orange-500/20" },
  MEDIUM: { badge: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30", text: "text-yellow-400", border: "border-yellow-500/20" },
  LOW: { badge: "bg-blue-500/15 text-blue-400 border-blue-500/30", text: "text-blue-400", border: "border-blue-500/20" },
  INFO: { badge: "bg-slate-500/15 text-slate-400 border-slate-500/30", text: "text-slate-400", border: "border-slate-500/20" },
};

function SummaryBadge({ label, count, styles }: { label: string; count: number; styles: string }) {
  return (
    <div className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${styles}`}>
      <span className="text-lg font-bold">{count}</span>
      <span className="text-xs uppercase tracking-wide opacity-80">{label}</span>
    </div>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const styles = SEVERITY_STYLES[finding.severity];
  return (
    <div className={`rounded-lg border bg-slate-900/60 p-4 ${styles.border}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded border px-2 py-0.5 text-xs font-semibold ${styles.badge}`}>
          {finding.severity}
        </span>
        <span className="font-mono text-sm font-semibold text-slate-200">{finding.ruleId}</span>
        <span className="text-sm text-slate-300">{finding.ruleName}</span>
      </div>
      <div className="mt-2 font-mono text-xs text-slate-500">
        {finding.filePath}:{finding.line}
      </div>
      <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 font-mono text-xs text-slate-300">
        {finding.snippet}
      </pre>
      <p className="mt-2 text-sm text-slate-400">{finding.description}</p>
    </div>
  );
}

export function ResultsView({
  result,
  sourceLabel,
}: {
  result: ScanResult;
  sourceLabel: string;
}) {
  const grouped = new Map<Severity, Finding[]>();
  for (const finding of result.findings) {
    const bucket = grouped.get(finding.severity) ?? [];
    bucket.push(finding);
    grouped.set(finding.severity, bucket);
  }

  return (
    <div className="mt-8 space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold text-slate-100">Results</h2>
          <p className="text-sm text-slate-500">
            {sourceLabel} · {result.scannedFiles} file{result.scannedFiles === 1 ? "" : "s"} scanned
          </p>
        </div>
      </div>

      <div className="flex flex-wrap gap-3">
        <SummaryBadge label="Critical" count={result.summary.critical} styles={SEVERITY_STYLES.CRITICAL.badge} />
        <SummaryBadge label="High" count={result.summary.high} styles={SEVERITY_STYLES.HIGH.badge} />
        <SummaryBadge label="Medium" count={result.summary.medium} styles={SEVERITY_STYLES.MEDIUM.badge} />
        <SummaryBadge label="Low" count={result.summary.low} styles={SEVERITY_STYLES.LOW.badge} />
        <SummaryBadge label="Info" count={result.summary.info} styles={SEVERITY_STYLES.INFO.badge} />
      </div>

      {result.findings.length === 0 ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-6 text-center text-emerald-400">
          ✔ No issues found across the scanned rules.
        </div>
      ) : (
        <div className="space-y-6">
          {SEVERITY_ORDER.map((severity) => {
            const findings = grouped.get(severity);
            if (!findings || findings.length === 0) return null;
            return (
              <div key={severity} className="space-y-2">
                <h3 className={`text-sm font-semibold ${SEVERITY_STYLES[severity].text}`}>
                  {severity} ({findings.length})
                </h3>
                <div className="space-y-2">
                  {findings.map((finding, i) => (
                    <FindingCard key={`${finding.ruleId}-${finding.filePath}-${finding.line}-${i}`} finding={finding} />
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
