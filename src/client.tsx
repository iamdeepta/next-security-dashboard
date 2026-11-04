'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AppCheckStatus, HeaderStatus, PackageInfo, SafeUpgradeOption, SecurityReport, Severity, Vulnerability } from './types.js';
import { SEVERITY_ORDER } from './types.js';

export interface SecurityDashboardProps {
  /** API endpoint that returns the security report JSON. Defaults to "/api/security-scan". */
  endpoint?: string;
  /** Auto-refresh interval in ms. 0 (default) disables polling. */
  refreshIntervalMs?: number;
  /** Pre-fetched report (e.g. from a Server Component). When given, no fetch happens on mount. */
  initialReport?: SecurityReport;
}

type Tab = 'vulns' | 'packages' | 'headers' | 'appsec';

const ALL_SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low'];

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#e5484d',
  high: '#f76b15',
  moderate: '#ffb224',
  low: '#46a758',
};

function severityLabel(s: Severity): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function downloadBlob(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    try {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
      return true;
    } catch {
      return false;
    }
  }
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const onClick = async () => {
    const ok = await copyText(text);
    if (ok) {
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1600);
    }
  };
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);
  return (
    <button type="button" className="nsd-btn nsd-btn-sm" onClick={onClick}>
      {copied ? 'Copied ✓' : label}
    </button>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`nsd-badge nsd-badge-${severity}`}>{severityLabel(severity)}</span>
  );
}

function SafeUpgradeChips({ options }: { options: SafeUpgradeOption[] }) {
  if (options.length === 0) return null;
  return (
    <span className="nsd-safe-chips">
      {options.map((opt, i) => (
        <code
          key={opt.version}
          className={
            i === 0 ? 'nsd-mono nsd-safe-chip nsd-safe-chip-rec' : 'nsd-mono nsd-safe-chip'
          }
          title={opt.label}
        >
          {i === 0 ? `★ ${opt.version}` : opt.version}
        </code>
      ))}
    </span>
  );
}

function HeaderStatusBadge({ status }: { status: HeaderStatus }) {
  const labels: Record<HeaderStatus, string> = {
    ok: 'OK',
    warning: 'Warning',
    missing: 'Missing',
    na: 'N/A',
  };
  return <span className={`nsd-badge nsd-badge-header-${status}`}>{labels[status]}</span>;
}

function AppCheckBadge({ status }: { status: AppCheckStatus }) {
  const labels: Record<AppCheckStatus, string> = {
    pass: 'Pass',
    warn: 'Warning',
    fail: 'Fail',
    na: 'N/A',
  };
  return <span className={`nsd-badge nsd-badge-app-${status}`}>{labels[status]}</span>;
}

function Donut({ counts }: { counts: SecurityReport['counts'] }) {
  const total = counts.critical + counts.high + counts.moderate + counts.low;
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const segments = ALL_SEVERITIES.map((sev) => {
    const value = counts[sev];
    const len = total > 0 ? (value / total) * circumference : 0;
    const seg = { sev, value, len, offset };
    offset += len;
    return seg;
  });
  return (
    <div className="nsd-donut-wrap">
      <svg className="nsd-donut" viewBox="0 0 140 140" role="img" aria-label="Vulnerabilities by severity">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--nsd-track)" strokeWidth="18" />
        {total > 0 &&
          segments
            .filter((s) => s.len > 0)
            .map((s) => (
              <circle
                key={s.sev}
                cx="70"
                cy="70"
                r={radius}
                fill="none"
                stroke={SEVERITY_COLORS[s.sev]}
                strokeWidth="18"
                strokeDasharray={`${s.len} ${circumference - s.len}`}
                strokeDashoffset={-s.offset}
                transform="rotate(-90 70 70)"
              />
            ))}
        <text x="70" y="68" textAnchor="middle" className="nsd-donut-number">
          {total}
        </text>
        <text x="70" y="86" textAnchor="middle" className="nsd-donut-label">
          issues
        </text>
      </svg>
      <ul className="nsd-legend">
        {ALL_SEVERITIES.map((sev) => (
          <li key={sev}>
            <span className="nsd-dot" style={{ background: SEVERITY_COLORS[sev] }} />
            {severityLabel(sev)}
            <strong>{counts[sev]}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

/**
 * Estimated scan progress from elapsed time. The server scan is one long
 * operation (npm audit dominates it) with no sub-step reporting, so the
 * bar is stage-based: it advances toward 90% while the scan runs and only
 * reaches 100% when the report actually arrives. The stage text says what
 * is happening so a slow scan never looks frozen.
 */
function progressForElapsed(ms: number): { pct: number; stage: string } {
  if (ms < 5000) {
    return { pct: 8 + (ms / 5000) * 17, stage: 'Reading installed packages…' };
  }
  if (ms < 20000) {
    return {
      pct: 25 + ((ms - 5000) / 15000) * 30,
      stage: 'Running npm audit — this is usually the slowest step…',
    };
  }
  if (ms < 60000) {
    return { pct: 55 + ((ms - 20000) / 40000) * 20, stage: 'Checking the results…' };
  }
  return {
    pct: Math.min(90, 75 + (ms - 60000) / 60000),
    stage: 'Still checking — a large project can take a couple of minutes…',
  };
}

export function SecurityDashboard({
  endpoint = '/api/security-scan',
  refreshIntervalMs = 0,
  initialReport,
}: SecurityDashboardProps) {
  const [report, setReport] = useState<SecurityReport | null>(initialReport ?? null);
  const [loading, setLoading] = useState(!initialReport);
  const [error, setError] = useState<string | null>(null);
  const [scanNonce, setScanNonce] = useState(0);
  const [progress, setProgress] = useState(0);
  const [progressStage, setProgressStage] = useState('Reading installed packages…');
  const [tab, setTab] = useState<Tab>('vulns');
  const [dark, setDark] = useState(false);

  // Filters
  const [query, setQuery] = useState('');
  const [sevFilter, setSevFilter] = useState<Severity[]>([...ALL_SEVERITIES]);
  const [fixableOnly, setFixableOnly] = useState(false);
  const [directFilter, setDirectFilter] = useState<'all' | 'direct' | 'transitive'>('all');
  const [envFilter, setEnvFilter] = useState<'all' | 'prod' | 'dev'>('all');
  const [sortKey, setSortKey] = useState<'severity' | 'name' | 'upgrade'>('severity');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [pkgQuery, setPkgQuery] = useState('');
  const [vulnOnly, setVulnOnly] = useState(false);

  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia) {
      setDark(window.matchMedia('(prefers-color-scheme: dark)').matches);
    }
  }, []);

  const load = useCallback(
    async (fresh: boolean) => {
      setLoading(true);
      setError(null);
      setScanNonce((n) => n + 1);
      setProgress(5);
      setProgressStage('Reading installed packages…');
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 240_000);
      try {
        const sep = endpoint.includes('?') ? '&' : '?';
        const res = await fetch(`${endpoint}${fresh ? `${sep}fresh=1` : ''}`, {
          cache: 'no-store',
          signal: controller.signal,
        });
        const data = (await res.json()) as SecurityReport & { error?: { message: string } };
        if (!res.ok) {
          throw new Error(data?.error?.message ?? `Scan request failed (${res.status})`);
        }
        setReport(data);
      } catch (err) {
        if (err instanceof Error && err.name === 'AbortError') {
          setError(
            'The scan took over 4 minutes and was stopped. This usually means npm audit is very slow on this project — try again, or speed it up with auditTimeoutMs, enableSafeUpgradeLookup: false, or a longer cacheTtlMs.',
          );
        } else {
          setError(err instanceof Error ? err.message : 'Failed to load the security report.');
        }
      } finally {
        clearTimeout(timeout);
        setLoading(false);
      }
    },
    [endpoint],
  );

  useEffect(() => {
    if (!loading) return undefined;
    const startedAt = Date.now();
    const id = setInterval(() => {
      const { pct, stage } = progressForElapsed(Date.now() - startedAt);
      setProgress(Math.round(pct));
      setProgressStage(stage);
    }, 500);
    return () => clearInterval(id);
  }, [loading, scanNonce]);

  useEffect(() => {
    if (!initialReport) void load(false);
  }, [initialReport, load]);

  useEffect(() => {
    if (refreshIntervalMs > 0) {
      const id = setInterval(() => void load(false), refreshIntervalMs);
      return () => clearInterval(id);
    }
    return undefined;
  }, [refreshIntervalMs, load]);

  const filteredVulns = useMemo(() => {
    if (!report) return [];
    const q = query.trim().toLowerCase();
    const list = report.vulnerabilities.filter((v) => {
      if (!sevFilter.includes(v.severity)) return false;
      if (fixableOnly && !v.fixAvailable) return false;
      if (directFilter === 'direct' && !v.isDirect) return false;
      if (directFilter === 'transitive' && v.isDirect) return false;
      if (envFilter === 'prod' && v.isDev) return false;
      if (envFilter === 'dev' && !v.isDev) return false;
      if (q) {
        const hay = `${v.packageName} ${v.advisories.map((a) => a.title).join(' ')} ${v.advisories
          .flatMap((a) => a.cveIds)
          .join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    return [...list].sort((a, b) => {
      if (sortKey === 'name') return a.packageName.localeCompare(b.packageName);
      if (sortKey === 'upgrade') {
        if (!a.recommendedUpgrade && b.recommendedUpgrade) return 1;
        if (a.recommendedUpgrade && !b.recommendedUpgrade) return -1;
        return (a.recommendedUpgrade ?? '').localeCompare(b.recommendedUpgrade ?? '');
      }
      return (
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        a.packageName.localeCompare(b.packageName)
      );
    });
  }, [report, query, sevFilter, fixableOnly, directFilter, envFilter, sortKey]);

  const filteredPackages = useMemo(() => {
    if (!report) return [];
    const q = pkgQuery.trim().toLowerCase();
    return report.packages.filter((p: PackageInfo) => {
      if (vulnOnly && !p.vulnerable) return false;
      if (directFilter === 'direct' && !p.isDirect) return false;
      if (directFilter === 'transitive' && p.isDirect) return false;
      if (envFilter === 'prod' && p.isDev) return false;
      if (envFilter === 'dev' && !p.isDev) return false;
      if (q && !p.name.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [report, pkgQuery, vulnOnly, directFilter, envFilter]);

  const toggleSeverity = (sev: Severity) => {
    setSevFilter((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev],
    );
  };

  const exportJson = () => {
    if (!report) return;
    downloadBlob('security-report.json', JSON.stringify(report, null, 2), 'application/json');
  };

  const exportCsv = () => {
    if (!report) return;
    const header = [
      'Package',
      'Installed',
      'Severity',
      'Direct',
      'Environment',
      'Advisory',
      'CVE/GHSA',
      'Vulnerable range',
      'Patched versions',
      'Recommended upgrade',
      'Safe upgrade options',
      'Fix command',
    ];
    const rows = report.vulnerabilities.map((v: Vulnerability) => {
      const ids = [
        ...v.advisories.flatMap((a) => a.cveIds),
        ...v.advisories.map((a) => a.ghsaId).filter((x): x is string => !!x),
      ].join(' ');
      return [
        v.packageName,
        v.installedVersion,
        v.severity,
        v.isDirect ? 'direct' : 'transitive',
        v.isDev ? 'dev' : 'prod',
        v.advisories.map((a) => a.title).join(' | '),
        ids,
        v.vulnerableRange,
        v.patchedVersions.join(' '),
        v.recommendedUpgrade ?? '',
        v.safeUpgradeOptions.map((o) => o.version).join(' '),
        v.fixCommand ?? '',
      ]
        .map(csvCell)
        .join(',');
    });
    downloadBlob(
      'security-report.csv',
      [header.map(csvCell).join(','), ...rows].join('\n'),
      'text/csv',
    );
  };

  const scanFailed =
    !!report?.error && report.source === 'none' && report.packages.length === 0;

  return (
    <div className="nsd-dashboard" data-nsd-theme={dark ? 'dark' : 'light'}>
      <header className="nsd-header">
        <div>
          <h1 className="nsd-title">Security Dashboard</h1>
          <p className="nsd-subtitle">
            {report?.appName ? (
              <>
                <code>{report.appName}</code> ·{' '}
              </>
            ) : null}
            Dependency vulnerabilities &amp; security headers
            {report ? (
              <>
                {' '}
                · scanned{' '}
                {new Date(report.generatedAt).toLocaleString()} via {report.toolVersions.scanner}
              </>
            ) : null}
          </p>
        </div>
        <div className="nsd-header-actions">
          <button type="button" className="nsd-btn" onClick={() => setDark((d) => !d)}>
            {dark ? '☀️ Light' : '🌙 Dark'}
          </button>
          <button type="button" className="nsd-btn" onClick={() => void load(true)} disabled={loading}>
            {loading ? 'Scanning…' : '↻ Re-scan'}
          </button>
          <button type="button" className="nsd-btn" onClick={exportJson} disabled={!report}>
            ↓ JSON
          </button>
          <button type="button" className="nsd-btn" onClick={exportCsv} disabled={!report}>
            ↓ CSV
          </button>
        </div>
      </header>

      {loading && !report && (
        <div className="nsd-skeleton-wrap" aria-busy="true">
          <div
            className="nsd-progress"
            role="progressbar"
            aria-valuenow={progress}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Security scan progress"
          >
            <div className="nsd-progress-top">
              <span>{progressStage}</span>
              <span>{progress}%</span>
            </div>
            <div className="nsd-progress-track">
              <div className="nsd-progress-fill" style={{ width: `${progress}%` }} />
            </div>
          </div>
          <div className="nsd-skeleton nsd-skeleton-cards" />
          <div className="nsd-skeleton nsd-skeleton-table" />
          <div className="nsd-skeleton nsd-skeleton-table" />
          <p className="nsd-muted">Running npm audit &amp; checking security headers…</p>
        </div>
      )}

      {loading && report && (
        <div
          className="nsd-progress nsd-progress-slim"
          role="progressbar"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="Re-scan progress"
        >
          <div className="nsd-progress-top">
            <span>{progressStage}</span>
            <span>{progress}%</span>
          </div>
          <div className="nsd-progress-track">
            <div className="nsd-progress-fill" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {error && !report && (
        <div className="nsd-error" role="alert">
          <strong>Scan failed.</strong> {error}
          <div>
            <button type="button" className="nsd-btn nsd-btn-primary" onClick={() => void load(true)}>
              Retry
            </button>
          </div>
        </div>
      )}

      {report && scanFailed && (
        <div className="nsd-error" role="alert">
          <strong>Scan failed.</strong> {report.error?.message}{' '}
          {report.error?.detail ? <span className="nsd-muted">{report.error.detail}</span> : null}
          <div>
            <button type="button" className="nsd-btn nsd-btn-primary" onClick={() => void load(true)}>
              Retry
            </button>
          </div>
        </div>
      )}

      {report && !scanFailed && (
        <>
          {report.error && (
            <div className="nsd-notice" role="status">
              <strong>Note:</strong> {report.error.message}{' '}
              {report.error.detail ? <span className="nsd-muted">{report.error.detail}</span> : null}
            </div>
          )}

          <section className="nsd-cards" aria-label="Summary">
            <div className="nsd-card">
              <span className="nsd-card-label">Packages</span>
              <span className="nsd-card-value">{report.counts.total}</span>
              <span className="nsd-card-sub">
                {report.packages.filter((p) => p.isDirect).length} direct ·{' '}
                {report.packages.filter((p) => !p.isDirect).length} transitive
              </span>
            </div>
            <div className="nsd-card">
              <span className="nsd-card-label">Vulnerable</span>
              <span className="nsd-card-value">{report.counts.vulnerable}</span>
              <span className="nsd-card-sub">{report.counts.fixable} with an available fix</span>
            </div>
            <div className="nsd-card nsd-card-donut">
              <Donut counts={report.counts} />
            </div>
            <div className="nsd-card">
              <span className="nsd-card-label">Header score</span>
              <span className="nsd-card-value">
                {report.headers?.score ?? '—'}
                {report.headers?.score != null ? <span className="nsd-card-unit">/100</span> : null}
              </span>
              <span className="nsd-card-sub">
                {report.headers
                  ? report.headers.checks.filter((c) => c.status === 'ok').length +
                    ' of ' +
                    report.headers.checks.filter((c) => c.status !== 'na').length +
                    ' headers OK'
                  : 'Header check unavailable'}
              </span>
            </div>
          </section>

          {report.vulnerabilities.length === 0 && (
            <div className="nsd-empty" role="status">
              <div className="nsd-empty-emoji">🎉</div>
              <strong>No vulnerabilities found.</strong>
              <p>
                {report.source === 'npm-audit'
                  ? 'npm audit reported no known vulnerabilities for the installed dependencies.'
                  : 'The fallback check found no known vulnerabilities for the installed dependencies.'}{' '}
                Keep it that way — re-scan after every dependency change.
              </p>
            </div>
          )}

          <nav className="nsd-tabs" aria-label="Dashboard sections">
            <button
              type="button"
              className={tab === 'vulns' ? 'nsd-tab nsd-tab-active' : 'nsd-tab'}
              onClick={() => setTab('vulns')}
            >
              Vulnerabilities ({report.counts.vulnerable})
            </button>
            <button
              type="button"
              className={tab === 'packages' ? 'nsd-tab nsd-tab-active' : 'nsd-tab'}
              onClick={() => setTab('packages')}
            >
              Packages ({report.counts.total})
            </button>
            <button
              type="button"
              className={tab === 'headers' ? 'nsd-tab nsd-tab-active' : 'nsd-tab'}
              onClick={() => setTab('headers')}
            >
              Security headers
            </button>
            <button
              type="button"
              className={tab === 'appsec' ? 'nsd-tab nsd-tab-active' : 'nsd-tab'}
              onClick={() => setTab('appsec')}
            >
              App security
              {report.appSecurity
                ? ` (${report.appSecurity.counts.fail + report.appSecurity.counts.warn})`
                : ''}
            </button>
          </nav>

          {tab === 'vulns' && (
            <section aria-label="Vulnerabilities">
              <div className="nsd-filters">
                <input
                  className="nsd-input"
                  type="search"
                  placeholder="Search package, advisory or CVE…"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  aria-label="Search vulnerabilities"
                />
                <div className="nsd-chip-row" aria-label="Severity filter">
                  {ALL_SEVERITIES.map((sev) => (
                    <button
                      type="button"
                      key={sev}
                      className={
                        sevFilter.includes(sev) ? 'nsd-chip nsd-chip-on' : 'nsd-chip'
                      }
                      onClick={() => toggleSeverity(sev)}
                      aria-pressed={sevFilter.includes(sev)}
                    >
                      <span className="nsd-dot" style={{ background: SEVERITY_COLORS[sev] }} />
                      {severityLabel(sev)}
                    </button>
                  ))}
                </div>
                <label className="nsd-check">
                  <input
                    type="checkbox"
                    checked={fixableOnly}
                    onChange={(e) => setFixableOnly(e.target.checked)}
                  />{' '}
                  Fixable only
                </label>
                <select
                  className="nsd-select"
                  value={directFilter}
                  onChange={(e) =>
                    setDirectFilter(e.target.value as 'all' | 'direct' | 'transitive')
                  }
                  aria-label="Direct or transitive"
                >
                  <option value="all">Direct + transitive</option>
                  <option value="direct">Direct only</option>
                  <option value="transitive">Transitive only</option>
                </select>
                <select
                  className="nsd-select"
                  value={envFilter}
                  onChange={(e) => setEnvFilter(e.target.value as 'all' | 'prod' | 'dev')}
                  aria-label="Production or development"
                >
                  <option value="all">Prod + dev</option>
                  <option value="prod">Production only</option>
                  <option value="dev">Dev only</option>
                </select>
                <select
                  className="nsd-select"
                  value={sortKey}
                  onChange={(e) => setSortKey(e.target.value as 'severity' | 'name' | 'upgrade')}
                  aria-label="Sort vulnerabilities"
                >
                  <option value="severity">Sort: severity</option>
                  <option value="name">Sort: package name</option>
                  <option value="upgrade">Sort: recommended upgrade</option>
                </select>
              </div>

              {filteredVulns.length === 0 ? (
                <p className="nsd-muted nsd-empty-note">
                  No vulnerabilities match the current filters.
                </p>
              ) : (
                <div className="nsd-table-wrap">
                  <table className="nsd-table">
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Installed</th>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Advisory</th>
                        <th>Safe upgrades</th>
                        <th aria-label="Expand" />
                      </tr>
                    </thead>
                    <tbody>
                      {filteredVulns.map((v) => {
                        const key = `${v.packageName}@${v.installedVersion}`;
                        const isOpen = expanded === key;
                        return [
                          <tr key={key} className="nsd-row-main">
                            <td>
                              <code className="nsd-mono">{v.packageName}</code>
                            </td>
                            <td>
                              <code className="nsd-mono">{v.installedVersion}</code>
                            </td>
                            <td>
                              <SeverityBadge severity={v.severity} />
                            </td>
                            <td>
                              <span className="nsd-tag">{v.isDirect ? 'direct' : 'transitive'}</span>{' '}
                              <span className="nsd-tag">{v.isDev ? 'dev' : 'prod'}</span>
                            </td>
                            <td className="nsd-advisory-cell">
                              {v.advisories[0]?.title ?? '—'}
                              {v.advisories.length > 1 ? (
                                <span className="nsd-muted"> +{v.advisories.length - 1} more</span>
                              ) : null}
                            </td>
                            <td>
                              {v.safeUpgradeOptions.length > 0 ? (
                                <SafeUpgradeChips options={v.safeUpgradeOptions} />
                              ) : v.recommendedUpgrade ? (
                                <code className="nsd-mono">{v.recommendedUpgrade}</code>
                              ) : v.fixAvailable ? (
                                <span className="nsd-muted">via npm audit fix</span>
                              ) : (
                                <span className="nsd-muted">no fix available</span>
                              )}
                            </td>
                            <td>
                              <button
                                type="button"
                                className="nsd-btn nsd-btn-sm"
                                onClick={() => setExpanded(isOpen ? null : key)}
                                aria-expanded={isOpen}
                              >
                                {isOpen ? 'Hide' : 'Details'}
                              </button>
                            </td>
                          </tr>,
                          isOpen ? (
                            <tr key={`${key}-detail`} className="nsd-row-detail">
                              <td colSpan={7}>
                                <div className="nsd-detail">
                                  <dl>
                                    <div>
                                      <dt>Vulnerable range</dt>
                                      <dd>
                                        <code className="nsd-mono">{v.vulnerableRange || '—'}</code>
                                      </dd>
                                    </div>
                                    <div>
                                      <dt>Safe upgrade options</dt>
                                      <dd>
                                        {v.safeUpgradeOptions.length ? (
                                          v.safeUpgradeOptions.map((opt) => (
                                            <span key={opt.version} className="nsd-safe-opt">
                                              <code className="nsd-mono nsd-code-chip">
                                                {opt.version}
                                              </code>
                                              <span className="nsd-muted">{opt.label}</span>
                                            </span>
                                          ))
                                        ) : (
                                          <span className="nsd-muted">none known</span>
                                        )}
                                      </dd>
                                    </div>
                                    <div>
                                      <dt>Patched versions</dt>
                                      <dd>
                                        {v.patchedVersions.length ? (
                                          v.patchedVersions.map((p) => (
                                            <code key={p} className="nsd-mono nsd-code-chip">
                                              {p}
                                            </code>
                                          ))
                                        ) : (
                                          <span className="nsd-muted">none known</span>
                                        )}
                                      </dd>
                                    </div>
                                    {!v.isDirect && v.pulledInBy.length > 0 && (
                                      <div>
                                        <dt>Pulled in by</dt>
                                        <dd>
                                          {v.pulledInBy.map((d) => (
                                            <code key={d} className="nsd-mono nsd-code-chip">
                                              {d}
                                            </code>
                                          ))}
                                        </dd>
                                      </div>
                                    )}
                                  </dl>
                                  <h4 className="nsd-detail-heading">Advisories</h4>
                                  <ul className="nsd-advisory-list">
                                    {v.advisories.map((a, i) => (
                                      <li key={`${a.title}-${i}`}>
                                        <SeverityBadge severity={a.severity} />{' '}
                                        <strong>{a.title}</strong>{' '}
                                        {a.cvssScore != null && (
                                          <span className="nsd-muted">CVSS {a.cvssScore}</span>
                                        )}
                                        {a.cwe.length > 0 && (
                                          <span className="nsd-muted">
                                            {' '}
                                            · {a.cwe.join(', ')}
                                          </span>
                                        )}
                                        <div className="nsd-links">
                                          {a.ghsaId && (
                                            <a
                                              href={`https://github.com/advisories/${a.ghsaId}`}
                                              target="_blank"
                                              rel="noreferrer"
                                            >
                                              {a.ghsaId} ↗
                                            </a>
                                          )}
                                          {a.cveIds.map((cve) => (
                                            <a
                                              key={cve}
                                              href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                                              target="_blank"
                                              rel="noreferrer"
                                            >
                                              {cve} ↗
                                            </a>
                                          ))}
                                          {a.url && !a.ghsaId && (
                                            <a href={a.url} target="_blank" rel="noreferrer">
                                              Advisory ↗
                                            </a>
                                          )}
                                          <span className="nsd-muted">
                                            via {a.source === 'osv.dev' ? 'fallback database' : 'npm audit'}
                                          </span>
                                        </div>
                                      </li>
                                    ))}
                                  </ul>
                                  {v.fixCommand && (
                                    <div className="nsd-fix">
                                      <code className="nsd-mono nsd-fix-cmd">{v.fixCommand}</code>
                                      <CopyButton text={v.fixCommand} label="Copy fix command" />
                                    </div>
                                  )}
                                </div>
                              </td>
                            </tr>
                          ) : null,
                        ];
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}

          {tab === 'packages' && (
            <section aria-label="Package inventory">
              <div className="nsd-filters">
                <input
                  className="nsd-input"
                  type="search"
                  placeholder="Search packages…"
                  value={pkgQuery}
                  onChange={(e) => setPkgQuery(e.target.value)}
                  aria-label="Search packages"
                />
                <label className="nsd-check">
                  <input
                    type="checkbox"
                    checked={vulnOnly}
                    onChange={(e) => setVulnOnly(e.target.checked)}
                  />{' '}
                  Vulnerable only
                </label>
                <select
                  className="nsd-select"
                  value={directFilter}
                  onChange={(e) =>
                    setDirectFilter(e.target.value as 'all' | 'direct' | 'transitive')
                  }
                  aria-label="Direct or transitive"
                >
                  <option value="all">Direct + transitive</option>
                  <option value="direct">Direct only</option>
                  <option value="transitive">Transitive only</option>
                </select>
                <select
                  className="nsd-select"
                  value={envFilter}
                  onChange={(e) => setEnvFilter(e.target.value as 'all' | 'prod' | 'dev')}
                  aria-label="Production or development"
                >
                  <option value="all">Prod + dev</option>
                  <option value="prod">Production only</option>
                  <option value="dev">Dev only</option>
                </select>
              </div>
              <div className="nsd-table-wrap">
                <table className="nsd-table">
                  <thead>
                    <tr>
                      <th>Package</th>
                      <th>Version</th>
                      <th>Type</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredPackages.map((p: PackageInfo) => (
                      <tr key={`${p.name}@${p.version}`}>
                        <td>
                          <code className="nsd-mono">{p.name}</code>
                        </td>
                        <td>
                          <code className="nsd-mono">{p.version}</code>
                        </td>
                        <td>
                          <span className="nsd-tag">{p.isDirect ? 'direct' : 'transitive'}</span>{' '}
                          <span className="nsd-tag">{p.isDev ? 'dev' : 'prod'}</span>
                        </td>
                        <td>
                          {p.vulnerable ? (
                            <span className="nsd-vuln-flags">
                              {p.severities.map((s, i) => (
                                <SeverityBadge key={`${s}-${i}`} severity={s} />
                              ))}
                            </span>
                          ) : (
                            <span className="nsd-muted">clean</span>
                          )}
                        </td>
                      </tr>
                    ))}
                    {filteredPackages.length === 0 && (
                      <tr>
                        <td colSpan={4} className="nsd-muted">
                          No packages match the current filters.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {tab === 'headers' && (
            <section aria-label="Security headers">
              {!report.headers || report.headers.error ? (
                <div className="nsd-error" role="alert">
                  <strong>Header check unavailable.</strong>{' '}
                  {report.headers?.error ??
                    'The header check did not return data. Re-scan to try again.'}
                </div>
              ) : (
                <>
                  <div className="nsd-headers-meta">
                    <span>
                      Checked <code className="nsd-mono">{report.headers.url}</code> · HTTP{' '}
                      {report.headers.statusCode ?? '—'} · score{' '}
                      <strong>{report.headers.score}/100</strong>
                    </span>
                    <span className="nsd-muted">
                      Fetched with cache disabled so it reflects the current configuration.
                    </span>
                  </div>
                  <div className="nsd-header-cards">
                    {report.headers.checks.map((check) => (
                      <article key={check.header} className="nsd-header-card">
                        <div className="nsd-header-card-top">
                          <h3 className="nsd-header-card-name">{check.displayName}</h3>
                          <HeaderStatusBadge status={check.status} />
                        </div>
                        <p className="nsd-header-card-value">
                          {check.value != null ? (
                            <code className="nsd-mono">{check.value}</code>
                          ) : (
                            <span className="nsd-muted">not sent</span>
                          )}
                        </p>
                        <p className="nsd-header-card-expl">{check.explanation}</p>
                        {check.status !== 'ok' && (
                          <details className="nsd-fix-details">
                            <summary>Show fix (next.config.js)</summary>
                            <pre className="nsd-code">
                              <code>{check.fixSnippet}</code>
                            </pre>
                            <CopyButton text={check.fixSnippet} label="Copy snippet" />
                          </details>
                        )}
                      </article>
                    ))}
                  </div>
                </>
              )}
            </section>
          )}

          {tab === 'appsec' && (
            <section aria-label="App security">
              {!report.appSecurity ? (
                <div className="nsd-error" role="alert">
                  <strong>App security analysis was not run.</strong> Enable it with the
                  handler option <code className="nsd-mono">includeAppChecks: true</code>.
                </div>
              ) : (
                <>
                  {report.appSecurity.error && (
                    <div className="nsd-notice" role="status">
                      <strong>Note:</strong> {report.appSecurity.error}
                    </div>
                  )}
                  <div className="nsd-headers-meta">
                    <span>
                      Scanned <strong>{report.appSecurity.filesScanned}</strong> source
                      file(s) · {report.appSecurity.counts.pass} passed,{' '}
                      {report.appSecurity.counts.warn} warnings,{' '}
                      {report.appSecurity.counts.fail} failures
                    </span>
                    <span className="nsd-muted">
                      Static findings are heuristics — review each one. Runtime checks ran
                      against {report.appSecurity.origin ?? 'no origin'}.
                    </span>
                  </div>
                  <div className="nsd-header-cards">
                    {report.appSecurity.checks.map((check) => (
                      <article key={check.id} className="nsd-header-card">
                        <div className="nsd-header-card-top">
                          <h3 className="nsd-header-card-name">{check.title}</h3>
                          <span>
                            <AppCheckBadge status={check.status} />{' '}
                            {check.severity && <SeverityBadge severity={check.severity} />}
                          </span>
                        </div>
                        <p className="nsd-header-card-expl">{check.summary}</p>
                        <p>
                          <span className="nsd-tag">{check.category}</span>
                        </p>
                        {check.evidence.length > 0 && (
                          <ul className="nsd-check-evidence">
                            {check.evidence.map((e, i) => (
                              <li key={i}>
                                <code className="nsd-mono">{e}</code>
                              </li>
                            ))}
                          </ul>
                        )}
                        {check.locations.length > 0 && (
                          <div className="nsd-check-loc">
                            {check.locations.map((l) => (
                              <div key={`${l.file}:${l.line}`}>
                                <code className="nsd-mono">
                                  {l.file}:{l.line}
                                </code>{' '}
                                <code className="nsd-mono nsd-code-chip">{l.snippet}</code>
                              </div>
                            ))}
                          </div>
                        )}
                        <details className="nsd-fix-details">
                          <summary>How to fix</summary>
                          <pre className="nsd-code">
                            <code>{check.fix}</code>
                          </pre>
                          <CopyButton text={check.fix} label="Copy fix" />
                        </details>
                      </article>
                    ))}
                  </div>
                </>
              )}
            </section>
          )}
        </>
      )}
    </div>
  );
}

export default SecurityDashboard;
