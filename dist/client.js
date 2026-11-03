'use client';
import { jsx as _jsx, jsxs as _jsxs, Fragment as _Fragment } from "react/jsx-runtime";
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { SEVERITY_ORDER } from './types.js';
const ALL_SEVERITIES = ['critical', 'high', 'moderate', 'low'];
const SEVERITY_COLORS = {
    critical: '#e5484d',
    high: '#f76b15',
    moderate: '#ffb224',
    low: '#46a758',
};
function severityLabel(s) {
    return s.charAt(0).toUpperCase() + s.slice(1);
}
function downloadBlob(filename, content, mime) {
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
async function copyText(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    }
    catch {
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
        }
        catch {
            return false;
        }
    }
}
function csvCell(value) {
    return `"${value.replace(/"/g, '""')}"`;
}
function CopyButton({ text, label = 'Copy' }) {
    const [copied, setCopied] = useState(false);
    const timer = useRef(null);
    const onClick = async () => {
        const ok = await copyText(text);
        if (ok) {
            setCopied(true);
            if (timer.current)
                clearTimeout(timer.current);
            timer.current = setTimeout(() => setCopied(false), 1600);
        }
    };
    useEffect(() => () => {
        if (timer.current)
            clearTimeout(timer.current);
    }, []);
    return (_jsx("button", { type: "button", className: "nsd-btn nsd-btn-sm", onClick: onClick, children: copied ? 'Copied ✓' : label }));
}
function SeverityBadge({ severity }) {
    return (_jsx("span", { className: `nsd-badge nsd-badge-${severity}`, children: severityLabel(severity) }));
}
function SafeUpgradeChips({ options }) {
    if (options.length === 0)
        return null;
    return (_jsx("span", { className: "nsd-safe-chips", children: options.map((opt, i) => (_jsx("code", { className: i === 0 ? 'nsd-mono nsd-safe-chip nsd-safe-chip-rec' : 'nsd-mono nsd-safe-chip', title: opt.label, children: i === 0 ? `★ ${opt.version}` : opt.version }, opt.version))) }));
}
function HeaderStatusBadge({ status }) {
    const labels = {
        ok: 'OK',
        warning: 'Warning',
        missing: 'Missing',
        na: 'N/A',
    };
    return _jsx("span", { className: `nsd-badge nsd-badge-header-${status}`, children: labels[status] });
}
function AppCheckBadge({ status }) {
    const labels = {
        pass: 'Pass',
        warn: 'Warning',
        fail: 'Fail',
        na: 'N/A',
    };
    return _jsx("span", { className: `nsd-badge nsd-badge-app-${status}`, children: labels[status] });
}
function Donut({ counts }) {
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
    return (_jsxs("div", { className: "nsd-donut-wrap", children: [_jsxs("svg", { className: "nsd-donut", viewBox: "0 0 140 140", role: "img", "aria-label": "Vulnerabilities by severity", children: [_jsx("circle", { cx: "70", cy: "70", r: radius, fill: "none", stroke: "var(--nsd-track)", strokeWidth: "18" }), total > 0 &&
                        segments
                            .filter((s) => s.len > 0)
                            .map((s) => (_jsx("circle", { cx: "70", cy: "70", r: radius, fill: "none", stroke: SEVERITY_COLORS[s.sev], strokeWidth: "18", strokeDasharray: `${s.len} ${circumference - s.len}`, strokeDashoffset: -s.offset, transform: "rotate(-90 70 70)" }, s.sev))), _jsx("text", { x: "70", y: "68", textAnchor: "middle", className: "nsd-donut-number", children: total }), _jsx("text", { x: "70", y: "86", textAnchor: "middle", className: "nsd-donut-label", children: "issues" })] }), _jsx("ul", { className: "nsd-legend", children: ALL_SEVERITIES.map((sev) => (_jsxs("li", { children: [_jsx("span", { className: "nsd-dot", style: { background: SEVERITY_COLORS[sev] } }), severityLabel(sev), _jsx("strong", { children: counts[sev] })] }, sev))) })] }));
}
export function SecurityDashboard({ endpoint = '/api/security-scan', refreshIntervalMs = 0, initialReport, }) {
    const [report, setReport] = useState(initialReport ?? null);
    const [loading, setLoading] = useState(!initialReport);
    const [error, setError] = useState(null);
    const [tab, setTab] = useState('vulns');
    const [dark, setDark] = useState(false);
    // Filters
    const [query, setQuery] = useState('');
    const [sevFilter, setSevFilter] = useState([...ALL_SEVERITIES]);
    const [fixableOnly, setFixableOnly] = useState(false);
    const [directFilter, setDirectFilter] = useState('all');
    const [envFilter, setEnvFilter] = useState('all');
    const [sortKey, setSortKey] = useState('severity');
    const [expanded, setExpanded] = useState(null);
    const [pkgQuery, setPkgQuery] = useState('');
    const [vulnOnly, setVulnOnly] = useState(false);
    useEffect(() => {
        if (typeof window !== 'undefined' && window.matchMedia) {
            setDark(window.matchMedia('(prefers-color-scheme: dark)').matches);
        }
    }, []);
    const load = useCallback(async (fresh) => {
        setLoading(true);
        setError(null);
        try {
            const sep = endpoint.includes('?') ? '&' : '?';
            const res = await fetch(`${endpoint}${fresh ? `${sep}fresh=1` : ''}`, {
                cache: 'no-store',
            });
            const data = (await res.json());
            if (!res.ok) {
                throw new Error(data?.error?.message ?? `Scan request failed (${res.status})`);
            }
            setReport(data);
        }
        catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load the security report.');
        }
        finally {
            setLoading(false);
        }
    }, [endpoint]);
    useEffect(() => {
        if (!initialReport)
            void load(false);
    }, [initialReport, load]);
    useEffect(() => {
        if (refreshIntervalMs > 0) {
            const id = setInterval(() => void load(false), refreshIntervalMs);
            return () => clearInterval(id);
        }
        return undefined;
    }, [refreshIntervalMs, load]);
    const filteredVulns = useMemo(() => {
        if (!report)
            return [];
        const q = query.trim().toLowerCase();
        const list = report.vulnerabilities.filter((v) => {
            if (!sevFilter.includes(v.severity))
                return false;
            if (fixableOnly && !v.fixAvailable)
                return false;
            if (directFilter === 'direct' && !v.isDirect)
                return false;
            if (directFilter === 'transitive' && v.isDirect)
                return false;
            if (envFilter === 'prod' && v.isDev)
                return false;
            if (envFilter === 'dev' && !v.isDev)
                return false;
            if (q) {
                const hay = `${v.packageName} ${v.advisories.map((a) => a.title).join(' ')} ${v.advisories
                    .flatMap((a) => a.cveIds)
                    .join(' ')}`.toLowerCase();
                if (!hay.includes(q))
                    return false;
            }
            return true;
        });
        return [...list].sort((a, b) => {
            if (sortKey === 'name')
                return a.packageName.localeCompare(b.packageName);
            if (sortKey === 'upgrade') {
                if (!a.recommendedUpgrade && b.recommendedUpgrade)
                    return 1;
                if (a.recommendedUpgrade && !b.recommendedUpgrade)
                    return -1;
                return (a.recommendedUpgrade ?? '').localeCompare(b.recommendedUpgrade ?? '');
            }
            return (SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
                a.packageName.localeCompare(b.packageName));
        });
    }, [report, query, sevFilter, fixableOnly, directFilter, envFilter, sortKey]);
    const filteredPackages = useMemo(() => {
        if (!report)
            return [];
        const q = pkgQuery.trim().toLowerCase();
        return report.packages.filter((p) => {
            if (vulnOnly && !p.vulnerable)
                return false;
            if (directFilter === 'direct' && !p.isDirect)
                return false;
            if (directFilter === 'transitive' && p.isDirect)
                return false;
            if (envFilter === 'prod' && p.isDev)
                return false;
            if (envFilter === 'dev' && !p.isDev)
                return false;
            if (q && !p.name.toLowerCase().includes(q))
                return false;
            return true;
        });
    }, [report, pkgQuery, vulnOnly, directFilter, envFilter]);
    const toggleSeverity = (sev) => {
        setSevFilter((prev) => prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev]);
    };
    const exportJson = () => {
        if (!report)
            return;
        downloadBlob('security-report.json', JSON.stringify(report, null, 2), 'application/json');
    };
    const exportCsv = () => {
        if (!report)
            return;
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
        const rows = report.vulnerabilities.map((v) => {
            const ids = [
                ...v.advisories.flatMap((a) => a.cveIds),
                ...v.advisories.map((a) => a.ghsaId).filter((x) => !!x),
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
        downloadBlob('security-report.csv', [header.map(csvCell).join(','), ...rows].join('\n'), 'text/csv');
    };
    const scanFailed = !!report?.error && report.source === 'none' && report.packages.length === 0;
    return (_jsxs("div", { className: "nsd-dashboard", "data-nsd-theme": dark ? 'dark' : 'light', children: [_jsxs("header", { className: "nsd-header", children: [_jsxs("div", { children: [_jsx("h1", { className: "nsd-title", children: "Security Dashboard" }), _jsxs("p", { className: "nsd-subtitle", children: [report?.appName ? (_jsxs(_Fragment, { children: [_jsx("code", { children: report.appName }), " \u00B7", ' '] })) : null, "Dependency vulnerabilities & security headers", report ? (_jsxs(_Fragment, { children: [' ', "\u00B7 scanned", ' ', new Date(report.generatedAt).toLocaleString(), " via ", report.toolVersions.scanner] })) : null] })] }), _jsxs("div", { className: "nsd-header-actions", children: [_jsx("button", { type: "button", className: "nsd-btn", onClick: () => setDark((d) => !d), children: dark ? '☀️ Light' : '🌙 Dark' }), _jsx("button", { type: "button", className: "nsd-btn", onClick: () => void load(true), disabled: loading, children: loading ? 'Scanning…' : '↻ Re-scan' }), _jsx("button", { type: "button", className: "nsd-btn", onClick: exportJson, disabled: !report, children: "\u2193 JSON" }), _jsx("button", { type: "button", className: "nsd-btn", onClick: exportCsv, disabled: !report, children: "\u2193 CSV" })] })] }), loading && !report && (_jsxs("div", { className: "nsd-skeleton-wrap", "aria-busy": "true", children: [_jsx("div", { className: "nsd-skeleton nsd-skeleton-cards" }), _jsx("div", { className: "nsd-skeleton nsd-skeleton-table" }), _jsx("div", { className: "nsd-skeleton nsd-skeleton-table" }), _jsx("p", { className: "nsd-muted", children: "Running npm audit & checking security headers\u2026" })] })), error && !report && (_jsxs("div", { className: "nsd-error", role: "alert", children: [_jsx("strong", { children: "Scan failed." }), " ", error, _jsx("div", { children: _jsx("button", { type: "button", className: "nsd-btn nsd-btn-primary", onClick: () => void load(true), children: "Retry" }) })] })), report && scanFailed && (_jsxs("div", { className: "nsd-error", role: "alert", children: [_jsx("strong", { children: "Scan failed." }), " ", report.error?.message, ' ', report.error?.detail ? _jsx("span", { className: "nsd-muted", children: report.error.detail }) : null, _jsx("div", { children: _jsx("button", { type: "button", className: "nsd-btn nsd-btn-primary", onClick: () => void load(true), children: "Retry" }) })] })), report && !scanFailed && (_jsxs(_Fragment, { children: [report.error && (_jsxs("div", { className: "nsd-notice", role: "status", children: [_jsx("strong", { children: "Note:" }), " ", report.error.message] })), _jsxs("section", { className: "nsd-cards", "aria-label": "Summary", children: [_jsxs("div", { className: "nsd-card", children: [_jsx("span", { className: "nsd-card-label", children: "Packages" }), _jsx("span", { className: "nsd-card-value", children: report.counts.total }), _jsxs("span", { className: "nsd-card-sub", children: [report.packages.filter((p) => p.isDirect).length, " direct \u00B7", ' ', report.packages.filter((p) => !p.isDirect).length, " transitive"] })] }), _jsxs("div", { className: "nsd-card", children: [_jsx("span", { className: "nsd-card-label", children: "Vulnerable" }), _jsx("span", { className: "nsd-card-value", children: report.counts.vulnerable }), _jsxs("span", { className: "nsd-card-sub", children: [report.counts.fixable, " with an available fix"] })] }), _jsx("div", { className: "nsd-card nsd-card-donut", children: _jsx(Donut, { counts: report.counts }) }), _jsxs("div", { className: "nsd-card", children: [_jsx("span", { className: "nsd-card-label", children: "Header score" }), _jsxs("span", { className: "nsd-card-value", children: [report.headers?.score ?? '—', report.headers?.score != null ? _jsx("span", { className: "nsd-card-unit", children: "/100" }) : null] }), _jsx("span", { className: "nsd-card-sub", children: report.headers
                                            ? report.headers.checks.filter((c) => c.status === 'ok').length +
                                                ' of ' +
                                                report.headers.checks.filter((c) => c.status !== 'na').length +
                                                ' headers OK'
                                            : 'Header check unavailable' })] })] }), report.vulnerabilities.length === 0 && (_jsxs("div", { className: "nsd-empty", role: "status", children: [_jsx("div", { className: "nsd-empty-emoji", children: "\uD83C\uDF89" }), _jsx("strong", { children: "No vulnerabilities found." }), _jsxs("p", { children: [report.source === 'npm-audit'
                                        ? 'npm audit reported no known vulnerabilities for the installed dependencies.'
                                        : 'The OSV.dev fallback found no known vulnerabilities for the installed dependencies.', ' ', "Keep it that way \u2014 re-scan after every dependency change."] })] })), _jsxs("nav", { className: "nsd-tabs", "aria-label": "Dashboard sections", children: [_jsxs("button", { type: "button", className: tab === 'vulns' ? 'nsd-tab nsd-tab-active' : 'nsd-tab', onClick: () => setTab('vulns'), children: ["Vulnerabilities (", report.counts.vulnerable, ")"] }), _jsxs("button", { type: "button", className: tab === 'packages' ? 'nsd-tab nsd-tab-active' : 'nsd-tab', onClick: () => setTab('packages'), children: ["Packages (", report.counts.total, ")"] }), _jsx("button", { type: "button", className: tab === 'headers' ? 'nsd-tab nsd-tab-active' : 'nsd-tab', onClick: () => setTab('headers'), children: "Security headers" }), _jsxs("button", { type: "button", className: tab === 'appsec' ? 'nsd-tab nsd-tab-active' : 'nsd-tab', onClick: () => setTab('appsec'), children: ["App security", report.appSecurity
                                        ? ` (${report.appSecurity.counts.fail + report.appSecurity.counts.warn})`
                                        : ''] })] }), tab === 'vulns' && (_jsxs("section", { "aria-label": "Vulnerabilities", children: [_jsxs("div", { className: "nsd-filters", children: [_jsx("input", { className: "nsd-input", type: "search", placeholder: "Search package, advisory or CVE\u2026", value: query, onChange: (e) => setQuery(e.target.value), "aria-label": "Search vulnerabilities" }), _jsx("div", { className: "nsd-chip-row", "aria-label": "Severity filter", children: ALL_SEVERITIES.map((sev) => (_jsxs("button", { type: "button", className: sevFilter.includes(sev) ? 'nsd-chip nsd-chip-on' : 'nsd-chip', onClick: () => toggleSeverity(sev), "aria-pressed": sevFilter.includes(sev), children: [_jsx("span", { className: "nsd-dot", style: { background: SEVERITY_COLORS[sev] } }), severityLabel(sev)] }, sev))) }), _jsxs("label", { className: "nsd-check", children: [_jsx("input", { type: "checkbox", checked: fixableOnly, onChange: (e) => setFixableOnly(e.target.checked) }), ' ', "Fixable only"] }), _jsxs("select", { className: "nsd-select", value: directFilter, onChange: (e) => setDirectFilter(e.target.value), "aria-label": "Direct or transitive", children: [_jsx("option", { value: "all", children: "Direct + transitive" }), _jsx("option", { value: "direct", children: "Direct only" }), _jsx("option", { value: "transitive", children: "Transitive only" })] }), _jsxs("select", { className: "nsd-select", value: envFilter, onChange: (e) => setEnvFilter(e.target.value), "aria-label": "Production or development", children: [_jsx("option", { value: "all", children: "Prod + dev" }), _jsx("option", { value: "prod", children: "Production only" }), _jsx("option", { value: "dev", children: "Dev only" })] }), _jsxs("select", { className: "nsd-select", value: sortKey, onChange: (e) => setSortKey(e.target.value), "aria-label": "Sort vulnerabilities", children: [_jsx("option", { value: "severity", children: "Sort: severity" }), _jsx("option", { value: "name", children: "Sort: package name" }), _jsx("option", { value: "upgrade", children: "Sort: recommended upgrade" })] })] }), filteredVulns.length === 0 ? (_jsx("p", { className: "nsd-muted nsd-empty-note", children: "No vulnerabilities match the current filters." })) : (_jsx("div", { className: "nsd-table-wrap", children: _jsxs("table", { className: "nsd-table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "Package" }), _jsx("th", { children: "Installed" }), _jsx("th", { children: "Severity" }), _jsx("th", { children: "Type" }), _jsx("th", { children: "Advisory" }), _jsx("th", { children: "Safe upgrades" }), _jsx("th", { "aria-label": "Expand" })] }) }), _jsx("tbody", { children: filteredVulns.map((v) => {
                                                const key = `${v.packageName}@${v.installedVersion}`;
                                                const isOpen = expanded === key;
                                                return [
                                                    _jsxs("tr", { className: "nsd-row-main", children: [_jsx("td", { children: _jsx("code", { className: "nsd-mono", children: v.packageName }) }), _jsx("td", { children: _jsx("code", { className: "nsd-mono", children: v.installedVersion }) }), _jsx("td", { children: _jsx(SeverityBadge, { severity: v.severity }) }), _jsxs("td", { children: [_jsx("span", { className: "nsd-tag", children: v.isDirect ? 'direct' : 'transitive' }), ' ', _jsx("span", { className: "nsd-tag", children: v.isDev ? 'dev' : 'prod' })] }), _jsxs("td", { className: "nsd-advisory-cell", children: [v.advisories[0]?.title ?? '—', v.advisories.length > 1 ? (_jsxs("span", { className: "nsd-muted", children: [" +", v.advisories.length - 1, " more"] })) : null] }), _jsx("td", { children: v.safeUpgradeOptions.length > 0 ? (_jsx(SafeUpgradeChips, { options: v.safeUpgradeOptions })) : v.recommendedUpgrade ? (_jsx("code", { className: "nsd-mono", children: v.recommendedUpgrade })) : v.fixAvailable ? (_jsx("span", { className: "nsd-muted", children: "via npm audit fix" })) : (_jsx("span", { className: "nsd-muted", children: "no fix available" })) }), _jsx("td", { children: _jsx("button", { type: "button", className: "nsd-btn nsd-btn-sm", onClick: () => setExpanded(isOpen ? null : key), "aria-expanded": isOpen, children: isOpen ? 'Hide' : 'Details' }) })] }, key),
                                                    isOpen ? (_jsx("tr", { className: "nsd-row-detail", children: _jsx("td", { colSpan: 7, children: _jsxs("div", { className: "nsd-detail", children: [_jsxs("dl", { children: [_jsxs("div", { children: [_jsx("dt", { children: "Vulnerable range" }), _jsx("dd", { children: _jsx("code", { className: "nsd-mono", children: v.vulnerableRange || '—' }) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Safe upgrade options" }), _jsx("dd", { children: v.safeUpgradeOptions.length ? (v.safeUpgradeOptions.map((opt) => (_jsxs("span", { className: "nsd-safe-opt", children: [_jsx("code", { className: "nsd-mono nsd-code-chip", children: opt.version }), _jsx("span", { className: "nsd-muted", children: opt.label })] }, opt.version)))) : (_jsx("span", { className: "nsd-muted", children: "none known" })) })] }), _jsxs("div", { children: [_jsx("dt", { children: "Patched versions" }), _jsx("dd", { children: v.patchedVersions.length ? (v.patchedVersions.map((p) => (_jsx("code", { className: "nsd-mono nsd-code-chip", children: p }, p)))) : (_jsx("span", { className: "nsd-muted", children: "none known" })) })] }), !v.isDirect && v.pulledInBy.length > 0 && (_jsxs("div", { children: [_jsx("dt", { children: "Pulled in by" }), _jsx("dd", { children: v.pulledInBy.map((d) => (_jsx("code", { className: "nsd-mono nsd-code-chip", children: d }, d))) })] }))] }), _jsx("h4", { className: "nsd-detail-heading", children: "Advisories" }), _jsx("ul", { className: "nsd-advisory-list", children: v.advisories.map((a, i) => (_jsxs("li", { children: [_jsx(SeverityBadge, { severity: a.severity }), ' ', _jsx("strong", { children: a.title }), ' ', a.cvssScore != null && (_jsxs("span", { className: "nsd-muted", children: ["CVSS ", a.cvssScore] })), a.cwe.length > 0 && (_jsxs("span", { className: "nsd-muted", children: [' ', "\u00B7 ", a.cwe.join(', ')] })), _jsxs("div", { className: "nsd-links", children: [a.ghsaId && (_jsxs("a", { href: `https://github.com/advisories/${a.ghsaId}`, target: "_blank", rel: "noreferrer", children: [a.ghsaId, " \u2197"] })), a.cveIds.map((cve) => (_jsxs("a", { href: `https://nvd.nist.gov/vuln/detail/${cve}`, target: "_blank", rel: "noreferrer", children: [cve, " \u2197"] }, cve))), a.url && !a.ghsaId && (_jsx("a", { href: a.url, target: "_blank", rel: "noreferrer", children: "Advisory \u2197" })), _jsxs("span", { className: "nsd-muted", children: ["via ", a.source] })] })] }, `${a.title}-${i}`))) }), v.fixCommand && (_jsxs("div", { className: "nsd-fix", children: [_jsx("code", { className: "nsd-mono nsd-fix-cmd", children: v.fixCommand }), _jsx(CopyButton, { text: v.fixCommand, label: "Copy fix command" })] }))] }) }) }, `${key}-detail`)) : null,
                                                ];
                                            }) })] }) }))] })), tab === 'packages' && (_jsxs("section", { "aria-label": "Package inventory", children: [_jsxs("div", { className: "nsd-filters", children: [_jsx("input", { className: "nsd-input", type: "search", placeholder: "Search packages\u2026", value: pkgQuery, onChange: (e) => setPkgQuery(e.target.value), "aria-label": "Search packages" }), _jsxs("label", { className: "nsd-check", children: [_jsx("input", { type: "checkbox", checked: vulnOnly, onChange: (e) => setVulnOnly(e.target.checked) }), ' ', "Vulnerable only"] }), _jsxs("select", { className: "nsd-select", value: directFilter, onChange: (e) => setDirectFilter(e.target.value), "aria-label": "Direct or transitive", children: [_jsx("option", { value: "all", children: "Direct + transitive" }), _jsx("option", { value: "direct", children: "Direct only" }), _jsx("option", { value: "transitive", children: "Transitive only" })] }), _jsxs("select", { className: "nsd-select", value: envFilter, onChange: (e) => setEnvFilter(e.target.value), "aria-label": "Production or development", children: [_jsx("option", { value: "all", children: "Prod + dev" }), _jsx("option", { value: "prod", children: "Production only" }), _jsx("option", { value: "dev", children: "Dev only" })] })] }), _jsx("div", { className: "nsd-table-wrap", children: _jsxs("table", { className: "nsd-table", children: [_jsx("thead", { children: _jsxs("tr", { children: [_jsx("th", { children: "Package" }), _jsx("th", { children: "Version" }), _jsx("th", { children: "Type" }), _jsx("th", { children: "Status" })] }) }), _jsxs("tbody", { children: [filteredPackages.map((p) => (_jsxs("tr", { children: [_jsx("td", { children: _jsx("code", { className: "nsd-mono", children: p.name }) }), _jsx("td", { children: _jsx("code", { className: "nsd-mono", children: p.version }) }), _jsxs("td", { children: [_jsx("span", { className: "nsd-tag", children: p.isDirect ? 'direct' : 'transitive' }), ' ', _jsx("span", { className: "nsd-tag", children: p.isDev ? 'dev' : 'prod' })] }), _jsx("td", { children: p.vulnerable ? (_jsx("span", { className: "nsd-vuln-flags", children: p.severities.map((s, i) => (_jsx(SeverityBadge, { severity: s }, `${s}-${i}`))) })) : (_jsx("span", { className: "nsd-muted", children: "clean" })) })] }, `${p.name}@${p.version}`))), filteredPackages.length === 0 && (_jsx("tr", { children: _jsx("td", { colSpan: 4, className: "nsd-muted", children: "No packages match the current filters." }) }))] })] }) })] })), tab === 'headers' && (_jsx("section", { "aria-label": "Security headers", children: !report.headers || report.headers.error ? (_jsxs("div", { className: "nsd-error", role: "alert", children: [_jsx("strong", { children: "Header check unavailable." }), ' ', report.headers?.error ??
                                    'The header check did not return data. Re-scan to try again.'] })) : (_jsxs(_Fragment, { children: [_jsxs("div", { className: "nsd-headers-meta", children: [_jsxs("span", { children: ["Checked ", _jsx("code", { className: "nsd-mono", children: report.headers.url }), " \u00B7 HTTP", ' ', report.headers.statusCode ?? '—', " \u00B7 score", ' ', _jsxs("strong", { children: [report.headers.score, "/100"] })] }), _jsx("span", { className: "nsd-muted", children: "Fetched with cache disabled so it reflects the current configuration." })] }), _jsx("div", { className: "nsd-header-cards", children: report.headers.checks.map((check) => (_jsxs("article", { className: "nsd-header-card", children: [_jsxs("div", { className: "nsd-header-card-top", children: [_jsx("h3", { className: "nsd-header-card-name", children: check.displayName }), _jsx(HeaderStatusBadge, { status: check.status })] }), _jsx("p", { className: "nsd-header-card-value", children: check.value != null ? (_jsx("code", { className: "nsd-mono", children: check.value })) : (_jsx("span", { className: "nsd-muted", children: "not sent" })) }), _jsx("p", { className: "nsd-header-card-expl", children: check.explanation }), check.status !== 'ok' && (_jsxs("details", { className: "nsd-fix-details", children: [_jsx("summary", { children: "Show fix (next.config.js)" }), _jsx("pre", { className: "nsd-code", children: _jsx("code", { children: check.fixSnippet }) }), _jsx(CopyButton, { text: check.fixSnippet, label: "Copy snippet" })] }))] }, check.header))) })] })) })), tab === 'appsec' && (_jsx("section", { "aria-label": "App security", children: !report.appSecurity ? (_jsxs("div", { className: "nsd-error", role: "alert", children: [_jsx("strong", { children: "App security analysis was not run." }), " Enable it with the handler option ", _jsx("code", { className: "nsd-mono", children: "includeAppChecks: true" }), "."] })) : (_jsxs(_Fragment, { children: [report.appSecurity.error && (_jsxs("div", { className: "nsd-notice", role: "status", children: [_jsx("strong", { children: "Note:" }), " ", report.appSecurity.error] })), _jsxs("div", { className: "nsd-headers-meta", children: [_jsxs("span", { children: ["Scanned ", _jsx("strong", { children: report.appSecurity.filesScanned }), " source file(s) \u00B7 ", report.appSecurity.counts.pass, " passed,", ' ', report.appSecurity.counts.warn, " warnings,", ' ', report.appSecurity.counts.fail, " failures"] }), _jsxs("span", { className: "nsd-muted", children: ["Static findings are heuristics \u2014 review each one. Runtime checks ran against ", report.appSecurity.origin ?? 'no origin', "."] })] }), _jsx("div", { className: "nsd-header-cards", children: report.appSecurity.checks.map((check) => (_jsxs("article", { className: "nsd-header-card", children: [_jsxs("div", { className: "nsd-header-card-top", children: [_jsx("h3", { className: "nsd-header-card-name", children: check.title }), _jsxs("span", { children: [_jsx(AppCheckBadge, { status: check.status }), ' ', check.severity && _jsx(SeverityBadge, { severity: check.severity })] })] }), _jsx("p", { className: "nsd-header-card-expl", children: check.summary }), _jsx("p", { children: _jsx("span", { className: "nsd-tag", children: check.category }) }), check.evidence.length > 0 && (_jsx("ul", { className: "nsd-check-evidence", children: check.evidence.map((e, i) => (_jsx("li", { children: _jsx("code", { className: "nsd-mono", children: e }) }, i))) })), check.locations.length > 0 && (_jsx("div", { className: "nsd-check-loc", children: check.locations.map((l) => (_jsxs("div", { children: [_jsxs("code", { className: "nsd-mono", children: [l.file, ":", l.line] }), ' ', _jsx("code", { className: "nsd-mono nsd-code-chip", children: l.snippet })] }, `${l.file}:${l.line}`))) })), _jsxs("details", { className: "nsd-fix-details", children: [_jsx("summary", { children: "How to fix" }), _jsx("pre", { className: "nsd-code", children: _jsx("code", { children: check.fix }) }), _jsx(CopyButton, { text: check.fix, label: "Copy fix" })] })] }, check.id))) })] })) }))] }))] }));
}
export default SecurityDashboard;
