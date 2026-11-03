export type Severity = 'critical' | 'high' | 'moderate' | 'low';
export declare const SEVERITY_ORDER: Record<Severity, number>;
export interface AdvisoryInfo {
    /** Human-readable advisory title. */
    title: string;
    /** Link to the advisory (GitHub Advisory Database / OSV), if known. */
    url: string | null;
    severity: Severity;
    /** Vulnerable version range, e.g. "<4.17.21". */
    range: string;
    cwe: string[];
    cvssScore: number | null;
    /** CVE identifiers, e.g. ["CVE-2020-8203"]. */
    cveIds: string[];
    /** GHSA identifier, e.g. "GHSA-29mw-wpgm-hmr9", if known. */
    ghsaId: string | null;
    /** Where this advisory came from: 'npm-audit' or 'osv.dev'. */
    source: string;
}
export interface SafeUpgradeOption {
    /** A published version that fixes every known advisory for this package. */
    version: string;
    /**
     * Why this version is listed, e.g. "Smallest fix", "Latest patch",
     * "Latest in v14", or "Latest".
     */
    label: string;
}
export interface Vulnerability {
    packageName: string;
    installedVersion: string;
    /** Worst severity across all advisories for this package. */
    severity: Severity;
    /** True when the package is a direct dependency of the app. */
    isDirect: boolean;
    /** True when the package is only used in development (devDependency / dev-only transitive). */
    isDev: boolean;
    /** Direct dependencies that pull this transitive package in (empty for direct deps). */
    pulledInBy: string[];
    advisories: AdvisoryInfo[];
    /** Combined vulnerable range, e.g. "<4.17.21". */
    vulnerableRange: string;
    /** Versions known to fix the vulnerability. */
    patchedVersions: string[];
    /** Minimal version that fixes it, or null when no patched version is known. */
    recommendedUpgrade: string | null;
    /**
     * Every safe version the user can upgrade to, curated from the npm
     * registry: the smallest fix, the latest safe patch/minor within the
     * installed major line, and the latest safe version overall. Empty
     * when no safe version is known. The first entry is the recommended
     * (smallest) upgrade. Falls back to the known patched versions when
     * the registry cannot be reached.
     */
    safeUpgradeOptions: SafeUpgradeOption[];
    /** Exact command to apply the recommended upgrade, or null. */
    fixCommand: string | null;
    /** Whether any fix is available at all. */
    fixAvailable: boolean;
}
export interface PackageInfo {
    name: string;
    version: string;
    isDirect: boolean;
    isDev: boolean;
    vulnerable: boolean;
    severities: Severity[];
}
export type HeaderStatus = 'ok' | 'warning' | 'missing' | 'na';
export interface HeaderCheck {
    /** Raw header name, e.g. "strict-transport-security". */
    header: string;
    displayName: string;
    status: HeaderStatus;
    /** Actual value sent by the server, or null when absent. */
    value: string | null;
    /** Plain-language explanation of what is wrong / right. */
    explanation: string;
    /** Ready-to-paste next.config.js headers() snippet for this header. */
    fixSnippet: string;
}
export interface HeadersResult {
    url: string;
    statusCode: number | null;
    checks: HeaderCheck[];
    /** 0-100 score over the checked headers (null when the fetch failed). */
    score: number | null;
    fetchedAt: string;
    error?: string;
}
export type AppCheckStatus = 'pass' | 'warn' | 'fail' | 'na';
export type AppCheckCategory = 'injection' | 'cookies' | 'exposure' | 'framing' | 'config';
export interface AppCheckLocation {
    /** Path relative to the app root, e.g. "app/page.tsx". */
    file: string;
    line: number;
    /** The matching source line, trimmed. */
    snippet: string;
}
export interface AppCheck {
    /** Stable id, e.g. "dangerous-html" or "runtime-framing". */
    id: string;
    category: AppCheckCategory;
    title: string;
    status: AppCheckStatus;
    /** Severity when the check fails or warns, null for pass/na. */
    severity: Severity | null;
    /** One-line plain-language summary of the result. */
    summary: string;
    /** Short observed facts supporting the result (header values, counts). */
    evidence: string[];
    /** How to fix the issue, or how to keep the passing state. */
    fix: string;
    /** Source locations for static findings (empty for runtime checks). */
    locations: AppCheckLocation[];
}
export interface AppSecurityReport {
    checkedAt: string;
    appRoot: string;
    /** Origin the runtime checks ran against, or null when unavailable. */
    origin: string | null;
    filesScanned: number;
    checks: AppCheck[];
    counts: {
        pass: number;
        warn: number;
        fail: number;
        na: number;
    };
    /** Set when the runtime checks could not run (e.g. origin unreachable). */
    error?: string;
}
export interface ScanError {
    code: string;
    message: string;
    detail?: string;
}
export interface SecurityReport {
    generatedAt: string;
    appName: string | null;
    appRoot: string;
    /** 'npm-audit' when npm audit supplied the data, 'osv' for the OSV.dev fallback, 'none' when both failed. */
    source: 'npm-audit' | 'osv' | 'none';
    toolVersions: {
        node: string;
        scanner: string;
    };
    packages: PackageInfo[];
    vulnerabilities: Vulnerability[];
    counts: {
        total: number;
        vulnerable: number;
        critical: number;
        high: number;
        moderate: number;
        low: number;
        fixable: number;
    };
    headers: HeadersResult | null;
    /** Host-app security analysis (source scan + runtime checks), or null when not run. */
    appSecurity: AppSecurityReport | null;
    error?: ScanError;
}
