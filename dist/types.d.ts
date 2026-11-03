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
    error?: ScanError;
}
