import type { SecurityReport } from './types.js';
export interface ScanOptions {
    /** App root to scan. Defaults to process.cwd(). */
    appRoot?: string;
    /** Timeout for `npm audit` in ms. Defaults to 120000. */
    auditTimeoutMs?: number;
    /** When npm audit fails, fall back to a vulnerability-database check. Defaults to false. */
    enableOsvFallback?: boolean;
    /**
     * Look up published versions on the npm registry to list every safe
     * upgrade option per vulnerability. Defaults to true. When disabled
     * (or the registry is unreachable) only the patched versions known
     * from the advisories are listed.
     */
    enableSafeUpgradeLookup?: boolean;
}
export declare function scanDependencies(appRoot: string, options?: ScanOptions): Promise<SecurityReport>;
