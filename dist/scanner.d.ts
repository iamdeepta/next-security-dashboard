import type { SecurityReport } from './types.js';
export interface ScanOptions {
    /** App root to scan. Defaults to process.cwd(). */
    appRoot?: string;
    /** Timeout for `npm audit` in ms. Defaults to 120000. */
    auditTimeoutMs?: number;
    /** When npm audit fails, fall back to the OSV.dev API. Defaults to true. */
    enableOsvFallback?: boolean;
}
export declare function scanDependencies(appRoot: string, options?: ScanOptions): Promise<SecurityReport>;
