import type { AppSecurityReport } from './types.js';
export interface AnalyzeOptions {
    /**
     * Origin to run the runtime checks against (e.g. "http://localhost:3000").
     * When omitted, runtime checks report "na" and only the static source
     * scan runs.
     */
    origin?: string | null;
    /** Run the runtime checks. Defaults to true when an origin is given. */
    includeRuntimeChecks?: boolean;
}
export declare function analyzeAppSecurity(appRoot: string, options?: AnalyzeOptions): Promise<AppSecurityReport>;
