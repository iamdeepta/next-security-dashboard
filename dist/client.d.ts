import type { SecurityReport } from './types.js';
export interface SecurityDashboardProps {
    /** API endpoint that returns the security report JSON. Defaults to "/api/security-scan". */
    endpoint?: string;
    /** Auto-refresh interval in ms. 0 (default) disables polling. */
    refreshIntervalMs?: number;
    /** Pre-fetched report (e.g. from a Server Component). When given, no fetch happens on mount. */
    initialReport?: SecurityReport;
}
export declare function SecurityDashboard({ endpoint, refreshIntervalMs, initialReport, }: SecurityDashboardProps): import("react/jsx-runtime").JSX.Element;
export default SecurityDashboard;
