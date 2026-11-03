import type { ScanOptions } from './scanner.js';
export interface HandlerOptions extends ScanOptions {
    /** Cache the scan result in memory for this many ms. Defaults to 60000. */
    cacheTtlMs?: number;
    /** Whether to fetch and analyse the app's own security headers. Defaults to true. */
    includeHeaders?: boolean;
    /**
     * Whether to analyse the host app itself (source scan for XSS/injection
     * patterns, cookie flags, exposed secrets, plus runtime checks for
     * version exposure, framing, cookies and source maps). Defaults to true.
     */
    includeAppChecks?: boolean;
    /**
     * Optional authorization gate. The scan exposes dependency and header
     * details, so in production you should protect this route, e.g.:
     *   authorize: (req) => req.headers.get('x-admin-secret') === process.env.ADMIN_SECRET
     * Return false (or a Promise of false) to respond 401.
     */
    authorize?: (request: Request) => boolean | Promise<boolean>;
}
/**
 * Route-handler factory for `app/api/security-scan/route.ts`:
 *
 * ```ts
 * import { createSecurityHandler } from 'next-security-dashboard';
 * export const dynamic = 'force-dynamic';
 * export const GET = createSecurityHandler();
 * ```
 *
 * GET returns the JSON security report. Add `?fresh=1` to bypass the cache.
 */
export declare function createSecurityHandler(options?: HandlerOptions): (request: Request) => Promise<Response>;
