import { analyzeAppSecurity } from './analyzer.js';
import { fetchAndAnalyzeHeaders } from './headers.js';
import { scanDependencies } from './scanner.js';
/**
 * Which URL the header/app checks fetch. Priority:
 * 1. NEXT_SECURITY_DASHBOARD_URL — an explicit operator override (e.g. check
 *    a different deployment on purpose).
 * 2. The origin of the incoming request — the server actually being viewed.
 *    NEXT_PUBLIC_APP_URL / VERCEL_URL must NOT win here: when they point at
 *    a different deployment (production, or a stale localhost port), the
 *    checks would keep reporting the other server's headers forever and
 *    config changes in the viewed app would appear to have no effect.
 * 3. NEXT_PUBLIC_APP_URL, then VERCEL_URL — only when the request URL has
 *    no usable origin (programmatic use without an HTTP request).
 */
function deriveOrigin(request, requestUrl) {
    const env = (typeof process !== 'undefined' ? process.env : {});
    if (env.NEXT_SECURITY_DASHBOARD_URL)
        return env.NEXT_SECURITY_DASHBOARD_URL.replace(/\/$/, '');
    if (requestUrl.origin && requestUrl.origin !== 'null')
        return requestUrl.origin;
    if (env.NEXT_PUBLIC_APP_URL)
        return env.NEXT_PUBLIC_APP_URL.replace(/\/$/, '');
    if (env.VERCEL_URL)
        return `https://${env.VERCEL_URL}`;
    return requestUrl.origin;
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
export function createSecurityHandler(options = {}) {
    const { cacheTtlMs = 60000, includeHeaders = true, includeAppChecks = true, authorize, ...scanOptions } = options;
    let cached = null;
    return async function GET(request) {
        if (authorize) {
            let allowed = false;
            try {
                allowed = await authorize(request);
            }
            catch {
                allowed = false;
            }
            if (!allowed) {
                return Response.json({
                    error: {
                        code: 'UNAUTHORIZED',
                        message: 'This security scan route requires authorization.',
                    },
                }, { status: 401 });
            }
        }
        const requestUrl = new URL(request.url);
        const fresh = requestUrl.searchParams.get('fresh') === '1';
        if (!fresh && cached && Date.now() - cached.at < cacheTtlMs) {
            return Response.json(cached.report);
        }
        const appRoot = scanOptions.appRoot ?? process.cwd();
        const report = await scanDependencies(appRoot, scanOptions);
        if (includeHeaders) {
            const origin = deriveOrigin(request, requestUrl);
            try {
                report.headers = await fetchAndAnalyzeHeaders(origin);
            }
            catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                const fallback = {
                    url: origin,
                    statusCode: null,
                    checks: [],
                    score: null,
                    fetchedAt: new Date().toISOString(),
                    error: `Header check failed: ${message}`,
                };
                report.headers = fallback;
            }
        }
        if (includeAppChecks) {
            try {
                report.appSecurity = await analyzeAppSecurity(appRoot, {
                    origin: deriveOrigin(request, requestUrl),
                });
            }
            catch (err) {
                const message = err instanceof Error ? err.message : String(err);
                const fallback = {
                    checkedAt: new Date().toISOString(),
                    appRoot,
                    origin: deriveOrigin(request, requestUrl),
                    filesScanned: 0,
                    checks: [],
                    counts: { pass: 0, warn: 0, fail: 0, na: 0 },
                    error: `App security analysis failed: ${message}`,
                };
                report.appSecurity = fallback;
            }
        }
        cached = { at: Date.now(), report };
        return Response.json(report);
    };
}
