import { fetchAndAnalyzeHeaders } from './headers.js';
import { scanDependencies } from './scanner.js';
import type { ScanOptions } from './scanner.js';
import type { HeadersResult, SecurityReport } from './types.js';

export interface HandlerOptions extends ScanOptions {
  /** Cache the scan result in memory for this many ms. Defaults to 60000. */
  cacheTtlMs?: number;
  /** Whether to fetch and analyse the app's own security headers. Defaults to true. */
  includeHeaders?: boolean;
  /**
   * Optional authorization gate. The scan exposes dependency and header
   * details, so in production you should protect this route, e.g.:
   *   authorize: (req) => req.headers.get('x-admin-secret') === process.env.ADMIN_SECRET
   * Return false (or a Promise of false) to respond 401.
   */
  authorize?: (request: Request) => boolean | Promise<boolean>;
}

function deriveOrigin(request: Request, requestUrl: URL): string {
  const env = (typeof process !== 'undefined' ? process.env : {}) as Record<
    string,
    string | undefined
  >;
  if (env.NEXT_PUBLIC_APP_URL) return env.NEXT_PUBLIC_APP_URL.replace(/\/$/, '');
  if (env.VERCEL_URL) return `https://${env.VERCEL_URL}`;
  if (env.NEXT_SECURITY_DASHBOARD_URL) return env.NEXT_SECURITY_DASHBOARD_URL.replace(/\/$/, '');
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
export function createSecurityHandler(options: HandlerOptions = {}) {
  const {
    cacheTtlMs = 60000,
    includeHeaders = true,
    authorize,
    ...scanOptions
  } = options;
  let cached: { at: number; report: SecurityReport } | null = null;

  return async function GET(request: Request): Promise<Response> {
    if (authorize) {
      let allowed = false;
      try {
        allowed = await authorize(request);
      } catch {
        allowed = false;
      }
      if (!allowed) {
        return Response.json(
          {
            error: {
              code: 'UNAUTHORIZED',
              message: 'This security scan route requires authorization.',
            },
          },
          { status: 401 },
        );
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
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        const fallback: HeadersResult = {
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

    cached = { at: Date.now(), report };
    return Response.json(report);
  };
}
