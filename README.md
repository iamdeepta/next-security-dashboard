# next-security-dashboard

A beautiful, self-contained security dashboard for Next.js apps. Install it,
wire up two small files, and visiting `/security` shows:

- **Every installed package** — name, version, direct vs transitive, prod vs dev.
- **Every known vulnerability** — severity, advisory title, CVE/GHSA links,
  vulnerable range, patched versions, **every safe upgrade version**
  (smallest fix, latest safe patch/minor within the installed major line,
  and latest safe version overall, looked up on the npm registry), and the
  exact `npm install <pkg>@<version>` fix command.
- **Security-header audit** — X-Frame-Options, Strict-Transport-Security,
  X-XSS-Protection, X-Content-Type-Options, Content-Security-Policy,
  Referrer-Policy and Permissions-Policy, each with its real value, a
  plain-language explanation, an overall score, and a ready-to-paste
  `next.config.js` fix snippet.

The UI ships its own namespaced CSS (`nsd-*` classes) — **no Tailwind
required** in the host app — and includes search, severity/direct/prod-dev
filters, fixable-only toggle, sorting, expandable advisory details, JSON/CSV
export, a dark-mode toggle, and loading/error/empty states.

## Install

```bash
npm install next-security-dashboard
```

Requires Node 18+, React 18+ and Next.js 13+ (App Router) as peer
dependencies. No other runtime dependencies.

## Wiring (3 small files)

**1. API route — `app/api/security-scan/route.ts`**

```ts
import { createSecurityHandler } from 'next-security-dashboard';

export const dynamic = 'force-dynamic';

export const GET = createSecurityHandler();
```

**2. Global stylesheet — import once in your root layout (`app/layout.tsx`)**

Next.js only allows global CSS in the root layout:

```tsx
import 'next-security-dashboard/style.css';
```

**3. Page — `app/security/page.tsx`**

```tsx
import { SecurityDashboard } from 'next-security-dashboard/client';

export default function SecurityPage() {
  return (
    <main style={{ padding: 24 }}>
      <SecurityDashboard />
    </main>
  );
}
```

Then open `/security`. The dashboard fetches the report from
`/api/security-scan` (override with the `endpoint` prop) and re-scans on
demand. `?fresh=1` on the API URL bypasses the 60-second in-memory cache.

## Component props

| Prop | Default | Description |
| --- | --- | --- |
| `endpoint` | `"/api/security-scan"` | URL of the scan API route. |
| `refreshIntervalMs` | `0` | Auto-refresh interval (0 = off). |
| `initialReport` | — | Pre-fetched report; skips the client fetch. |

## Handler options

```ts
export const GET = createSecurityHandler({
  cacheTtlMs: 60_000,        // in-memory cache TTL
  includeHeaders: true,      // also audit the app's own response headers
  auditTimeoutMs: 120_000,   // timeout for `npm audit`
  enableOsvFallback: true,   // fall back to OSV.dev when npm audit fails
  enableSafeUpgradeLookup: true, // list every safe upgrade version (registry lookup)
  appRoot: process.cwd(),    // app root to scan
  authorize: (req) =>        // OPTIONAL but recommended in production
    req.headers.get('x-admin-secret') === process.env.ADMIN_SECRET,
});
```

> ⚠️ **Protect this route in production.** The report lists your exact
> dependency versions and vulnerabilities — information that helps an
> attacker. Use the `authorize` option, Next.js middleware, or keep the
> route out of production builds.

## How the scan works

**Dependency inventory.** The scanner reads the host app's `package.json`
and lockfile. `package-lock.json` is read first (name, version, `dev` flag,
and which direct dependency pulls each transitive package in). If there is
no lockfile it falls back to reading installed versions from
`node_modules`, then to the version ranges in `package.json`. `pnpm-lock.yaml`
and `yarn.lock` are not parsed directly — `npm audit` still runs against the
project, and the OSV.dev fallback resolves versions from `node_modules`.

**Vulnerabilities — primary: `npm audit`.** The handler runs
`npm audit --json` in the app root (with a timeout). Note that `npm audit`
exits non-zero whenever vulnerabilities exist — that is expected and is
*not* treated as a failure; only unparseable output counts as a failed
audit. Each entry yields: severity, direct/transitive, prod/dev, advisory
title/URL/range, and fix data (`fixAvailable.version` = the minimal patched
version, rendered as `npm install <pkg>@<version>`).

**Safe upgrade options — npm registry.** For each vulnerable package the
scanner also looks up the package's published versions on the npm registry
and lists every version that is safe to upgrade to: the smallest version
that fixes all advisories, the latest safe patch within the installed minor
line, the latest safe version within the installed major line, and the
latest safe version overall (plain releases only, deprecated versions
excluded). The smallest option is the recommended upgrade. When the
registry cannot be reached (or `enableSafeUpgradeLookup: false`), the table
falls back to the patched versions known from the advisories.

**Vulnerabilities — fallback: OSV.dev.** If `npm audit` fails or is
unavailable, the scanner queries the OSV.dev `querybatch` API once per
installed `package@version` (which returns only vulnerability IDs), then
fetches the full record for each ID (`/v1/vulns/{id}`) to read the summary,
severity, SEMVER `introduced`/`fixed` events, and aliases, and recommends
the smallest fixed version above the installed one. Severity comes from the
record's `database_specific.severity` when present, otherwise from a CVSS
3.1 base-score computed from the vector. Requests use global `fetch`, with
a `curl` fallback for proxied environments where Node's fetch cannot reach
the internet directly. If the OSV.dev API is unreachable too, the report
carries a structured `error: { code: 'SCAN_FAILED', message, detail }` and
the UI shows a retry state instead of pretending the app is clean.

**Security headers.** The handler fetches the app's own origin (from the
incoming request URL, falling back to `NEXT_PUBLIC_APP_URL`,
`NEXT_SECURITY_DASHBOARD_URL`, or `VERCEL_URL`) with `cache: 'no-store'`
and analyses the response headers:

| Header | OK | Warning | Missing |
| --- | --- | --- | --- |
| Content-Security-Policy | Restrictive script policy, no `unsafe-inline`/`unsafe-eval`/wildcards | Present but weak (unsafe-inline, wildcards, no `default-src`/`script-src`) | Not sent |
| Strict-Transport-Security | `max-age ≥ 31536000` + `includeSubDomains` | Present but short `max-age` / no `includeSubDomains` | Not sent over HTTPS |
| X-Frame-Options | `DENY` / `SAMEORIGIN` | `ALLOW-FROM` (obsolete) | Not sent |
| X-Content-Type-Options | `nosniff` | Other value | Not sent |
| X-XSS-Protection | `0` (modern recommendation) | `1…` (legacy filter) / absent | — (absent = warning) |
| Referrer-Policy | Strict value | Leaky value / absent | — (absent = warning) |
| Permissions-Policy | Present | — | Absent (warning) |

HSTS over plain `http` is reported as **N/A with an explanation**, not a
failure — the header is only meaningful over HTTPS. The header score is
0–100, weighted (CSP 30, HSTS 20, X-Frame-Options 15, X-Content-Type-Options
15, Permissions-Policy 10, X-XSS-Protection 5, Referrer-Policy 5), with
N/A headers excluded from the denominator.

## Programmatic use

```ts
import { scanDependencies, analyzeHeaders } from 'next-security-dashboard';

const report = await scanDependencies('/path/to/app');
console.log(report.counts, report.vulnerabilities[0]?.safeUpgradeOptions);
```

## Limitations

- The scan runs server-side (`npm audit` needs registry access, and the
  OSV.dev fallback needs internet). In fully offline environments both fail
  and the UI shows the structured error. The safe-upgrade registry lookup
  also needs internet; when it fails, the table falls back to the patched
  versions from the advisories.
- `npm audit` only knows about the default npm registry audit endpoint;
  private registries with their own audit data may differ.
- Advisory CVE IDs come from OSV.dev `aliases`; `npm audit` advisories
  expose the GHSA link but not the CVE list, so CVE chips may be empty for
  audit-sourced rows.
- Header checks inspect one response (the app root, following redirects).
  Per-route headers (e.g. different headers on `/api/*`) are not checked.
- App Router only. The Pages Router is not supported (the handler uses
  standard `Request`/`Response`, so it can be adapted, but the documented
  wiring targets App Router).
- The package is ESM-only (`"type": "module"`). The client component must
  be ESM for Next.js React Fast Refresh; a CommonJS build fails to compile
  in the App Router.
- Scans are cached in memory for 60s per server instance; use `?fresh=1`
  or the Re-scan button for an immediate fresh scan.

## License

MIT
