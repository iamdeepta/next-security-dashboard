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
- **Host-app security analysis** — a static scan of the app's own source
  for XSS/injection patterns (`dangerouslySetInnerHTML`, `innerHTML`,
  `eval`, `javascript:` links, `target="_blank"` without `noopener`),
  cookie flags, `NEXT_PUBLIC_` secrets and the `poweredByHeader` setting,
  plus runtime checks of the running app: framework/server version
  exposure, iframe framing (clickjacking), cookie `Secure`/`HttpOnly`/
  `SameSite` flags, public source maps and generator meta tags. Every
  finding names the file and line and ships a fix.
- **Scan progress** — while a scan runs, the dashboard shows a stage-based
  progress bar with a percentage, so a slow scan never looks frozen. The
  percentage is estimated from elapsed time (`npm audit` is usually the
  slowest step) and reaches 100% only when the report arrives; if a scan
  takes over 4 minutes the dashboard stops and offers a retry.

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

## Automatic setup (recommended)

Installing the package asks you to choose — but only when the install is
interactive (a real terminal). Non-interactive installs (CI, scripts) only
print a hint and add nothing.

- **Automatic** — creates the API route, the `/security` page and the
  stylesheet import in your project. Existing files are never overwritten.
- **Manual** — adds nothing; wire it up yourself with the 3 files below.

The same choice is available anytime after installing:

```bash
npx next-security-dashboard setup            # ask: automatic or manual
npx next-security-dashboard setup --auto     # scaffold without asking
npx next-security-dashboard setup --manual   # print the manual steps only
npx next-security-dashboard setup --dry-run  # preview what --auto would do
```

`NSD_SETUP=auto|manual|skip` overrides the prompt (useful for scripts and
CI). Automatic setup supports the App Router (`app/` or `src/app/`,
TypeScript or JavaScript); Pages Router projects get the manual steps.

## Uninstall

`npm uninstall` alone does **not** remove the scaffolded files — npm does not
run uninstall hooks, so the cleanup command below is the way to remove them
(it works before or after uninstalling; after uninstalling, `npx` fetches the
package to run it). It deletes the scaffolded API route and `/security` page
and removes the stylesheet import line from the root layout — the layout file
itself is always kept. A file you edited after setup is left untouched (and
reported), so customised code is never deleted. Pure line-ending changes
(CRLF vs LF, e.g. from a Windows editor) do not count as an edit.

```bash
npx next-security-dashboard uninstall            # remove scaffolded files
npx next-security-dashboard uninstall --dry-run  # preview what would go
```

## Manual wiring (3 small files)

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
  includeAppChecks: true,    // also analyse the host app's own source + runtime behaviour
  auditTimeoutMs: 120_000,   // timeout for `npm audit`
  enableOsvFallback: false,  // OFF by default; opt in to fall back to a vulnerability database when npm audit fails
  enableSafeUpgradeLookup: true, // list every safe upgrade version (registry lookup)
  includeNotices: false,     // OFF by default; opt in to show the scan notice banner (e.g. when npm audit fails and the fallback is used)
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
(abbreviated metadata, so even very large packages stay fast) and lists
every version that is safe to upgrade to: the smallest version that fixes
all advisories, the latest safe patch within the installed minor line, the
latest safe version within the installed major line, and the latest safe
version overall (plain releases only, deprecated versions excluded). The
smallest option is the recommended upgrade. When the registry cannot be
reached (or `enableSafeUpgradeLookup: false`), the table falls back to the
patched versions known from the advisories — but only versions at or above
the fix floor (the highest patched version across all advisories for that
package), so a version that fixes one advisory and leaves others open is
never listed as safe; the scanner also fetches the tiny `/latest` document
so the latest safe stable version is shown even when the full version list
cannot be downloaded.

**Vulnerabilities — fallback (off by default).** If `enableOsvFallback: true`
is passed and `npm audit` fails or is unavailable, the scanner queries the
OSV.dev `querybatch` API once per installed `package@version` (which returns
only vulnerability IDs), then fetches the full record for each ID (`/v1/vulns/{id}`) to read the summary,
severity, SEMVER `introduced`/`fixed` events, and aliases, and recommends
the smallest fixed version above the installed one. The dashboard header
no longer names the fallback source in the "scanned … via …" line. When
audit fails and the fallback is used, the report carries an advisory
notice — but it is only shown as a banner when the handler is created
with `includeNotices: true`; by default the banner is hidden. A total scan
failure (both audit and fallback failing) is always reported, so a failed
scan never looks like a clean one. Severity comes from the
record's `database_specific.severity` when present, otherwise from a CVSS
3.1 base-score computed from the vector. Requests use global `fetch`, with
a `curl` fallback for proxied environments where Node's fetch cannot reach
the internet directly. If the OSV.dev API is unreachable too, the report
carries a structured `error: { code: 'SCAN_FAILED', message, detail }` and
the UI shows a retry state instead of pretending the app is clean.

**When `npm audit` cannot run.** With the fallback off, an unusable audit
result no longer reports a bare "did not return usable data": the report's
error names the underlying reason and npm's own error text is kept beside
it (shown in the UI as a banner only when `includeNotices: true`). The common reasons are a missing `package-lock.json` (`npm audit`
needs one — run `npm install`, or pass `enableOsvFallback: true`), the
audit timing out (`auditTimeoutMs`, default 120s), a registry login or
network failure, and an old npm (<= 6) audit format, which is parsed
directly.

**Security headers.** The handler fetches the app's own origin with
`cache: 'no-store'` and analyses the response headers. The request is made
directly over HTTP, not through the app's global `fetch`, so a fetch
monkey-patch in the host app (for example a request-logging
`instrumentation.ts` that rebuilds responses) cannot hide the headers the
server actually sends. The origin is the
URL of the incoming request — the server actually being viewed — unless
`NEXT_SECURITY_DASHBOARD_URL` is set, which explicitly overrides it (e.g.
to check a different deployment on purpose). Only when the request URL has
no usable origin does it fall back to `NEXT_PUBLIC_APP_URL`, then
`VERCEL_URL`, so a stale app URL in the environment can never silently
redirect the checks to another server:

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

## Host-app security analysis

`analyzeAppSecurity(appRoot, { origin })` (also run automatically by the
route handler, which passes the request origin) checks the app itself:

**Static source scan** (up to 400 source files under the app root, excluding
`node_modules`, `.next`, `dist` and `public`). Each pattern is a heuristic —
review every finding before changing code:

| Check | What it flags |
| --- | --- |
| `dangerouslySetInnerHTML` | Raw HTML inserted into the page (XSS if user-controlled) |
| `innerHTML` / `document.write` | Direct DOM HTML writes bypassing React's escaping |
| `eval` / `new Function` | Strings executed as code |
| `javascript:` links | Links that run script on click |
| `document.cookie` writes | Cookies set from JavaScript (cannot be `HttpOnly`) |
| `cookies().set(…)` flags | Server cookies missing `httpOnly` / `secure` |
| `NEXT_PUBLIC_*` secrets | Variables whose names look like secrets, inlined into the browser bundle |
| `target="_blank"` | Links without `rel="noopener"` (tabnabbing) |
| `poweredByHeader` | `next.config` not disabling the `X-Powered-By` header |

**Runtime checks** (against the running app's origin): framework/server
version headers, iframe framing, cookie flags on `Set-Cookie` responses,
publicly reachable JavaScript source maps, and generator meta tags. When no
origin is available (programmatic use without a request URL) these report
N/A. Findings carry file/line locations, evidence and a fix; the dashboard
shows them on the **App security** tab.

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
