import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { directFetch } from './direct-fetch.js';
const MAX_FILES = 400;
const MAX_FILE_BYTES = 250_000;
const SKIP_DIRS = new Set([
    'node_modules',
    '.next',
    '.git',
    'dist',
    'build',
    'coverage',
    '.turbo',
    'public',
    '.vercel',
    '.cache',
]);
const SOURCE_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.mts', '.cts']);
function lineOf(text, index) {
    let line = 1;
    for (let i = 0; i < index && i < text.length; i += 1) {
        if (text.charCodeAt(i) === 10)
            line += 1;
    }
    return line;
}
function loc(rel, lines, line) {
    return { file: rel, line, snippet: (lines[line - 1] ?? '').trim().slice(0, 200) };
}
async function collectSourceFiles(appRoot) {
    const out = [];
    const stack = [appRoot];
    while (stack.length > 0 && out.length < MAX_FILES) {
        const dir = stack.pop();
        let dirents;
        try {
            dirents = await fs.readdir(dir, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const dirent of dirents) {
            if (out.length >= MAX_FILES)
                break;
            const full = path.join(dir, dirent.name);
            if (dirent.isDirectory()) {
                if (SKIP_DIRS.has(dirent.name))
                    continue;
                stack.push(full);
                continue;
            }
            if (!dirent.isFile())
                continue;
            if (!SOURCE_EXTS.has(path.extname(dirent.name).toLowerCase()))
                continue;
            let stat;
            try {
                stat = await fs.stat(full);
            }
            catch {
                continue;
            }
            if (stat.size > MAX_FILE_BYTES)
                continue;
            let text;
            try {
                text = await fs.readFile(full, 'utf8');
            }
            catch {
                continue;
            }
            if (text.includes('\0'))
                continue; // binary
            const rel = path.relative(appRoot, full).split(path.sep).join('/');
            out.push({ rel, text, lines: text.split('\n') });
        }
    }
    return out;
}
const SIMPLE_PATTERNS = [
    {
        id: 'dangerous-html',
        category: 'injection',
        title: 'dangerouslySetInnerHTML usage',
        severity: 'high',
        regex: /dangerouslySetInnerHTML/g,
        summary: (n) => `${n} use(s) of dangerouslySetInnerHTML — raw HTML is inserted into the page. If any of it comes from user input, an attacker can run scripts in visitors' browsers (XSS).`,
        fix: 'Render user content as text (React escapes it by default). If HTML is truly required, sanitize it first with a library such as DOMPurify and keep a strong Content-Security-Policy.',
    },
    {
        id: 'inner-html',
        category: 'injection',
        title: 'innerHTML / document.write usage',
        severity: 'high',
        regex: /\.innerHTML\s*=|document\.write\s*\(/g,
        summary: (n) => `${n} direct DOM HTML write(s). Assigning HTML strings bypasses React's escaping and can execute attacker-controlled markup.`,
        fix: 'Use React rendering or textContent instead of innerHTML / document.write. If HTML must be injected, sanitize it first (e.g. DOMPurify).',
    },
    {
        id: 'code-eval',
        category: 'injection',
        title: 'eval / new Function usage',
        severity: 'high',
        regex: /\beval\s*\(|\bnew\s+Function\s*\(/g,
        summary: (n) => `${n} dynamic code execution call(s). eval and new Function run strings as code — if any part of the string comes from user input, it is remote code execution in the browser.`,
        fix: 'Avoid eval / new Function entirely. Use JSON.parse for data, or an allow-listed dispatch table for behaviour.',
    },
    {
        id: 'javascript-href',
        category: 'injection',
        title: 'javascript: URL in a link',
        severity: 'moderate',
        regex: /href\s*=\s*["'{`][^"'`{}]*javascript\s*:|href\s*=\s*\{`[^`]*javascript\s*:/gi,
        summary: (n) => `${n} link(s) with a javascript: URL. Clicking one runs script in the page context, which attackers abuse for phishing and XSS.`,
        fix: 'Use https: URLs or internal routes. Never build a link href from unsanitized user input.',
    },
    {
        id: 'document-cookie',
        category: 'cookies',
        title: 'document.cookie writes',
        severity: 'moderate',
        regex: /document\.cookie\s*=/g,
        summary: (n) => `${n} client-side cookie write(s). Cookies set from JavaScript cannot be HttpOnly, so any XSS flaw can steal them.`,
        fix: 'Set cookies on the server (Route Handler / Server Action / middleware) with HttpOnly, Secure and SameSite flags instead of document.cookie.',
    },
    {
        id: 'exposed-secret-env',
        category: 'exposure',
        title: 'Possibly secret value exposed to the browser',
        severity: 'high',
        regex: /process\.env\.(NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE|API_KEY|APIKEY)[A-Z0-9_]*)/g,
        summary: (n) => `${n} reference(s) to a NEXT_PUBLIC_ variable whose name looks like a secret. NEXT_PUBLIC_ values are inlined into the browser bundle — anyone can read them.`,
        fix: 'Move the value to a server-only environment variable (remove the NEXT_PUBLIC_ prefix) and read it only in Server Components, Route Handlers or Server Actions. Rotate the exposed value.',
    },
    {
        id: 'unsafe-blank-target',
        category: 'injection',
        title: 'target="_blank" without rel="noopener"',
        severity: 'low',
        regex: /<a[^>]*target=(["'])_blank\1[^>]*>/g,
        summary: (n) => `${n} link(s) open in a new tab without rel="noopener" on the same line (multi-line tags need a manual look). The opened page can reach window.opener and redirect the original tab (tabnabbing).`,
        fix: 'Add rel="noopener noreferrer" to every target="_blank" link.',
    },
];
function findSimpleLocations(file, regex) {
    const out = [];
    const re = new RegExp(regex.source, regex.flags);
    let match;
    while ((match = re.exec(file.text)) !== null) {
        const line = lineOf(file.text, match.index);
        out.push(loc(file.rel, file.lines, line));
        if (match[0].length === 0)
            re.lastIndex += 1;
    }
    return out;
}
/** cookies().set(…) calls whose options omit HttpOnly or Secure. */
function findUnsafeCookieSets(file) {
    const out = [];
    const re = /cookies\(\)\.set\(/g;
    let match;
    while ((match = re.exec(file.text)) !== null) {
        const window = file.text.slice(match.index, match.index + 400);
        const hasHttpOnly = /httpOnly\s*:\s*true/i.test(window);
        const hasSecure = /secure\s*:\s*true/i.test(window);
        if (!hasHttpOnly || !hasSecure) {
            const line = lineOf(file.text, match.index);
            out.push(loc(file.rel, file.lines, line));
        }
    }
    return out;
}
function checkPoweredByHeader(files) {
    const base = {
        id: 'powered-by-header',
        category: 'config',
        title: 'X-Powered-By header (Next.js version exposure)',
        severity: 'low',
        locations: [],
    };
    const configs = files.filter((f) => /^next\.config\.(js|ts|mjs|cjs|mts|cts)$/.test(f.rel));
    const disabled = configs.some((f) => /poweredByHeader\s*:\s*false/.test(f.text));
    if (disabled) {
        return {
            ...base,
            status: 'pass',
            severity: null,
            summary: 'poweredByHeader is disabled in next.config — the X-Powered-By header is not sent.',
            evidence: configs.map((f) => `${f.rel}: poweredByHeader: false`),
            fix: 'Keep poweredByHeader: false in next.config.',
        };
    }
    return {
        ...base,
        status: 'warn',
        severity: 'low',
        summary: 'Next.js sends an X-Powered-By: Next.js header by default, advertising the framework to anyone who probes the site.',
        evidence: configs.length > 0
            ? configs.map((f) => `${f.rel}: no poweredByHeader: false found`)
            : ['No next.config file found — the default applies.'],
        fix: "Set poweredByHeader: false in next.config:\n\nconst nextConfig = {\n  poweredByHeader: false,\n};",
    };
}
function staticChecks(files) {
    const checks = [];
    for (const pattern of SIMPLE_PATTERNS) {
        const locations = files.flatMap((f) => findSimpleLocations(f, pattern.regex));
        // The blank-target pattern needs its rel check: drop matches that
        // already carry noopener in the same tag.
        const filtered = pattern.id === 'unsafe-blank-target'
            ? locations.filter((l) => {
                const file = files.find((f) => f.rel === l.file);
                const line = file?.lines[l.line - 1] ?? '';
                return !/rel\s*=\s*["'][^"']*noopener/.test(line);
            })
            : locations;
        if (filtered.length === 0) {
            checks.push({
                id: pattern.id,
                category: pattern.category,
                title: pattern.title,
                status: 'pass',
                severity: null,
                summary: `No occurrences found in ${files.length} scanned file(s).`,
                evidence: [],
                fix: pattern.fix,
                locations: [],
            });
        }
        else {
            checks.push({
                id: pattern.id,
                category: pattern.category,
                title: pattern.title,
                status: pattern.severity === 'low' ? 'warn' : 'fail',
                severity: pattern.severity,
                summary: pattern.summary(filtered.length),
                evidence: [`${filtered.length} occurrence(s) in scanned source files.`],
                fix: pattern.fix,
                locations: filtered,
            });
        }
    }
    const cookieSets = files.flatMap(findUnsafeCookieSets);
    checks.push({
        id: 'cookie-set-flags',
        category: 'cookies',
        title: 'Server cookie set without HttpOnly / Secure flags',
        status: cookieSets.length === 0 ? 'pass' : 'warn',
        severity: cookieSets.length === 0 ? null : 'moderate',
        summary: cookieSets.length === 0
            ? `No cookies().set(…) calls missing flags found in ${files.length} scanned file(s).`
            : `${cookieSets.length} cookies().set(…) call(s) without HttpOnly and/or Secure in the options. Such cookies can be read by scripts or sent over plain http.`,
        evidence: cookieSets.length === 0
            ? []
            : [`${cookieSets.length} call(s) missing httpOnly: true and/or secure: true.`],
        fix: 'Pass all three flags when setting cookies:\n\ncookies().set(name, value, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });',
        locations: cookieSets,
    });
    checks.push(checkPoweredByHeader(files));
    return checks;
}
async function fetchPage(origin) {
    const target = origin.replace(/\/$/, '');
    try {
        // Direct request: a fetch monkey-patch in the host app must not be
        // able to hide what the server actually sends (see direct-fetch.ts).
        const res = await directFetch(target, { timeoutMs: 10000 });
        const html = await res.text().catch(() => '');
        return { headers: res.headers, url: res.url || target, status: res.status, html };
    }
    catch {
        return null;
    }
}
function getSetCookies(headers) {
    const anyHeaders = headers;
    if (typeof anyHeaders.getSetCookie === 'function') {
        try {
            return anyHeaders.getSetCookie();
        }
        catch {
            // fall through
        }
    }
    const raw = headers.get('set-cookie');
    return raw ? [raw] : [];
}
function parseDirectives(csp) {
    const map = new Map();
    for (const part of csp.split(';')) {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        if (tokens.length === 0)
            continue;
        map.set(tokens[0].toLowerCase(), tokens.slice(1));
    }
    return map;
}
function checkVersionHeaders(page) {
    const poweredBy = page.headers.get('x-powered-by');
    const server = page.headers.get('server');
    const evidence = [];
    if (poweredBy)
        evidence.push(`X-Powered-By: ${poweredBy}`);
    if (server)
        evidence.push(`Server: ${server}`);
    const exposesVersion = (server != null && /\d/.test(server)) || poweredBy != null;
    if (poweredBy || server) {
        return {
            id: 'runtime-version-headers',
            category: 'exposure',
            title: 'Framework / server version exposed in response headers',
            status: exposesVersion ? 'warn' : 'pass',
            severity: exposesVersion ? 'low' : null,
            summary: exposesVersion
                ? 'Response headers advertise the framework/server. Version details help attackers pick known exploits for this stack.'
                : 'Response headers do not advertise framework or server versions.',
            evidence: evidence.length > 0 ? evidence : ['No X-Powered-By or Server header observed.'],
            fix: "Set poweredByHeader: false in next.config, and strip or generalize the Server header at the reverse proxy / hosting layer (never include software versions).",
            locations: [],
        };
    }
    return {
        id: 'runtime-version-headers',
        category: 'exposure',
        title: 'Framework / server version exposed in response headers',
        status: 'pass',
        severity: null,
        summary: 'No X-Powered-By or Server header was observed on the homepage response.',
        evidence: [],
        fix: 'Keep poweredByHeader: false in next.config and keep version details out of response headers.',
        locations: [],
    };
}
function checkFraming(page) {
    const xfo = page.headers.get('x-frame-options');
    const csp = page.headers.get('content-security-policy');
    const frameAncestors = csp ? parseDirectives(csp).get('frame-ancestors') : undefined;
    const protectedByXfo = xfo != null && /^(DENY|SAMEORIGIN)$/i.test(xfo.trim());
    const protectedByCsp = frameAncestors != null &&
        (frameAncestors.includes("'none'") || frameAncestors.includes("'self'"));
    const evidence = [];
    if (xfo)
        evidence.push(`X-Frame-Options: ${xfo}`);
    if (frameAncestors)
        evidence.push(`CSP frame-ancestors: ${frameAncestors.join(' ')}`);
    if (protectedByXfo || protectedByCsp) {
        return {
            id: 'runtime-framing',
            category: 'framing',
            title: 'Site can be embedded in another site’s iframe (clickjacking)',
            status: 'pass',
            severity: null,
            summary: 'Framing is restricted — the page cannot be embedded by arbitrary third-party sites.',
            evidence,
            fix: 'Keep the framing restriction: X-Frame-Options DENY/SAMEORIGIN or a CSP frame-ancestors directive.',
            locations: [],
        };
    }
    return {
        id: 'runtime-framing',
        category: 'framing',
        title: 'Site can be embedded in another site’s iframe (clickjacking)',
        status: 'fail',
        severity: 'moderate',
        summary: 'No X-Frame-Options header and no CSP frame-ancestors directive were observed, so any site can embed this page in an iframe and trick visitors into clicking hidden elements.',
        evidence: evidence.length > 0 ? evidence : ['Neither header was sent on the homepage response.'],
        fix: "Send X-Frame-Options: DENY (or SAMEORIGIN) and a CSP frame-ancestors 'none' directive via next.config headers().",
        locations: [],
    };
}
function checkRuntimeCookies(page) {
    const base = {
        id: 'runtime-cookies',
        category: 'cookies',
        title: 'Cookies: Secure / HttpOnly / SameSite flags',
        locations: [],
    };
    const rawCookies = getSetCookies(page.headers);
    if (rawCookies.length === 0) {
        return {
            ...base,
            status: 'na',
            severity: null,
            summary: 'The homepage response set no cookies, so no cookie flags could be observed.',
            evidence: ['No Set-Cookie header on the homepage response.'],
            fix: 'When the app sets cookies (for example after sign-in), set them with HttpOnly, Secure and SameSite flags — and re-run this check on a response that sets them.',
        };
    }
    const isHttps = page.url.toLowerCase().startsWith('https://');
    const problems = [];
    const evidence = [];
    for (const cookie of rawCookies) {
        const name = cookie.split(';')[0].trim().split('=')[0] || '(unnamed)';
        const lower = cookie.toLowerCase();
        const missing = [];
        if (!/;\s*httponly\b/.test(lower))
            missing.push('HttpOnly');
        if (!/;\s*samesite\s*=/i.test(cookie))
            missing.push('SameSite');
        if (!/;\s*secure\b/.test(lower)) {
            missing.push(isHttps ? 'Secure' : 'Secure (served over plain http)');
        }
        evidence.push(`${name}: ${missing.length === 0 ? 'all flags present' : `missing ${missing.join(', ')}`}`);
        if (missing.length > 0)
            problems.push(`${name} is missing ${missing.join(', ')}`);
    }
    if (problems.length === 0) {
        return {
            ...base,
            status: 'pass',
            severity: null,
            summary: `All ${rawCookies.length} observed cookie(s) carry Secure, HttpOnly and SameSite flags.`,
            evidence,
            fix: 'Keep setting cookies with HttpOnly, Secure and SameSite flags.',
        };
    }
    return {
        ...base,
        status: 'warn',
        severity: 'moderate',
        summary: `${problems.length} of ${rawCookies.length} observed cookie(s) are missing flags: ${problems.join('; ')}.`,
        evidence,
        fix: 'Set cookies server-side with all three flags:\n\ncookies().set(name, value, { httpOnly: true, secure: true, sameSite: "lax", path: "/" });\n\nServe the site over HTTPS so the Secure flag can take effect.',
    };
}
async function checkSourceMaps(page, origin) {
    const base = {
        id: 'runtime-source-maps',
        category: 'exposure',
        title: 'JavaScript source maps publicly reachable',
        locations: [],
    };
    const originBase = origin.replace(/\/$/, '');
    const jsUrls = [...page.html.matchAll(/\/_next\/static\/[^"'`\s)]+?\.js\b/g)].map((m) => m[0]);
    const unique = [...new Set(jsUrls)].slice(0, 3);
    if (unique.length === 0) {
        return {
            ...base,
            status: 'na',
            severity: null,
            summary: 'No Next.js JavaScript chunks were found in the homepage HTML, so source-map exposure could not be tested.',
            evidence: [],
            fix: 'Keep productionBrowserSourceMaps disabled (the Next.js default) so production builds do not publish source maps.',
        };
    }
    for (const jsUrl of unique) {
        let jsText = '';
        try {
            const res = await directFetch(`${originBase}${jsUrl}`, { timeoutMs: 10000 });
            if (!res.ok)
                continue;
            jsText = await res.text().catch(() => '');
        }
        catch {
            continue;
        }
        const mapMatch = /\/\/# sourceMappingURL=(\S+)/.exec(jsText);
        if (!mapMatch)
            continue;
        const mapUrl = mapMatch[1];
        const absolute = mapUrl.startsWith('http') ? mapUrl : `${originBase}${jsUrl.split('/').slice(0, -1).join('/')}/${mapUrl}`;
        try {
            const mapRes = await directFetch(absolute, { timeoutMs: 10000 });
            const mapText = await mapRes.text().catch(() => '');
            if (mapRes.ok && mapText.includes('"sources"')) {
                return {
                    ...base,
                    status: 'warn',
                    severity: 'moderate',
                    summary: 'A JavaScript source map is publicly reachable and lists original source files. Anyone can download it and read the app’s unminified source, including comments and file structure.',
                    evidence: [`Source map reachable: ${absolute}`],
                    fix: 'Do not deploy development builds. Keep productionBrowserSourceMaps disabled in next.config and do not publish .next/static or .map files publicly.',
                };
            }
        }
        catch {
            // unreachable map — treat as not exposed
        }
    }
    return {
        ...base,
        status: 'pass',
        severity: null,
        summary: 'Checked JavaScript chunks served to the homepage — no publicly reachable source map was found.',
        evidence: [`${unique.length} chunk(s) checked.`],
        fix: 'Keep productionBrowserSourceMaps disabled so production builds do not publish source maps.',
    };
}
function checkGeneratorMeta(page) {
    const match = /<meta[^>]*name=["']generator["'][^>]*>/i.exec(page.html);
    if (match) {
        return {
            id: 'runtime-generator-meta',
            category: 'exposure',
            title: 'Generator meta tag exposes framework details',
            status: 'warn',
            severity: 'low',
            summary: 'The homepage HTML contains a generator meta tag advertising the stack.',
            evidence: [match[0].slice(0, 160)],
            fix: 'Remove the generator meta tag from the page metadata.',
            locations: [],
        };
    }
    return {
        id: 'runtime-generator-meta',
        category: 'exposure',
        title: 'Generator meta tag exposes framework details',
        status: 'pass',
        severity: null,
        summary: 'No generator meta tag was found in the homepage HTML.',
        evidence: [],
        fix: 'Keep generator details out of page metadata.',
        locations: [],
    };
}
function naRuntimeCheck(id, category, title, reason) {
    return {
        id,
        category,
        title,
        status: 'na',
        severity: null,
        summary: reason,
        evidence: [],
        fix: 'Run the dashboard against the running app (the handler passes the request origin) to evaluate this check.',
        locations: [],
    };
}
async function runtimeChecks(origin) {
    const page = await fetchPage(origin);
    if (!page) {
        const reason = `Could not fetch ${origin} to run the runtime checks.`;
        return {
            error: reason,
            checks: [
                naRuntimeCheck('runtime-version-headers', 'exposure', 'Framework / server version exposed in response headers', reason),
                naRuntimeCheck('runtime-framing', 'framing', 'Site can be embedded in another site’s iframe (clickjacking)', reason),
                naRuntimeCheck('runtime-cookies', 'cookies', 'Cookies: Secure / HttpOnly / SameSite flags', reason),
                naRuntimeCheck('runtime-source-maps', 'exposure', 'JavaScript source maps publicly reachable', reason),
                naRuntimeCheck('runtime-generator-meta', 'exposure', 'Generator meta tag exposes framework details', reason),
            ],
        };
    }
    return {
        checks: [
            checkVersionHeaders(page),
            checkFraming(page),
            checkRuntimeCookies(page),
            await checkSourceMaps(page, origin),
            checkGeneratorMeta(page),
        ],
    };
}
/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */
export async function analyzeAppSecurity(appRoot, options = {}) {
    const files = await collectSourceFiles(appRoot);
    const checks = staticChecks(files);
    const origin = options.origin ?? null;
    const runRuntime = (options.includeRuntimeChecks ?? true) && origin != null;
    let error;
    if (runRuntime) {
        const runtime = await runtimeChecks(origin);
        checks.push(...runtime.checks);
        error = runtime.error;
    }
    else if (origin == null) {
        const reason = 'No origin was available, so the runtime checks (headers, cookies, source maps) did not run. The handler passes the request origin automatically.';
        checks.push(naRuntimeCheck('runtime-version-headers', 'exposure', 'Framework / server version exposed in response headers', reason), naRuntimeCheck('runtime-framing', 'framing', 'Site can be embedded in another site’s iframe (clickjacking)', reason), naRuntimeCheck('runtime-cookies', 'cookies', 'Cookies: Secure / HttpOnly / SameSite flags', reason), naRuntimeCheck('runtime-source-maps', 'exposure', 'JavaScript source maps publicly reachable', reason), naRuntimeCheck('runtime-generator-meta', 'exposure', 'Generator meta tag exposes framework details', reason));
    }
    const counts = { pass: 0, warn: 0, fail: 0, na: 0 };
    for (const check of checks)
        counts[check.status] += 1;
    return {
        checkedAt: new Date().toISOString(),
        appRoot,
        origin,
        filesScanned: files.length,
        checks,
        counts,
        ...(error ? { error } : {}),
    };
}
