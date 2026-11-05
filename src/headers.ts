import { directFetch } from './direct-fetch.js';
import type { HeaderCheck, HeadersResult, HeaderStatus } from './types.js';

const HEADER_FIX_INTRO = `// next.config.js
/** @type {import('next').NextConfig} */
const nextConfig = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: KEY, value: VALUE },
        ],
      },
    ];
  },
};`;

function snippet(key: string, value: string): string {
  // JSON.stringify so values containing quotes (e.g. CSP's 'self') stay
  // valid JavaScript instead of terminating the string literal early.
  return HEADER_FIX_INTRO.replace('KEY', JSON.stringify(key)).replace(
    'VALUE',
    JSON.stringify(value),
  );
}

function get(headers: Headers, name: string): string | null {
  const value = headers.get(name);
  return value === null ? null : value;
}

function parseDirectives(csp: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    map.set(tokens[0].toLowerCase(), tokens.slice(1));
  }
  return map;
}

function checkContentSecurityPolicy(value: string | null): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'content-security-policy',
    displayName: 'Content-Security-Policy',
    value,
    fixSnippet: snippet(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    ),
  };
  if (value === null) {
    return {
      ...base,
      status: 'missing',
      explanation:
        'No Content-Security-Policy is sent. Without a CSP the page has no allow-list for scripts, styles or embeds, so a single injected script (e.g. via user content) can run with full page privileges.',
    };
  }
  const directives = parseDirectives(value);
  const scriptSrc = directives.get('script-src') ?? directives.get('default-src') ?? [];
  const problems: string[] = [];
  if (!directives.has('default-src') && !directives.has('script-src')) {
    problems.push('neither default-src nor script-src is set, so scripts are effectively unrestricted');
  }
  if (scriptSrc.includes("'unsafe-inline'")) {
    problems.push("script-src allows 'unsafe-inline', which defeats most XSS protection");
  }
  if (scriptSrc.includes("'unsafe-eval'")) {
    problems.push("script-src allows 'unsafe-eval'");
  }
  if (scriptSrc.includes('*')) {
    problems.push('script-src allows the * wildcard, letting scripts load from any origin');
  }
  if (scriptSrc.some((s) => s.startsWith('https:') || s.startsWith('http:'))) {
    problems.push('script-src allows whole schemes (https:/http:), which is broader than named hosts');
  }
  if (problems.length > 0) {
    return {
      ...base,
      status: 'warning',
      explanation: `CSP is present but weak: ${problems.join('; ')}.`,
    };
  }
  return {
    ...base,
    status: 'ok',
    explanation:
      'CSP is present with a restrictive script policy and no unsafe-inline / unsafe-eval / wildcards in script sources.',
  };
}

function checkHsts(value: string | null, isHttps: boolean): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'strict-transport-security',
    displayName: 'Strict-Transport-Security (HSTS)',
    value,
    fixSnippet: snippet(
      'Strict-Transport-Security',
      'max-age=63072000; includeSubDomains; preload',
    ),
  };
  if (!isHttps) {
    return {
      ...base,
      status: 'na',
      explanation:
        'HSTS is only meaningful over HTTPS. This check ran over plain http, so the header is reported as N/A — not a failure. Deploy behind HTTPS and the header will be evaluated.',
    };
  }
  if (value === null) {
    return {
      ...base,
      status: 'missing',
      explanation:
        'No HSTS header is sent over HTTPS. Browsers may still accept plain-http connections to this origin, leaving the first visit open to downgrade attacks.',
    };
  }
  const maxAge = /max-age=(\d+)/i.exec(value);
  const age = maxAge ? parseInt(maxAge[1], 10) : 0;
  const hasSubDomains = /includeSubDomains/i.test(value);
  if (age >= 31536000 && hasSubDomains) {
    return {
      ...base,
      status: 'ok',
      explanation: `HSTS is set with max-age=${age} and includeSubDomains — browsers will refuse plain-http connections for this origin and its subdomains.`,
    };
  }
  const problems: string[] = [];
  if (age < 31536000) problems.push(`max-age is only ${age} (at least 31536000 / 1 year is recommended)`);
  if (!hasSubDomains) problems.push('includeSubDomains is missing');
  return {
    ...base,
    status: 'warning',
    explanation: `HSTS is present but weak: ${problems.join('; ')}.`,
  };
}

function checkFrameOptions(value: string | null): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'x-frame-options',
    displayName: 'X-Frame-Options',
    value,
    fixSnippet: snippet('X-Frame-Options', 'DENY'),
  };
  if (value === null) {
    return {
      ...base,
      status: 'missing',
      explanation:
        'No X-Frame-Options header. The page can be framed by any site, which enables clickjacking attacks. (A CSP frame-ancestors directive is the modern replacement.)',
    };
  }
  const v = value.trim().toUpperCase();
  if (v === 'DENY' || v === 'SAMEORIGIN') {
    return { ...base, status: 'ok', explanation: `X-Frame-Options is set to ${v}.` };
  }
  return {
    ...base,
    status: 'warning',
    explanation: `X-Frame-Options is "${value}" — ALLOW-FROM is obsolete and ignored by modern browsers. Use DENY or SAMEORIGIN (or CSP frame-ancestors).`,
  };
}

function checkXssProtection(value: string | null): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'x-xss-protection',
    displayName: 'X-XSS-Protection',
    value,
    fixSnippet: snippet('X-XSS-Protection', '0'),
  };
  if (value === null) {
    return {
      ...base,
      status: 'warning',
      explanation:
        'X-XSS-Protection is absent. Modern browsers have removed this legacy XSS filter; its absence is not critical when a strong CSP exists, but explicitly setting it to 0 avoids inconsistent legacy behaviour.',
    };
  }
  if (value.trim() === '0') {
    return {
      ...base,
      status: 'ok',
      explanation:
        'X-XSS-Protection is 0, the modern recommendation — the legacy filter is disabled and CSP handles XSS defence.',
    };
  }
  return {
    ...base,
    status: 'warning',
    explanation: `X-XSS-Protection is "${value}". The legacy filter (1; mode=block) can itself introduce vulnerabilities; the modern recommendation is 0 together with a strong CSP.`,
  };
}

function checkContentTypeOptions(value: string | null): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'x-content-type-options',
    displayName: 'X-Content-Type-Options',
    value,
    fixSnippet: snippet('X-Content-Type-Options', 'nosniff'),
  };
  if (value === null) {
    return {
      ...base,
      status: 'missing',
      explanation:
        'No X-Content-Type-Options header. Browsers may MIME-sniff responses, so a user-uploaded file served as text/plain could be executed as a script.',
    };
  }
  if (value.trim().toLowerCase() === 'nosniff') {
    return { ...base, status: 'ok', explanation: 'X-Content-Type-Options is nosniff — MIME sniffing is disabled.' };
  }
  return { ...base, status: 'warning', explanation: `Unexpected value "${value}" — expected "nosniff".` };
}

function checkReferrerPolicy(value: string | null): HeaderCheck {
  const strict = new Set([
    'no-referrer',
    'same-origin',
    'strict-origin',
    'strict-origin-when-cross-origin',
  ]);
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'referrer-policy',
    displayName: 'Referrer-Policy',
    value,
    fixSnippet: snippet('Referrer-Policy', 'strict-origin-when-cross-origin'),
  };
  if (value === null) {
    return {
      ...base,
      status: 'warning',
      explanation:
        'No Referrer-Policy header. The browser default may leak full URLs (including query strings) to other origins when users follow links.',
    };
  }
  const first = value.split(',')[0].trim().toLowerCase();
  if (strict.has(first)) {
    return { ...base, status: 'ok', explanation: `Referrer-Policy is "${first}" — referrer data sent cross-origin is limited.` };
  }
  return {
    ...base,
    status: 'warning',
    explanation: `Referrer-Policy is "${value}" — values such as unsafe-url leak the full URL cross-origin. Prefer strict-origin-when-cross-origin.`,
  };
}

function checkPermissionsPolicy(value: string | null): HeaderCheck {
  const base: Omit<HeaderCheck, 'status' | 'explanation'> = {
    header: 'permissions-policy',
    displayName: 'Permissions-Policy',
    value,
    fixSnippet: snippet('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'),
  };
  if (value === null) {
    return {
      ...base,
      status: 'warning',
      explanation:
        'No Permissions-Policy header. Powerful features (camera, microphone, geolocation) are available to the page and any embedded frames by default.',
    };
  }
  return {
    ...base,
    status: 'ok',
    explanation: 'Permissions-Policy is set — powerful browser features are restricted by policy.',
  };
}

const WEIGHTS: Record<string, number> = {
  'content-security-policy': 30,
  'strict-transport-security': 20,
  'x-frame-options': 15,
  'x-content-type-options': 15,
  'x-xss-protection': 5,
  'referrer-policy': 5,
  'permissions-policy': 10,
};

export function analyzeHeaders(
  headers: Headers,
  url: string,
  statusCode: number | null,
): HeadersResult {
  const isHttps = url.toLowerCase().startsWith('https://');
  const checks: HeaderCheck[] = [
    checkContentSecurityPolicy(get(headers, 'content-security-policy')),
    checkHsts(get(headers, 'strict-transport-security'), isHttps),
    checkFrameOptions(get(headers, 'x-frame-options')),
    checkContentTypeOptions(get(headers, 'x-content-type-options')),
    checkXssProtection(get(headers, 'x-xss-protection')),
    checkReferrerPolicy(get(headers, 'referrer-policy')),
    checkPermissionsPolicy(get(headers, 'permissions-policy')),
  ];

  let earned = 0;
  let possible = 0;
  for (const check of checks) {
    const weight = WEIGHTS[check.header] ?? 0;
    if (check.status === 'na') continue; // excluded from the score entirely
    possible += weight;
    if (check.status === 'ok') earned += weight;
    else if (check.status === 'warning') earned += weight / 2;
  }
  const score = possible > 0 ? Math.round((earned / possible) * 100) : null;

  return { url, statusCode, checks, score, fetchedAt: new Date().toISOString() };
}

/** Fetch the app's own origin and analyse the response headers. Uses a
 * direct node:http/https request (see direct-fetch.ts) instead of global
 * fetch, so a fetch monkey-patch in the host app cannot hide the headers
 * the server actually sends. */
export async function fetchAndAnalyzeHeaders(origin: string): Promise<HeadersResult> {
  const target = origin.replace(/\/$/, '');
  try {
    const res = await directFetch(target, { timeoutMs: 10000 });
    // Drain the body so the connection can be reused; we only need headers.
    await res.arrayBuffer().catch(() => undefined);
    return analyzeHeaders(res.headers, res.url || target, res.status);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      url: target,
      statusCode: null,
      checks: [],
      score: null,
      fetchedAt: new Date().toISOString(),
      error: `Could not fetch ${target} to inspect headers: ${message}`,
    };
  }
}

export type { HeaderStatus };
