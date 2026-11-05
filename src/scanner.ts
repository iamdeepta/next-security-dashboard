import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import type {
  AdvisoryInfo,
  PackageInfo,
  SafeUpgradeOption,
  ScanError,
  SecurityReport,
  Severity,
  Vulnerability,
} from './types.js';
import { SEVERITY_ORDER } from './types.js';

export interface ScanOptions {
  /** App root to scan. Defaults to process.cwd(). */
  appRoot?: string;
  /** Timeout for `npm audit` in ms. Defaults to 120000. */
  auditTimeoutMs?: number;
  /** When npm audit fails, fall back to a vulnerability-database check. Defaults to false. */
  enableOsvFallback?: boolean;
  /**
   * Look up published versions on the npm registry to list every safe
   * upgrade option per vulnerability. Defaults to true. When disabled
   * (or the registry is unreachable) only the patched versions known
   * from the advisories are listed.
   */
  enableSafeUpgradeLookup?: boolean;
}

interface LockEntry {
  name: string;
  version: string;
  dev: boolean;
  /** Names this package depends on (deps + peer + optional). */
  dependencies: string[];
}

interface Inventory {
  /** Unique entries keyed by name@version. */
  entries: LockEntry[];
  /** First entry seen per package name. */
  byName: Map<string, LockEntry>;
  direct: Set<string>;
  directDev: Set<string>;
  /** True when the inventory came from a lockfile (most reliable). */
  fromLockfile: boolean;
}

const VALID_SEVERITIES: Severity[] = ['critical', 'high', 'moderate', 'low'];

function asSeverity(value: unknown, fallback: Severity = 'moderate'): Severity {
  return typeof value === 'string' &&
    (VALID_SEVERITIES as string[]).includes(value.toLowerCase())
    ? (value.toLowerCase() as Severity)
    : fallback;
}

function parseSemver(v: string): [number, number, number] {
  const clean = v.trim().replace(/^[v=^~<> ]+/, '').split('-')[0].split('+')[0];
  const parts = clean.split('.').map((p) => {
    const n = parseInt(p, 10);
    return Number.isNaN(n) ? 0 : n;
  });
  return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}

function compareSemver(a: string, b: string): number {
  const [a1, a2, a3] = parseSemver(a);
  const [b1, b2, b3] = parseSemver(b);
  return a1 - b1 || a2 - b2 || a3 - b3;
}

function maxSemver(versions: string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (!best || compareSemver(v, best) > 0) best = v;
  }
  return best;
}

/** Smallest fixed version strictly greater than the installed version. */
function minimalFix(installed: string, fixed: string[]): string | null {
  const greater = fixed.filter((v) => {
    try {
      return compareSemver(v, installed) > 0;
    } catch {
      return false;
    }
  });
  if (greater.length === 0) return null;
  greater.sort(compareSemver);
  return greater[0];
}

/** True when the version is a plain x.y.z release (no prerelease suffix). */
function isReleaseVersion(v: string): boolean {
  const clean = v.trim().replace(/^[v= ]+/, '');
  return /^\d+\.\d+\.\d+$/.test(clean);
}

function severityFromScore(score: number | null | undefined): Severity {
  if (score == null || Number.isNaN(score)) return 'moderate';
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'moderate';
  return 'low';
}

async function readJsonFile<T>(file: string): Promise<T | null> {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8')) as T;
  } catch {
    return null;
  }
}

function lockEntryName(key: string): string | null {
  if (!key) return null;
  const parts = key.split('node_modules/');
  const last = parts[parts.length - 1].replace(/\/$/, '');
  return last || null;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

/* ------------------------------------------------------------------ */
/* Inventory                                                           */
/* ------------------------------------------------------------------ */

async function inventoryFromLockfile(
  appRoot: string,
  pkg: Record<string, unknown>,
): Promise<Inventory | null> {
  const lock = await readJsonFile<Record<string, unknown>>(
    path.join(appRoot, 'package-lock.json'),
  );
  if (!lock || !isObject(lock.packages)) return null;

  const direct = new Set<string>(Object.keys((pkg.dependencies ?? {}) as object));
  const directDev = new Set<string>(
    Object.keys((pkg.devDependencies ?? {}) as object),
  );

  const seen = new Map<string, LockEntry>();
  const byName = new Map<string, LockEntry>();
  for (const [key, raw] of Object.entries(lock.packages)) {
    const name = lockEntryName(key);
    if (!name || !isObject(raw) || typeof raw.version !== 'string') continue;
    const deps = new Set<string>();
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
      const obj = raw[field];
      if (isObject(obj)) for (const dep of Object.keys(obj)) deps.add(dep);
    }
    const dedupeKey = `${name}@${raw.version}`;
    const existing = seen.get(dedupeKey);
    if (existing) {
      existing.dev = existing.dev || raw.dev === true;
      for (const d of deps) if (!existing.dependencies.includes(d)) existing.dependencies.push(d);
      continue;
    }
    const entry: LockEntry = {
      name,
      version: raw.version,
      dev: raw.dev === true,
      dependencies: [...deps],
    };
    seen.set(dedupeKey, entry);
    if (!byName.has(name)) byName.set(name, entry);
  }
  if (seen.size === 0) return null;
  return { entries: [...seen.values()], byName, direct, directDev, fromLockfile: true };
}

async function inventoryFromNodeModules(
  appRoot: string,
  pkg: Record<string, unknown>,
): Promise<Inventory | null> {
  const base = path.join(appRoot, 'node_modules');
  const direct = new Set<string>(Object.keys((pkg.dependencies ?? {}) as object));
  const directDev = new Set<string>(
    Object.keys((pkg.devDependencies ?? {}) as object),
  );
  const entries: LockEntry[] = [];
  const byName = new Map<string, LockEntry>();
  let dirents;
  try {
    dirents = await fs.readdir(base, { withFileTypes: true });
  } catch {
    return null;
  }
  const readPkg = async (dir: string, name: string) => {
    const manifest = await readJsonFile<Record<string, unknown>>(
      path.join(dir, 'package.json'),
    );
    if (!manifest || typeof manifest.version !== 'string') return;
    const deps = new Set<string>();
    for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
      const obj = manifest[field];
      if (isObject(obj)) for (const dep of Object.keys(obj)) deps.add(dep);
    }
    const entry: LockEntry = {
      name,
      version: manifest.version,
      dev: directDev.has(name) && !direct.has(name),
      dependencies: [...deps],
    };
    entries.push(entry);
    if (!byName.has(name)) byName.set(name, entry);
  };
  for (const dirent of dirents) {
    if (!dirent.isDirectory() || dirent.name.startsWith('.')) continue;
    if (dirent.name.startsWith('@')) {
      let scoped;
      try {
        scoped = await fs.readdir(path.join(base, dirent.name), { withFileTypes: true });
      } catch {
        continue;
      }
      for (const sub of scoped) {
        if (!sub.isDirectory()) continue;
        await readPkg(path.join(base, dirent.name, sub.name), `${dirent.name}/${sub.name}`);
      }
    } else {
      await readPkg(path.join(base, dirent.name), dirent.name);
    }
  }
  if (entries.length === 0) return null;
  return { entries, byName, direct, directDev, fromLockfile: false };
}

function inventoryFromPackageJson(pkg: Record<string, unknown>): Inventory {
  const entries: LockEntry[] = [];
  const byName = new Map<string, LockEntry>();
  const direct = new Set<string>();
  const directDev = new Set<string>();
  for (const [field, target] of [
    ['dependencies', direct],
    ['devDependencies', directDev],
  ] as const) {
    const deps = pkg[field];
    if (!isObject(deps)) continue;
    for (const [name, range] of Object.entries(deps)) {
      target.add(name);
      const entry: LockEntry = {
        name,
        version: typeof range === 'string' ? range : 'unknown',
        dev: field === 'devDependencies',
        dependencies: [],
      };
      entries.push(entry);
      if (!byName.has(name)) byName.set(name, entry);
    }
  }
  return { entries, byName, direct, directDev, fromLockfile: false };
}

function pulledInBy(
  vulnName: string,
  inventory: Inventory,
  directNames: string[],
): string[] {
  const result: string[] = [];
  for (const directName of directNames) {
    const entry = inventory.byName.get(directName);
    if (entry && entry.dependencies.includes(vulnName)) result.push(directName);
  }
  return result;
}

function isDevPackage(
  name: string,
  entry: LockEntry | undefined,
  inventory: Inventory,
): boolean {
  if (inventory.direct.has(name)) return false;
  if (inventory.directDev.has(name)) return true;
  return entry?.dev ?? false;
}

/* ------------------------------------------------------------------ */
/* npm audit                                                           */
/* ------------------------------------------------------------------ */

interface AuditOutcome {
  parsed: Record<string, unknown> | null;
  stderr: string;
  /** Human-readable reason the audit produced no usable data (null when parsed). */
  failure: string | null;
}

/**
 * Turn a failed `npm audit` run into a reason the user can act on, instead
 * of a generic "no usable data" message. The raw stderr is still kept as
 * `detail` on the report error; this classifies the common cases.
 */
function classifyAuditFailure(
  error: unknown,
  stderr: string,
  stdoutText: string,
  timeoutMs: number,
): string {
  const err = error as { code?: unknown; signal?: unknown } | null;
  if (err?.code === 'ETIMEDOUT' || err?.signal === 'SIGTERM') {
    return `npm audit timed out after ${Math.round(timeoutMs / 1000)}s. Raise auditTimeoutMs, or run the scan when the registry is reachable.`;
  }
  if (err?.code === 'ENOENT') {
    return `'npm' was not found on PATH, so npm audit could not run.`;
  }
  if (/ENOLOCK|requires a lockfile|no lockfile/i.test(stderr)) {
    return `npm audit needs a package-lock.json in this project (run 'npm install' to generate one), or pass enableOsvFallback: true to check without it.`;
  }
  // Registry rejections surface in stderr ("npm error ...") and/or in an
  // error JSON on stdout ({ message: "403 Forbidden - POST .../audits/quick" }).
  const haystack = `${stderr}\n${stdoutText.slice(0, 500)}`;
  if (/ENEEDAUTH|E401|E403|403 Forbidden|401 Unauthorized|policy_denied|authentication|must be logged in/i.test(haystack)) {
    return 'npm audit was rejected by the npm registry (access denied). Check registry access/authentication, or pass enableOsvFallback: true.';
  }
  if (/ENOTFOUND|EAI_AGAIN|ECONNREFUSED|ENETUNREACH|network|socket hang up/i.test(haystack)) {
    return 'npm audit could not reach the npm registry (network error).';
  }
  if (stdoutText.trim()) {
    return 'npm audit returned output in a format this version does not understand.';
  }
  return `npm audit produced no output. Run 'npm audit --json' in the project directory to see the underlying error.`;
}

function runNpmAudit(appRoot: string, timeoutMs: number): Promise<AuditOutcome> {
  return new Promise((resolve) => {
    execFile(
      'npm',
      ['audit', '--json'],
      { cwd: appRoot, timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        // NOTE: npm audit exits non-zero when vulnerabilities are found, so
        // a non-zero exit is expected and NOT a failure — only unparseable
        // stdout counts as a failed audit.
        const text = String(stdout ?? '');
        const errText = String(stderr ?? '');
        try {
          const parsed = JSON.parse(text) as Record<string, unknown>;
          // Modern npm (>=7): { vulnerabilities: {...} }.
          // Older npm (<=6): { advisories: {...} } — same data, older shape.
          if (isObject(parsed) && (isObject(parsed.vulnerabilities) || isObject(parsed.advisories))) {
            resolve({ parsed, stderr: errText, failure: null });
            return;
          }
        } catch {
          // fall through to failure
        }
        resolve({
          parsed: null,
          stderr: errText || text.slice(0, 500),
          failure: classifyAuditFailure(error, errText, text, timeoutMs),
        });
      },
    );
  });
}

function parseAuditReport(
  report: Record<string, unknown>,
  inventory: Inventory,
): Vulnerability[] {
  const vulns = report.vulnerabilities as Record<string, Record<string, unknown>>;
  const directNames = [...inventory.direct, ...inventory.directDev];
  const result: Vulnerability[] = [];

  for (const [name, entry] of Object.entries(vulns)) {
    const advisories: AdvisoryInfo[] = [];
    const via = Array.isArray(entry.via) ? entry.via : [];
    for (const item of via) {
      if (typeof item !== 'object' || item === null) continue; // string items = chained vuln names
      const rec = item as Record<string, unknown>;
      const url = typeof rec.url === 'string' ? rec.url : null;
      const ghsaMatch = url ? url.match(/GHSA-[a-z0-9-]+/i) : null;
      const cwe = Array.isArray(rec.cwe)
        ? (rec.cwe.filter((c) => typeof c === 'string') as string[])
        : [];
      const cvss = isObject(rec.cvss) ? rec.cvss : null;
      const cvssScore =
        cvss && typeof cvss.score === 'number' ? (cvss.score as number) : null;
      advisories.push({
        title: typeof rec.title === 'string' ? rec.title : `Advisory for ${name}`,
        url,
        severity: asSeverity(rec.severity, asSeverity(entry.severity, 'moderate')),
        range: typeof rec.range === 'string' ? rec.range : '',
        cwe,
        cvssScore,
        cveIds: [],
        ghsaId: ghsaMatch ? ghsaMatch[0].toUpperCase() : null,
        source: 'npm-audit',
      });
    }

    const lockEntry = inventory.byName.get(name);
    const installedVersion = lockEntry?.version ?? 'unknown';
    const isDirect =
      typeof entry.isDirect === 'boolean'
        ? entry.isDirect
        : inventory.direct.has(name) || inventory.directDev.has(name);
    const isDev =
      typeof entry.dev === 'boolean'
        ? entry.dev
        : isDevPackage(name, lockEntry, inventory);

    // Fix information.
    let fixAvailable = false;
    let recommendedUpgrade: string | null = null;
    let fixCommand: string | null = null;
    const patchedVersions: string[] = [];
    const fix = entry.fixAvailable;
    if (isObject(fix)) {
      fixAvailable = true;
      if (typeof fix.version === 'string') {
        recommendedUpgrade = fix.version;
        patchedVersions.push(fix.version);
        fixCommand = `npm install ${name}@${fix.version}`;
      } else {
        fixCommand = 'npm audit fix';
      }
    } else if (fix === true) {
      fixAvailable = true;
      fixCommand = 'npm audit fix';
    }

    const worst: Severity = advisories.length
      ? advisories
          .map((a) => a.severity)
          .sort((a, b) => SEVERITY_ORDER[a] - SEVERITY_ORDER[b])[0]
      : asSeverity(entry.severity, 'moderate');

    result.push({
      packageName: name,
      installedVersion,
      severity: worst,
      isDirect,
      isDev,
      pulledInBy: isDirect ? [] : pulledInBy(name, inventory, directNames),
      advisories,
      vulnerableRange:
        typeof entry.range === 'string' && entry.range
          ? entry.range
          : advisories[0]?.range ?? '',
      patchedVersions,
      recommendedUpgrade,
      safeUpgradeOptions: [],
      fixCommand,
      fixAvailable,
    });
  }
  return result;
}

/**
 * Parse the older `npm audit --json` shape (npm <= 6): `{ advisories: { id:
 * { module_name, severity, title, url, vulnerable_versions,
 * patched_versions, cwe, cvss } } }`. Patched versions arrive as a range
 * string (e.g. ">=4.17.21"), not a plain version, so no concrete upgrade
 * version is claimed — `npm audit fix` is the repair path.
 */
function parseAuditLegacyReport(
  report: Record<string, unknown>,
  inventory: Inventory,
): Vulnerability[] {
  const advisoriesMap = report.advisories as Record<string, Record<string, unknown>>;
  const directNames = [...inventory.direct, ...inventory.directDev];
  const result: Vulnerability[] = [];

  for (const rec of Object.values(advisoriesMap)) {
    if (!isObject(rec)) continue;
    const name = typeof rec.module_name === 'string' ? rec.module_name : null;
    if (!name) continue;
    const severity = asSeverity(rec.severity, 'moderate');
    const patched = typeof rec.patched_versions === 'string' ? rec.patched_versions : '';
    const hasPatch = patched !== '' && patched !== '<0.0.0';
    const cwe = Array.isArray(rec.cwe)
      ? (rec.cwe.filter((c) => typeof c === 'string') as string[])
      : [];
    const cvss = isObject(rec.cvss) ? rec.cvss : null;
    const lockEntry = inventory.byName.get(name);
    const installedVersion = lockEntry?.version ?? 'unknown';
    const isDirect = inventory.direct.has(name) || inventory.directDev.has(name);
    const isDev = isDevPackage(name, lockEntry, inventory);
    const advisory: AdvisoryInfo = {
      title: typeof rec.title === 'string' ? rec.title : `Advisory for ${name}`,
      url: typeof rec.url === 'string' ? rec.url : null,
      severity,
      range: typeof rec.vulnerable_versions === 'string' ? rec.vulnerable_versions : '',
      cwe,
      cvssScore: cvss && typeof cvss.score === 'number' ? (cvss.score as number) : null,
      cveIds: [],
      ghsaId: null,
      source: 'npm-audit',
    };
    result.push({
      packageName: name,
      installedVersion,
      severity,
      isDirect,
      isDev,
      pulledInBy: isDirect ? [] : pulledInBy(name, inventory, directNames),
      advisories: [advisory],
      vulnerableRange: advisory.range,
      patchedVersions: [],
      recommendedUpgrade: null,
      safeUpgradeOptions: [],
      fixCommand: hasPatch ? 'npm audit fix' : null,
      fixAvailable: hasPatch,
    });
  }
  return result;
}

/* ------------------------------------------------------------------ */
/* OSV.dev fallback                                                    */
/* ------------------------------------------------------------------ */

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{
      type: string;
      events: Array<Record<string, string>>;
    }>;
    versions?: string[];
  }>;
}

/**
 * Shared JSON transport for OSV.dev and the npm registry: global fetch
 * first (works in normal deployments), then the `curl` binary as a
 * fallback — curl honours HTTP(S)_PROXY env vars, while Node's
 * fetch/undici does not reliably do so in proxied sandboxes, where the
 * direct request hangs until timeout.
 * Returns null when the request could not be completed at all.
 */
async function fetchJsonWithFallback<T>(
  url: string,
  body?: string,
  init?: { headers?: Record<string, string>; timeoutMs?: number },
): Promise<T | null> {
  const timeoutMs = init?.timeoutMs ?? 20000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(
      url,
      body !== undefined
        ? {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
            body,
            signal: controller.signal,
          }
        : { headers: init?.headers, signal: controller.signal },
    );
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    // Fall through to the curl transport below.
  } finally {
    clearTimeout(timer);
  }
  try {
    const args = ['-sS', '--compressed', '--max-time', String(Math.ceil(timeoutMs / 1000))];
    if (init?.headers) {
      for (const [key, value] of Object.entries(init.headers)) {
        args.push('-H', `${key}: ${value}`);
      }
    }
    if (body !== undefined) {
      args.push('-X', 'POST', '-H', 'Content-Type: application/json', '-d', body);
    }
    args.push(url);
    const stdout = await new Promise<string>((resolve, reject) => {
      execFile(
        'curl',
        args,
        { timeout: timeoutMs + 5000, maxBuffer: 32 * 1024 * 1024, windowsHide: true },
        (error, out) => {
          if (error) reject(error);
          else resolve(String(out));
        },
      );
    });
    return JSON.parse(stdout) as T;
  } catch {
    return null;
  }
}

/**
 * querybatch returns MINIMAL records ({id, modified} only), so this step
 * only discovers which packages have vulnerabilities and their IDs; the
 * full records (summary, severity, ranges, aliases) are fetched per ID
 * by fetchOsvVulnDetails below.
 */
async function queryOsvBatch(
  queries: Array<{ name: string; version: string }>,
): Promise<{ results: Map<string, string[]>; anySuccess: boolean }> {
  const out = new Map<string, string[]>();
  let anySuccess = false;
  const CHUNK = 100;
  for (let i = 0; i < queries.length; i += CHUNK) {
    const chunk = queries.slice(i, i + CHUNK);
    const body = JSON.stringify({
      queries: chunk.map((q) => ({
        package: { name: q.name, ecosystem: 'npm' },
        version: q.version,
      })),
    });
    const parsed = await fetchJsonWithFallback<{ results?: Array<{ vulns?: Array<{ id: string }> }> }>(
      'https://api.osv.dev/v1/querybatch',
      body,
    );
    if (!parsed) continue;
    anySuccess = true;
    (parsed.results ?? []).forEach((r, idx) => {
      const key = `${chunk[idx].name}@${chunk[idx].version}`;
      const ids = (r.vulns ?? []).map((v) => v.id).filter(Boolean);
      if (ids.length) out.set(key, ids);
    });
  }
  return { results: out, anySuccess };
}

/** Fetch full OSV records for each unique vulnerability ID (bounded parallelism). */
async function fetchOsvVulnDetails(ids: string[]): Promise<Map<string, OsvVuln>> {
  const out = new Map<string, OsvVuln>();
  const unique = [...new Set(ids)];
  const CONCURRENCY = 6;
  for (let i = 0; i < unique.length; i += CONCURRENCY) {
    const chunk = unique.slice(i, i + CONCURRENCY);
    const settled = await Promise.all(
      chunk.map(async (id) => ({
        id,
        detail: await fetchJsonWithFallback<OsvVuln>(
          `https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,
        ),
      })),
    );
    for (const { id, detail } of settled) {
      if (detail) out.set(id, detail);
    }
  }
  return out;
}

/** CVSS v3.1 base score from a vector string (e.g. "CVSS:3.1/AV:N/AC:L/..."). */
function cvss31BaseScore(vector: string): number | null {
  if (!vector.startsWith('CVSS:3.')) return null;
  const m: Record<string, string> = {};
  for (const part of vector.split('/').slice(1)) {
    const idx = part.indexOf(':');
    if (idx > 0) m[part.slice(0, idx)] = part.slice(idx + 1);
  }
  const av: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const ac: Record<string, number> = { L: 0.77, H: 0.44 };
  const prU: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
  const prC: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };
  const ui: Record<string, number> = { N: 0.85, R: 0.62 };
  const cia: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
  const scopeChanged = m.S === 'C';
  const avV = av[m.AV];
  const acV = ac[m.AC];
  const prV = (scopeChanged ? prC : prU)[m.PR];
  const uiV = ui[m.UI];
  const cV = cia[m.C];
  const iV = cia[m.I];
  const aV = cia[m.A];
  if ([avV, acV, prV, uiV, cV, iV, aV].some((v) => v === undefined)) return null;
  const isc = 1 - (1 - cV) * (1 - iV) * (1 - aV);
  let impact: number;
  if (scopeChanged) {
    impact = isc <= 0 ? 0 : 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15);
  } else {
    impact = 6.42 * isc;
  }
  if (impact <= 0) return 0;
  const exploit = 8.22 * avV * acV * prV * uiV;
  const raw = scopeChanged ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
  // CVSS "roundup": smallest 1-decimal number >= raw (epsilon-tolerant).
  return Math.ceil((raw - 1e-9) * 10) / 10;
}

function osvSeverity(vuln: OsvVuln): { severity: Severity; cvssScore: number | null } {
  const db = vuln.database_specific?.severity?.toLowerCase();
  const dbSeverity: Severity | null =
    db === 'critical' || db === 'high' || db === 'moderate' || db === 'low' ? db : null;
  for (const s of vuln.severity ?? []) {
    const vectorScore = cvss31BaseScore(s.score);
    if (vectorScore !== null) {
      return { severity: dbSeverity ?? severityFromScore(vectorScore), cvssScore: vectorScore };
    }
    const numeric = parseFloat(s.score);
    if (!Number.isNaN(numeric)) {
      return { severity: dbSeverity ?? severityFromScore(numeric), cvssScore: numeric };
    }
  }
  return { severity: dbSeverity ?? 'moderate', cvssScore: null };
}

function osvVulnToVulnerability(
  entry: LockEntry,
  vuln: OsvVuln,
  inventory: Inventory,
): Vulnerability | null {
  const { severity, cvssScore } = osvSeverity(vuln);
  const cveIds = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-'));
  const ghsaId = vuln.id.startsWith('GHSA-') ? vuln.id : null;
  const cwe = vuln.database_specific?.cwe_ids ?? [];

  // Collect fixed versions + a human range from the SEMVER ranges.
  const fixedVersions: string[] = [];
  const rangeParts: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced = '0';
      let fixed: string | null = null;
      for (const event of range.events ?? []) {
        if (typeof event.introduced === 'string') introduced = event.introduced;
        if (typeof event.fixed === 'string') {
          fixed = event.fixed;
          fixedVersions.push(event.fixed);
        }
      }
      rangeParts.push(fixed ? `>=${introduced}, <${fixed}` : `>=${introduced}`);
    }
  }
  const recommended = minimalFix(entry.version, fixedVersions);
  const isDirect = inventory.direct.has(entry.name) || inventory.directDev.has(entry.name);
  const directNames = [...inventory.direct, ...inventory.directDev];
  // Clean the merged range for display: drop duplicates, and drop
  // open-ended ">=X" fragments when bounded fragments exist (those come
  // from records that only list an introduced version).
  const uniqueRanges = [...new Set(rangeParts)];
  const bounded = uniqueRanges.filter((r) => r.includes('<'));
  const displayRange = (bounded.length > 0 ? bounded : uniqueRanges).join(' || ');
  return {
    packageName: entry.name,
    installedVersion: entry.version,
    severity,
    isDirect,
    isDev: isDevPackage(entry.name, entry, inventory),
    pulledInBy: isDirect ? [] : pulledInBy(entry.name, inventory, directNames),
    advisories: [
      {
        title: vuln.summary ?? vuln.details?.split('\n')[0] ?? vuln.id,
        url: ghsaId ? `https://github.com/advisories/${ghsaId}` : null,
        severity,
        range: displayRange,
        cwe,
        cvssScore,
        cveIds,
        ghsaId,
        source: 'osv.dev',
      },
    ],
    vulnerableRange: displayRange,
    patchedVersions: [...new Set(fixedVersions)].sort(compareSemver),
    recommendedUpgrade: recommended,
    safeUpgradeOptions: [],
    fixCommand: recommended ? `npm install ${entry.name}@${recommended}` : null,
    fixAvailable: recommended !== null,
  };
}

async function scanWithOsv(inventory: Inventory): Promise<Vulnerability[]> {
  const queries = inventory.entries
    .filter((e) => e.version && !/^[~^<>= ]/.test(e.version) && e.version !== 'unknown')
    .map((e) => ({ name: e.name, version: e.version }));
  if (queries.length === 0) return [];
  const { results, anySuccess } = await queryOsvBatch(queries);
  if (!anySuccess) {
    throw new Error('The fallback vulnerability database could not be reached (all query batches failed).');
  }
  const allIds = [...new Set([...results.values()].flat())];
  const details = await fetchOsvVulnDetails(allIds);
  const vulns: Vulnerability[] = [];
  for (const entry of inventory.entries) {
    const ids = results.get(`${entry.name}@${entry.version}`);
    if (!ids) continue;
    for (const id of ids) {
      const full = details.get(id);
      if (full) {
        const converted = osvVulnToVulnerability(entry, full, inventory);
        if (converted) vulns.push(converted);
      } else {
        // Detail fetch failed for this ID: keep the finding with honest
        // minimal data rather than dropping a known vulnerability.
        const isDirect =
          inventory.direct.has(entry.name) || inventory.directDev.has(entry.name);
        const directNames = [...inventory.direct, ...inventory.directDev];
        vulns.push({
          packageName: entry.name,
          installedVersion: entry.version,
          severity: 'moderate',
          isDirect,
          isDev: isDevPackage(entry.name, entry, inventory),
          pulledInBy: isDirect ? [] : pulledInBy(entry.name, inventory, directNames),
          advisories: [
            {
              title: id,
              url: id.startsWith('GHSA-') ? `https://github.com/advisories/${id}` : null,
              severity: 'moderate',
              range: '',
              cwe: [],
              cvssScore: null,
              cveIds: [],
              ghsaId: id.startsWith('GHSA-') ? id : null,
              source: 'osv.dev',
            },
          ],
          vulnerableRange: '',
          patchedVersions: [],
          recommendedUpgrade: null,
          safeUpgradeOptions: [],
          fixCommand: null,
          fixAvailable: false,
        });
      }
    }
  }
  // Merge multiple advisories for the same package into one row.
  const merged = new Map<string, Vulnerability>();
  for (const v of vulns) {
    const existing = merged.get(v.packageName);
    if (!existing) {
      merged.set(v.packageName, v);
      continue;
    }
    existing.advisories.push(...v.advisories);
    existing.patchedVersions = [...new Set([...existing.patchedVersions, ...v.patchedVersions])].sort(compareSemver);
    if (SEVERITY_ORDER[v.severity] < SEVERITY_ORDER[existing.severity]) existing.severity = v.severity;
    const best = minimalFix(v.installedVersion, existing.patchedVersions);
    existing.recommendedUpgrade = best;
    existing.fixCommand = best ? `npm install ${v.packageName}@${best}` : null;
    existing.fixAvailable = best !== null;
    if (v.vulnerableRange) {
      const parts = new Set([
        ...existing.vulnerableRange.split(' || ').filter(Boolean),
        ...v.vulnerableRange.split(' || ').filter(Boolean),
      ]);
      const list = [...parts];
      const bounded = list.filter((r) => r.includes('<'));
      existing.vulnerableRange = (bounded.length > 0 ? bounded : list).join(' || ');
    }
  }
  return [...merged.values()];
}

/* ------------------------------------------------------------------ */
/* Safe upgrade options (npm registry)                                 */
/* ------------------------------------------------------------------ */

interface RegistryDoc {
  versions?: Record<string, { deprecated?: unknown }>;
}

function registryEscapeName(name: string): string {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash > 0) {
      return `${encodeURIComponent(name.slice(0, slash))}%2f${encodeURIComponent(name.slice(slash + 1))}`;
    }
  }
  return encodeURIComponent(name);
}

async function fetchRegistryVersions(
  name: string,
): Promise<{ versions: string[]; deprecated: Set<string> } | null> {
  // Abbreviated ("corgi") metadata: same version list, far smaller than the
  // full packument, with a longer timeout so huge packages (e.g. next,
  // 4000+ versions) do not time out on slow connections.
  const doc = await fetchJsonWithFallback<RegistryDoc>(
    `https://registry.npmjs.org/${registryEscapeName(name)}`,
    undefined,
    {
      headers: { Accept: 'application/vnd.npm.install-v1+json' },
      timeoutMs: 60000,
    },
  );
  if (!doc || !doc.versions) return null;
  const deprecated = new Set<string>();
  const versions: string[] = [];
  for (const [version, meta] of Object.entries(doc.versions)) {
    versions.push(version);
    if (meta && typeof meta.deprecated === 'string' && meta.deprecated) {
      deprecated.add(version);
    }
  }
  return { versions, deprecated };
}

/**
 * Lightweight latest-stable check: the /latest document is a few KB, so
 * it works even when the full packument fetch fails. Returns null when
 * the version is not a plain release or the request could not complete.
 */
async function fetchLatestVersion(
  name: string,
): Promise<{ version: string; deprecated: boolean } | null> {
  const doc = await fetchJsonWithFallback<{ version?: unknown; deprecated?: unknown }>(
    `https://registry.npmjs.org/${registryEscapeName(name)}/latest`,
    undefined,
    { timeoutMs: 15000 },
  );
  if (!doc || typeof doc.version !== 'string' || !isReleaseVersion(doc.version)) {
    return null;
  }
  return {
    version: doc.version,
    deprecated: typeof doc.deprecated === 'string' && doc.deprecated.length > 0,
  };
}

/**
 * Curate the safe upgrade options from every published version: the
 * smallest version that fixes all advisories, the latest safe patch
 * within the installed minor line, the latest safe version within the
 * installed major line, and the latest safe version overall. A version
 * counts as safe when it is at or above the fix floor (the highest
 * known patched version), above the installed version, a plain
 * release, and not deprecated.
 */
function computeSafeOptions(
  installed: string,
  floor: string,
  published: string[],
  deprecated: Set<string>,
): SafeUpgradeOption[] {
  const candidates = published
    .filter((v) => isReleaseVersion(v) && !deprecated.has(v))
    .filter((v) => compareSemver(v, floor) >= 0 && compareSemver(v, installed) > 0)
    .sort(compareSemver);
  if (candidates.length === 0) return [];

  const [major, minor] = parseSemver(installed);
  const lastWith = (pred: (v: string) => boolean): string | null => {
    let best: string | null = null;
    for (const v of candidates) if (pred(v)) best = v;
    return best;
  };
  const minimal = candidates[0];
  const latestPatch = lastWith((v) => {
    const [ma, mi] = parseSemver(v);
    return ma === major && mi === minor;
  });
  const latestMinor = lastWith((v) => parseSemver(v)[0] === major);
  const latest = candidates[candidates.length - 1];

  const picks: SafeUpgradeOption[] = [{ version: minimal, label: 'Smallest fix' }];
  if (latestPatch && latestPatch !== minimal) {
    picks.push({ version: latestPatch, label: 'Latest patch' });
  }
  if (latestMinor && latestMinor !== minimal && latestMinor !== latestPatch) {
    picks.push({ version: latestMinor, label: `Latest in v${major}` });
  }
  if (latest !== minimal && latest !== latestPatch && latest !== latestMinor) {
    picks.push({ version: latest, label: 'Latest' });
  }
  const seen = new Set<string>();
  const options = picks
    .filter((p) => (seen.has(p.version) ? false : (seen.add(p.version), true)))
    .sort((a, b) => compareSemver(a.version, b.version));
  if (options.length === 1) options[0].label = 'Recommended';
  return options;
}

/**
 * Offline fallback: the patched versions known from the advisories. Only
 * versions at or above the fix floor (the highest patched version across
 * ALL advisories for this package) are listed — a version that fixes one
 * advisory but not the others is not a safe upgrade and must not appear
 * here. Applies to every package; the floor is computed per row.
 */
function fallbackSafeOptions(vuln: Vulnerability): SafeUpgradeOption[] {
  const floor = maxSemver(vuln.patchedVersions);
  const fixed = [...new Set(vuln.patchedVersions)]
    .filter((v) => {
      try {
        return (
          compareSemver(v, vuln.installedVersion) > 0 &&
          (floor === null || compareSemver(v, floor) >= 0)
        );
      } catch {
        return false;
      }
    })
    .sort(compareSemver);
  const options = fixed.map((version, i) => ({
    version,
    label: i === 0 ? 'Smallest fix' : 'Patched version',
  }));
  if (options.length === 1) options[0].label = 'Recommended';
  return options;
}

async function enrichWithSafeUpgrades(
  vulns: Vulnerability[],
  enableLookup: boolean,
): Promise<void> {
  // Fallback options first, so every row lists something even when the
  // registry cannot be reached.
  for (const v of vulns) {
    v.safeUpgradeOptions = fallbackSafeOptions(v);
    // The recommended upgrade is the smallest version that fixes ALL
    // advisories for the package (the floor), not the smallest patched
    // version of any single advisory — e.g. next 16.3.6 fixes one
    // advisory but leaves the RCEs fixed in 16.4.1 open.
    if (v.safeUpgradeOptions.length > 0) {
      v.recommendedUpgrade = v.safeUpgradeOptions[0].version;
      v.fixCommand = `npm install ${v.packageName}@${v.safeUpgradeOptions[0].version}`;
    }
  }
  if (!enableLookup) return;

  const CONCURRENCY = 4;
  for (let i = 0; i < vulns.length; i += CONCURRENCY) {
    const chunk = vulns.slice(i, i + CONCURRENCY);
    await Promise.all(
      chunk.map(async (v) => {
        const floor = maxSemver(v.patchedVersions) ?? v.recommendedUpgrade;
        if (!floor) return;
        let registry: { versions: string[]; deprecated: Set<string> } | null = null;
        try {
          registry = await fetchRegistryVersions(v.packageName);
        } catch {
          registry = null;
        }
        if (!registry) {
          // Packument unreachable: still try the tiny /latest document so
          // the latest safe stable version is shown even in degraded
          // conditions (the fallback options above already carry the
          // smallest fully-safe version).
          try {
            const latest = await fetchLatestVersion(v.packageName);
            if (
              latest &&
              !latest.deprecated &&
              floor &&
              compareSemver(latest.version, floor) >= 0 &&
              compareSemver(latest.version, v.installedVersion) > 0 &&
              !v.safeUpgradeOptions.some((o) => o.version === latest.version)
            ) {
              v.safeUpgradeOptions = [...v.safeUpgradeOptions, { version: latest.version, label: 'Latest' }].sort(
                (a, b) => compareSemver(a.version, b.version),
              );
              // A lone fallback option was labelled 'Recommended'; with a
              // second option it is the smallest fix instead.
              if (v.safeUpgradeOptions.length > 1 && v.safeUpgradeOptions[0].label === 'Recommended') {
                v.safeUpgradeOptions[0].label = 'Smallest fix';
              }
            }
          } catch {
            // Latest check failed too; the floor-filtered fallback stands.
          }
          return;
        }
        const options = computeSafeOptions(
          v.installedVersion,
          floor,
          registry.versions,
          registry.deprecated,
        );
        if (options.length === 0) return;
        v.safeUpgradeOptions = options;
        // The recommended upgrade is the smallest safe version.
        v.recommendedUpgrade = options[0].version;
        v.fixCommand = `npm install ${v.packageName}@${options[0].version}`;
      }),
    );
  }
}

/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */

export async function scanDependencies(
  appRoot: string,
  options: ScanOptions = {},
): Promise<SecurityReport> {
  const auditTimeoutMs = options.auditTimeoutMs ?? 120000;
  const enableOsvFallback = options.enableOsvFallback ?? false;

  const pkg = (await readJsonFile<Record<string, unknown>>(
    path.join(appRoot, 'package.json'),
  )) ?? {};
  const appName = typeof pkg.name === 'string' ? pkg.name : null;

  const inventory =
    (await inventoryFromLockfile(appRoot, pkg)) ??
    (await inventoryFromNodeModules(appRoot, pkg)) ??
    inventoryFromPackageJson(pkg);

  let vulnerabilities: Vulnerability[] = [];
  let source: SecurityReport['source'] = 'none';
  let error: ScanError | undefined;

  const audit = await runNpmAudit(appRoot, auditTimeoutMs);
  if (audit.parsed) {
    source = 'npm-audit';
    vulnerabilities = isObject(audit.parsed.vulnerabilities)
      ? parseAuditReport(audit.parsed, inventory)
      : parseAuditLegacyReport(audit.parsed, inventory);
  } else if (enableOsvFallback) {
    try {
      vulnerabilities = await scanWithOsv(inventory);
      source = 'osv';
      if (audit.failure) {
        // Advisory notice only: the UI shows this as a banner above real
        // data, not as a failed scan.
        error = {
          code: 'AUDIT_UNAVAILABLE',
          message: `${audit.failure} Results come from the fallback vulnerability database.`,
          detail: audit.stderr.slice(0, 300),
        };
      }
    } catch (err) {
      error = {
        code: 'SCAN_FAILED',
        message: 'Both npm audit and the fallback check failed.',
        detail: err instanceof Error ? err.message : String(err),
      };
    }
  } else {
    error = {
      code: 'AUDIT_FAILED',
      message: `${audit.failure ?? 'npm audit did not return usable data.'} The fallback vulnerability check is turned off (pass enableOsvFallback: true to use it).`,
      detail: audit.stderr.slice(0, 300),
    };
  }

  const vulnByName = new Map<string, Severity[]>();
  for (const v of vulnerabilities) {
    const list = vulnByName.get(v.packageName) ?? [];
    list.push(v.severity);
    vulnByName.set(v.packageName, list);
  }

  await enrichWithSafeUpgrades(
    vulnerabilities,
    options.enableSafeUpgradeLookup ?? true,
  );

  const packages: PackageInfo[] = inventory.entries.map((e) => {
    const sevs = vulnByName.get(e.name) ?? [];
    return {
      name: e.name,
      version: e.version,
      isDirect: inventory.direct.has(e.name) || inventory.directDev.has(e.name),
      isDev: isDevPackage(e.name, e, inventory),
      vulnerable: sevs.length > 0,
      severities: sevs,
    };
  });

  const counts = {
    total: packages.length,
    vulnerable: vulnByName.size,
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    fixable: 0,
  };
  for (const v of vulnerabilities) {
    counts[v.severity] += 1;
    if (v.fixAvailable) counts.fixable += 1;
  }

  return {
    generatedAt: new Date().toISOString(),
    appName,
    appRoot,
    source,
    toolVersions: { node: process.version, scanner: source === 'osv' ? 'fallback vulnerability database' : source === 'npm-audit' ? 'npm audit' : 'scan unavailable' },
    packages,
    vulnerabilities: vulnerabilities.sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        a.packageName.localeCompare(b.packageName),
    ),
    counts,
    headers: null,
    appSecurity: null,
    ...(error ? { error } : {}),
  };
}
