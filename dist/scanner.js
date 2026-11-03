import { execFile } from 'node:child_process';
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import { SEVERITY_ORDER } from './types.js';
const VALID_SEVERITIES = ['critical', 'high', 'moderate', 'low'];
function asSeverity(value, fallback = 'moderate') {
    return typeof value === 'string' &&
        VALID_SEVERITIES.includes(value.toLowerCase())
        ? value.toLowerCase()
        : fallback;
}
function parseSemver(v) {
    const clean = v.trim().replace(/^[v=^~<> ]+/, '').split('-')[0].split('+')[0];
    const parts = clean.split('.').map((p) => {
        const n = parseInt(p, 10);
        return Number.isNaN(n) ? 0 : n;
    });
    return [parts[0] ?? 0, parts[1] ?? 0, parts[2] ?? 0];
}
function compareSemver(a, b) {
    const [a1, a2, a3] = parseSemver(a);
    const [b1, b2, b3] = parseSemver(b);
    return a1 - b1 || a2 - b2 || a3 - b3;
}
function maxSemver(versions) {
    let best = null;
    for (const v of versions) {
        if (!best || compareSemver(v, best) > 0)
            best = v;
    }
    return best;
}
/** Smallest fixed version strictly greater than the installed version. */
function minimalFix(installed, fixed) {
    const greater = fixed.filter((v) => {
        try {
            return compareSemver(v, installed) > 0;
        }
        catch {
            return false;
        }
    });
    if (greater.length === 0)
        return null;
    greater.sort(compareSemver);
    return greater[0];
}
/** True when the version is a plain x.y.z release (no prerelease suffix). */
function isReleaseVersion(v) {
    const clean = v.trim().replace(/^[v= ]+/, '');
    return /^\d+\.\d+\.\d+$/.test(clean);
}
function severityFromScore(score) {
    if (score == null || Number.isNaN(score))
        return 'moderate';
    if (score >= 9)
        return 'critical';
    if (score >= 7)
        return 'high';
    if (score >= 4)
        return 'moderate';
    return 'low';
}
async function readJsonFile(file) {
    try {
        return JSON.parse(await fs.readFile(file, 'utf8'));
    }
    catch {
        return null;
    }
}
function lockEntryName(key) {
    if (!key)
        return null;
    const parts = key.split('node_modules/');
    const last = parts[parts.length - 1].replace(/\/$/, '');
    return last || null;
}
function isObject(value) {
    return typeof value === 'object' && value !== null;
}
/* ------------------------------------------------------------------ */
/* Inventory                                                           */
/* ------------------------------------------------------------------ */
async function inventoryFromLockfile(appRoot, pkg) {
    const lock = await readJsonFile(path.join(appRoot, 'package-lock.json'));
    if (!lock || !isObject(lock.packages))
        return null;
    const direct = new Set(Object.keys((pkg.dependencies ?? {})));
    const directDev = new Set(Object.keys((pkg.devDependencies ?? {})));
    const seen = new Map();
    const byName = new Map();
    for (const [key, raw] of Object.entries(lock.packages)) {
        const name = lockEntryName(key);
        if (!name || !isObject(raw) || typeof raw.version !== 'string')
            continue;
        const deps = new Set();
        for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
            const obj = raw[field];
            if (isObject(obj))
                for (const dep of Object.keys(obj))
                    deps.add(dep);
        }
        const dedupeKey = `${name}@${raw.version}`;
        const existing = seen.get(dedupeKey);
        if (existing) {
            existing.dev = existing.dev || raw.dev === true;
            for (const d of deps)
                if (!existing.dependencies.includes(d))
                    existing.dependencies.push(d);
            continue;
        }
        const entry = {
            name,
            version: raw.version,
            dev: raw.dev === true,
            dependencies: [...deps],
        };
        seen.set(dedupeKey, entry);
        if (!byName.has(name))
            byName.set(name, entry);
    }
    if (seen.size === 0)
        return null;
    return { entries: [...seen.values()], byName, direct, directDev, fromLockfile: true };
}
async function inventoryFromNodeModules(appRoot, pkg) {
    const base = path.join(appRoot, 'node_modules');
    const direct = new Set(Object.keys((pkg.dependencies ?? {})));
    const directDev = new Set(Object.keys((pkg.devDependencies ?? {})));
    const entries = [];
    const byName = new Map();
    let dirents;
    try {
        dirents = await fs.readdir(base, { withFileTypes: true });
    }
    catch {
        return null;
    }
    const readPkg = async (dir, name) => {
        const manifest = await readJsonFile(path.join(dir, 'package.json'));
        if (!manifest || typeof manifest.version !== 'string')
            return;
        const deps = new Set();
        for (const field of ['dependencies', 'peerDependencies', 'optionalDependencies']) {
            const obj = manifest[field];
            if (isObject(obj))
                for (const dep of Object.keys(obj))
                    deps.add(dep);
        }
        const entry = {
            name,
            version: manifest.version,
            dev: directDev.has(name) && !direct.has(name),
            dependencies: [...deps],
        };
        entries.push(entry);
        if (!byName.has(name))
            byName.set(name, entry);
    };
    for (const dirent of dirents) {
        if (!dirent.isDirectory() || dirent.name.startsWith('.'))
            continue;
        if (dirent.name.startsWith('@')) {
            let scoped;
            try {
                scoped = await fs.readdir(path.join(base, dirent.name), { withFileTypes: true });
            }
            catch {
                continue;
            }
            for (const sub of scoped) {
                if (!sub.isDirectory())
                    continue;
                await readPkg(path.join(base, dirent.name, sub.name), `${dirent.name}/${sub.name}`);
            }
        }
        else {
            await readPkg(path.join(base, dirent.name), dirent.name);
        }
    }
    if (entries.length === 0)
        return null;
    return { entries, byName, direct, directDev, fromLockfile: false };
}
function inventoryFromPackageJson(pkg) {
    const entries = [];
    const byName = new Map();
    const direct = new Set();
    const directDev = new Set();
    for (const [field, target] of [
        ['dependencies', direct],
        ['devDependencies', directDev],
    ]) {
        const deps = pkg[field];
        if (!isObject(deps))
            continue;
        for (const [name, range] of Object.entries(deps)) {
            target.add(name);
            const entry = {
                name,
                version: typeof range === 'string' ? range : 'unknown',
                dev: field === 'devDependencies',
                dependencies: [],
            };
            entries.push(entry);
            if (!byName.has(name))
                byName.set(name, entry);
        }
    }
    return { entries, byName, direct, directDev, fromLockfile: false };
}
function pulledInBy(vulnName, inventory, directNames) {
    const result = [];
    for (const directName of directNames) {
        const entry = inventory.byName.get(directName);
        if (entry && entry.dependencies.includes(vulnName))
            result.push(directName);
    }
    return result;
}
function isDevPackage(name, entry, inventory) {
    if (inventory.direct.has(name))
        return false;
    if (inventory.directDev.has(name))
        return true;
    return entry?.dev ?? false;
}
function runNpmAudit(appRoot, timeoutMs) {
    return new Promise((resolve) => {
        execFile('npm', ['audit', '--json'], { cwd: appRoot, timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (_error, stdout, stderr) => {
            // NOTE: npm audit exits non-zero when vulnerabilities are found, so
            // a non-zero exit is expected and NOT a failure — only unparseable
            // stdout counts as a failed audit.
            const text = String(stdout ?? '');
            try {
                const parsed = JSON.parse(text);
                if (isObject(parsed) && isObject(parsed.vulnerabilities)) {
                    resolve({ parsed, stderr: String(stderr ?? '') });
                    return;
                }
            }
            catch {
                // fall through to failure
            }
            resolve({ parsed: null, stderr: String(stderr ?? '') || text.slice(0, 500) });
        });
    });
}
function parseAuditReport(report, inventory) {
    const vulns = report.vulnerabilities;
    const directNames = [...inventory.direct, ...inventory.directDev];
    const result = [];
    for (const [name, entry] of Object.entries(vulns)) {
        const advisories = [];
        const via = Array.isArray(entry.via) ? entry.via : [];
        for (const item of via) {
            if (typeof item !== 'object' || item === null)
                continue; // string items = chained vuln names
            const rec = item;
            const url = typeof rec.url === 'string' ? rec.url : null;
            const ghsaMatch = url ? url.match(/GHSA-[a-z0-9-]+/i) : null;
            const cwe = Array.isArray(rec.cwe)
                ? rec.cwe.filter((c) => typeof c === 'string')
                : [];
            const cvss = isObject(rec.cvss) ? rec.cvss : null;
            const cvssScore = cvss && typeof cvss.score === 'number' ? cvss.score : null;
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
        const isDirect = typeof entry.isDirect === 'boolean'
            ? entry.isDirect
            : inventory.direct.has(name) || inventory.directDev.has(name);
        const isDev = typeof entry.dev === 'boolean'
            ? entry.dev
            : isDevPackage(name, lockEntry, inventory);
        // Fix information.
        let fixAvailable = false;
        let recommendedUpgrade = null;
        let fixCommand = null;
        const patchedVersions = [];
        const fix = entry.fixAvailable;
        if (isObject(fix)) {
            fixAvailable = true;
            if (typeof fix.version === 'string') {
                recommendedUpgrade = fix.version;
                patchedVersions.push(fix.version);
                fixCommand = `npm install ${name}@${fix.version}`;
            }
            else {
                fixCommand = 'npm audit fix';
            }
        }
        else if (fix === true) {
            fixAvailable = true;
            fixCommand = 'npm audit fix';
        }
        const worst = advisories.length
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
            vulnerableRange: typeof entry.range === 'string' && entry.range
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
 * Shared JSON transport for OSV.dev and the npm registry: global fetch
 * first (works in normal deployments), then the `curl` binary as a
 * fallback — curl honours HTTP(S)_PROXY env vars, while Node's
 * fetch/undici does not reliably do so in proxied sandboxes, where the
 * direct request hangs until timeout.
 * Returns null when the request could not be completed at all.
 */
async function fetchJsonWithFallback(url, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 20000);
    try {
        const res = await fetch(url, body !== undefined
            ? {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body,
                signal: controller.signal,
            }
            : { signal: controller.signal });
        if (!res.ok)
            return null;
        return (await res.json());
    }
    catch {
        // Fall through to the curl transport below.
    }
    finally {
        clearTimeout(timer);
    }
    try {
        const args = ['-sS', '--max-time', '25'];
        if (body !== undefined) {
            args.push('-X', 'POST', '-H', 'Content-Type: application/json', '-d', body);
        }
        args.push(url);
        const stdout = await new Promise((resolve, reject) => {
            execFile('curl', args, { timeout: 30000, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (error, out) => {
                if (error)
                    reject(error);
                else
                    resolve(String(out));
            });
        });
        return JSON.parse(stdout);
    }
    catch {
        return null;
    }
}
/**
 * querybatch returns MINIMAL records ({id, modified} only), so this step
 * only discovers which packages have vulnerabilities and their IDs; the
 * full records (summary, severity, ranges, aliases) are fetched per ID
 * by fetchOsvVulnDetails below.
 */
async function queryOsvBatch(queries) {
    const out = new Map();
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
        const parsed = await fetchJsonWithFallback('https://api.osv.dev/v1/querybatch', body);
        if (!parsed)
            continue;
        anySuccess = true;
        (parsed.results ?? []).forEach((r, idx) => {
            const key = `${chunk[idx].name}@${chunk[idx].version}`;
            const ids = (r.vulns ?? []).map((v) => v.id).filter(Boolean);
            if (ids.length)
                out.set(key, ids);
        });
    }
    return { results: out, anySuccess };
}
/** Fetch full OSV records for each unique vulnerability ID (bounded parallelism). */
async function fetchOsvVulnDetails(ids) {
    const out = new Map();
    const unique = [...new Set(ids)];
    const CONCURRENCY = 6;
    for (let i = 0; i < unique.length; i += CONCURRENCY) {
        const chunk = unique.slice(i, i + CONCURRENCY);
        const settled = await Promise.all(chunk.map(async (id) => ({
            id,
            detail: await fetchJsonWithFallback(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`),
        })));
        for (const { id, detail } of settled) {
            if (detail)
                out.set(id, detail);
        }
    }
    return out;
}
/** CVSS v3.1 base score from a vector string (e.g. "CVSS:3.1/AV:N/AC:L/..."). */
function cvss31BaseScore(vector) {
    if (!vector.startsWith('CVSS:3.'))
        return null;
    const m = {};
    for (const part of vector.split('/').slice(1)) {
        const idx = part.indexOf(':');
        if (idx > 0)
            m[part.slice(0, idx)] = part.slice(idx + 1);
    }
    const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
    const ac = { L: 0.77, H: 0.44 };
    const prU = { N: 0.85, L: 0.62, H: 0.27 };
    const prC = { N: 0.85, L: 0.68, H: 0.5 };
    const ui = { N: 0.85, R: 0.62 };
    const cia = { N: 0, L: 0.22, H: 0.56 };
    const scopeChanged = m.S === 'C';
    const avV = av[m.AV];
    const acV = ac[m.AC];
    const prV = (scopeChanged ? prC : prU)[m.PR];
    const uiV = ui[m.UI];
    const cV = cia[m.C];
    const iV = cia[m.I];
    const aV = cia[m.A];
    if ([avV, acV, prV, uiV, cV, iV, aV].some((v) => v === undefined))
        return null;
    const isc = 1 - (1 - cV) * (1 - iV) * (1 - aV);
    let impact;
    if (scopeChanged) {
        impact = isc <= 0 ? 0 : 7.52 * (isc - 0.029) - 3.25 * Math.pow(isc - 0.02, 15);
    }
    else {
        impact = 6.42 * isc;
    }
    if (impact <= 0)
        return 0;
    const exploit = 8.22 * avV * acV * prV * uiV;
    const raw = scopeChanged ? Math.min(1.08 * (impact + exploit), 10) : Math.min(impact + exploit, 10);
    // CVSS "roundup": smallest 1-decimal number >= raw (epsilon-tolerant).
    return Math.ceil((raw - 1e-9) * 10) / 10;
}
function osvSeverity(vuln) {
    const db = vuln.database_specific?.severity?.toLowerCase();
    const dbSeverity = db === 'critical' || db === 'high' || db === 'moderate' || db === 'low' ? db : null;
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
function osvVulnToVulnerability(entry, vuln, inventory) {
    const { severity, cvssScore } = osvSeverity(vuln);
    const cveIds = (vuln.aliases ?? []).filter((a) => a.startsWith('CVE-'));
    const ghsaId = vuln.id.startsWith('GHSA-') ? vuln.id : null;
    const cwe = vuln.database_specific?.cwe_ids ?? [];
    // Collect fixed versions + a human range from the SEMVER ranges.
    const fixedVersions = [];
    const rangeParts = [];
    for (const affected of vuln.affected ?? []) {
        for (const range of affected.ranges ?? []) {
            if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM')
                continue;
            let introduced = '0';
            let fixed = null;
            for (const event of range.events ?? []) {
                if (typeof event.introduced === 'string')
                    introduced = event.introduced;
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
async function scanWithOsv(inventory) {
    const queries = inventory.entries
        .filter((e) => e.version && !/^[~^<>= ]/.test(e.version) && e.version !== 'unknown')
        .map((e) => ({ name: e.name, version: e.version }));
    if (queries.length === 0)
        return [];
    const { results, anySuccess } = await queryOsvBatch(queries);
    if (!anySuccess) {
        throw new Error('OSV.dev API could not be reached (all query batches failed).');
    }
    const allIds = [...new Set([...results.values()].flat())];
    const details = await fetchOsvVulnDetails(allIds);
    const vulns = [];
    for (const entry of inventory.entries) {
        const ids = results.get(`${entry.name}@${entry.version}`);
        if (!ids)
            continue;
        for (const id of ids) {
            const full = details.get(id);
            if (full) {
                const converted = osvVulnToVulnerability(entry, full, inventory);
                if (converted)
                    vulns.push(converted);
            }
            else {
                // Detail fetch failed for this ID: keep the finding with honest
                // minimal data rather than dropping a known vulnerability.
                const isDirect = inventory.direct.has(entry.name) || inventory.directDev.has(entry.name);
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
    const merged = new Map();
    for (const v of vulns) {
        const existing = merged.get(v.packageName);
        if (!existing) {
            merged.set(v.packageName, v);
            continue;
        }
        existing.advisories.push(...v.advisories);
        existing.patchedVersions = [...new Set([...existing.patchedVersions, ...v.patchedVersions])].sort(compareSemver);
        if (SEVERITY_ORDER[v.severity] < SEVERITY_ORDER[existing.severity])
            existing.severity = v.severity;
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
function registryEscapeName(name) {
    if (name.startsWith('@')) {
        const slash = name.indexOf('/');
        if (slash > 0) {
            return `${encodeURIComponent(name.slice(0, slash))}%2f${encodeURIComponent(name.slice(slash + 1))}`;
        }
    }
    return encodeURIComponent(name);
}
async function fetchRegistryVersions(name) {
    const doc = await fetchJsonWithFallback(`https://registry.npmjs.org/${registryEscapeName(name)}`);
    if (!doc || !doc.versions)
        return null;
    const deprecated = new Set();
    const versions = [];
    for (const [version, meta] of Object.entries(doc.versions)) {
        versions.push(version);
        if (meta && typeof meta.deprecated === 'string' && meta.deprecated) {
            deprecated.add(version);
        }
    }
    return { versions, deprecated };
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
function computeSafeOptions(installed, floor, published, deprecated) {
    const candidates = published
        .filter((v) => isReleaseVersion(v) && !deprecated.has(v))
        .filter((v) => compareSemver(v, floor) >= 0 && compareSemver(v, installed) > 0)
        .sort(compareSemver);
    if (candidates.length === 0)
        return [];
    const [major, minor] = parseSemver(installed);
    const lastWith = (pred) => {
        let best = null;
        for (const v of candidates)
            if (pred(v))
                best = v;
        return best;
    };
    const minimal = candidates[0];
    const latestPatch = lastWith((v) => {
        const [ma, mi] = parseSemver(v);
        return ma === major && mi === minor;
    });
    const latestMinor = lastWith((v) => parseSemver(v)[0] === major);
    const latest = candidates[candidates.length - 1];
    const picks = [{ version: minimal, label: 'Smallest fix' }];
    if (latestPatch && latestPatch !== minimal) {
        picks.push({ version: latestPatch, label: 'Latest patch' });
    }
    if (latestMinor && latestMinor !== minimal && latestMinor !== latestPatch) {
        picks.push({ version: latestMinor, label: `Latest in v${major}` });
    }
    if (latest !== minimal && latest !== latestPatch && latest !== latestMinor) {
        picks.push({ version: latest, label: 'Latest' });
    }
    const seen = new Set();
    const options = picks
        .filter((p) => (seen.has(p.version) ? false : (seen.add(p.version), true)))
        .sort((a, b) => compareSemver(a.version, b.version));
    if (options.length === 1)
        options[0].label = 'Recommended';
    return options;
}
/** Offline fallback: the patched versions known from the advisories. */
function fallbackSafeOptions(vuln) {
    const fixed = [...new Set(vuln.patchedVersions)]
        .filter((v) => {
        try {
            return compareSemver(v, vuln.installedVersion) > 0;
        }
        catch {
            return false;
        }
    })
        .sort(compareSemver);
    return fixed.map((version, i) => ({
        version,
        label: i === 0 ? 'Smallest fix' : 'Patched version',
    }));
}
async function enrichWithSafeUpgrades(vulns, enableLookup) {
    // Fallback options first, so every row lists something even when the
    // registry cannot be reached.
    for (const v of vulns)
        v.safeUpgradeOptions = fallbackSafeOptions(v);
    if (!enableLookup)
        return;
    const CONCURRENCY = 4;
    for (let i = 0; i < vulns.length; i += CONCURRENCY) {
        const chunk = vulns.slice(i, i + CONCURRENCY);
        await Promise.all(chunk.map(async (v) => {
            const floor = maxSemver(v.patchedVersions) ?? v.recommendedUpgrade;
            if (!floor)
                return;
            let registry = null;
            try {
                registry = await fetchRegistryVersions(v.packageName);
            }
            catch {
                registry = null;
            }
            if (!registry)
                return;
            const options = computeSafeOptions(v.installedVersion, floor, registry.versions, registry.deprecated);
            if (options.length === 0)
                return;
            v.safeUpgradeOptions = options;
            // The recommended upgrade is the smallest safe version.
            v.recommendedUpgrade = options[0].version;
            v.fixCommand = `npm install ${v.packageName}@${options[0].version}`;
        }));
    }
}
/* ------------------------------------------------------------------ */
/* Public entry point                                                  */
/* ------------------------------------------------------------------ */
export async function scanDependencies(appRoot, options = {}) {
    const auditTimeoutMs = options.auditTimeoutMs ?? 120000;
    const enableOsvFallback = options.enableOsvFallback ?? true;
    const pkg = (await readJsonFile(path.join(appRoot, 'package.json'))) ?? {};
    const appName = typeof pkg.name === 'string' ? pkg.name : null;
    const inventory = (await inventoryFromLockfile(appRoot, pkg)) ??
        (await inventoryFromNodeModules(appRoot, pkg)) ??
        inventoryFromPackageJson(pkg);
    let vulnerabilities = [];
    let source = 'none';
    let error;
    const audit = await runNpmAudit(appRoot, auditTimeoutMs);
    if (audit.parsed) {
        source = 'npm-audit';
        vulnerabilities = parseAuditReport(audit.parsed, inventory);
    }
    else if (enableOsvFallback) {
        try {
            vulnerabilities = await scanWithOsv(inventory);
            source = 'osv';
            if (audit.stderr) {
                // Advisory notice only: the UI shows this as a banner above real
                // data, not as a failed scan.
                error = {
                    code: 'AUDIT_UNAVAILABLE',
                    message: 'npm audit did not return usable data; results come from the OSV.dev fallback.',
                    detail: audit.stderr.slice(0, 300),
                };
            }
        }
        catch (err) {
            error = {
                code: 'SCAN_FAILED',
                message: 'Both npm audit and the OSV.dev fallback failed.',
                detail: err instanceof Error ? err.message : String(err),
            };
        }
    }
    else {
        error = {
            code: 'AUDIT_FAILED',
            message: 'npm audit did not return usable data and the OSV.dev fallback is disabled.',
            detail: audit.stderr.slice(0, 300),
        };
    }
    const vulnByName = new Map();
    for (const v of vulnerabilities) {
        const list = vulnByName.get(v.packageName) ?? [];
        list.push(v.severity);
        vulnByName.set(v.packageName, list);
    }
    await enrichWithSafeUpgrades(vulnerabilities, options.enableSafeUpgradeLookup ?? true);
    const packages = inventory.entries.map((e) => {
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
        if (v.fixAvailable)
            counts.fixable += 1;
    }
    return {
        generatedAt: new Date().toISOString(),
        appName,
        appRoot,
        source,
        toolVersions: { node: process.version, scanner: source === 'osv' ? 'osv.dev' : 'npm audit' },
        packages,
        vulnerabilities: vulnerabilities.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
            a.packageName.localeCompare(b.packageName)),
        counts,
        headers: null,
        appSecurity: null,
        ...(error ? { error } : {}),
    };
}
