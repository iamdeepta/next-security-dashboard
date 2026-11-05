#!/usr/bin/env node
/**
 * Setup CLI for next-security-dashboard.
 *
 * Lets the user choose, at install time or later, whether the dashboard
 * files are added to their project automatically or wired up manually:
 *
 *   npx next-security-dashboard setup            # ask (automatic / manual)
 *   npx next-security-dashboard setup --auto     # scaffold without asking
 *   npx next-security-dashboard setup --manual   # print manual instructions only
 *   npx next-security-dashboard setup --dry-run  # show what would change
 *
 * The postinstall hook (`node ./dist/cli.js postinstall`) runs the same
 * choice, but only when the install is interactive: it never writes files
 * without an explicit answer, never blocks a non-interactive install, and
 * never fails the install. NSD_SETUP=auto|manual|skip overrides the prompt.
 *
 * The scaffolder never overwrites an existing file.
 */
import { promises as fs } from 'node:fs';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const PACKAGE_NAME = 'next-security-dashboard';
const CSS_IMPORT = `import '${PACKAGE_NAME}/style.css';`;

const ROUTE_FILE = `import { createSecurityHandler } from '${PACKAGE_NAME}';

export const dynamic = 'force-dynamic';

export const GET = createSecurityHandler();
// To show the scan notice banner, pass { includeNotices: true }.
`;

const PAGE_FILE = `import { SecurityDashboard } from '${PACKAGE_NAME}/client';

export default function SecurityPage() {
  return (
    <main style={{ padding: 24 }}>
      <SecurityDashboard />
    </main>
  );
}
`;

const MANUAL_STEPS = `Manual setup (3 small files):

1. API route — app/api/security-scan/route.ts

   import { createSecurityHandler } from '${PACKAGE_NAME}';

   export const dynamic = 'force-dynamic';

   export const GET = createSecurityHandler();
   // To show the scan notice banner, pass { includeNotices: true }.

2. Stylesheet — import once in your root layout (app/layout.tsx)

   import '${PACKAGE_NAME}/style.css';

3. Page — app/security/page.tsx

   import { SecurityDashboard } from '${PACKAGE_NAME}/client';

   export default function SecurityPage() {
     return (
       <main style={{ padding: 24 }}>
         <SecurityDashboard />
       </main>
     );
   }

Then open /security. Full docs: https://github.com/iamdeepta/next-security-dashboard`;

interface ScaffoldReport {
  created: string[];
  skipped: string[];
  notes: string[];
}

async function fileExists(file: string): Promise<boolean> {
  try {
    await fs.access(file);
    return true;
  } catch {
    return false;
  }
}

async function readJson(file: string): Promise<Record<string, unknown> | null> {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** Resolve the host project root: INIT_CWD (npm/pnpm) first, then the parent of node_modules. */
function resolveProjectRoot(explicit?: string): string {
  if (explicit) return path.resolve(explicit);
  const initCwd = process.env.INIT_CWD;
  if (initCwd) return path.resolve(initCwd);
  // dist/cli.js -> package dir -> node_modules -> project root
  let dir = path.dirname(fileURLToPath(import.meta.url));
  const parts = dir.split(path.sep);
  const nmIndex = parts.lastIndexOf('node_modules');
  if (nmIndex > 0) return parts.slice(0, nmIndex).join(path.sep) || path.sep;
  return process.cwd();
}

function addCssImport(layoutSource: string): string | null {
  if (layoutSource.includes(`${PACKAGE_NAME}/style.css`)) return null;
  const lines = layoutSource.split('\n');
  let insertAt = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i].trim();
    if (/^['"]use (client|server)['"];?$/.test(line)) {
      insertAt = i + 1;
      continue;
    }
    if (/^import\s/.test(line)) {
      insertAt = i + 1;
      continue;
    }
    if (line === '' || line.startsWith('//')) continue;
    break;
  }
  lines.splice(insertAt, 0, CSS_IMPORT);
  return lines.join('\n');
}

async function scaffold(
  root: string,
  opts: { dryRun: boolean },
): Promise<ScaffoldReport | { error: string }> {
  const pkg = await readJson(path.join(root, 'package.json'));
  if (!pkg) {
    return { error: `No package.json found in ${root} — nothing was added.` };
  }
  if (pkg.name === PACKAGE_NAME) {
    return { error: 'This is the package repository itself — nothing was added.' };
  }

  const useTs = await fileExists(path.join(root, 'tsconfig.json'));
  const routeExt = useTs ? 'ts' : 'js';
  const pageExt = useTs ? 'tsx' : 'jsx';

  const appDir =
    (await fileExists(path.join(root, 'src', 'app')))
      ? path.join(root, 'src', 'app')
      : (await fileExists(path.join(root, 'app')))
        ? path.join(root, 'app')
        : null;
  if (!appDir) {
    if (await fileExists(path.join(root, 'pages'))) {
      return {
        error:
          'This project uses the Pages Router (no app/ directory). Automatic setup supports the App Router only — follow the manual steps printed above.',
      };
    }
    return { error: 'No app/ directory found — nothing was added.' };
  }

  const report: ScaffoldReport = { created: [], skipped: [], notes: [] };
  const rel = (p: string): string => path.relative(root, p).split(path.sep).join('/');

  const targets: Array<{ file: string; content: string }> = [
    {
      file: path.join(appDir, 'api', 'security-scan', `route.${routeExt}`),
      content: ROUTE_FILE,
    },
    {
      file: path.join(appDir, 'security', `page.${pageExt}`),
      content: PAGE_FILE,
    },
  ];

  for (const target of targets) {
    if (await fileExists(target.file)) {
      report.skipped.push(`${rel(target.file)} (already exists, left untouched)`);
      continue;
    }
    if (!opts.dryRun) {
      await fs.mkdir(path.dirname(target.file), { recursive: true });
      await fs.writeFile(target.file, target.content, 'utf8');
    }
    report.created.push(rel(target.file));
  }

  // Stylesheet import in the root layout.
  const layoutExts = useTs ? ['tsx', 'ts', 'jsx', 'js'] : ['jsx', 'js', 'tsx', 'ts'];
  let layoutFile: string | null = null;
  for (const ext of layoutExts) {
    const candidate = path.join(appDir, `layout.${ext}`);
    if (await fileExists(candidate)) {
      layoutFile = candidate;
      break;
    }
  }
  if (!layoutFile) {
    report.notes.push(
      'No root layout found — add this import once in your root layout: ' + CSS_IMPORT,
    );
  } else {
    const source = await fs.readFile(layoutFile, 'utf8');
    const updated = addCssImport(source);
    if (updated === null) {
      report.skipped.push(`${rel(layoutFile)} (stylesheet import already present)`);
    } else {
      if (!opts.dryRun) await fs.writeFile(layoutFile, updated, 'utf8');
      report.created.push(`${rel(layoutFile)} (stylesheet import added)`);
    }
  }

  report.notes.push('Run the dev server and open /security to see the dashboard.');
  report.notes.push(
    `To remove the dashboard later, run \`npx ${PACKAGE_NAME} uninstall\` before \`npm uninstall\` — npm does not run uninstall hooks, so a plain 'npm uninstall' leaves the scaffolded files behind.`,
  );
  return report;
}

function printReport(report: ScaffoldReport, dryRun: boolean): void {
  for (const line of report.created) {
    console.log(`${dryRun ? 'Would create' : 'Created'}: ${line}`);
  }
  for (const line of report.skipped) {
    console.log(`Skipped: ${line}`);
  }
  for (const line of report.notes) {
    console.log(line);
  }
}

/* ------------------------------------------------------------------ */
/* Uninstall: remove only what the scaffolder wrote                    */
/* ------------------------------------------------------------------ */

/**
 * A scaffolded file is removed only when its contents are byte-identical
 * (ignoring surrounding whitespace) to the template the scaffolder wrote.
 * A file the user edited is left untouched — deleting customised code on
 * uninstall would destroy their work. Line endings are normalised before
 * comparing: on Windows an editor may rewrite the file with CRLF, which
 * must not make a pristine scaffolded file look user-edited.
 */
function normalizeLineEndings(text: string): string {
  return text.replace(/\r\n/g, '\n');
}

async function checkScaffolded(
  file: string,
  template: string,
): Promise<'removed' | 'kept-modified' | 'absent'> {
  let content: string;
  try {
    content = await fs.readFile(file, 'utf8');
  } catch {
    return 'absent';
  }
  const same =
    normalizeLineEndings(content).trim() === normalizeLineEndings(template).trim();
  return same ? 'removed' : 'kept-modified';
}

async function removeIfScaffolded(
  file: string,
  template: string,
): Promise<'removed' | 'kept-modified' | 'absent'> {
  const outcome = await checkScaffolded(file, template);
  if (outcome === 'removed') await fs.unlink(file);
  return outcome;
}

/** Remove a directory, but only if it is empty (never deletes other files). */
async function removeDirIfEmpty(dir: string): Promise<void> {
  try {
    await fs.rm(dir, { recursive: false });
  } catch {
    // Non-empty, missing or otherwise busy — leave it alone.
  }
}

const CSS_IMPORT_LINE = /^import\s+['"]next-security-dashboard\/style\.css['"];?\s*$/;

/**
 * Remove the stylesheet import line from the root layout. The layout file
 * itself is always kept — only the import line goes.
 */
async function stripCssImport(
  file: string,
  dryRun: boolean,
): Promise<'stripped' | 'unchanged' | 'absent'> {
  let content: string;
  try {
    content = await fs.readFile(file, 'utf8');
  } catch {
    return 'absent';
  }
  const eol = content.includes('\r\n') ? '\r\n' : '\n';
  const lines = content.split(/\r?\n/);
  const kept = lines.filter((line) => !CSS_IMPORT_LINE.test(line.trim()));
  if (kept.length === lines.length) return 'unchanged';
  if (!dryRun) await fs.writeFile(file, kept.join(eol), 'utf8');
  return 'stripped';
}

async function runUninstall(args: string[]): Promise<number> {
  const dryRun = args.includes('--dry-run');
  const rootIndex = args.indexOf('--root');
  const rootArg = rootIndex >= 0 ? args[rootIndex + 1] : undefined;
  const root = resolveProjectRoot(rootArg);
  const rel = (p: string): string => path.relative(root, p).split(path.sep).join('/');

  const pkg = await readJson(path.join(root, 'package.json'));
  if (!pkg || pkg.name === PACKAGE_NAME) return 0;

  const removed: string[] = [];
  const kept: string[] = [];

  const appDirs = [path.join(root, 'src', 'app'), path.join(root, 'app')];
  for (const appDir of appDirs) {
    for (const ext of ['ts', 'js']) {
      const route = path.join(appDir, 'api', 'security-scan', `route.${ext}`);
      const outcome = dryRun
        ? await checkScaffolded(route, ROUTE_FILE)
        : await removeIfScaffolded(route, ROUTE_FILE);
      if (outcome === 'removed') {
        removed.push(rel(route));
        if (!dryRun) {
          await removeDirIfEmpty(path.join(appDir, 'api', 'security-scan'));
          await removeDirIfEmpty(path.join(appDir, 'api'));
        }
      } else if (outcome === 'kept-modified') {
        kept.push(`${rel(route)} (modified, left untouched)`);
      }
    }
    for (const ext of ['tsx', 'jsx']) {
      const page = path.join(appDir, 'security', `page.${ext}`);
      const outcome = dryRun
        ? await checkScaffolded(page, PAGE_FILE)
        : await removeIfScaffolded(page, PAGE_FILE);
      if (outcome === 'removed') {
        removed.push(rel(page));
        if (!dryRun) await removeDirIfEmpty(path.join(appDir, 'security'));
      } else if (outcome === 'kept-modified') {
        kept.push(`${rel(page)} (modified, left untouched)`);
      }
    }
    for (const ext of ['tsx', 'ts', 'jsx', 'js']) {
      const layout = path.join(appDir, `layout.${ext}`);
      const outcome = await stripCssImport(layout, dryRun);
      if (outcome === 'stripped') {
        removed.push(`${rel(layout)} (stylesheet import line removed, file kept)`);
      }
    }
  }

  for (const line of removed) {
    console.log(`${dryRun ? 'Would remove' : 'Removed'}: ${line}`);
  }
  for (const line of kept) {
    console.log(`Kept: ${line}`);
  }
  if (removed.length === 0 && kept.length === 0) {
    console.log('Nothing to remove — no scaffolded dashboard files were found.');
  }
  return 0;
}

type Choice = 'auto' | 'manual';

/** Ask the user to choose. Resolves 'manual' on timeout, EOF or any unclear answer. */
function askChoice(timeoutMs: number | null): Promise<Choice> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return Promise.resolve('manual');
  }
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  return new Promise<Choice>((resolve) => {
    let settled = false;
    const settle = (choice: Choice): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rl.close();
      resolve(choice);
    };
    const timer =
      timeoutMs === null
        ? undefined
        : setTimeout(() => settle('manual'), timeoutMs);
    rl.question(
      `\n${PACKAGE_NAME}: set up the dashboard automatically?\n` +
        '  1) Automatic — create the API route, the /security page and the stylesheet import\n' +
        '  2) Manual — I will wire it up myself (default)\n' +
        'Choose 1 or 2 (default 2): ',
      (answer) => {
        const a = answer.trim().toLowerCase();
        settle(a === '1' || a === 'auto' || a === 'automatic' || a === 'y' || a === 'yes' ? 'auto' : 'manual');
      },
    );
    rl.on('close', () => settle('manual'));
  });
}

function printHelp(): void {
  console.log(
    `${PACKAGE_NAME} — setup CLI\n\n` +
      'Usage:\n' +
      '  npx next-security-dashboard setup [--auto|--manual|--dry-run] [--root <dir>]\n\n' +
      '  setup          Ask whether to set up automatically or manually.\n' +
      '  setup --auto   Create the API route, /security page and stylesheet import.\n' +
      '  setup --manual Print the manual wiring steps; add no files.\n' +
      '  setup --dry-run Show what --auto would change, without writing.\n' +
      '  uninstall [--dry-run] [--root <dir>]\n' +
      '             Remove the scaffolded files and the stylesheet import\n' +
      '             line from the layout (the layout file itself is kept).\n' +
      '             Files you edited are left untouched.\n\n' +
      'Existing files are never overwritten. NSD_SETUP=auto|manual|skip\n' +
      'overrides the prompt (useful for scripts and CI).',
  );
}

async function runSetup(args: string[]): Promise<number> {
  const auto = args.includes('--auto');
  const manual = args.includes('--manual');
  const dryRun = args.includes('--dry-run');
  const rootIndex = args.indexOf('--root');
  const rootArg = rootIndex >= 0 ? args[rootIndex + 1] : undefined;
  const envChoice = process.env.NSD_SETUP?.toLowerCase();

  if (manual || envChoice === 'manual' || envChoice === 'skip') {
    console.log(MANUAL_STEPS);
    return 0;
  }

  let choice: Choice = 'manual';
  if (auto || dryRun || envChoice === 'auto') {
    choice = 'auto';
  } else if (process.stdin.isTTY && process.stdout.isTTY) {
    choice = await askChoice(null);
  } else {
    console.log(
      'No interactive terminal detected — nothing was added.\n' +
        `Run \`npx ${PACKAGE_NAME} setup\` to choose automatic setup, or:\n`,
    );
    console.log(MANUAL_STEPS);
    return 0;
  }

  if (choice === 'manual') {
    console.log(MANUAL_STEPS);
    return 0;
  }

  const root = resolveProjectRoot(rootArg);
  const result = await scaffold(root, { dryRun });
  if ('error' in result) {
    console.log(result.error);
    console.log(MANUAL_STEPS);
    return 0;
  }
  printReport(result, dryRun);
  return 0;
}

/**
 * Postinstall hook: same choice, but strictly safe for installs.
 * Non-interactive installs only get a one-line hint. Interactive installs
 * get the prompt with a 30s timeout (default: manual). Never exits non-zero.
 */
async function runPostinstall(): Promise<number> {
  try {
    const envChoice = process.env.NSD_SETUP?.toLowerCase();
    if (envChoice === 'skip' || envChoice === 'manual') {
      if (envChoice === 'manual') {
        console.log(`\n${PACKAGE_NAME}: manual setup selected — run \`npx ${PACKAGE_NAME} setup\` for the wiring steps.`);
      }
      return 0;
    }
    const root = resolveProjectRoot();
    const pkg = await readJson(path.join(root, 'package.json'));
    if (!pkg || pkg.name === PACKAGE_NAME) return 0;

    if (envChoice === 'auto') {
      const result = await scaffold(root, { dryRun: false });
      if (!('error' in result)) printReport(result, false);
      return 0;
    }

    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      console.log(
        `\n${PACKAGE_NAME} installed. Run \`npx ${PACKAGE_NAME} setup\` to add the dashboard files automatically, or wire it manually (see README).`,
      );
      return 0;
    }

    const choice = await askChoice(30_000);
    if (choice === 'auto') {
      const result = await scaffold(root, { dryRun: false });
      if ('error' in result) {
        console.log(result.error);
      } else {
        printReport(result, false);
      }
    } else {
      console.log(`\nManual setup selected — run \`npx ${PACKAGE_NAME} setup\` anytime for the wiring steps.`);
    }
    return 0;
  } catch {
    // The install must never fail because of setup.
    return 0;
  }
}

async function ownVersion(): Promise<string> {
  try {
    const pkgPath = fileURLToPath(new URL('../package.json', import.meta.url));
    const pkg = JSON.parse(await fs.readFile(pkgPath, 'utf8')) as {
      version?: unknown;
    };
    return typeof pkg.version === 'string' ? pkg.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

async function main(): Promise<number> {
  const [command, ...rest] = process.argv.slice(2);
  if (command === 'setup' || command === 'init') return runSetup(rest);
  if (command === 'uninstall' || command === 'remove') return runUninstall(rest);
  if (command === 'postinstall') return runPostinstall();
  if (command === 'preuninstall') {
    // Uninstall hook: never fail the uninstall, whatever happens.
    try {
      return await runUninstall(rest);
    } catch {
      return 0;
    }
  }
  if (command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return 0;
  }
  if (command === '--version' || command === '-v') {
    console.log(await ownVersion());
    return 0;
  }
  printHelp();
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch(() => process.exit(0));
