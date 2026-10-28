// L0 facts: read the filesystem and git, describe the action, decide nothing.
// Everything the reviewer cannot see is invisible to it, so this is the only
// module allowed to touch fs/git, and its output is the reviewer's whole world.
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { normalizePath, isWithin, pathApiFor } from './paths.js';
import { splitSegments, operandsOf, isDynamic } from './parse.js';
import { matchPath } from './policy.js';

export const MAX_TARGETS = 20;

const SHELL_TOOLS = new Set(['bash', 'shell', 'terminal', 'pwsh', 'powershell', 'cmd', 'run_command', 'execute_command']);
// Session bookkeeping: they edit the conversation (fold / unfold / todo), never
// the disk or the network. Exact names only — a tool that merely contains
// "compress" must stay classified by its own name.
const SESSION_TOOLS = new Set(['compress', 'decompress', 'acp_status', 'acp_cache', 'todo_write']);
const PATH_KEYS = ['path', 'file_path', 'notebook_path', 'target', 'filename', 'abs_path', 'filePath'];

const READ_PROGRAMS = new Set(['ls', 'dir', 'cat', 'type', 'head', 'tail', 'less', 'more', 'grep', 'egrep', 'rg', 'find',
    'fd', 'wc', 'sort', 'uniq', 'cut', 'tr', 'diff', 'cmp', 'stat', 'file', 'which', 'where', 'type', 'Get',
    'pwd', 'echo', 'printf', 'date', 'hostname', 'whoami', 'id', 'du', 'df', 'free', 'env', 'printenv', 'test',
    'true', 'false', 'git', 'Get-ChildItem', 'Get-Content', 'Get-Item', 'Select-String']);
// Navigation only moves the shell; it never touches the filesystem. It used to
// fall through to `exec`, and since a real command line is usually
// `cd dir && grep ... | head -20`, that one token was enough to send a purely
// read-only action to the reviewer.
const NAVIGATE_PROGRAMS = new Set(['cd', 'pushd', 'popd', 'chdir', 'Set-Location']);
// For these the first non-flag operand is a SEARCH PATTERN, not a path.
// `grep -rn 'file|path|dir' .` used to resolve to two paths, one of them
// `c:\...\file|path|dir` — which then showed up in the ledger and in the
// evidence block the reviewer reads.
const PATTERN_PROGRAMS = new Set(['grep', 'egrep', 'rg', 'Select-String']);
// Stream filters: read stdin, write stdout. They are state-changing only when
// they rewrite their input in place, which is a separate check below.
const FILTER_PROGRAMS = new Set(['awk', 'gawk', 'mawk', 'sed', 'jq', 'yq']);
const IN_PLACE_EDIT_FLAGS = /^(?:-i|--in-place)/;
const DELETE_PROGRAMS = new Set(['rm', 'unlink', 'del', 'erase', 'erase', 'rmdir', 'trash', 'Remove-Item', 'Remove-Item']);
const DESTROY_PROGRAMS = new Set(['shred', 'dd', 'mkfs', 'fdisk', 'wipefs', 'format', 'cipher']);
const PRIVILEGE_PROGRAMS = new Set(['sudo', 'runas', 'chmod', 'chown', 'cacls', 'icacls', 'reg', 'netsh', 'sc', 'setfacl', 'takeown', 'Set-Acl']);
const VCS_HISTORY_PROGRAMS = new Set(['git', 'hg', 'svn']);

// Discarding stderr is not a write to a path; treating it as one turned every
// `ls x 2>/dev/null` into an out-of-workspace target.
const REDIRECT_SINKS = new Set(['/dev/null', '/dev/stdin', '/dev/stdout', '/dev/stderr', 'nul']);
const isSink = (text) => REDIRECT_SINKS.has(String(text ?? '').toLowerCase());

const fsProbe = {
    lstat: (target) => lstatSync(target),
    spawn: (command, args) => spawnSync(command, args, { encoding: 'utf8', windowsHide: true, timeout: 5000 }),
};

function shellTargets(args) {
    return String(args?.command ?? args?.cmd ?? '');
}

function nonShellOpClass(toolName) {
    const name = String(toolName ?? '').toLowerCase();
    if (SESSION_TOOLS.has(name))
        return 'internal';
    if (/delete|remove|trash|unlink/.test(name))
        return 'delete';
    if (/read|^ls$|glob|grep|search|view|list|fetch|webfetch|websearch/.test(name))
        return 'read';
    if (/write|edit|create|patch|notebook/.test(name))
        return 'write';
    return 'other';
}

function nonShellPaths(args) {
    const found = [];
    for (const key of PATH_KEYS) {
        const value = args?.[key];
        if (typeof value === 'string' && value.trim() !== '')
            found.push(value);
    }
    for (const key of ['paths', 'files', 'targets']) {
        const value = args?.[key];
        if (Array.isArray(value))
            found.push(...value.filter(item => typeof item === 'string' && item.trim() !== ''));
    }
    return found;
}

function segmentOpClass(segment) {
    const program = segment.program;
    if (DESTROY_PROGRAMS.has(program))
        return 'destroy';
    if (PRIVILEGE_PROGRAMS.has(program))
        return 'privilege';
    if (DELETE_PROGRAMS.has(program))
        return 'delete';
    if (program === 'mv' || program === 'Rename-Item')
        return 'rename';
    if (segment.redirects.some(redirect => !isSink(redirect.text)))
        return 'write';
    // `sed -i` rewrites the file in place, so it is a write however the flag
    // is spelled — and it must be decided before the filter whitelist below.
    if (FILTER_PROGRAMS.has(program) && segment.words.some(word => word.kind !== 'operand'
        && IN_PLACE_EDIT_FLAGS.test(word.text)))
        return 'write';
    if (READ_PROGRAMS.has(program)) {
        if (VCS_HISTORY_PROGRAMS.has(program)) {
            const words = segment.words.map(word => word.text);
            if (program === 'git' && words.includes('push') && words.some(word => word === '--force' || word === '-f' || word === '--force-with-lease'))
                return 'history-rewrite';
            if (program === 'git' && (words.includes('clean') || (words.includes('reset') && words.includes('--hard'))
                || (words.includes('checkout', ) && words.includes('--')) || words.includes('restore')))
                return 'delete';
        }
        return 'read';
    }
    if (['touch', 'mkdir', 'cp', 'copy', 'Write-Output', 'tee', 'New-Item', 'Set-Content', 'Add-Content'].includes(program))
        return 'write';
    if (NAVIGATE_PROGRAMS.has(program) || FILTER_PROGRAMS.has(program))
        return 'read';
    return 'exec';
}

function fileFacts(target, probe) {
    try {
        const stat = probe.lstat(target);
        return {
            exists: true,
            kind: stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other',
            bytes: stat.size,
        };
    }
    catch {
        return { exists: false, kind: 'absent', bytes: undefined };
    }
}

/** One batched index read + one status read for the whole call. */
function gitStates(workspace, relatives, probe) {
    const states = new Map();
    if (relatives.length === 0)
        return { states, repo: false };
    const probeRepo = probe.spawn('git', ['-C', workspace, 'rev-parse', '--is-inside-work-tree']);
    if (probeRepo.error !== undefined || probeRepo.status !== 0)
        return { states, repo: false };
    const listed = probe.spawn('git', ['-C', workspace, 'ls-files', '-z', '--', ...relatives]);
    if (listed.error === undefined && listed.status === 0) {
        for (const entry of String(listed.stdout ?? '').split('\0').filter(Boolean))
            states.set(entry.replaceAll('\\', '/').toLowerCase(), 'tracked');
    }
    const status = probe.spawn('git', ['-C', workspace, 'status', '--porcelain=v1', '-z',
        '--untracked-files=all', '--ignored', '--', ...relatives]);
    if (status.error === undefined && status.status === 0) {
        for (const entry of String(status.stdout ?? '').split('\0').filter(Boolean)) {
            const mark = entry.slice(0, 2);
            const path = entry.slice(3).replaceAll('\\', '/').toLowerCase();
            if (states.has(path))
                continue;
            if (mark === '??')
                states.set(path, 'untracked');
            else if (mark === '!!')
                states.set(path, 'ignored');
            else
                states.set(path, 'tracked');
        }
    }
    return { states, repo: true };
}

function rootHitFor(normalized, roots, opClass) {
    if (isWithin(roots.workspace, normalized, roots.home))
        return 'workspace';
    // A trust root is an `allow` row from the rule table, so it can be scoped to
    // the operations the operator actually allowed (read / write / delete).
    if (roots.trusted.some(rule => matchPath(rule, normalized, opClass)))
        return 'trusted';
    if (roots.dshOpen.some(rule => matchPath(rule, normalized, opClass)))
        return 'dsh-open';
    return 'outside';
}

/**
 * Build the action record for one tool call.
 *
 * `targets` are literals only; a dynamic operand (`$(...)`, glob, brace
 * expansion) is kept as `dynamic: true` with no filesystem read, because its
 * real target is unknowable here and must not be presented as a proven fact.
 */
export function collectFacts({ toolName, args, roots, probe = fsProbe }) {
    const isShell = SHELL_TOOLS.has(String(toolName ?? '').toLowerCase())
        || typeof shellTargets(args) === 'string' && typeof args?.command === 'string';
    const segments = isShell
        ? splitSegments(shellTargets(args)).map(segment => ({
            program: segment.program,
            opClass: segmentOpClass(segment),
            // Ordered argument words (flags included): the command plane matches
            // "program + argument prefix", which needs the sequence, not a set.
            words: segment.words.map(word => word.text),
            flags: segment.words.filter(word => word.kind !== 'operand').map(word => word.text),
            operands: operandsOf(segment),
            redirects: segment.redirects.map(redirect => redirect.text),
            opaque: segment.opaque === true,
        }))
        : [];
    const literalInputs = [];
    if (isShell) {
        for (const segment of segments) {
            const skipFirst = PATTERN_PROGRAMS.has(segment.program);
            let seen = 0;
            for (const operand of segment.operands) {
                seen += 1;
                if (skipFirst === true && seen === 1)
                    continue;
                literalInputs.push({ text: operand, segment, dynamic: isDynamic(operand) });
            }
            for (const redirect of segment.redirects) {
                if (isSink(redirect))
                    continue;
                literalInputs.push({ text: redirect, segment, dynamic: isDynamic(redirect) });
            }
        }
    }
    else {
        const synthetic = { program: String(toolName ?? ''), opClass: nonShellOpClass(toolName), words: [], flags: [], operands: [], redirects: [], opaque: false };
        segments.push(synthetic);
        for (const value of nonShellPaths(args))
            literalInputs.push({ text: value, segment: synthetic, dynamic: isDynamic(value) });
    }

    const prepared = literalInputs.map((input) => {
        if (input.dynamic)
            return { input: input.text, dynamic: true, opClass: input.segment.opClass };
        const normalized = normalizePath(input.text, roots.workspace, roots.home);
        return {
            input: input.text,
            path: normalized,
            dynamic: false,
            opClass: input.segment.opClass,
            program: input.segment.program,
            rootHit: rootHitFor(normalized, roots, input.segment.opClass),
            ...fileFacts(normalized, probe),
        };
    });
    const relatives = prepared
        .filter(target => target.dynamic === false && target.rootHit === 'workspace')
        .map(target => pathApiFor(target.path).relative(roots.workspace, target.path).replaceAll('\\', '/'));
    const { states, repo } = gitStates(roots.workspace, relatives, probe);
    for (const target of prepared) {
        if (target.dynamic === true || target.rootHit !== 'workspace')
            continue;
        const rel = pathApiFor(target.path).relative(roots.workspace, target.path).replaceAll('\\', '/').toLowerCase();
        target.gitState = states.get(rel) ?? (repo ? 'unknown' : 'not-a-repo');
    }
    // Only an unparseable segment that CHANGES STATE makes the action
    // unverifiable; a `$(...)` inside a read-only segment stays evidence.
    const opaque = segments.some(segment => segment.opaque === true && segment.opClass !== 'read')
        || (isShell === true && segments.length === 0 && String(args?.command ?? '').trim() !== '');
    const actionHash = createHash('sha256')
        .update(`${toolName}|${JSON.stringify(isShell ? String(args?.command ?? args?.cmd ?? '') : args ?? {})}`)
        .digest('hex')
        .slice(0, 16);
    return {
        toolName: String(toolName ?? ''),
        isShell,
        actionHash,
        workspace: roots.workspace,
        segments,
        targets: prepared,
        opaque,
        truncated: prepared.length > MAX_TARGETS,
        counts: {
            total: prepared.length,
            dynamic: prepared.filter(target => target.dynamic === true).length,
            deletes: prepared.filter(target => target.opClass === 'delete').length,
        },
    };
}

export { fsProbe, READ_PROGRAMS, DELETE_PROGRAMS, DESTROY_PROGRAMS, PRIVILEGE_PROGRAMS, segmentOpClass };
