// L0 path facts: one normalization used by every layer, plus containment.
// Deliberately independent of the old plugin's `paths.js` so a verdict cannot
// hide inside a path helper.
import nodePath from 'node:path';
import os from 'node:os';

const WIN32 = process.platform === 'win32';

export function pathApiFor(candidate, cwd) {
    if (/^[A-Za-z]:[\\/]/.test(candidate) || candidate.startsWith('\\\\'))
        return nodePath.win32;
    // A leading slash is already an answer: POSIX absolute, whatever the
    // working directory looks like.
    if (candidate.startsWith('/'))
        return nodePath.posix;
    // A bare relative operand inherits the working directory's style; resolving
    // it with the wrong API silently produced a path inside the wrong tree.
    if (typeof cwd === 'string' && (/^[A-Za-z]:[\\/]/.test(cwd) || cwd.startsWith('\\\\')))
        return nodePath.win32;
    return nodePath.posix;
}

/** `/c/dir` and `//c` on Windows are drive spellings, not POSIX roots. */
export function canonicalizeMsys(input) {
    if (!WIN32 || typeof input !== 'string')
        return input;
    if (/^\/{2}[A-Za-z]\/?$/.test(input))
        return `${input[2].toUpperCase()}:\\`;
    if (input.startsWith('//'))
        return input.replace(/\//g, '\\');
    const drive = /^\/([A-Za-z])(\/|$)/.exec(input);
    if (drive === null)
        return input;
    return `${drive[1].toUpperCase()}:\\${input.slice(3).replace(/\//g, '\\')}`;
}

/** `\\?\`, `\\??\` and `\??\` are the same target in three spellings. */
export function canonicalizeNamespace(input) {
    const lower = input.toLowerCase();
    if (lower.startsWith('\\\\?\\unc\\'))
        return `\\\\${input.slice(8)}`;
    if (lower.startsWith('\\\\??\\unc\\'))
        return `\\\\${input.slice(9)}`;
    if (lower.startsWith('\\\\?\\') || lower.startsWith('\\??\\'))
        return input.slice(4);
    return input;
}

/** Absolute, separator-normalized, and case-folded on Windows. */
export function normalizePath(input, cwd, home = os.homedir()) {
    const canonical = canonicalizeNamespace(canonicalizeMsys(String(input ?? '').trim()));
    const expanded = canonical === '~'
        ? home
        : (canonical.startsWith('~/') || canonical.startsWith('~\\'))
            ? pathApiFor(home).join(home, canonical.slice(2))
            : canonical;
    const api = pathApiFor(expanded, cwd);
    const absolute = api.isAbsolute(expanded) ? expanded : api.resolve(cwd ?? process.cwd(), expanded);
    const normalized = api.normalize(absolute);
    return api === nodePath.win32 ? normalized.toLowerCase() : normalized;
}

export function isWithin(root, target, home) {
    const normalizedRoot = normalizePath(root, root, home);
    const normalizedTarget = normalizePath(target, root, home);
    const api = pathApiFor(normalizedRoot);
    if (pathApiFor(normalizedTarget) !== api)
        return false;
    const relative = api.relative(normalizedRoot, normalizedTarget);
    return relative === ''
        || (!relative.startsWith(`..${api.sep}`) && relative !== '..' && !api.isAbsolute(relative));
}

/** Whether the target IS a filesystem root (`c:\`, `\`). */
export function isFilesystemRoot(target, home) {
    const normalized = normalizePath(target, target, home);
    const api = pathApiFor(normalized);
    return api.parse(normalized).root === normalized;
}

export function segmentsOf(normalized) {
    return normalized.split(/[\\/]/).filter(Boolean);
}

export function basenameOf(normalized) {
    const parts = segmentsOf(normalized);
    return parts.length === 0 ? '' : parts[parts.length - 1];
}

export function homeRoot() {
    return normalizePath(os.homedir(), process.cwd());
}

export { nodePath as path, os };
