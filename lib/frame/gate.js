// Host plumbing: which sessions this frame owns, which roots a call lives in,
// and what the user actually said. No verdicts here.
import { homedir } from 'node:os';
import { join } from 'node:path';
import { normalizePath, isWithin, isFilesystemRoot, pathApiFor, segmentsOf, basenameOf } from './paths.js';
import { SENSITIVE_SEGMENTS, isSensitiveBasename } from './grant.js';
import { trustRules } from './policy.js';
import { sanitizeText } from './sanitize.js';

const WINDOWS_CRITICAL = /^[a-z]:\\(?:windows|program files|program files \(x86\)|programdata|boot)(?:\\|$)/;
const POSIX_CRITICAL = /^\/(?:etc|bin|sbin|usr|lib|var|opt|home|root|private|system|library)(?:\/|$)/;

/** The leading literal directories of a pattern, used by the shape guards. */
function literalPrefix(path) {
    const parts = path.split(/[\\/]/);
    const kept = [];
    for (const part of parts) {
        if (/[*?]/.test(part))
            break;
        kept.push(part);
    }
    return kept.join(path.includes('\\') && !path.includes('/') ? '\\' : '/');
}

/**
 * Shape guard for an `allow` row that is being used as a trust root. Rows under
 * DSH_HOME are openings (a subtree, never the whole tree); everything else has
 * to be a deliberate, deep, non-privileged path — the same guards the old
 * separate `trustedDirs` / `dshOpen` keys carried, now on one table.
 */
export function trustRejection(pattern, roots) {
    if (typeof pattern !== 'string' || pattern.trim() === '')
        return 'blank';
    const text = pattern.trim();
    if (text.startsWith('re:'))
        return 'regex-operand';
    if (!/^(?:[A-Za-z]:[\\/]|\\\\|\/|~[\\/])/.test(text))
        return 'not-absolute';
    const normalized = normalizePath(text, roots.workspace ?? process.cwd(), roots.home);
    const prefix = literalPrefix(normalized);
    const parts = segmentsOf(prefix);
    const api = pathApiFor(normalized);
    if (isWithin(roots.dshHome, prefix, roots.home)) {
        if (prefix === roots.dshHome)
            return 'whole-state-tree';
        if (parts.some(part => SENSITIVE_SEGMENTS.includes(part) && part !== '.dsh'))
            return 'credential-or-client-tree';
        if (isSensitiveBasename(basenameOf(prefix).toLowerCase()))
            return 'credential-material';
        return undefined;
    }
    if (isFilesystemRoot(normalized, roots.home))
        return 'filesystem-root';
    if (normalized === roots.home)
        return 'home-root';
    if (parts.length < 3)
        return 'too-broad';
    if (parts.some(part => SENSITIVE_SEGMENTS.includes(part)))
        return 'credential-or-client-tree';
    if (WINDOWS_CRITICAL.test(normalized) || POSIX_CRITICAL.test(normalized))
        return 'os-critical-tree';
    if (api.dirname(prefix) === roots.home || api.dirname(prefix) === api.parse(prefix).root)
        return 'too-broad';
    if (prefix === roots.workspace)
        return 'workspace-root';
    if (isSensitiveBasename(basenameOf(prefix).toLowerCase()))
        return 'credential-material';
    return undefined;
}

export function resolveRoots(cwd, config = {}) {
    const home = normalizePath(homedir(), process.cwd());
    const workspace = normalizePath(cwd ?? process.cwd(), home);
    const dshHome = normalizePath(process.env.DSH_HOME?.trim() || join(home, '.dsh'), home);
    const scope = { home, workspace, dshHome };
    const trusted = [];
    const dshOpen = [];
    const rejected = [];
    for (const rule of trustRules(config)) {
        const rejection = trustRejection(rule.match, scope);
        if (rejection !== undefined) {
            rejected.push({ dir: rule.match, reason: rejection });
            continue;
        }
        const entry = { ...rule, match: normalizePath(rule.match, workspace, home) };
        if (isWithin(dshHome, literalPrefix(entry.match), home))
            dshOpen.push(entry);
        else
            trusted.push(entry);
    }
    return {
        home,
        workspace,
        dshHome,
        trusted,
        dshOpen,
        rejectedTrusted: rejected,
    };
}

/** The durable raw permission identity, never the folded current(). */
export function rawPresetOf(permissionPresets, session) {
    if (session === undefined || session === null || typeof permissionPresets?.permissionState !== 'function')
        return undefined;
    try {
        const state = permissionPresets.permissionState(session);
        return typeof state?.preset === 'string' ? state.preset : undefined;
    }
    catch {
        return undefined;
    }
}

/** Names in `gateNames` that the host's live permission catalog does not offer. */
export function missingGatedPresets(permissionPresets, gateNames) {
    if (typeof permissionPresets?.optionOf !== 'function')
        return [];
    return (Array.isArray(gateNames) ? gateNames : []).filter((name) => {
        try {
            permissionPresets.optionOf(name);
            return false;
        }
        catch {
            return true;
        }
    });
}

/** Walk the subagent parent chain until a gated ancestor owns the execution. */
export function authorityFor(exec, parentAgent, permissionPresets, gateNames) {
    const directSession = exec?.agent?.session;
    if (gateNames.includes(rawPresetOf(permissionPresets, directSession) ?? ''))
        return exec.agent;
    let session = directSession;
    const visited = new Set();
    while (session?.header?.origin === 'subagent' && session.header.parentSession !== undefined) {
        const key = String(session.header.parentSession);
        if (visited.has(key))
            return undefined;
        visited.add(key);
        const parent = parentAgent?.(session.header.parentSession);
        if (parent === undefined)
            return undefined;
        if (gateNames.includes(rawPresetOf(permissionPresets, parent.session) ?? ''))
            return parent;
        session = parent.session;
    }
    return undefined;
}

export function rootSessionId(exec, parentAgent) {
    let session = exec?.agent?.session;
    const visited = new Set();
    while (session?.header?.origin === 'subagent' && session.header.parentSession !== undefined) {
        const key = String(session.header.parentSession);
        if (visited.has(key))
            break;
        visited.add(key);
        const parent = parentAgent?.(session.header.parentSession);
        if (parent?.session?.id == null)
            break;
        session = parent.session;
    }
    return session?.id;
}

function textOf(content) {
    if (Array.isArray(content))
        return content.filter(block => block?.type === 'text').map(block => block.text).join('\n');
    return content;
}

// Tone is not authorization. Angry one-liners used to travel into the evidence
// block labelled `trusted_user_intent`, and the reviewer began refusing harmless
// actions on that basis — verbatim from the ledger: "User intent is abusive and
// does not authorize this specific grep/head read action".
//
// The repair is a demotion, not a deletion: a heated line keeps its content but
// loses its authorizing label, and travels in the non-authorizing background
// block instead. A curse that also carries a real instruction (「你他妈…不看看
// 为什么没通过」) is therefore still read in full — only the label changes.
const ABUSE_PATTERN = /(傻[逼叉子屄]|蠢货|蠢材|白痴|废物|脑子有病|有病|去死|滚开|他妈|妈的|妈了个|狗屎|智障|fuck|shit|stupid|idiot|dumb|useless|damn|wtf)/i;

function authorizationClass(text) {
    return ABUSE_PATTERN.test(String(text ?? '')) ? 'background' : 'authorizing';
}

/**
 * What the user actually asked for, newest first: session events plus anything
 * still sitting in the agent inbox (steered prompts arrive after the last
 * event). Plugin-injected messages are never authorization evidence.
 *
 * Each entry carries an `authorizing` class. A line whose class is `background`
 * must never reach the reviewer as authorization — evidence.js enforces that by
 * routing it into the non-authorizing block.
 */
export function userIntents(authority, { maxMessages = 8, budget = 6_000 } = {}) {
    const found = [];
    const events = typeof authority?.session?.snapshotEvents === 'function' ? authority.session.snapshotEvents() : [];
    for (let index = (events?.length ?? 0) - 1; index >= 0 && found.length < maxMessages; index -= 1) {
        const event = events[index];
        if (event?.type !== 'user/message' || event.data?.source?.kind !== 'user')
            continue;
        const text = String(textOf(event.data.content) ?? '').trim();
        if (text !== '')
            found.push({ seq: index, origin: 'user-message', text: sanitizeText(text, 1_500), authorizing: authorizationClass(text) });
    }
    const inbox = authority?.inbox;
    for (const batch of [...(inbox?.nextStep ?? []), ...(inbox?.nextTurn ?? [])]) {
        const message = Array.isArray(batch) ? batch[0] : batch;
        if (message?.source?.kind !== 'user')
            continue;
        const text = String(textOf(message.content) ?? '').trim();
        if (text !== '')
            found.push({ seq: Number.MAX_SAFE_INTEGER, origin: 'inbox', text: sanitizeText(text, 1_500), authorizing: authorizationClass(text) });
    }
    let used = 0;
    const admitted = [];
    for (const intent of found) {
        if (used + intent.text.length > budget)
            break;
        used += intent.text.length;
        admitted.push(intent);
    }
    return admitted.reverse();
}

export function sessionModelLabel(session) {
    const config = typeof session?.requestHeader === 'function' ? session.requestHeader()?.config : undefined;
    return config?.provider !== undefined ? `${config.provider}/${config.model}` : 'unknown';
}
