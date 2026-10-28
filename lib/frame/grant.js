// L1 grant: the code-enforced floor. It answers one question — may a model
// RELEASE this action at all — and it can only narrow, never widen.
//
//   never    : not presented to the reviewer; a human must answer.
//   confirm  : reviewed for advice, but ALLOW carries no release power.
//   auto     : ALLOW releases (only when config.mode === 'auto').
import { isFilesystemRoot, normalizePath, segmentsOf, basenameOf, isWithin } from './paths.js';
import { matchPath } from './policy.js';

const SENSITIVE_SEGMENTS = ['.ssh', '.gnupg', '.aws', '.azure', '.kube', '.git', '.copilot', '.docker', '.dsh', '.workbuddy', '.qoder'];
const SENSITIVE_SUBTREES = ['.config/gcloud', 'appdata/roaming/gcloud', 'appdata/local/gcloud', 'appdata/roaming/azure',
    'appdata/roaming/cloudsdk', 'appdata/roaming/microsoft/credentials', 'library/application support/google-cloud-sdk'];
const PLAIN_SENSITIVE = new Set(['.gitconfig', '.gitmodules', '.netrc', '.npmrc', '.pypirc', '.mcp.json']);
const CREDENTIAL_BASENAME = /(credential|secret|token|password|apikey|api_key|passwd)/i;
const KEY_BASENAME = /\.(pem|key|p12|pfx|kdbx|jks|keystore)$/i;
const SSH_KEY_BASENAME = /^id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$/i;
const DOTENV_BASENAME = /^\.env(\..+)?$/i;
const DOTENV_EXEMPT = /^\.env\.(example|sample|template)$/i;
const SHELL_RC_BASENAME = /^\.(?:ba|z|k|c|tc)sh(?:rc|_profile|_login|_logout)$|^\.(?:bash|zsh)?profile$|^\.(?:profile|zlogin|zlogout|bash_login|bash_logout)$/;
const WINDOWS_CRITICAL = /^[a-z]:\\(?:windows|program files|program files \(x86\)|programdata|boot)(?:\\|$)/;
const POSIX_CRITICAL = /^\/(?:etc|bin|sbin|usr|lib|lib64|var|opt|home|root|private|system|library)(?:\/|$)/;

const CONFIRM_OP_CLASSES = new Set(['destroy', 'privilege', 'history-rewrite']);

// 一次删除超过这么多条，就不再算「批量小、看得清」：可以送去审，但不能自动放行。
// 这是代码里的一档常量，不是配置项——配置页上没有它，写成 config.* 就是骗人。
const MAX_AUTO_DELETE_TARGETS = 20;

// A delete flag the frame cannot interpret is a delete whose real operand set
// is unknown (`--files0-from list` reads paths from a file, `-i` waits on a
// terminal), so it may be reviewed but never auto-released.
const RECURSIVE_FLAG = /-[a-z]*r[a-z]*/i;
const KNOWN_DELETE_FLAGS = new Set(['-', '--', '-f', '-v', '--force', '--verbose']);

const NEVER_REASONS = new Set(['unresolved-path', 'credential-or-client-tree', 'credential-material',
    'os-critical-tree', 'filesystem-root', 'home-root', 'workspace-root', 'harness-state-tree']);

const CONFIRM_REASONS = new Set(['unresolvable-operand', 'opaque-command', 'batch-too-large',
    'path-outside-trusted-roots', 'symlink-operand', 'delete-of-non-file', 'unclassified-tool',
    'unrecognized-delete-flag', 'unrecoverable-content']);

export function isSensitiveBasename(name) {
    if (name === '' || DOTENV_EXEMPT.test(name))
        return false;
    return PLAIN_SENSITIVE.has(name) || DOTENV_BASENAME.test(name) || CREDENTIAL_BASENAME.test(name)
        || KEY_BASENAME.test(name) || SSH_KEY_BASENAME.test(name) || SHELL_RC_BASENAME.test(name);
}

/** Why a resolved path can never be auto-released; undefined when it can. */
export function neverReasonFor(target, roots) {
    const path = target.path;
    if (typeof path !== 'string' || path === '')
        return 'unresolved-path';
    const segments = segmentsOf(path).map(segment => segment.toLowerCase());
    const base = basenameOf(path).toLowerCase();
    const slashed = path.replaceAll('\\', '/');
    // An operator-opened DSH_HOME subtree stops being "harness state", but it is
    // still not a credential tree: only the `.dsh` segment itself is excused.
    const opened = roots.dshOpen.some(rule => matchPath(rule, path, target.opClass));
    const clientSegments = opened ? SENSITIVE_SEGMENTS.filter(segment => segment !== '.dsh') : SENSITIVE_SEGMENTS;
    if (segments.some(segment => clientSegments.includes(segment)))
        return 'credential-or-client-tree';
    if (SENSITIVE_SUBTREES.some(tree => slashed.includes(`/${tree}`)))
        return 'credential-or-client-tree';
    if (isSensitiveBasename(base))
        return 'credential-material';
    if (WINDOWS_CRITICAL.test(path) || POSIX_CRITICAL.test(path))
        return 'os-critical-tree';
    // A root only needs forbidding when the action CHANGES something.
    // `rm -rf /workspace` must never be auto-released, but `grep x /workspace`
    // and `cd /workspace` touch nothing. It is exactly this over-reach that
    // dragged every harmless read command in front of the reviewer.
    if (target.opClass !== 'read') {
        if (isFilesystemRoot(path, roots.home))
            return 'filesystem-root';
        if (path === normalizePath(roots.home, roots.home, roots.home))
            return 'home-root';
        if (path === roots.workspace)
            return 'workspace-root';
    }
    if (target.opClass === 'delete' && !opened && roots.dshHome !== undefined
        && isWithin(roots.dshHome, path, roots.home))
        return 'harness-state-tree';
    return undefined;
}

function disposabilityFacts(facts) {
    const deletes = facts.targets.filter(target => target.opClass === 'delete' || target.opClass === 'destroy');
    if (deletes.length === 0)
        return undefined;
    return deletes.map((target) => {
        if (target.dynamic === true)
            return `${target.input} (unresolvable operand)`;
        const git = target.gitState === undefined ? '' : `, ${target.gitState}`;
        return `${target.path} (${target.kind}, ${target.bytes ?? '?'} B, ${target.rootHit}${git})`;
    }).join('; ');
}

/**
 * Facts → grant state. Every collected reason travels to the ledger.
 *
 * `floor` 是内置行的当前档位（`policy.floorActions`）：理由命中了，但那一行被改成
 * `ai`／`release`／停用，就不再往上升一档——**内置项全部可改**是这一版的前提。
 * 改成 `deny` 则直接拒。默认（表里没有覆盖行）＝`ask`，也就是今天的行为：必人工。
 */
export function grantFor(facts, roots, floor = new Map()) {
    const lift = reason => {
        const action = floor.get(reason) ?? 'ask';
        return action === 'ai' || action === 'release' ? 'off' : action;
    };
    const denied = new Set();
    const keep = reason => {
        const action = lift(reason);
        if (action === 'deny') {
            denied.add(reason);
            return false;
        }
        return action !== 'off';
    };
    const reasons = new Set();
    for (const target of facts.targets) {
        // An unresolvable operand only hides a real effect when its segment
        // changes state; `echo exit=$?` next to a proven deletion stays evidence.
        if (target.dynamic === true) {
            if (target.opClass !== 'read' && keep('unresolvable-operand'))
                reasons.add('unresolvable-operand');
            continue;
        }
        const never = neverReasonFor(target, roots);
        if (never !== undefined && keep(never))
            reasons.add(never);
    }
    if (facts.opaque && keep('opaque-command'))
        reasons.add('opaque-command');
    for (const segment of facts.segments) {
        for (const op of CONFIRM_OP_CLASSES) {
            const reason = `elevated-operation:${op}`;
            if (segment.opClass === op && keep(reason))
                reasons.add(reason);
        }
        if (segment.opClass === 'other' && !facts.isShell && keep('unclassified-tool'))
            reasons.add('unclassified-tool');
        if (segment.opClass === 'delete' || segment.opClass === 'destroy') {
            if (segment.flags.some(flag => RECURSIVE_FLAG.test(flag) || flag === '--recursive')
                && keep('recursive-delete'))
                reasons.add('recursive-delete');
            if (segment.flags.some(flag => !KNOWN_DELETE_FLAGS.has(flag) && !/^-[fv]+$/i.test(flag))
                && keep('unrecognized-delete-flag'))
                reasons.add('unrecognized-delete-flag');
        }
    }
    if ((facts.counts.deletes > MAX_AUTO_DELETE_TARGETS || facts.truncated) && keep('batch-too-large'))
        reasons.add('batch-too-large');
    if (facts.targets.some(target => target.dynamic === false && target.rootHit === 'outside')
        && keep('path-outside-trusted-roots'))
        reasons.add('path-outside-trusted-roots');
    if (facts.targets.some(target => target.kind === 'symlink') && keep('symlink-operand'))
        reasons.add('symlink-operand');
    // `absent` means there is nothing to delete: a repeated `rm -f` after a
    // successful first run must not cost a human click. Only real things that
    // are not plain files (a directory, a symlink, a device) stay off-limits.
    if (facts.targets.some(target => target.opClass === 'delete'
        && target.kind !== 'file' && target.kind !== 'absent') && keep('delete-of-non-file'))
        reasons.add('delete-of-non-file');
    // Content that exists nowhere else (non-zero bytes, untracked, not in a
    // declared disposable tree) is not proven disposable: review, never release.
    const deletes = facts.targets.filter(target => target.opClass === 'delete' && target.dynamic !== true);
    if (deletes.some(target => target.kind === 'file' && !(target.bytes === 0 || target.gitState === 'tracked'
        || target.rootHit === 'trusted' || target.rootHit === 'dsh-open')) && keep('unrecoverable-content'))
        reasons.add('unrecoverable-content');

    const list = [...reasons];
    const disposability = disposabilityFacts(facts);
    if (denied.size > 0)
        return { state: 'deny', reasons: [...new Set([...denied, ...list])], disposability };
    if (list.some(reason => NEVER_REASONS.has(reason)))
        return { state: 'never', reasons: list, disposability };
    const confirmLike = list.some(reason => CONFIRM_REASONS.has(reason) || reason.startsWith('elevated-operation:'));
    if (confirmLike)
        return { state: 'confirm', reasons: list, disposability };
    return { state: 'auto', reasons: list, disposability };
}

export { SENSITIVE_SEGMENTS, NEVER_REASONS, CONFIRM_REASONS };
