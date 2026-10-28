/**
 * dsh-auto-approval-frame — an interception and audit frame for DeepSeek Harness.
 *
 * One ladder per tool call: 内置行 → 有序规则表 → 只读／会话内部事实门 →
 * AI 快判 → AI 深评 → 人工 → 结果脱敏. The ladder itself lives in
 * `frame/ladder.js` and is shared by this file (real decisions) and the
 * `/explain` route (模拟审批) — there is no second implementation to drift from.
 * Every call, decision and human answer lands in the audit store
 * (day segments, hash chain, manifest, retention); the settings page reads it
 * over a same-origin carrier route.
 *
 * Invariants this file is responsible for:
 *  - a rule row can `deny` or `ask` decisively; `allow` only means "this plane
 *    does not stop it" and the call still faces the fact gate and the AI.
 *  - `approval/request` never recomputes facts or grant (see pending.js).
 *  - a grant of `never` does not reach the model.
 *  - ALLOW releases only when grant === 'auto' and mode === 'auto'.
 *  - a release that cannot be written to the audit store is downgraded to an ask.
 */
import z from '@deepseek-ai/schemastery';
import { homedir } from 'node:os';
import { readModelGroups } from './frame/profile.js';
import { join } from 'node:path';
import { projectEvidence } from './frame/evidence.js';
import { buildSystemPrompt, mayRelease, parseVerdict } from './frame/verdict.js';
import { reviewAction } from './frame/review.js';
import { createPendingStore } from './frame/pending.js';
import { createAuditStore } from './frame/audit.js';
import { RULE_ACTIONS, RULE_PLANES, effectiveRows, scanSensitive, sensitiveRows, toRule } from './frame/policy.js';
import { createSecretVault } from './frame/vault.js';
import { restoreVaultedWrites } from './frame/restore.js';
import { ladderRuleCounts, ladderSteps, ladderVerdict, walkLadder } from './frame/ladder.js';
import { authorityFor, missingGatedPresets, rawPresetOf, resolveRoots, rootSessionId, sessionModelLabel, userIntents } from './frame/gate.js';
import { redactSecrets, sanitizeText } from './frame/sanitize.js';

export const name = 'dsh-auto-approval-frame';
// `userQuestions` 是命中敏感形状时那张三选一卡片的来源；组合里没有它≠没有敏感保护，
// 那时按各行写死的动作走（询问那一档退回它自己的默认动作），绝不因此放行。
export const inject = ['approval', 'permissionPresets', 'sessions', 'tools', 'llm', 'agents', 'settings', 'userQuestions'];
const SETTINGS_NS = 'auto-approval-frame';
const AUDIT_ROUTE = '/api/auto-approval-frame/audit';
const AUDIT_EXPORT_ROUTE = '/api/auto-approval-frame/audit/export';
const AUDIT_CLEAR_ROUTE = '/api/auto-approval-frame/audit/clear';
const EXPLAIN_ROUTE = '/api/auto-approval-frame/explain';
const FRAME_ROUTE = '/api/auto-approval-frame/frame';
const MODELS_ROUTE = '/api/auto-approval-frame/models';
const SECRETS_ROUTE = '/api/auto-approval-frame/secrets';

const DSH_HOME_PATH = () => process.env.DSH_HOME?.trim() || join(homedir(), '.dsh');

const EDITABLE_KEYS = ['enabled', 'mode', 'reviewerSource', 'reviewerProvider', 'reviewerModel',
    'reviewerMaxTokens', 'reviewerTimeoutMs', 'evidenceBudget',
    'reviewRules', 'commandRules', 'fileRules', 'networkRules', 'toolRules', 'sensitiveRules',
    'sensitiveDetect', 'autoRestoreSecrets', 'fastJudge', 'fastJudgeMaxTokens', 'fastJudgeTimeoutMs',
    'retentionDays', 'maxTotalBytes', 'maxSegmentBytes'];
// Patch-only: which sessions the frame owns, and diagnostics.
// A card cannot widen trust here, so an automated UI write cannot reach them.
const HOST_ONLY_KEYS = ['gatedPresets', 'debug'];

/** Rows of the rule tables. A file row decides per operation; others use `action`. */
const ruleArray = (plane) => z.array(z.object({
    id: z.string().default(''),
    plane: z.string().default(plane),
    match: z.string().default(''),
    action: z.string().default(''),
    read: z.string().default(''),
    write: z.string().default(''),
    delete: z.string().default(''),
    // 检测规则专用：`preset`＝它盖住的那条内置形状（空＝用户自己加的行）；
    // `enabled:false`＝这一行不表态（内置形状也能关，不必删行、也不会被下次启动复活）。
    preset: z.string().default(''),
    label: z.string().default(''),
    enabled: z.boolean().default(true),
})).default([]);

/** Config keys that hold rule rows rather than plain strings. */
const RULE_KEYS = {
    toolRules: 'tool',
    commandRules: 'command',
    fileRules: 'file',
    networkRules: 'network',
    sensitiveRules: 'sensitive',
};

/**
 * The three separate scope keys (v0.5.x) are now `allow` / `ask` rows in the
 * file table. Prohibition rows are inserted first so a broad later `allow`
 * subtree cannot shadow them inside the same plane.
 *
 * Migration runs only while the file table is still empty. Once the operator
 * owns rows, the legacy keys are dead text: re-applying them would duplicate
 * rows on every boot and resurrect a row the operator deliberately deleted.
 */
function migrateLegacyScopes(plain) {
    const list = value => (Array.isArray(value) ? value : []).filter(item => typeof item === 'string' && item.trim() !== '');
    const existing = Array.isArray(plain.fileRules) ? plain.fileRules : [];
    if (existing.length > 0) {
        // 已经有自己的表了：旧键只是残留文字，不再参与判定。
        const { trustedDirs, dshOpen, neverAutoExtra, ...rest } = plain;
        return rest;
    }
    const row = (match, action) => ({ match, read: action, write: action, delete: action });
    const legacy = [
        ...list(plain.neverAutoExtra).map(match => row(match, 'ask')),
        // 旧的两个范围键都是「这一层不拦、继续判」＝现在的 `ai` 档（信任声明由 gate 读 ai/release）。
        ...list(plain.trustedDirs).map(match => row(match, 'ai')),
        ...list(plain.dshOpen).map(match => row(match, 'ai')),
    ];
    if (legacy.length === 0)
        return plain;
    const { trustedDirs, dshOpen, neverAutoExtra, ...rest } = plain;
    return { ...rest, fileRules: legacy };
}

export const Config = z.object({
    enabled: z.boolean().default(true),
    mode: z.union(['off', 'advise', 'auto']).default('auto'),
    gatedPresets: z.array(z.string()).default(['auto-approval']),
    reviewerSource: z.union(['session', 'preset']).default('session'),
    reviewerProvider: z.string().default(''),
    reviewerModel: z.string().default(''),
    reviewerMaxTokens: z.number().default(512).min(64).max(4_096),
    reviewerTimeoutMs: z.number().default(20_000).min(1_000).max(120_000),
    evidenceBudget: z.number().default(16_000).min(2_000).max(48_000),
    reviewRules: z.array(z.string()).default([]),
    commandRules: ruleArray('command'),
    fileRules: ruleArray('file'),
    networkRules: ruleArray('network'),
    toolRules: ruleArray('tool'),
    sensitiveRules: ruleArray('sensitive'),
    sensitiveDetect: z.boolean().default(true),
    // 默认关：把明文回填进文件是本插件唯一会写用户文件的一支，要人自己在「敏感信息」卡上开。
    autoRestoreSecrets: z.boolean().default(false),
    fastJudge: z.boolean().default(true),
    fastJudgeMaxTokens: z.number().default(256).min(64).max(1_024),
    fastJudgeTimeoutMs: z.number().default(3_000).min(500).max(30_000),
    retentionDays: z.number().default(90).min(1).max(3_650),
    maxTotalBytes: z.number().default(512 * 1024 * 1024).min(1024 * 1024),
    maxSegmentBytes: z.number().default(50 * 1024 * 1024).min(1024 * 1024),
    debug: z.boolean().default(false),
});

for (const key of EDITABLE_KEYS)
    Config.dict[key] = Config.dict[key].extra('volatile', true);
/**
 * What this call is about to do, in the operator's own words. The chain stores
 * parsed targets, but a parsed target list cannot answer the question an audit
 * actually asks — "what was about to happen" — which is why the raw action is
 * carried too, redacted before it is truncated so a token cannot survive a cut.
 */
function actionTextOf(exec) {
    const args = exec?.arguments ?? {};
    const command = typeof args.command === 'string' ? args.command
        : typeof args.cmd === 'string' ? args.cmd
            : undefined;
    return command ?? `${exec?.name ?? '-'} ${JSON.stringify(args)}`;
}

/** A card-owned volatile field arrives as a `{ get() }` reference, not a value. */
function unwrapVolatile(value) {
    if (value === null || typeof value !== 'object')
        return value;
    if (typeof value.get === 'function')
        return unwrapVolatile(value.get());
    if (Array.isArray(value))
        return value.map(unwrapVolatile);
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, unwrapVolatile(child)]));
}

function isLoopbackHost(hostname) {
    if (hostname === 'localhost' || hostname === '[::1]' || hostname === '::1')
        return true;
    if (/^\[?::ffff:(?:7f[0-9a-f]{2}:[0-9a-f]{1,4}|127(?:\.\d{1,3}){3})\]?$/i.test(hostname))
        return true;
    const parts = hostname.split('.');
    return parts.length === 4 && parts[0] === '127'
        && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

/**
 * The ledger route is read by the settings page itself: same-origin over the
 * carrier. A non-HTTP scheme can only come from the carrier, so it counts as
 * loopback; anything else must resolve to loopback and not be cross-site.
 */
function isTrustedLedgerRequest(request) {
    try {
        const url = new URL(request.url);
        const carrierOwned = url.protocol !== 'http:' && url.protocol !== 'https:';
        const authority = carrierOwned ? '127.0.0.1' : (request.headers.get('host') ?? url.host);
        if (authority === '')
            return false;
        const host = new URL(`http://${authority}`);
        if (!isLoopbackHost(host.hostname))
            return false;
        if (request.headers.get('sec-fetch-site') === 'cross-site')
            return false;
        const origin = request.headers.get('origin');
        return origin === null || new URL(origin).host === host.host;
    }
    catch {
        return false;
    }
}

function jsonResponse(status, body) {
    return new Response(JSON.stringify(body), {
        status,
        headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
    });
}

/** Query-string view of the audit filters the settings page sends. */
function filtersOf(request) {
    const url = new URL(request.url);
    const number = name => {
        const raw = url.searchParams.get(name);
        if (raw === null || raw === '')
            return undefined;
        const value = Number(raw);
        return Number.isFinite(value) ? value : undefined;
    };
    return {
        from: number('from'),
        to: number('to'),
        decision: url.searchParams.get('decision') ?? '',
        category: url.searchParams.get('category') ?? '',
        q: url.searchParams.get('q') ?? '',
        hide: (url.searchParams.get('hide') ?? '').split(',').map(item => item.trim()).filter(Boolean),
        // 分页的默认值与上下界只住在 store.query 一处（offset<0 归 0、limit 夹到 1..500）；
        // 这里再夹一遍就是第二个所有者，两处会漂，而且会改 store 的语义。
        offset: number('offset'),
        limit: number('limit'),
    };
}

/** Short, fact-only prompt body for the fast tier; no user text, no evidence blocks. */
function fastEvidence({ toolName, commandPreview, targets, grant }) {
    return [
        `tool: ${toolName ?? '-'}`,
        `action: ${commandPreview || '-'}`,
        `targets: ${(targets ?? []).slice(0, 6).join(' ') || '-'}`,
        `grant: ${grant.state}`,
    ].join('\n');
}

/**
 * 把文本块里检测到的段落换成确定性 token。
 * 铸不出 token（映射表写不下去）＝这段遮不掉，绝不能把原文交给模型——
 * 由调用方按 `failed` 走拒绝，不给第二条放行路径。
 */
function maskBlocks(blocks, rows, vault, source) {
    const tokens = [];
    let failed = 0;
    const output = (Array.isArray(blocks) ? blocks : []).map((block) => {
        if (block?.type !== 'text' || typeof block.text !== 'string')
            return block;
        const scan = scanSensitive(block.text, rows);
        if (scan.ranges.length === 0)
            return block;
        let text = block.text;
        for (const range of scan.ranges) {
            // ranges 已按起点降序：从后往前换，前面的下标不会漂。
            const token = vault.register(text.slice(range.from, range.to), {
                detector: range.detector, label: range.label, source,
            });
            if (token === undefined) {
                failed += 1;
                continue;
            }
            tokens.push(token);
            text = `${text.slice(0, range.from)}${token}${text.slice(range.to)}`;
        }
        return { ...block, text };
    });
    return { blocks: output, tokens: [...new Set(tokens)], failed };
}

/** 整段结果里最严的那一档动作，以及命中它的检测器名字（问一句就要用这些名字）。 */
function scanBlocks(blocks, rows) {
    const texts = (Array.isArray(blocks) ? blocks : [])
        .filter(block => block?.type === 'text' && typeof block.text === 'string')
        .map(block => block.text);
    let action = '';
    const labels = new Set();
    for (const text of texts) {
        const scan = scanSensitive(text, rows);
        if (scan.action === '')
            continue;
        for (const hit of scan.hits)
            labels.add(hit.row.label || hit.row.preset || hit.row.match);
        // 档位强弱只有一处定义：同一套词表按顺序就是强弱序，这里不另抄一张 rank 表。
        if (action === '' || RULE_ACTIONS.indexOf(scan.action) > RULE_ACTIONS.indexOf(action))
            action = scan.action;
    }
    return { action, labels: [...labels].join('、') };
}

/**
 * Schemastery declares but does not validate, so every value is resolved here
 * against the schema's own default and bounds — one source, no second table.
 */
function resolveConfig(raw) {
    const plain = migrateLegacyScopes(unwrapVolatile(raw) ?? {});
    const out = {};
    for (const [key, field] of Object.entries(Config.dict)) {
        const meta = field.meta ?? {};
        const value = plain[key];
        if (value === undefined) {
            out[key] = Array.isArray(meta.default) ? [...meta.default] : meta.default;
            continue;
        }
        if (field.type === 'number') {
            const numeric = Number(value);
            if (!Number.isFinite(numeric)) {
                out[key] = meta.default;
                continue;
            }
            const min = Number.isFinite(meta.min) ? meta.min : Number.MIN_SAFE_INTEGER;
            const max = Number.isFinite(meta.max) ? meta.max : Number.MAX_SAFE_INTEGER;
            out[key] = Math.min(Math.max(numeric, min), max);
            continue;
        }
        if (field.type === 'union') {
            const allowed = (field.list ?? []).map(item => item?.value);
            out[key] = allowed.includes(value) ? value : meta.default;
            continue;
        }
        if (field.type === 'array') {
            if (RULE_KEYS[key] !== undefined) {
                // Rows keep their shape; a half-typed row resolves to nothing.
                out[key] = (Array.isArray(value) ? value : [])
                    .map(item => toRule(item, RULE_KEYS[key]))
                    .filter(rule => rule !== undefined);
                continue;
            }
            out[key] = Array.isArray(value)
                ? value.filter(item => item !== undefined && item !== null).map(String)
                : [...(meta.default ?? [])];
            continue;
        }
        if (field.type === 'boolean') {
            out[key] = typeof value === 'boolean' ? value : meta.default;
            continue;
        }
        out[key] = typeof value === 'string' ? value : String(value);
    }
    return out;
}

export function apply(ctx, rawConfig, overrides = {}) {
    // The two host effects (a model call, a filesystem read) are the only
    // seams; a test may replace them, the runtime never passes them.
    const runReview = overrides.review ?? reviewAction;
    const anyCtx = ctx;
    const approval = anyCtx.get('approval');
    const permissionPresets = anyCtx.get('permissionPresets');
    const llm = anyCtx.get('llm');
    const settings = anyCtx.get('settings');
    const parentAgent = (sessionId) => anyCtx.get('agents')?.get(sessionId);
    if (approval?.config?.policy === 'never') {
        // Host premise made loud: with the approval service pinned to `never`
        // no ask is emitted, so the frame gates nothing and says nothing.
        console.warn('[dsh-auto-approval-frame] host approval policy is never; the frame stays inactive until it is ask');
    }
    const stateDir = join(DSH_HOME_PATH(), 'auto-approval-frame');
    const auditDir = join(stateDir, 'audit');
    const pending = createPendingStore();
    // callId → the frame's own decision, so the final tool result can be tied
    // back to the row that allowed/asked it. Bounded: a call that never
    // produces a result must not grow the map forever.
    const decidedByCall = new Map();
    let config = safeResolve(rawConfig);
    let booted = false;
    const openStore = () => createAuditStore({
        dir: auditDir,
        maxSegmentBytes: config.maxSegmentBytes,
        retentionDays: config.retentionDays,
        maxTotalBytes: config.maxTotalBytes,
    });
    let store = openStore();
    // 明文↔token 的映射表：与台账同一目录、绝不进台账。
    const vault = createSecretVault({ dir: stateDir });
    // 那张三选一卡片走宿主自己的问答通道（不是自研面板）；没有它≠没有敏感保护，
    // 只是「询问」那一档退回本行的默认处置。
    const userQuestions = anyCtx.get('userQuestions');

    function safeResolve(value) {
        try {
            return resolveConfig(value);
        }
        catch (error) {
            console.error('[dsh-auto-approval-frame] invalid config, running schema defaults', error);
            return resolveConfig({});
        }
    }

    function applyStoredRow() {
        try {
            const row = settings?.describe?.().find?.(entry => entry.ns === SETTINGS_NS);
            const merged = { ...rawConfig, ...(row?.value ?? {}) };
            const next = safeResolve(merged);
            const changed = EDITABLE_KEYS.filter(key => JSON.stringify(next[key]) !== JSON.stringify(config[key]));
            config = next;
            if (changed.some(key => key === 'retentionDays' || key === 'maxTotalBytes' || key === 'maxSegmentBytes'))
                store = openStore();
            if (booted && changed.length > 0)
                store.append({
                    category: 'config',
                    eventType: 'config.changed',
                    decision: 'info',
                    layer: 'config',
                    keys: changed,
                    message: `配置变更：${changed.join('、')}`,
                });
            return true;
        }
        catch (error) {
            console.error('[dsh-auto-approval-frame] stored config invalid, keeping live config', error);
            return false;
        }
    }
    applyStoredRow();
    // The host's live catalog is the only authority on whether a managed tier
    // exists; a fresh profile has no `auto-approval` unless the bundle patch
    // table survives (a profile `permission` row can replace it).
    const gatedMissing = () => missingGatedPresets(permissionPresets, config.gatedPresets);

    const migration = store.migrateLegacy(join(stateDir, 'decisions.jsonl'));
    if (migration.ok === false)
        console.warn(`[dsh-auto-approval-frame] legacy audit migration failed: ${migration.reason}`);

    const missingGated = gatedMissing();
    if (missingGated.length > 0)
        console.warn(`[dsh-auto-approval-frame] managed permission preset(s) missing: ${missingGated.join(', ')}; the frame will not manage any session until they exist`);
    const boot = store.append({
        category: 'lifecycle',
        eventType: 'lifecycle.boot',
        decision: 'info',
        layer: 'lifecycle',
        mode: config.mode,
        reviewer: config.reviewerSource,
        gatedPresets: config.gatedPresets,
        missingGatedPresets: missingGated,
        stateDir,
        message: missingGated.length > 0
            ? `受管权限档不在宿主权限表：${missingGated.join(', ')}；在这些档出现前，本插件不接管任何会话`
            : `仅接管这些权限档的会话：${config.gatedPresets.join(', ')}；其余档的调用只记录、不判定`,
    });
    booted = true;
    if (boot.ok === false)
        console.warn(`[dsh-auto-approval-frame] audit store is unwritable (${boot.reason}); every verdict will fall back to a human ask`);

    // The settings page runs in the webview, which has no filesystem access. The
    // host reads the audit store and answers the page's same-origin requests; no
    // copy is written anywhere. Registered on the carrier's Fetch registry, the
    // same plane the built-in plugins use, so the carrier's own auth fence runs
    // before these handlers.
    /**
     * Dry-run the chain on one command line. The model is never called: this
     * answers "which step decides this, and why", not "would the AI agree".
     * A bare path is tried as a deletion — the harshest action it could take.
     */
    function explain(input) {
        const asPath = /^(?:[A-Za-z]:[\/]|\\|\/|~[\/])/.test(input) && !/\s/.test(input);
        // 与 tools/pre-execute 同一条链：walkLadder → ladderSteps → ladderVerdict。
        // 模拟审批不再自己走一遍事实／下界／规则，所以它不可能和真判定说两套。
        const cwd = process.cwd();
        const walk = walkLadder({
            toolName: 'bash',
            args: { command: asPath ? `rm -f "${input}"` : input },
            config,
            roots: resolveRoots(cwd, config),
        });
        const steps = ladderSteps(walk, { enabled: config.enabled, gatedPresets: config.gatedPresets });
        const { counts, total } = ladderRuleCounts(config);
        return {
            input,
            command: walk.command,
            asPath,
            verdict: ladderVerdict(walk, { enabled: config.enabled }),
            steps,
            rules: counts,
            ruleTotal: total,
            // 真判定按各自会话的 cwd 解析路径，模拟只能按插件所在目录；
            // 不说清这一条，跨目录的会话就会觉得「模拟和实际不一样」。
            cwd,
            caveat: `按目录 ${cwd} 判定；若该会话的工作目录不同，路径相关的落点可能不一样。`
        };
    }

    const bindAuditRoutes = (routeCtx, connection) => {
        const register = (path, methods, fetch, label) => routeCtx.effect(
            () => connection.fetch.register({ path, methods, requestBody: 'buffered', fetch }),
            label,
        );
        register(AUDIT_ROUTE, ['GET'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            try {
                return jsonResponse(200, { ok: true, ...store.query(filtersOf(request)), chain: store.verify() });
            }
            catch (error) {
                return jsonResponse(500, { ok: false, error: String(error?.message ?? error) });
            }
        }, 'dsh-auto-approval-frame: audit query route');
        register(AUDIT_EXPORT_ROUTE, ['GET'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            try {
                const format = new URL(request.url).searchParams.get('format') === 'md' ? 'md' : 'jsonl';
                return new Response(store.exportText(filtersOf(request), format), {
                    status: 200,
                    headers: {
                        'content-type': format === 'md' ? 'text/markdown; charset=utf-8' : 'application/x-ndjson; charset=utf-8',
                        'content-disposition': `attachment; filename="auto-approval-frame-audit.${format === 'md' ? 'md' : 'jsonl'}"`,
                        'cache-control': 'no-store',
                    },
                });
            }
            catch (error) {
                return jsonResponse(500, { ok: false, error: String(error?.message ?? error) });
            }
        }, 'dsh-auto-approval-frame: audit export route');
        register(AUDIT_CLEAR_ROUTE, ['POST'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            try {
                store.clear();
                return jsonResponse(200, { ok: true });
            }
            catch (error) {
                return jsonResponse(500, { ok: false, error: String(error?.message ?? error) });
            }
        }, 'dsh-auto-approval-frame: audit clear route');
        // 模拟审批：把一条命令喂给判定链，逐步回它在每一关的落点。不调模型，
        // 所以它答的是「为什么会这样」，不是「AI 会不会同意」。
        register(EXPLAIN_ROUTE, ['GET'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            const input = (new URL(request.url).searchParams.get('q') ?? '').trim();
            if (input === '')
                return jsonResponse(400, { ok: false, error: '给一条命令或路径再模拟' });
            if (input.length > 2_000)
                return jsonResponse(400, { ok: false, error: '模拟审批的输入上限 2000 字' });
            return jsonResponse(200, { ok: true, ...explain(input) });
        }, 'dsh-auto-approval-frame: dry-run route');
        // What the code floor forbids, and which trust rows survived validation:
        // the rule table shows these as read-only context so the operator can see
        // what a row can and cannot overturn.
        register(FRAME_ROUTE, ['GET'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            const roots = resolveRoots(process.cwd(), config);
            const shape = rule => ({
                match: rule.match,
                read: rule.read ?? '',
                write: rule.write ?? '',
                delete: rule.delete ?? '',
            });
            return jsonResponse(200, {
                ok: true,
                mode: config.mode,
                debug: config.debug,
                gatedPresets: config.gatedPresets,
                missingGatedPresets: gatedMissing(),
                // 五个平面的**生效表**（内置行＋用户行合成）都从宿主这里出一份：
                // 页面渲染它，不再自己拼第二份内置清单（两份内置清单＝迟早对不上）。
                rows: Object.fromEntries(RULE_PLANES.map(plane => [plane,
                    effectiveRows(config, plane).map(rule => ({
                        id: rule.id,
                        preset: rule.preset ?? '',
                        label: rule.label ?? '',
                        match: rule.match,
                        action: rule.action,
                        read: rule.read ?? '',
                        write: rule.write ?? '',
                        delete: rule.delete ?? '',
                        enabled: rule.enabled !== false,
                    }))])),
                trusted: roots.trusted.map(shape),
                dshOpen: roots.dshOpen.map(shape),
                rejected: roots.rejectedTrusted,
            });
        }, 'dsh-auto-approval-frame: frame overview route');
        // 敏感信息表：token、检测器、字符数、出处、回写开关。
        // 明文**默认不出这张接口**（只给 head 4 字与长度）；要看完整明文，得带着
        // 那一枚 token 单独取一次，并且每一笔都进台账——「谁看过哪条凭据」是可查的。
        register(SECRETS_ROUTE, ['GET', 'POST'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            const url = new URL(request.url);
            if (request.method === 'GET') {
                const reveal = url.searchParams.get('token') ?? '';
                if (reveal !== '') {
                    const plain = vault.plainOf(reveal);
                    if (plain === undefined)
                        return jsonResponse(404, { ok: false, error: '映射表里没有这枚占位符' });
                    trace({
                        category: 'sensitive', eventType: 'sensitive.revealed', decision: 'info',
                        layer: 'redact', token: reveal, message: `明文被查看一次：${reveal}`,
                    });
                    return jsonResponse(200, { ok: true, token: reveal, plain });
                }
                return jsonResponse(200, {
                    ok: true,
                    entries: vault.list(),
                    autoRestore: config.autoRestoreSecrets === true,
                    limits: vault.limits(),
                });
            }
            let body;
            try {
                const buffer = request.body?.buffer ?? Buffer.from(await request.arrayBuffer());
                body = JSON.parse(buffer.toString('utf8') || '{}');
            }
            catch {
                return jsonResponse(400, { ok: false, error: '请求体不是 JSON' });
            }
            if (body.clear === true) {
                const cleared = vault.clear();
                trace({
                    category: 'sensitive', eventType: 'sensitive.vault-cleared', decision: 'info',
                    layer: 'redact', message: `清空敏感映射表：${cleared} 条（旧占位符从此换不回明文）`,
                });
                return jsonResponse(200, { ok: true, cleared });
            }
            if (typeof body.token === 'string' && body.token !== '') {
                if (body.remove === true) {
                    const gone = vault.remove(body.token);
                    trace({
                        category: 'sensitive', eventType: 'sensitive.vault-removed', decision: 'info',
                        layer: 'redact', token: body.token, message: `删掉一条映射：${body.token}`,
                    });
                    return jsonResponse(200, { ok: gone });
                }
                return jsonResponse(200, { ok: vault.setRestore(body.token, body.restore === true) });
            }
            return jsonResponse(400, { ok: false, error: '要带 token，或者 clear:true' });
        }, 'dsh-auto-approval-frame: secret vault route');
        register(MODELS_ROUTE, ['GET'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            try {
                const catalog = readModelGroups(DSH_HOME_PATH());
                return jsonResponse(200, { ok: true, ...catalog });
            }
            catch (error) {
                return jsonResponse(500, { ok: false, error: String(error?.message ?? error) });
            }
        }, 'dsh-auto-approval-frame: model catalog route');
    };
    const connection = anyCtx.get?.('connection');
    if (connection?.fetch?.register !== undefined) {
        bindAuditRoutes(anyCtx, connection);
    }
    else if (typeof anyCtx.inject === 'function') {
        anyCtx.inject(['connection'], (connCtx) => {
            const late = connCtx.get('connection');
            if (late?.fetch?.register !== undefined)
                bindAuditRoutes(connCtx, late);
        });
    }

    anyCtx.on('settings/document-updated', (ns) => {
        if (ns !== SETTINGS_NS)
            return;
        applyStoredRow();
    });
    anyCtx.on('session/disposed', (session) => {
        pending.dropSession(session?.id);
    });

    function trace(record) {
        const written = store.append(record);
        if (written.ok === false && config.debug)
            console.warn(`[dsh-auto-approval-frame] audit write failed: ${written.reason}`);
        return written;
    }

    function askText(grant, verdict) {
        const head = grant.state === 'never'
            ? `内置行拦下（${grant.reasons.join(', ')}）：这一步只能由你确认`
            : `需要你确认（${grant.state}${grant.reasons.length > 0 ? ` · ${grant.reasons.join(', ')}` : ''}）`;
        const advice = verdict === undefined || verdict.status === 'unable'
            ? (verdict?.unableReason === undefined
                ? ''
                : `｜AI 评审不可用：${verdict.unableReason}`)
            : `｜AI: ${verdict.decision} ${verdict.reasonCode} ${sanitizeText(verdict.summary ?? '', 200)}`;
        return redactSecrets(`${head}${advice}`).slice(0, 600);
    }

    anyCtx.on('tools/pre-execute', async (exec, next) => {
        if (!config.enabled)
            return next();
        const toolName = exec.name ?? null;
        const command = actionTextOf(exec);
        const commandPreview = sanitizeText(redactSecrets(command), 400);
        const authority = authorityFor(exec, parentAgent, permissionPresets, config.gatedPresets);
        const sessionId = rootSessionId(exec, parentAgent) ?? authority?.session?.id ?? null;
        const record = fields => {
            const written = trace({
                category: 'tool',
                eventType: `tool.${fields.decision}`,
                toolName,
                sessionId,
                toolCallId: exec.callId ?? null,
                commandPreview,
                ...fields,
            });
            if (exec.callId !== undefined && exec.callId !== null) {
                decidedByCall.set(String(exec.callId), { decision: fields.decision, layer: fields.layer });
                if (decidedByCall.size > 512)
                    decidedByCall.delete(decidedByCall.keys().next().value);
            }
            return written;
        };

        // Every call is audited; a session outside the managed presets is only recorded.
        if (authority === undefined) {
            record({ decision: 'delegated', layer: 'none', message: '该会话权限档不在受管列表：只记录，不判定' });
            return next();
        }
        const cwd = exec.agent?.session?.header?.cwd ?? process.cwd();
        const roots = resolveRoots(cwd, config);
        // 一条链，两个出口：这里和 /explain 都调 walkLadder，所以「模拟审批」不可能
        // 报出一个真判定不会给的答案（此前它是第二套实现，已经分叉过一次）。
        const walk = walkLadder({ toolName, args: exec.arguments, config, roots, probe: overrides.probe });
        const { facts, grant, outcome } = walk;
        const targets = facts.targets.map(target => target.path ?? target.input).slice(0, 12);
        const layers = { grant: grant.state, reasons: grant.reasons, targets, disposability: grant.disposability };
        let releasedWrite;
        for (const row of [...walk.emits, outcome.audit]) {
            if (row !== undefined) releasedWrite = record({ ...row, ...layers });
        }
        if (outcome.kind === 'deny')
            return { kind: 'deny', reason: redactSecrets(`auto-approval-frame: 规则拦截（${outcome.plane}）${outcome.rule}`) };
        // 出参侧的敏感命中：这一侧**只有拒绝／允许**——宿主禁止改写参数，所以「脱敏」
        // 在这里不是少做一个按钮，是物理上做不了。没人答＝不执行（与今天不答就不执行同一条）。
        // 问答通道不存在时不猜：退回原来的宿主审批面板（两键，语义仍是拒绝／允许）。
        if (outcome.kind === 'ask' && outcome.plane === 'sensitive' && typeof userQuestions?.ask === 'function') {
            const action = await askDisposition(exec, outcome.rule,
                '这一步改不了你正要执行的这条命令本身（宿主禁止插件改写参数），所以只有拒绝或允许；'
                + '遮是结果那一侧自己在做的事，跟这里的档位无关。',
                [
                    { action: 'deny', label: '拒绝', detail: '这条调用不执行' },
                    { action: 'release', label: '允许', detail: '按原文执行（明文会留在命令与它的产物里）' },
                ]) ?? 'deny';
            if (action === 'release') {
                record({
                    decision: 'allowed', layer: 'rules', plane: 'sensitive', rule: outcome.rule,
                    message: '敏感检测命中，人选择允许（出参侧无法脱敏）', ...layers,
                });
                return { kind: 'allow' };
            }
            record({
                decision: 'blocked', layer: 'rules', plane: 'sensitive', rule: outcome.rule,
                message: '敏感检测命中，人选择拒绝', ...layers,
            });
            return { kind: 'deny', reason: redactSecrets(`auto-approval-frame: 敏感检测拦下（${outcome.rule}）`) };
        }
        if (outcome.kind === 'ask') {
            if (outcome.by === 'rules') pending.put(exec.callId, {
                actionHash: facts.actionHash,
                sessionId,
                grant: grant.state,
                reasons: grant.reasons,
                verdict: { status: 'unable', unableReason: 'reviewer_unable', summary: `规则：${outcome.rule}` },
            });
            return {
                kind: 'ask',
                reason: outcome.reason,
                displayReason: outcome.by === 'floor' ? askText(grant) : outcome.displayReason,
            };
        }
        // 模式已关闭：本插件不判，交回宿主面板（不是本插件放行的，所以不要求台账可写）。
        if (outcome.kind === 'delegate') return next();
        if (outcome.kind === 'release') {
            // 事实门这一档也是「本插件放行」。台账写不进去就没有可追责的放行，
            // 与快判／深评同一条规矩：降级成人工，而不是悄悄放过去。
            if (releasedWrite?.ok === false)
                return { kind: 'ask', reason: 'auto-approval-frame: audit unwritable', displayReason: '审计台账写入失败，需人工确认' };
            return next();
        }

                // L2: fast judge — one single write inside the frame's own trust scope.
        let verdict;
        if (config.fastJudge && grant.state === 'auto') {
            const segment = facts.segments[0];
            const eligible = facts.segments.length === 1
                && (segment?.opClass === 'write' || segment?.opClass === 'delete')
                && facts.opaque === false;
            if (eligible) {
                verdict = await runReview({
                    llm,
                    session: authority.session,
                    evidence: fastEvidence({ toolName, commandPreview, targets, grant }),
                    config,
                    signal: exec.signal,
                    tier: 'fast',
                });
                if (mayRelease(verdict, grant, config.mode)) {
                    const released = record({
                        decision: 'allowed', layer: 'fast', ...layers,
                        reasonCode: verdict.reasonCode,
                        durationMs: verdict.durationMs,
                        message: sanitizeText(verdict.summary ?? '', 200),
                    });
                    // Same invariant as the deep tier: no durable trace, no release.
                    if (released.ok === false)
                        return { kind: 'ask', reason: 'auto-approval-frame: audit unwritable', displayReason: '审计台账写入失败，需人工确认' };
                    return { kind: 'allow' };
                }
                // ask / unable / invalid all escalate; only an explicit allow releases.
                verdict = undefined;
            }
        }

        // L3: deep review — the only other source of ALLOW besides the fact gate.
        const projected = projectEvidence({
            facts,
            grant,
            intents: userIntents(authority, { budget: Math.max(1_000, Math.floor(config.evidenceBudget * 0.35)) }),
            background: `tool=${exec.name} model=${sessionModelLabel(authority.session)} trusted=${roots.trusted.length} rejectedTrusted=${JSON.stringify(roots.rejectedTrusted)}`,
            config,
        });
        if (projected.tooLarge === true) {
            verdict = { status: 'unable', unableReason: 'context_too_large', summary: `evidence needs ${projected.needed} over cap ${projected.cap}` };
        }
        else {
            verdict = await runReview({
                llm,
                session: authority.session,
                evidence: projected.text,
                config,
                signal: exec.signal,
                tier: 'deep',
            });
        }
        const release = mayRelease(verdict, grant, config.mode);
        const refuse = !release && grant.state === 'auto' && verdict.status === 'reviewed' && verdict.decision === 'block';
        // The entry records what the frame actually did, not just what the model
        // said: a reviewed block in a confirm-grade session still ends in an ask.
        const decision = release ? 'allowed' : refuse ? 'blocked' : 'ask';
        const written = record({
            decision,
            layer: 'deep',
            ...layers,
            reviewStatus: verdict.status,
            reviewerDecision: verdict.decision,
            reasonCode: verdict.reasonCode,
            unableReason: verdict.unableReason,
            message: sanitizeText(verdict.summary ?? '', 240),
            rawOutput: verdict.rawOutput,
            durationMs: verdict.durationMs,
            reviewer: verdict.model,
            evidenceChars: projected.size,
            evidenceDropped: projected.dropped,
        });
        if (written.ok === false) {
            // No durable trace means no accountable release: ask a human instead.
            return { kind: 'ask', reason: 'auto-approval-frame: audit unwritable', displayReason: '审计台账写入失败，需人工确认' };
        }
        if (release)
            return { kind: 'allow' };
        if (refuse) {
            // A reviewed block is decisive: the countdown would only delay the
            // same answer, and the model's reason travels back to the agent.
            return { kind: 'deny', reason: redactSecrets(`auto-approval-frame: AI blocked (${verdict.reasonCode}) ${sanitizeText(verdict.summary ?? '', 200)}`) };
        }
        pending.put(exec.callId, {
            actionHash: facts.actionHash,
            sessionId,
            grant: grant.state,
            reasons: grant.reasons,
            verdict: { status: verdict.status, decision: verdict.decision, reasonCode: verdict.reasonCode, unableReason: verdict.unableReason, summary: verdict.summary },
        });
        return {
            kind: 'ask',
            reason: 'auto-approval-frame: human confirmation required',
            displayReason: askText(grant, verdict),
        };
    });

    // The approval plane only reads: no collectFacts, no grantFor, no review.
    // `global` matters: the host dispatches this waterfall on the agent's scope,
    // and a root listener without it is filtered out — that is why human answers
    // never reached the audit before.
    anyCtx.on('approval/request', async (req, next) => {
        const record = pending.take(req.callId);
        if (record === undefined)
            return next();
        const outcome = await next();
        trace({
            category: 'approval',
            eventType: 'approval.answer',
            decision: outcome === 'allowed-once' ? 'approved' : outcome === 'rejected' ? 'rejected' : 'info',
            layer: 'human',
            sessionId: record.sessionId ?? null,
            toolCallId: req.callId ?? null,
            toolName: req.toolName ?? null,
            grant: record.grant,
            reasons: record.reasons,
            message: `人工答复：${outcome}`,
            advice: record.verdict,
        });
        return outcome;
    }, { global: true });

    // Observe the frozen final result: an ask is not an outcome, and a tool that
    // fails after approval otherwise leaves no trace of what actually happened.
    anyCtx.on('tools/result', (exec, result) => {
        const callId = exec?.callId;
        if (callId === undefined || callId === null)
            return;
        const key = String(callId);
        const prior = decidedByCall.get(key);
        if (prior === undefined)
            return;
        decidedByCall.delete(key);
        const text = (Array.isArray(result?.content) ? result.content : [])
            .filter(block => block?.type === 'text' && typeof block.text === 'string')
            .map(block => block.text)
            .join('\n')
            .trim();
        trace({
            category: 'tool',
            eventType: 'tool.result',
            decision: result?.isError === true ? 'failed' : 'info',
            layer: prior.layer,
            toolName: exec?.name ?? null,
            sessionId: rootSessionId(exec, parentAgent) ?? null,
            toolCallId: key,
            message: sanitizeText(redactSecrets(text || '（无输出）'), 400),
        });
    }, { global: true });

    // 结果侧的处置**只有两问**：这段遮完要不要交给模型。遮不遮不由这里决定——
    // 命中就遮是上面那条腿自己的事，档位（拒绝／人工／AI／允许）管的是那一次调用。
    // 问不到人（没人答／子代理没有人类应答者／没组合问答服务）＝遮完照常交给模型。
    const SECRET_ASK_TIMEOUT_MS = 45_000;
    const DISPOSITION_OPTIONS = [
        { action: 'deny', label: '拒绝', detail: '这段结果不进模型上下文（已经执行的动作不回退）' },
        { action: 'release', label: '允许', detail: '遮掉凭据后交给模型（明文永不入上下文）' },
    ];

    async function askDisposition(exec, labels, detail, options) {
        if (typeof userQuestions?.ask !== 'function')
            return undefined;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), SECRET_ASK_TIMEOUT_MS);
        try {
            const answer = await userQuestions.ask({
                questions: [{
                    id: 'auto-approval-frame-sensitive',
                    question: `结果里检测到 ${labels}，怎么处置？`,
                    detail,
                    options: options.map(option => ({ label: option.label, description: option.detail })),
                }],
                ...(exec.agent !== undefined ? { agent: exec.agent } : {}),
                signal: controller.signal,
            });
            const selected = answer?.answers?.[0]?.selected?.[0];
            return options.find(option => option.label === selected)?.action;
        }
        catch {
            // 超时／不是 live root／被别的应答者接走：交给默认档，不在这儿重试。
            return undefined;
        }
        finally {
            clearTimeout(timer);
        }
    }

    anyCtx.on('tools/post-execute', async (exec, result, next) => {
        pending.sweep();
        const decision = await next();
        const sessionId = rootSessionId(exec, parentAgent) ?? null;
        // 回写腿：模型可能把占位符写进了配置文件。宿主禁止改参数，所以只能在它写完之后
        // 按文件层把**我们自己铸的** token 换回明文。默认关（config.autoRestoreSecrets）。
        // 它先于「这段结果给不给模型」：文件已经落地了，结果被拦不等于文件可以不修。
        if (config.autoRestoreSecrets === true && vault.size() > 0) {
            const cwd = exec.agent?.session?.header?.cwd ?? process.cwd();
            const fixed = restoreVaultedWrites({
                toolName: exec.name,
                args: exec.arguments,
                roots: resolveRoots(cwd, config),
                vault,
                probe: overrides.probe,
            });
            for (const row of fixed) {
                if (row.tokens.length === 0 && row.skipped === undefined)
                    continue;
                trace({
                    category: 'sensitive',
                    eventType: row.tokens.length > 0 ? 'sensitive.restored' : 'sensitive.restore-skipped',
                    decision: row.tokens.length > 0 ? 'info' : 'blocked',
                    layer: 'redact',
                    sessionId,
                    toolCallId: exec.callId ?? null,
                    toolName: exec.name ?? null,
                    path: row.path,
                    message: row.tokens.length > 0
                        ? `已把 ${row.tokens.length} 个占位符换回明文：${row.path}`
                        : `占位符没回写：${row.path}（${row.skipped}）`,
                });
            }
        }
        if (decision?.kind !== 'accept')
            return decision;
        const blocks = Array.isArray(decision.content) ? decision.content : result?.content;
        const rows = sensitiveRows(config);
        const scan = scanBlocks(blocks, rows);
        const source = sanitizeText(redactSecrets(exec?.name ?? ''), 60);
        let out = decision;
        if (scan.action !== '') {
            // 先遮，再按档位决定这段要不要给模型／要不要问人。
            const masked = maskBlocks(blocks, rows, vault, source);
            const action = scan.action === 'ask'
                ? await askDisposition(exec, scan.labels,
                    '命中段落已经换成占位符，磁盘上什么都没动；要把占位符换回明文，去「敏感信息」卡开自动回写。',
                    DISPOSITION_OPTIONS) ?? 'release'
                : scan.action;
            const layers = {
                category: 'sensitive',
                layer: 'redact',
                sessionId,
                toolCallId: exec.callId ?? null,
                toolName: exec.name ?? null,
            };
            if (action === 'deny') {
                trace({
                    ...layers,
                    eventType: 'sensitive.blocked',
                    decision: 'blocked',
                    message: `结果含${scan.labels}，按你的选择没有交给模型`,
                });
                return {
                    kind: 'block',
                    feedback: [{ type: 'text', text: `auto-approval-frame: 这段结果含${scan.labels}，人已选择不交给模型。` }],
                };
            }
            // 遮是这一条腿自己的动作，与档位无关；只有上面 `deny` 那一支把它省掉了（直接不给模型）。
            if (masked.failed > 0) {
                // 映射表写不下去＝遮不掉。不退回原文，也不悄悄放行：这段不给模型。
                trace({
                    ...layers,
                    eventType: 'sensitive.blocked',
                    decision: 'blocked',
                    message: `脱敏失败（映射表不可写），含${scan.labels} 的结果未交给模型`,
                });
                return {
                    kind: 'block',
                    feedback: [{ type: 'text', text: 'auto-approval-frame: 敏感脱敏的映射表写不下去，这段结果没交给模型。' }],
                };
            }
            trace({
                ...layers,
                eventType: 'sensitive.redacted',
                decision: 'info',
                detectors: scan.labels,
                tokens: masked.tokens.length,
                action,
                message: `结果已脱敏：${scan.labels}（${masked.tokens.length} 处，占位符已入「敏感信息」表）`,
            });
            out = { ...decision, content: masked.blocks };
        }
        return out;
    });

    return {
        name,
        Config,
        // Exposed for the offline regression and for a boot self-check.
        inspect: () => ({
            config: {
                mode: config.mode,
                fileRules: config.fileRules,
                commandRules: config.commandRules,
                reviewerSource: config.reviewerSource,
            },
            stateDir,
            pending: pending.size(),
            audit: store.verify(),
            // 回归与启动自检读这两项：映射表的内容不外泄（只给条数与 token 列表）。
            secrets: () => ({ count: vault.size(), entries: vault.list(), path: vault.path }),
            detectors: () => sensitiveRows(config).map(rule => rule.id),
            recent: (count = 20) => store.query({ limit: count }).entries,
            parseVerdict,
            buildSystemPrompt,
        }),
    };
}
