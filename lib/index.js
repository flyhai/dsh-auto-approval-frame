// AI生成
/** * dsh-auto-approval-frame — an interception and audit frame for DeepSeek Harness.
 *
 * One ladder per tool call: 事实取证 → 一张有序表（预设行＋你的行，含「已证明只读」）→
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
 *  - the human answer is read off the session log (`approval/asked` +
 *    `approval/decided`) and never recomputes facts or grant (see pending.js).
 *  - a grant of `never` does not reach the model.
 *  - ALLOW releases only when grant === 'auto' and mode === 'auto'.
 *  - a release that cannot be written to the audit store is downgraded to an ask.
 *  - when the audit store reports itself unwritable, the downgrade happens at the
 *    entry (deny still denies, releases and asks go to the human) and no review is
 *    paid for, so no ask can be born without a way to reach an outcome (A14 判据 6).
 */
import z from '@deepseek-ai/schemastery';
import { createHash } from 'node:crypto';
import { homedir } from 'node:os';
import { readModelGroups } from './frame/profile.js';
import { join } from 'node:path';
import { projectEvidence } from './frame/evidence.js';
import { basisCheckOf, buildSystemPrompt, checksByOf, contractOf, fastJudgeEligible, mayRelease, parseVerdict, QUESTION_CODES, withAlgorithmSafeguard, withAiConclusion} from './frame/verdict.js';
import { reviewAction, screenCard} from './frame/review.js';
import { createPendingStore } from './frame/pending.js';
import { createReceiptStore, targetDigestOf } from './frame/receipts.js';
import { contentHashOf, createProvenanceStore } from './frame/provenance.js';
import { classOf } from './frame/classkey.js';
import { createAuditStore } from './frame/audit.js';
import { NO_RULE_ROW, RULE_ACTIONS, RULE_PLANES, effectiveRows, openSensitiveRows, reasonText, scanSensitive, sealSensitiveRows, sensitiveRows, toRule, validateRuleRows } from './frame/policy.js';
import { acceptConfigVersion, configVersionOf, migrationNoticeOf, reviewSnapshotOf } from './frame/record.js';
import { TOKEN_PATTERN } from './frame/sensitive.js';
import { createSecretVault } from './frame/vault.js';
import { restoreVaultedWrites } from './frame/restore.js';
import { ladderRuleCounts, ladderSteps, ladderVerdict, walkLadder } from './frame/ladder.js';
// 判据 3：发布授权的一次性记账要用同一套匹配逻辑，不在 index 里另写一份。
import { publishAuthorized, publishTargetOf } from './frame/grant.js';
import { authorizationOf, authorityFor, missingGatedPresets, rawPresetOf, resolveRoots, rootSessionId, sessionModelLabel, userIntents } from './frame/gate.js';
import { redactSecrets, sanitizeText, setUserShapes } from './frame/sanitize.js';

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
const RULES_CODEC_ROUTE = '/api/auto-approval-frame/rules/codec';
const MODELS_ROUTE = '/api/auto-approval-frame/models';
const SECRETS_ROUTE = '/api/auto-approval-frame/secrets';
// 回填授权的用途名（F08）：签发与消费必须同一枚字符串，这里只有一条腿，写死。
const RESTORE_PURPOSE = 'tool-write';

const DSH_HOME_PATH = () => process.env.DSH_HOME?.trim() || join(homedir(), '.dsh');

const EDITABLE_KEYS = ['enabled', 'mode', 'reviewerSource', 'reviewerProvider', 'reviewerModel',
    'reviewerMaxTokens', 'reviewerTimeoutMs', 'evidenceBudget',
    'reviewRules', 'commandRules', 'fileRules', 'networkRules', 'toolRules', 'sensitiveRules', 'sourceRootDirs',
    'sensitiveDetect', 'autoRestoreSecrets', 'fastJudge', 'fastJudgeMaxTokens', 'fastJudgeTimeoutMs',
    'retentionDays', 'maxTotalBytes', 'maxSegmentBytes'];
// Patch-only: diagnostics only. `gatedPresets` is no longer a card option: the
// frame owns the tier it ships (`auto-approval`), so there is nothing for the
// operator to pick. The key stays for config compatibility and for hosts that
// want the frame to cover an extra tier they define themselves.
const HOST_ONLY_KEYS = ['debug', 'gatedPresets'];

// 宿主审批面板的四个结局（`ApprovalOutcome` 是闭合词表）：只有第一个是放行。
const ANSWER_DECISION = {
    'allowed-once': 'approved', rejected: 'rejected', cancelled: 'cancelled', unavailable: 'unavailable',
};
const ANSWER_TEXT = {
    'allowed-once': '同意（仅此一次）', rejected: '拒绝', cancelled: '没答（取消／关窗）', unavailable: '没有应答通道',
};

/** Rows of the rule tables. A file row decides per operation; others use `action`. */
const ruleArray = (plane) => z.array(z.object({
    id: z.string().default(''),
    plane: z.string().default(plane),
    match: z.string().default(''),
    action: z.string().default(''),
    read: z.string().default(''),
    write: z.string().default(''),
    delete: z.string().default(''),
    // 检测规则专用：`preset`＝它盖住的那条预设形状（空＝用户自己加的行）；
    // `enabled:false`＝这一行不表态（预设形状也能关，不必删行、也不会被下次启动复活）。
    preset: z.string().default(''),
    label: z.string().default(''),
    enabled: z.boolean().default(true),
    // 删掉的预设行留在档上（removed:true）＝它不再进生效表；schema 不声明就会被保存时抹掉，
    // 于是「已删除」的下一次启动又活了回来（F13）。
    removed: z.boolean().default(false),
})).default([]);

/** Config keys that hold rule rows rather than plain strings. */
const RULE_KEYS = {
    toolRules: 'tool',
    commandRules: 'command',
    fileRules: 'file',
    networkRules: 'network',
    sensitiveRules: 'sensitive',
};

/** * 规则表变更的**内容**：`keys` 只说得出"哪张表动过"，答不出"哪条 deny 没了、谁被降档"。
 * 台账是追责面，所以必须落到行原文（脱敏＋截断）。预设行的副本按 `preset` 认行，
 * 用户行按 `match` 认行——档位／开关变了算 `changed`，不是"一删一增"。
 */
export function configDiff(before, after, keys) {
    // 一格＝这一行的全部可表达意思（档位、按操作的作用面、开关、删除标记）。
    // 以前预设行只带 `preset` 作 cell：把「已证明只读」从放行改成人工，台账上看不出任何变化
    // ——而恰恰是这种调整最影响安全（F14）。
    const cell = row => JSON.stringify([
        row?.preset !== undefined && row.preset !== '' ? row.preset : null,
        row?.action ?? '', row?.read ?? '', row?.write ?? '', row?.delete ?? '',
        row?.enabled === false ? 'off' : '', row?.removed === true ? 'gone' : '',
    ]);
    // 空标签不是名字：`??` 会把 `label:''` 当值用，行原文就成了空串。
    // 敏感面例外：条件值本身就是秘密，台账里只写标签或序号，绝不写条件（重排那笔同理）。
    const rowText = (row, id, plane) => plane === 'sensitive'
        ? String(row?.label || '自定义敏感规则')
        : String(row?.label || row?.match || id);
    const out = [];
    for (const key of keys) {
        const plane = RULE_KEYS[key];
        if (plane === undefined)
            continue;
        const list = value => Array.isArray(value) ? value : [];
        const prior = new Map(list(before?.[key]).map(row => [String(row?.preset ?? '') !== ''
            ? `preset:${row.preset}` : `match:${plane}:${String(row?.match ?? '')}`, row]));
        const now = new Map(list(after?.[key]).map(row => [String(row?.preset ?? '') !== ''
            ? `preset:${row.preset}` : `match:${plane}:${String(row?.match ?? '')}`, row]));
        for (const [id, row] of prior) {
            if (!now.has(id))
                out.push({ table: key, change: 'removed', row: cell(row), text: rowText(row, id, plane) });
        }
        for (const [id, row] of now) {
            if (!prior.has(id))
                out.push({ table: key, change: 'added', row: cell(row), text: rowText(row, id, plane) });
            else if (cell(prior.get(id)) !== cell(row))
                out.push({
                    table: key, change: 'changed', from: cell(prior.get(id)), to: cell(row),
                    text: rowText(row, id, plane),
                });
        }
        // 纯调序：行没增没减没改档，但「谁先命中」变了——首条命中即停的表里，这就是安全语义变了。
        const was = [...prior.keys()];
        const nowIds = [...now.keys()];
        if (was.length === nowIds.length && was.every((id, at) => nowIds.includes(id))
            && was.some((id, at) => id !== nowIds[at])) {
            // 敏感面的行 id 里带着条件值的哈希前缀，不能直接进台账：按标签／序号说顺序。
            const labelAt = (row, at) => String(row?.label || `第 ${at + 1} 条`);
            out.push({
                table: key, change: 'reordered', text: `${key} 的顺序`,
                from: plane === 'sensitive'
                    ? was.map((id, at) => labelAt(prior.get(id), at)).join(' → ')
                    : was.join(' → '),
                to: plane === 'sensitive'
                    ? nowIds.map((id, at) => labelAt(now.get(id), at)).join(' → ')
                    : nowIds.join(' → '),
            });
        }
    }
    for (const key of keys.filter(name => RULE_KEYS[name] === undefined)) {
        const from = before?.[key];
        const to = after?.[key];
        if (JSON.stringify(from) !== JSON.stringify(to))
            out.push({ table: key, change: 'scalar', from: JSON.stringify(from ?? null), to: JSON.stringify(to ?? null) });
    }
    return out.slice(0, 24).map(item => {
        const redact = value => redactSecrets(sanitizeText(String(value ?? ''), 220));
        return { ...item, table: redact(item.table), text: redact(item.text), row: redact(item.row),
            from: item.from === undefined ? undefined : redact(item.from), to: item.to === undefined ? undefined : redact(item.to) };
    });
}

/** * The three separate scope keys (v0.5.x) are now `allow` / `ask` rows in the
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
    reviewerMaxTokens: z.number().default(2048).min(64).max(4_096),
    reviewerTimeoutMs: z.number().default(20_000).min(1_000).max(120_000),
    evidenceBudget: z.number().default(16_000).min(2_000).max(48_000),
    reviewRules: z.array(z.string()).default([]),
    commandRules: ruleArray('command'),
    fileRules: ruleArray('file'),
    // 源根搜索的补充目录（出厂空 ⇒ 扫描面与今天逐字相同）。
    sourceRootDirs: z.array(z.string()).default([]),
    networkRules: ruleArray('network'),
    toolRules: ruleArray('tool'),
    sensitiveRules: ruleArray('sensitive'),
    sensitiveDetect: z.boolean().default(true),
    // 默认开：但「开」只代表允许尝试回写——`restore.js` 的授权判定一个字没放宽，
    // 无证／证不合一律跳过（`sensitive.restore-skipped`），明文不落盘。
    autoRestoreSecrets: z.boolean().default(true),
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
/** * What this call is about to do, in the operator's own words. The chain stores
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

/** A card-owned volatile field arrives as a `{ get }` reference, not a value. */
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

/** * The ledger route is read by the settings page itself: same-origin over the
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

/** The host's live permission catalog, reduced to what the page renders. */
function permissionOptionsOf(permissionPresets) {
    if (typeof permissionPresets?.catalog !== 'function')
        return [];
    try {
        const catalog = permissionPresets.catalog();
        return (Array.isArray(catalog?.options) ? catalog.options : [])
            .map((option) => {
                const name = String(option?.value ?? option?.name ?? '').trim();
                const label = String(option?.name ?? option?.value ?? name).trim();
                const description = String(option?.description ?? '');
                return { name, label, description };
            })
            .filter(option => option.name !== '' && option.name !== 'custom');
    }
    catch {
        return [];
    }
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

/** * 宿主组合点返回的形态折成一个词。认不出的一律 `non-decision`——
 * 不能因为下游回了个字符串就替宿主宣布"这是放行"（F10：两个拥有者两套语义）。
 */
const handoffKindOf = value => {
    if (value === undefined || value === null)
        return 'delegated';
    if (typeof value === 'object' && typeof value.kind === 'string')
        return value.kind;
    return 'non-decision';
};

/** * 把工具产物里检测到的段落换成确定性 token——**不只 `type:'text'` 那一格**：
 * 结构化 value、嵌套数组与额外上下文递进来的字符串走同一道投影（F07）。
 * 铸不出 token（映射表写不下去）＝这段遮不掉，绝不能把原文交给模型——
 * 由调用方按 `failed` 走拒绝，不给第二条放行路径。
 * 二进制／编码载荷扫不了，如实计数交给账上写（不假装"全遮了"）。
 */
/** * 扫描的跳过规则按**内容大小**，不按字段名：`data`／`value` 这些名字既可能装 base64 图片，
 * 也常装结构化文本（我第一版按字段名跳，自己的测试用例当场把它打回——`data.list` 里的 key 没遮）。
 * 超长字符串（≥32 KB）几乎必然是二进制／编码载荷或大文件内容：不扫，但如实计数，不假装"全遮了"。
 */
const MAX_SCANNED_CHARS = 32_000;
const tooBigToScan = value => typeof value === 'string' && value.length >= MAX_SCANNED_CHARS;

/** 熵段（高熵令牌行）的固定占位符——遮住，但不铸 token、不进 vault（不可回写）。 */
const ENTROPY_PLACEHOLDER = '[已遮罩:高熵]';

function maskBlocks(blocks, rows, vault, source) {
    const tokens = [];
    let failed = 0;
    let unscanned = 0;
    /** 遮一段文本：命中却定位不到＝撤下；遮不掉（铸不出 token）＝计入失败。 */
    const maskText = (text) => {
        const scan = scanSensitive(text, rows);
        if (scan.unlocated.length > 0) {
            // 命中了却定位不到区间（带 `*` 的通配行、整行形状）＝这段遮不住。
            // 不退回原文、也不当"没命中"放过去：整段撤下并计入失败，由调用方走拒绝那支（F07）。
            failed += 1;
            return {
                text: `[已撤下：命中「${scan.unlocated.join('、')}」但定位不到具体片段，原文不交给模型]`,
                hit: true,
            };
        }
        if (scan.ranges.length === 0)
            return { text, hit: false };
        let out = text;
        for (const range of scan.ranges) {
            // 熵段只遮不铸 token——哈希清单动辄几百段，进 vault 会把敏感卡淹掉、
            // 也让"看着像秘密的哈希"占掉回写额度。形状行（真密钥）照旧铸 token，回写不变。
            // 混合重叠段（detector 里带「＋」）不在这里拆——宁可多铸一条，也不漏回写（见交付披露）。
            if (range.detector === 'high-entropy') {
                out = `${out.slice(0, range.from)}${ENTROPY_PLACEHOLDER}${out.slice(range.to)}`;
                continue;
            }
            // ranges 已按起点降序：从后往前换，前面的下标不会漂。
            const token = vault.register(out.slice(range.from, range.to), {
                detector: range.detector, label: range.label, source,
            });
            if (token === undefined) {
                failed += 1;
                continue;
            }
            tokens.push(token);
            out = `${out.slice(0, range.from)}${token}${out.slice(range.to)}`;
        }
        return { text: out, hit: true };
    };
    /** * 结构化的工具产物也走同一道投影（F07）：宿主允许 `additionalContexts`、结构化 value
     * 与自定义 finalization，过去只扫 `type==='text'` 的块，等于从这些口子递进来的内容
     * 完全不过敏感判据。递归只走进字符串与容器，二进制载荷字段不扫但如实计数。
     */
    const maskAny = (value, key = '') => {
        if (typeof value === 'string') {
            if (tooBigToScan(value)) {
                // A07：32KB～2MB 仍照扫照遮（分块只用于"值不值得判"，遮罩这边按整段扫）；
                // 判据 4：超过 2MB 不再「跳扫仍交原文」——裁到上限内扫遮，尾部如实标注，
                // 超出部分的原文不外发（unscanned 只记账不够，账挡不住外发）。
                if (value.length > 2_000_000) {
                    unscanned += 1;
                    const clipped = maskText(value.slice(0, 2_000_000)).text;
                    return `${clipped}\n…[已裁：原 ${value.length} 字超出 2MB 扫描上限，超出部分未扫描、不外发]`;
                }
                return maskText(value).text;
            }
            // 判据 1：结构化键值与文本赋值同语义。值自身形状够不着（如值里不带 `password=`）
            // 时，用 `键=值` 合成文本再探一次——文本侧 `password=x` 会命中 credential-assign，
            // 结构化侧 {password:'x'} 不补这条就漏。命中 ⇒ 值换成遮后串（键名保留在结构里）。
            if (key !== '' && maskText(value).hit !== true && `${key}=${value}`.length <= 2_000_000) {
                const composed = maskText(`${key}=${value}`);
                if (composed.hit === true)
                    return composed.text;
            }
            return maskText(value).text;
        }
        if (Array.isArray(value))
            return value.map(item => maskAny(item));
        if (value !== null && typeof value === 'object')
            return Object.fromEntries(Object.entries(value).map(([childKey, child]) => [childKey, maskAny(child, childKey)]));
        return value;
    };
    const output = (Array.isArray(blocks) ? blocks : []).map((block) => {
        if (block?.type === 'text' && typeof block.text === 'string') {
            // 判据 4：text 块与结构化值同一条处置——超 2MB 裁到上限内扫遮，不整段外发原文。
            if (block.text.length > 2_000_000) {
                unscanned += 1;
                const clipped = maskText(block.text.slice(0, 2_000_000)).text;
                return { ...block, text: `${clipped}\n…[已裁：原 ${block.text.length} 字超出 2MB 扫描上限，超出部分未扫描、不外发]` };
            }
            return { ...block, text: maskText(block.text).text };
        }
        return maskAny(block);
    });
    return { blocks: output, tokens: [...new Set(tokens)], failed, unscanned };
}

/** 整段结果里最严的那一档动作，以及命中它的检测器名字（问一句就要用这些名字）。 */
/** * 结果里所有"能被模型读成文本"的字符串——不只 `type:'text'` 那一格（F07）。
 * 结构化 value、`additionalContexts`、自定义 finalization 递进来的嵌套内容都从同一处取，
 * 检测与遮罩因此共用一个表面：两边不会一个看得见、一个看不见（那正是刚被自己的锁抓到的错）。
 * 超长串（≥32 KB）不扫，由遮罩那一侧如实计数。
 */
function collectTexts(value, key = '', out = []) {
    if (typeof value === 'string') {
        if (value !== '')
            out.push(value);
    }
    else if (Array.isArray(value)) {
        for (const item of value)
            collectTexts(item, key, out);
    }
    else if (value !== null && typeof value === 'object') {
        for (const [childKey, child] of Object.entries(value)) {
            // 判据 1：键值合成文本也进检测集合——遮罩侧（maskAny 的 key 参数）与
            // 检测侧（这里的动作判定）才看同一批形状，不会「遮了但动作没记／记了但没遮」。
            if (typeof child === 'string' && child !== '' && childKey !== '' && !tooBigToScan(child))
                out.push(`${childKey}=${child}`);
            collectTexts(child, childKey, out);
        }
    }
    return out;
}

function scanBlocks(blocks, rows) {
    const all = collectTexts(Array.isArray(blocks) ? blocks : []);
    // A07：大块不能"跳过就当干净"——跳过数要能被账上看见，哪怕整次结果只有这一块。
    const bigTexts = all.filter(text => tooBigToScan(text));
    const big = bigTexts.length;
    const texts = all.filter(text => !tooBigToScan(text));
    let action = '';
    const labels = new Set();
    // A07：大块也要按窗口扫一遍（不够精确但不再"跳过当干净"）；超 2MB 才记 unscanned。
    const SCAN_MAX_CHARS = 2_000_000;
    const CHUNK = 32_000;
    const OVERLAP = 2_000;
    const scanBig = text => {
        if (text.length > SCAN_MAX_CHARS)
            return null;
        let merged = { action: '', hits: [] };
        for (let at = 0; at < text.length; at += CHUNK - OVERLAP) {
            const scan = scanSensitive(text.slice(at, at + CHUNK), rows);
            if (scan.action === '')
                continue;
            for (const hit of scan.hits) merged.hits.push(hit);
            if (merged.action === '' || RULE_ACTIONS.indexOf(scan.action) > RULE_ACTIONS.indexOf(merged.action))
                merged.action = scan.action;
        }
        return merged;
    };
    const bigScanned = bigTexts.map(scanBig).filter(scan => scan !== null);
    const unscannedBig = big - bigScanned.length;
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
    for (const scan of bigScanned) {
        if (scan.action === '')
            continue;
        for (const hit of scan.hits)
            labels.add(hit.row.label || hit.row.preset || hit.row.match);
        if (action === '' || RULE_ACTIONS.indexOf(scan.action) > RULE_ACTIONS.indexOf(action))
            action = scan.action;
    }
    return { action, labels: [...labels].join('、'), big: unscannedBig };
}

/** * Schemastery declares but does not validate, so every value is resolved here
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
    // ──  §4：任务卡按会话存；进程内即可，重启丢卡就从原话重抽 ──
    const CARD_STORE = apply.CARD_STORE ?? new Map();
    apply.CARD_STORE = CARD_STORE;
    const userWordsOf = () => {
        try {
            const events = authority?.session?.snapshotEvents?.() ?? [];
            return events
                .filter(event => String(event?.type ?? '') === 'user/message')
                .map(event => (event?.data?.content ?? [])
                    .filter(part => part?.type === 'text')
                    .map(part => String(part.text ?? ''))
                    .join(' '))
                .filter(text => text.trim() !== '')
                .join('\n');
        }
        catch {
            return '';
        }
    };
    const fingerprintOf = text => createHash('sha256').update(String(text ?? '')).digest('hex').slice(0, 16);

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
    // 人刚放行过的同类动作记成回执（同会话、30 分钟、配置版本一变全失效），
    // 第二回合不再问。内存态：不落盘，重启即忘。
    const receipts = createReceiptStore();
    // callId → the frame's own decision, so the final tool result can be tied
    // back to the row that allowed/asked it. Bounded: a call that never
    // produces a result must not grow the map forever.
    const decidedByCall = new Map();
    // 脚本 provenance（C4）：写入落地后记 path＋sha256＋来源；执行脚本时按同 path 同 hash 查。
    const provenanceStore = createProvenanceStore();
    const writeTargetsByCall = new Map();
    const scriptByCall = new Map();
    // 宿主人工答复（allowed-once／allowed-always）按 callId 记一笔：floor／规则 ask 没有
    // decidedByCall 时，post-execute 仍能知道这次落地是人批的。
    const humanAllowedCalls = new Map();
    // 判据 3：发布授权一次性。`consumedPublish`＝已经成功用过的「会话｜远端｜分支」，
    // `pendingPublish`＝本次调用被授权覆盖、但还没确认落地的目标（要等执行成功才记账）。
    const consumedPublish = new Set();
    const pendingPublish = new Map();
    // 本进程里**真铸出过占位符**的会话（最近 512 个）。回写支路照旧对这些会话记账；
    // 没铸过的会话只回填、不记账——用户看到的那条「占位符没回写：neteco_app.exe（超过 4 MB）」
    // 就是这样冒出来的：当天在别的调用里脱敏过一次，之后每一次 `cp` 一个编译产物都来过一遍文件。
    // 回填本身不因此关闭（重启后会话换了、上下文里仍可能有旧占位符，回填要照做）。
    const vaultedSessions = new Map();
    const markVaulted = (sessionId) => {
        if (typeof sessionId !== 'string' || sessionId === '')
            return;
        vaultedSessions.delete(sessionId);
        vaultedSessions.set(sessionId, true);
        if (vaultedSessions.size > 512)
            vaultedSessions.delete(vaultedSessions.keys().next().value);
    };
    const consumedFor = (sessionId) => {
        const prefix = `${sessionId ?? ''}|`;
        return [...consumedPublish]
            .filter(key => key.startsWith(prefix))
            .map(key => {
                const [remote, branch] = key.slice(prefix.length).split('|');
                return { remote: remote ?? '', branch: branch ?? '' };
            });
    };
    let lastGoodConfig = null;
    // B12 判据 3：「配置损坏」是显式状态，不许藏在静默默认档里。损坏来源两种：
    // 解析抛异常（unparsable）与成功解析但带无效规则行（rules-invalid）。损坏时
    // safeResolve 保 last-good、不采用坏配置；这一格在页面（FRAME 路由）与台账各留一份。
    // （这三格必须声明在 safeResolve 首次调用之前——首调就在下一行。）
    let configDamage = null;
    // B12 判据 2：同一份损坏只落一次台账——损坏载荷不变就不重复刷。
    let damageLedgerKey = '';
    // B12 判据 4：迁移告知的生效版本。forward（存下的版本纪元更新）时生效版本用
    // acceptConfigVersion 返回值＝保持本机版本，不清空用户规则；正常时＝存下的版本串。
    let effectiveVersion = '';
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

    // A13：解析失败不许整份回 schema 默认值——那会把用户写好的 deny 行悄悄丢掉。
    // 留一份"上一次成功解析的完整配置"，坏输入一律退回它；首启没有上一份才用默认值。
    // B12 判据 3：**成功解析但内容失效**也按异常同级处理——任一规则行带 `invalid`
    // 标记（坏正则／档位不在册…）就判整份配置损坏：保 last-good、不采用、显式留格。
    function damagedRulesOf(resolved) {
        const out = [];
        for (const [key, plane] of Object.entries(RULE_KEYS)) {
            const rows = Array.isArray(resolved[key]) ? resolved[key] : [];
            rows.forEach((row, index) => {
                if (row?.invalid)
                    out.push({ key, plane, index, preset: row.preset ?? '',
                        // 敏感面的条件值是秘密：损坏报告只指到行号与原因，不回显条件。
                        match: plane === 'sensitive' ? '' : String(row.match ?? ''), reason: row.invalid });
            });
        }
        return out;
    }

    function safeResolve(value) {
        try {
            const next = resolveConfig(value);
            const damaged = damagedRulesOf(next);
            if (damaged.length > 0) {
                configDamage = { reason: 'rules-invalid', damaged, at: new Date().toISOString() };
                console.error(`[dsh-auto-approval-frame] config damaged (${damaged.length} invalid rule row(s)); keeping the previous good one`);
                return lastGoodConfig ?? resolveConfig({});
            }
            configDamage = null;
            lastGoodConfig = next;
            return next;
        }
        catch (error) {
            configDamage = { reason: 'unparsable', error: String(error?.message ?? error), at: new Date().toISOString() };
            console.error('[dsh-auto-approval-frame] invalid config; keeping the previous good one', error);
            return lastGoodConfig ?? resolveConfig({});
        }
    }

    // B12 判据 3：损坏格落台账——载荷不变只落一次；恢复合法后清空计数器（不落"恢复"件，
    // 恢复本身由 config.changed 件与 FRAME 路由的 configDamage:null 呈现）。
    function announceConfigDamage(source) {
        if (configDamage === null) {
            damageLedgerKey = '';
            return;
        }
        const key = JSON.stringify(configDamage);
        if (key === damageLedgerKey || booted === false || !store?.append)
            return;
        damageLedgerKey = key;
        const detail = configDamage.damaged ? `${configDamage.damaged.length} 条规则无效`
            : configDamage.violations ? `${configDamage.violations.length} 行保存被拒`
                : (configDamage.error ?? '解析失败');
        store.append({
            category: 'config',
            eventType: 'config.damaged',
            decision: 'info',
            layer: 'config',
            source,
            damage: configDamage,
            message: `配置损坏：保持上一次合法配置生效，坏配置未采用（${detail}）`,
        });
    }

    // B12 判据 4：告知「只一次」的依据落台账——同一对（存下版本 → 现版本）的告知件
    // 已经落过账就不再向页面递（重启不刷屏）；版本对变了才再告知。台账读不动时宁可
    // 多告一次也不静默吞掉。
    let migrationNoticeVisible = null;
    function announceMigration(notice, storedVersion, currentVersion) {
        const dedupKey = `migration ${storedVersion} => ${currentVersion}`;
        try {
            const seen = store.query({ category: 'config', q: dedupKey, limit: 1 });
            const fresh = (seen?.matched ?? 0) === 0;
            if (fresh)
                store.append({
                    category: 'config',
                    eventType: 'config.migration',
                    decision: 'info',
                    layer: 'config',
                    source: 'settings/document-updated',
                    storedVersion,
                    currentVersion,
                    level: notice.level,
                    effectiveVersion,
                    message: `${dedupKey} ${notice.text}`,
                });
            migrationNoticeVisible = fresh
                ? { level: notice.level, text: notice.text, storedVersion, currentVersion, effectiveVersion }
                : null;
        }
        catch {
            migrationNoticeVisible = { level: notice.level, text: notice.text, storedVersion, currentVersion, effectiveVersion };
        }
    }

    let sealingSensitive = false;
    // 自己刚写进去的那一组密文（按 match 串比）：宿主回推 document-updated 时据此认出
    // 「这是插件的改封，不是用户改了配置」，不往变更台账里写一条假的用户变更。
    let sealedPatchMatches = null;
    /** * 把宿主设置面里残留的明文敏感条件改写成密文（迁移／自愈）。
     * 写不进去只报一行：内存态不动，页面下次保存时还会再封一次。
     */
    async function sealStoredSensitiveRules() {
        if (sealingSensitive === true || typeof settings?.update !== 'function')
            return;
        sealingSensitive = true;
        try {
            const row = settings?.describe?.().find?.(entry => entry.ns === SETTINGS_NS);
            const rows = row?.value?.sensitiveRules;
            if (!Array.isArray(rows))
                return;
            const sealed = sealSensitiveRows(rows);
            if (JSON.stringify(sealed) === JSON.stringify(rows))
                return;
            sealedPatchMatches = sealed.map(item => String(item?.match ?? ''));
            await settings.update(SETTINGS_NS, { sensitiveRules: sealed });
        }
        catch (error) {
            console.error('[dsh-auto-approval-frame] sensitive rules could not be sealed at rest', error);
        }
        finally {
            sealingSensitive = false;
        }
    }

    function applyStoredRow() {
        try {
            const row = settings?.describe?.().find?.(entry => entry.ns === SETTINGS_NS);
            const merged = { ...rawConfig, ...(row?.value ?? {}) };
            // 敏感面的条件值在盘上是密文：验证与生效表都必须在明文上做，
            // 否则一条坏正则只要先被封起来就能绕过保存闸。
            const openedSensitive = openSensitiveRows(merged.sensitiveRules);
            if (openedSensitive.sealedCount > 0 || openedSensitive.needsSeal === true)
                merged.sensitiveRules = openedSensitive.rows;
            // 宿主回推的是不是我们自己刚写的那组密文：是 ⇒ 这次不算用户改配置。
            const storedMatches = Array.isArray(row?.value?.sensitiveRules)
                ? row.value.sensitiveRules.map(item => String(item?.match ?? ''))
                : [];
            const ownSeal = sealedPatchMatches !== null
                && JSON.stringify(storedMatches) === JSON.stringify(sealedPatchMatches);
            if (sealedPatchMatches !== null && ownSeal !== true && sealingSensitive !== true)
                sealedPatchMatches = null;
            // B12 判据 2：保存侧逐行闸。宿主设置面推进来的规则表先逐行验形：坏正则／
            // 档位不在册／缺 match 的显式空列在这一步**整单拒绝**——保留当前生效配置，
            // 错误指到具体表、具体行号与原因，不许再退化成「行进表但 enabled:false」的静默失效。
            const violations = [];
            for (const [key, plane] of Object.entries(RULE_KEYS)) {
                const check = validateRuleRows(merged[key], plane);
                if (!check.ok)
                    violations.push(...check.errors.map(error => ({ key, ...error })));
            }
            if (violations.length > 0) {
                configDamage = { reason: 'save-rejected', violations, at: new Date().toISOString() };
                console.error(`[dsh-auto-approval-frame] config save rejected (${violations.length} invalid row(s)); keeping the live config`);
                announceConfigDamage('settings/save-gate');
                return false;
            }
            const next = safeResolve(merged);
            const changed = EDITABLE_KEYS.filter(key => JSON.stringify(next[key]) !== JSON.stringify(config[key]));
            const prior = config;
            const priorVersion = configVersionOf(config);
            config = next;
            // B12 判据 4：迁移告知接线（23 留的口子）。存下的 configVersion（页面保存
            // 配置时一起写的）与现配置版本交给纯函数；forward 时生效版本用
            // acceptConfigVersion 的返回值（保持本机版本），用户规则一行不清空。
            const storedVersion = String(row?.value?.configVersion ?? '');
            const currentVersion = configVersionOf(next);
            const notice = migrationNoticeOf(storedVersion, currentVersion, next);
            effectiveVersion = acceptConfigVersion(priorVersion, storedVersion).version;
            migrationNoticeVisible = null;
            if (notice.level !== 'none' && notice.text !== '')
                announceMigration(notice, storedVersion, currentVersion);
            announceConfigDamage('settings/document-updated');
            if (changed.some(key => key === 'retentionDays' || key === 'maxTotalBytes' || key === 'maxSegmentBytes'))
                store = openStore();
            if (booted && changed.length > 0 && ownSeal !== true)
                store.append({
                    category: 'config',
                    eventType: 'config.changed',
                    decision: 'info',
                    layer: 'config',
                    keys: changed,
                    // 变更通道只有宿主设置面（本包不自带改配置的路由），所以来源写得死；
                    // 真正缺的是"改了什么"——没有它，事后无法回答哪条 deny 被删。
                    source: 'settings/document-updated',
                    diff: configDiff(prior, next, changed),
                    message: `配置变更：${changed.join('、')}`,
                });
            if (ownSeal === true)
                sealedPatchMatches = null;
            // 盘上仍是明文的用户条件：这一轮封回去（迁移／自愈）。异步写，不挡本次生效。
            if (openedSensitive.needsSeal === true)
                void sealStoredSensitiveRules();
            return true;
        }
        catch (error) {
            console.error('[dsh-auto-approval-frame] stored config invalid, keeping live config', error);
            return false;
        }
    }
    applyStoredRow();

    const migration = store.migrateLegacy(join(stateDir, 'decisions.jsonl'));
    if (migration.ok === false)
        console.warn(`[dsh-auto-approval-frame] legacy audit migration failed: ${migration.reason}`);

    const gatedMissing = () => missingGatedPresets(permissionPresets, config.gatedPresets);
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
    // B12 判据 3：启动时就带损坏（首启 rawConfig 无效／带 invalid 行）→ 台账留格。
    // applyStoredRow 在 booted 之前跑，损坏件由这里补落一次（载荷不变只此一件）。
    announceConfigDamage('lifecycle.boot');
    if (boot.ok === false)
        console.warn(`[dsh-auto-approval-frame] audit store is unwritable (${boot.reason}); 拦仍生效，要放行／要问人的一律交回人工，不付模型钱，也不记自己配不成对的 ask`);

    // The settings page runs in the webview, which has no filesystem access. The
    // host reads the audit store and answers the page's same-origin requests; no
    // copy is written anywhere. Registered on the carrier's Fetch registry, the
    // same plane the built-in plugins use, so the carrier's own auth fence runs
    // before these handlers.
    /** * Dry-run the chain on one command line. The model is never called: this
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
                // B12 判据 3／判据 4：损坏格与迁移告知格在此出页面——损坏非空＝当前
                // 生效的是上一次合法配置；告知只在第一次出现的那次会话里可见。
                configVersion: configVersionOf(config),
                effectiveVersion,
                configDamage,
                migrationNotice: migrationNoticeVisible,
                presetOptions: permissionOptionsOf(permissionPresets),
                // 五个平面的**生效表**（预设行＋用户行合成）都从宿主这里出一份：
                // 页面渲染它，不再自己拼第二份预设清单（两份预设清单＝迟早对不上）。
                rows: Object.fromEntries(RULE_PLANES.map(plane => [plane,
                    effectiveRows(config, plane, roots).map(rule => ({
                        id: rule.id,
                        preset: rule.preset ?? '',
                        label: rule.label ?? '',
                        match: rule.match,
                        action: rule.action,
                        // 命令面一行一条命令——`note` 是这一行的说明，页面把它摆在
                        // 命令行下方（命令面不再用 `match` 充当说明）。
                        note: rule.note ?? '',
                        read: rule.read ?? '',
                        write: rule.write ?? '',
                        delete: rule.delete ?? '',
                        enabled: rule.enabled !== false,
                        // 读不出来的行也要出现在页面上并写明原因——静默丢行＝悄悄放开它拦的东西（F13）。
                        invalid: rule.invalid ?? '',
                    }))])),
                trusted: roots.trusted.map(shape),
                dshOpen: roots.dshOpen.map(shape),
                rejected: roots.rejectedTrusted,
            });
        }, 'dsh-auto-approval-frame: frame overview route');
        // 页面的敏感规则编辑面：盘上是密文，页面上要明文。
        // `open` 只解不写；`seal` 先在明文上过保存闸再封——坏正则不能因为先被密封就绕过验证。
        register(RULES_CODEC_ROUTE, ['POST'], async (request) => {
            if (!isTrustedLedgerRequest(request))
                return jsonResponse(403, { ok: false, error: 'forbidden' });
            let body;
            try {
                const buffer = request.body?.buffer ?? Buffer.from(await request.arrayBuffer());
                body = JSON.parse(buffer.toString('utf8') || '{}');
            }
            catch {
                return jsonResponse(400, { ok: false, error: '请求体不是 JSON' });
            }
            if (body?.plane !== 'sensitive' || (body.op !== 'open' && body.op !== 'seal'))
                return jsonResponse(400, { ok: false, error: '只接敏感面的 open／seal' });
            const rows = body.rows;
            if (!Array.isArray(rows) || rows.length > 500)
                return jsonResponse(400, { ok: false, error: 'rows 不是行数组（上限 500）' });
            if (body.op === 'open') {
                const opened = openSensitiveRows(rows);
                return jsonResponse(200, { ok: true, rows: opened.rows, failed: opened.failed });
            }
            const check = validateRuleRows(rows, 'sensitive');
            if (!check.ok)
                return jsonResponse(400, { ok: false, error: '规则行不合法', violations: check.errors });
            return jsonResponse(200, { ok: true, rows: sealSensitiveRows(rows) });
        }, 'dsh-auto-approval-frame: sensitive rule codec route');
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
                    // 表写不下去时页面要能说实话：只给可写性与路径，不给内容。
                    storage: vault.storage(),
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
            // F08 受控回填：授权在这张表上签发——一个会话＋一个目的文件＋一种用途＋
            // 一段有效期（默认 10 分钟）＋一次性。没有这张证，回填腿一个字节都不写。
            if (body.grant === true) {
                const purpose = typeof body.purpose === 'string' && body.purpose !== ''
                    ? body.purpose : RESTORE_PURPOSE;
                const issued = vault.grantUse(String(body.token ?? ''), {
                    sessionId: String(body.sessionId ?? ''),
                    destination: String(body.destination ?? ''),
                    purpose,
                    ttlMs: Number.isFinite(body.ttlMinutes) ? Math.max(1, body.ttlMinutes) * 60_000 : undefined,
                    once: body.once !== false,
                    // 判据 4（接 的尾巴）：签发时就把「被批准的是哪一次调用、什么效果」写进证。
                    // 回填腿拿同一个 callId／同一个效果 hash 才消费得到；只接一侧会让全部消费判 grant.call。
                    callId: typeof body.callId === 'string' && body.callId !== '' ? body.callId : undefined,
                    effectHash: typeof body.effectHash === 'string' && body.effectHash !== '' ? body.effectHash : undefined,
                });
                trace({
                    category: 'sensitive',
                    eventType: issued.ok === true ? 'sensitive.granted' : 'sensitive.grant-refused',
                    decision: issued.ok === true ? 'info' : 'blocked',
                    layer: 'redact',
                    token: String(body.token ?? ''),
                    message: issued.ok === true
                        ? `签发一次回填授权：会话 ${body.sessionId} → ${body.destination}（用途 ${purpose}${body.once === false ? '，可复用' : '，一次性'}）`
                        : `回填授权没签出去：${issued.reason}`,
                });
                return jsonResponse(issued.ok === true ? 200 : 400, issued);
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
        receipts.dropSession(session?.id);
        for (const key of [...dispositions.keys()])
            if (key.startsWith(`${session?.id}|`))
                dispositions.delete(key);
    });

    function trace(record) {
        const written = store.append(record);
        if (written.ok === false && config.debug)
            console.warn(`[dsh-auto-approval-frame] audit write failed: ${written.reason}`);
        return written;
    }

    /** 判据 5：评审说不清的原因，弹框里说人话；没有映射就原样给码，不编。 */
    const UNABLE_TEXT = {
        timeout: '评审超时',
        cancelled: '评审被取消',
        schema_invalid: '评审输出不成形',
        reviewer_unable: '评审自己也判不了',
        context_too_large: '证据太多超出上下文',
    };

    /** unable 分两档——框架没证出来（readProofWhy 非空）／评审判不了（其余）。
     *  只对**含读段**的调用分档：写／删／外传不谈「只读证」，文案维持原样。
     *  两档都仍转人；这里只决定台账档位与弹框文案，不改放不放。 */
    function unableTierOf(verdict, facts) {
        if (verdict?.status !== 'unable' || facts?.hasReadSegment !== true)
            return undefined;
        return String(facts?.readProofWhy ?? '') !== '' ? 'framework' : 'reviewer';
    }

    /** * 判据 5：弹框第一句必须说清「是谁在问」——AI 升级／预设行／你的规则
     * 三种来源三种写法。过去固定写「预设行」：AI 判不了升上来的人，看到的是「预设行需要你确认」。
     */
    /** 把证据截断记录翻成人话：字段名保留，数字说清。 */
    function humanizeIncomplete(text) {
        return String(text ?? '')
            .replace(/segments\[\d+\]\./g, '')
            .replace(/argv\[\d+\]/g, '参数')
            .replace(/operands\[\d+\]/g, '操作数')
            .replace(/未全送达/g, '没送全')
            .replace(/保留 (\d+) 字，另有 (\d+) 字未包含/g, '只送了前 $1 字，少了 $2 字')
            .trim();
    }

    /** 问框里把实际目标摆出来（尤其是运行时展开/开关误判出来的路径）。 */
    function targetNoteOf(targets) {
        const list = Array.isArray(targets)
            ? targets.filter(target => target !== null && typeof target === 'object') : [];
        if (list.length === 0)
            return '';
        const shown = list.slice(0, 3).map(target => {
            const path = String(target.path ?? target.input ?? '');
            if (path === '')
                return '';
            const real = String(target.realPath ?? '');
            const dynamic = target.dynamic === true ? '（运行时展开）' : '';
            return real !== '' && real.toLowerCase() !== path.toLowerCase()
                ? `${path}（实际 ${real}）${dynamic}`
                : `${path}${dynamic}`;
        }).filter(text => text !== '');
        if (shown.length === 0)
            return '';
        const more = list.length > shown.length ? ` 等 ${list.length} 个` : '';
        return `目标：${shown.join('、')}${more}`;
    }

    /** 评审到底看到了什么：读同一份 visibility（证据投影算一次），不在这里另猜。 */
    function evidenceNoteOf(visibility) {
        if (visibility === undefined || visibility === null)
            return '';
        if (visibility.writeContent === 'included')
            return '评审看到了写入内容';
        if (visibility.writeContent === 'partial')
            return '评审看到的写入内容有截断';
        if (visibility.scriptBody === 'included')
            return '评审看到了命令里的代码正文';
        if (visibility.scriptBody === 'partial')
            return '评审看到的代码正文有截断';
        if (visibility.scriptBody === 'not-supplied')
            return '评审只看到命令与路径，没看到脚本文本';
        if (visibility.scriptBody === 'piped')
            return '评审看到的是管道命令';
        return '';
    }

    /** 写/改类问框的内容指纹：路径、行数、字节、hash 和前 200 字。 */
    function toolNoteOf({ toolName, args }) {
        const name = String(toolName ?? '').toLowerCase();
        const argText = args !== null && typeof args === 'object' ? args : {};
        const path = String(argText.file_path ?? argText.path ?? '');
        const body = name === 'write' && typeof argText.content === 'string'
            ? argText.content
            : name === 'edit' && typeof argText.new_string === 'string'
                ? argText.new_string
                : '';
        if (path === '' || body === '')
            return '';
        const lines = body.split(/\r?\n/).length;
        const bytes = Buffer.byteLength(body, 'utf8');
        const hash = createHash('sha256').update(body).digest('hex').slice(0, 12);
        const preview = redactSecrets(body).replace(/\s+/g, ' ').trim().slice(0, 200);
        const action = name === 'write' ? '将写入' : '将替换';
        return `${action}：${path}（${lines} 行 / ${bytes} 字节，sha256:${hash}）｜预览：${preview}${body.length > 200 ? '…' : ''}`;
    }

    const RELEASE_BLOCKER_TEXT = {
        evidence: '证据没送全',
        basis: '评审引用的行不成立',
        contract: '评审自己的三问没全真',
        interpreter: '脚本文本没送评审，且没有你批过的 hash',
        piped: '管道命令不在自动放行范围',
        'unstable-read': '目标靠运行时展开或通配，算不稳',
        'dynamic-mutation': '目标算不清且会改东西',
        irreversible: '这次动作会动到已有内容，不在自动放行范围',
        authorization: '评审没有拿到有效的依据或授权',
        grant: '当前授权档位不是 auto',
        mode: '当前模式不是 auto',
        'block-not-accepted': '评审建议拒绝，但当前档位不能直接拦下',
        'release-gate': '未满足自动放行条件',
    };

    /** 框架自己没放行的真实原因：卡片首句和台账 releaseBlockers 都读这一份。 */
    function releaseBlockerOf({ verdict, grant, config, evidenceComplete, projected, basis, contract, release }) {
        if (verdict === null || verdict === undefined || release === true)
            return undefined;
        if (verdict.status === 'reviewed' && verdict.decision === 'block') {
            return {
                id: 'block-not-accepted',
                text: RELEASE_BLOCKER_TEXT['block-not-accepted'],
                detail: String(verdict.reasonCode ?? ''),
            };
        }
        if (verdict.status !== 'reviewed' || verdict.decision !== 'allow')
            return undefined;
        let id;
        let detail = '';
        if (evidenceComplete !== true) {
            id = 'evidence';
            const missing = Array.isArray(projected?.incomplete) ? projected.incomplete : [];
            detail = missing.length > 0
                ? humanizeIncomplete(missing[0])
                : (projected?.tooLarge === true
                    ? `证据 ${projected.needed} 字超出上限 ${projected.cap} 字，未送评审` : '');
        }
        else if (basis !== undefined && basis !== null && basis.ok !== true) {
            id = 'basis';
            detail = String(basis.why ?? '引用校验未通过');
            const cited = String(basis.citedRule ?? '').trim();
            if (cited !== '')
                detail += `（评审引的是「${cited}」）`;
        }
        else if (contract !== undefined && contract !== null && contract.known === true && contract.allTrue !== true) {
            id = 'contract';
            const failed = Array.isArray(contract.failed) && contract.failed.length > 0
                ? contract.failed : (Array.isArray(contract.missing) ? contract.missing : []);
            detail = failed.length > 0 ? `缺/假：${failed.join('、')}` : '';
        }
        else if (String(config.mode ?? 'auto') !== 'auto') {
            id = 'mode';
        }
        else if (grant?.state !== 'auto') {
            id = 'grant';
            detail = String(grant?.state ?? '');
        }
        else if (verdict.aiStable === false) {
            id = String(verdict.aiStableWhy ?? 'release-gate');
        }
        else {
            id = 'release-gate';
        }
        return { id, text: RELEASE_BLOCKER_TEXT[id] ?? RELEASE_BLOCKER_TEXT['release-gate'], detail };
    }

    function askText({ by, rule, verdict, source, command, readOnly, unableTier, readProofWhy, targets, releaseBlock, evidenceNote, toolNote } = {}, grant) {
        const label = String(rule ?? '').trim();
        const stamp = label === '' ? '' : `：${label}`;
        const extra = grant === undefined ? '' : grant.reasons.map(reasonText).join('、');
        const tail = extra === '' ? '' : `｜另需确认：${extra}`;
        const targetNote = targetNoteOf(targets);
        const seenNote = evidenceNote === undefined || evidenceNote === '' ? '' : `｜评审看到：${evidenceNote}`;
        const contentNote = toolNote === undefined || toolNote === '' ? '' : `｜${toolNote}`;
        let head;
        let brief = '';
        let warn = '';
        if (verdict !== undefined && verdict !== null) {
            const why = verdict.unableReason === undefined
                ? '' : (UNABLE_TEXT[verdict.unableReason] ?? verdict.unableReason);
            // 差点漏看点了同意，所以把「同意＝放行这次动作」和评审原话
            // 都摆到人眼前——只给一个原因码，人无从判断该不该批。
            const detail = String(verdict.summary ?? '').trim();
            warn = '｜⚠ 同意＝放行这次动作；不在你的授权范围内请拒绝';
            // 证据装不下这条**根本没调模型**，不能走下面两档的「评审无法判断」。
            // 单独一档，直接把 summary 当主句（它已写明字数与「未送 AI、直接转人工」）。
            if (verdict.unableReason === 'context_too_large')
                head = `${sanitizeText(detail === '' ? '证据超出上限，未送 AI 评审' : detail, 160)}${stamp}${warn}`;
            // 判据 4：unable 分两档说清是谁没判出来——框架没证出来 vs 评审自己也判不了。
            else if (unableTier === 'framework') {
                head = `框架无法证明这个动作只读：${sanitizeText(String(readProofWhy ?? ''), 120)}，需要你确认${stamp}${warn}`;
                brief = detail === '' ? '' : `｜评审说明：${sanitizeText(detail, 160)}`;
            }
            else if (unableTier === 'reviewer')
                head = `评审无法判断：${sanitizeText(detail === '' ? (why === '' ? '没有给出理由' : why) : detail, 160)}，需要你确认${stamp}${warn}`;
            // 评审说 allow、框架却没放：必须说清是框架的哪道门，不许再把锅写成「AI 判不了」。
            else if (verdict.status === 'reviewed' && verdict.decision === 'allow' && releaseBlock !== undefined) {
                const reason = `${releaseBlock.text}${releaseBlock.detail === undefined || releaseBlock.detail === '' ? '' : `：${releaseBlock.detail}`}`;
                head = `评审建议放行，但未过自动放行线：${reason}，需要你确认${stamp}${warn}`;
                brief = detail === '' ? '' : `｜评审建议（未采纳）：${sanitizeText(detail, 160)}`;
            }
            // 评审说 block、当前档位却只能问人：说清是档位没让它直接拦，还是它压根没给机械理由。
            else if (verdict.status === 'reviewed' && verdict.decision === 'block') {
                const code = String(verdict.reasonCode ?? '').trim();
                const invalid = code === '' || code === 'other';
                head = invalid
                    ? `评审拒绝但没给机械理由（${code === '' ? '空' : code}），需要你确认${stamp}${warn}`
                    : `评审建议拒绝，但当前档位不能直接拦下，需要你确认${stamp}${warn}`;
                brief = detail === '' ? '' : `｜评审建议（未采纳）：${sanitizeText(detail, 160)}`;
            }
            else {
                head = `AI 判不了，需要你确认${stamp}${why === '' ? '' : `｜原因：${why}`}${warn}`;
                brief = detail === '' ? '' : `｜评审原话：${sanitizeText(detail, 160)}`;
            }
        }
        else if (by === 'floor')
            head = `预设行需要你确认${stamp}`;
        else if (label.startsWith('别的项目根且未点名'))
            // 这是事实闸，不是用户的规则命中（ladder 的来源映射会给成「你的行」）。
            head = `你未点名这条别的项目路径，需要你确认${stamp}`;
        else
            head = `你的规则需要你确认${stamp}`;
        const pieces = [head];
        if (contentNote !== '')
            pieces.push(contentNote);
        if (targetNote !== '')
            pieces.push(`｜${targetNote}`);
        if (brief !== '')
            pieces.push(brief);
        if (seenNote !== '')
            pieces.push(seenNote);
        if (tail !== '')
            pieces.push(tail);
        let text = redactSecrets(pieces.join(''));
        // 裸名多义时「问不清」＝人没法决。多义（候选 ≥2）、这次调用是纯读、
        // 且这条命令正是在问那个裸名时，把事实层实际 lstat 命中的候选目录列在文案最末（≤10）。
        // 判定、绑定、规则标签一字不动——人补全路径后走的是既有的 PATHISH 点名通路。
        const candidates = Array.isArray(source?.matches) ? source.matches : [];
        const names = Array.isArray(source?.names) ? source.names.map(name => String(name).toLowerCase()) : [];
        const asked = readOnly === true
            && names.some(name => name !== '' && String(command ?? '').toLowerCase().includes(name));
        if (candidates.length >= 2 && asked) {
            const shown = candidates.slice(0, 10).map(item => redactSecrets(String(item)));
            // 600 字上限先砍候选、不砍前面的告警句；按整条路径进退，不留半条。
            for (let count = shown.length; count >= 1; count -= 1) {
                const more = candidates.length > count ? `（另有 ${candidates.length - count} 条）` : '';
                const composed = `${text}｜候选源目录（≤10）：${shown.slice(0, count).join('、')}${more}`;
                if (composed.length <= 600) {
                    text = composed;
                    break;
                }
            }
        }
        // 裸名一个都没解析到、但某个扫描点条目超过 200 —— 明说「可能没扫全」，
        // 不再让「目录排在 200 之后」表现为「这台机器上没这个目录」。
        const limited = Array.isArray(source?.limited) ? source.limited : [];
        if (candidates.length === 0 && limited.length > 0 && asked)
            text = `${text}（这些目录条目多于 200，只看了前 200 条，可能没扫全：${limited.map(item => redactSecrets(String(item))).join('、')}）`;
        return text.slice(0, 600);
    }

    anyCtx.on('tools/pre-execute', async (exec, next) => {
        if (!config.enabled)
            return next();
        const toolName = exec.name ?? null;
        const command = actionTextOf(exec);
        const commandPreview = sanitizeText(redactSecrets(command), 400);
        const authority = authorityFor(exec, parentAgent, permissionPresets, config.gatedPresets);
        const sessionId = rootSessionId(exec, parentAgent) ?? authority?.session?.id ?? null;
        // 台账本身也是一个出口（F06）：`commandPreview` 早就遮过，但 `targets`／`disposability`／
        // `rawOutput`／模型 summary／规则原文这些字段此前**原样入库**——而审计库是可查询、可导出的明文面。
        // 同一个投影罩在所有文本字段上：只遮不裁，字段结构与可核对性保持不变。
        const projectField = value => {
            if (typeof value === 'string')
                return redactSecrets(value);
            if (Array.isArray(value))
                return value.map(projectField);
            if (value !== null && typeof value === 'object')
                return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, projectField(item)]));
            return value;
        };
        // Phase 6 净账：这一条调用花了多少判定时间、叫了几次模型、最后落不落到弹框——
        // 只数"框少了几次"会把自己骗成"优化过了"（报告 §5.5：不得用提示词字节或框数宣称总体优化）。
        const startedAt = Date.now();
        let aiCalls = 0;
        const record = fields => {
            const written = trace({
                category: 'tool',
                eventType: `tool.${fields.decision}`,
                totalMs: Date.now() - startedAt,
                aiCalls,
                toolName,
                sessionId,
                toolCallId: exec.callId ?? null,
                commandPreview,
                // 判据 4：判定行必须能事后回答「哪个配置版本批准的」——补上版本口径。
                // 与 frame.configVersion（本文件 :933）同源（configVersionOf(config)），不另造口径。
                configVersion: configVersionOf(config),
                ...projectField(fields),
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
        // A05：真入口把会话／callId／授权五格一起交给判定（record 在判定前构建，
        // 这是它拿到真实身份的唯一来源；模拟页没有会话，传 null 并如实标）。
        // 判据 3：把「本会话已经成功用过的发布目标」带进授权——
        // 同一个远端＋分支第二次出现时不再降级（一次性），要用户再说一遍。
        const authorization = authorizationOf(userIntents(authority), { consumed: consumedFor(sessionId) });
        // 事实层要按「用户消息里点没点名」算外项目读；ladder 的签名不在本版白名单里，
        // 所以授权随本次调用的 roots 一起下去（roots 每次 resolveRoots 新建，不是共享态）。
        roots.authorization = authorization;
        // 会话级源根绑定按 sessionId 隔离（取不到就是 null ⇒ 事实层一律不绑）。
        authorization.sessionId = sessionId ?? null;
        const walk = walkLadder({
            toolName, args: exec.arguments, config, roots, probe: overrides.probe,
            session: authority.session ?? null,
            callId: exec.callId ?? null,
            authorization,
        });
        const decideMs = Date.now() - startedAt;
        const { facts, grant, outcome } = walk;
        const callKey = exec.callId === undefined || exec.callId === null ? null : String(exec.callId);
        if (callKey !== null) {
            const writes = (facts.targets ?? [])
                .filter(target => target?.path && target.dynamic !== true
                    && ['write', 'rename'].includes(String(target.opClass)))
                .map(target => target.path);
            if (writes.length > 0)
                writeTargetsByCall.set(callKey, writes);
            const script = (facts.targets ?? [])
                .find(target => target?.role === 'script-read' && target.path && target.dynamic !== true);
            if (script !== undefined)
                scriptByCall.set(callKey, script.path);
            if (writeTargetsByCall.size > 512)
                writeTargetsByCall.delete(writeTargetsByCall.keys().next().value);
            if (scriptByCall.size > 512)
                scriptByCall.delete(scriptByCall.keys().next().value);
        }
        // 脚本执行前查一次 provenance：同 path 同 hash 才算数；读不到／没记录＝没有。
        const scriptPath = callKey === null ? undefined : scriptByCall.get(callKey);
        const scriptHashed = scriptPath === undefined ? undefined : contentHashOf(scriptPath);
        const provenance = scriptPath === undefined || scriptHashed === undefined
            ? undefined
            : provenanceStore.lookup({ sessionId, path: scriptPath, hash: scriptHashed.hash });
        // 判据 3：这次判定真的覆盖了哪几个发布目标，先挂在这个 callId 上；
        // 落地成功（post 段 `landed`）才记进 `consumedPublish`——失败不作数，允许重试。
        if (exec.callId !== undefined && exec.callId !== null) {
            const covered = facts.segments
                .filter(segment => publishAuthorized(segment, authorization))
                .map(segment => publishTargetOf(segment))
                .filter(target => target !== undefined);
            if (covered.length > 0)
                pendingPublish.set(String(exec.callId), covered);
        }
        // A14 判据 6：台账不可写时的降级要有界，而且要发生在**付模型钱之前**。
        // 旧做法照走全链，等到入账才发现 `ok===false` 再返 ask——每一问都白付一次深评，
        // 而那一问没进 pending（配不成对，只能等答案窗口超时），于是台账里堆开口没下文的 ask。
        // 现在入口读 `store.writable`：拦照旧拦（deny 不依赖账本），委托照旧委托，
        // 凡是要放行或要问人的，一律交回宿主面板由人裁——本帧不产自己记不了的行与配不成对的 pending。
        if (store.writable() === false) {
            if (outcome.kind === 'deny')
                return { kind: 'deny', reason: redactSecrets(`auto-approval-frame: 规则拦截（${outcome.plane}）${outcome.rule}`) };
            if (outcome.kind === 'delegate') return next();
            // 回写腿只看这一格、不看台账：把占位符换回明文是用户文件的事，不该被账本坏了拖停。
            if (exec.callId !== undefined && exec.callId !== null)
                decidedByCall.set(String(exec.callId), { decision: 'ask', layer: 'audit' });
            return {
                kind: 'ask',
                reason: 'auto-approval-frame: audit unwritable',
                displayReason: '审计台账写不进去：没有留痕的放行＝没有凭据的放行，这一步交回人工确认（本插件不评审，也不代替你放行）',
            };
        }
        const targets = facts.targets.map(target => target.path ?? target.input).slice(0, 12);
        // 台账也带上「哪几个目标落在别的项目根、有没有被点名」——字段自己指认，
        // 复盘时不用从 rule 文案反推（证据面与判定面同一份事实）。
        const foreignProjects = facts.targets
            .filter(target => target?.dynamic !== true && target?.foreignProject === true)
            .map(target => ({ path: target.path, root: target.foreignRoot, named: target.namedByUser === true }));
        // 台账带源根两格——绑上时是目录；多义没绑时是 ''＋候选计数（两行都能指认）。
        // 会话级绑定没有裸名（补齐的是完整路径），只要 root 非空也要落这两格。
        const sourceRootLayer = facts.sourceRoot?.root !== '' || facts.sourceRoot?.names?.length > 0
            ? {
                sourceRoot: facts.sourceRoot.root,
                sourceRootCandidates: facts.sourceRoot.candidates,
                // 扫描点触顶（>200 条）时台账明说，不再静默当成「没这个目录」。
                ...(facts.sourceRoot.limited?.length > 0 ? { sourceScanLimited: facts.sourceRoot.limited } : {}),
            }
            : {};
        const layers = {
            // FS／Git 探测的耗时现在合并在 decideMs 里；要拆成两格得在事实层加计时器
            //（那是执行端在飞的文件），拆完再报，不拿合并数冒充拆分数。
            decideMs,
            grant: grant.state, reasons: grant.reasons, reasonLabels: grant.reasons.map(reasonText),
            targets, disposability: grant.disposability,
            ...(foreignProjects.length === 0 ? {} : { foreignProjects }),
            ...sourceRootLayer,
        };
        // 条1＋条2：模型用来作保的两样都从**它自己读到的那一份**里取——行名＝证据块 `decidedBy[].rule`
        // 的来源（`hit.text`），引用＝同一份 `projected.text`。换个来源就会出现「它抄得到、机器验不了」。
        // 一行都没表态时，可指的那一行就是默认档本身（与证据块同一个常量的同一个值）。
        // 补充 的类键第四格也用这一份行名：回执「沿用的是哪一行的批准」必须和模型指的行同一个口径。
        // §4：按会话取卡、判「本次有没有新原话」，把【卡】块附在证据之后送评审。
        // 卡块附在证据**之后**：basis 的逐字引用仍取自 projected.text，不被新块搅浑。
        const cardKey = sessionId === null ? null : String(sessionId);
        const stored = cardKey === null ? undefined : CARD_STORE.get(cardKey);
        const wordsFingerprint = fingerprintOf(userWordsOf());
        const freshWords = stored === undefined ? true : stored.fingerprint !== wordsFingerprint;
        const hitRows = (walk.policy?.hits ?? []).map(hit => String(hit?.text ?? ''));
        const citableRows = hitRows.length === 0 ? [NO_RULE_ROW] : hitRows;
        // 补充：这一调用够不够格按「类」沿用人工放行（排除项与四成分见 classkey.js）。
        const klass = classOf({ toolName, rows: citableRows, targets: facts.targets,
            reasons: grant.reasons, segments: facts.segments });
        // 逐格可复核：建了键记四成分，没建记卡在哪一格——台账里能直接数出「哪一类不回放」。
        const classLedger = klass.key === undefined
            ? { built: false, skip: klass.why }
            : { built: true, key: klass.key, faces: klass.faces, roots: klass.roots, rows: klass.rows };
        // 同一会话里，这个动作刚被人放行过 ⇒ 第二回合不再问。
        // 回执只抵「问」：deny 在它之前就退了，sensitive 那一档（改参数做不到，只有拒绝／允许）
        // 与台账不可写的降级也各走各的门，不从这里放行。
        const reuseByReceipt = () => {
            const hit = receipts.check({
                sessionId,
                actionHash: facts.actionHash,
                toolName,
                targetDigest: targetDigestOf(facts.targets),
                configVersion: configVersionOf(config),
                classKey: klass.key,
            });
            if (hit === undefined)
                return {};
            // 重复调用升级：同一类已经沿用到帽 ⇒ 这一格交回人，并把「沿用了几次」写进弹框文案。
            if (hit.capped === true)
                return { escalate: hit };
            const written = trace({
                category: 'approval',
                eventType: 'approval.receipt',
                decision: 'allowed',
                layer: 'human',
                sessionId,
                toolCallId: exec.callId ?? null,
                toolName,
                grant: grant.state,
                reasons: grant.reasons,
                // 只写「沿用的是哪一次」：hash 前 8 位＋原答复时刻。
                message: hit.via === 'class'
                    ? `沿用同类回执：${String(hit.classKey ?? '').slice(0, 8)} 于 ${hit.answeredAt} 已放行同类动作，`
                        + `本次为第 ${hit.uses} 次沿用（面＝${hit.faces}｜根＝${hit.roots}），不再询问`
                    : `沿用人工回执：${String(hit.hash ?? '').slice(0, 8) || '—'} 于 ${hit.answeredAt} 已放行同类动作，本次不再询问`,
                ...(hit.via === 'class' ? { via: 'class', classKey: hit.classKey, classUses: hit.uses,
                    classApprovedAt: hit.answeredAt, classFaces: hit.faces, classRoots: hit.roots } : {}),
            });
            // 没有凭据的放行不成立：这一行写不进台账，就退回问人。
            return written?.ok === false ? {} : { reused: true };
        };
        const escalateText = (escalate) => escalate === undefined ? ''
            : `\n⚠ 同一类动作本会话已沿用人工放行 ${escalate.uses} 次（最初批准于 ${escalate.answeredAt}），`
                + '沿用上限已到 ⇒ 这一格重新问人。';
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
            const reused = reuseByReceipt();
            if (reused.reused === true)
                return { kind: 'allow' };
            // 预设行与用户行都走宿主面板；两种来源都要能记下这一问的答复，
            // 否则台账里会出现没有结局的 ask。
            pending.put(exec.callId, {
                actionHash: facts.actionHash,
                sessionId,
                commandPreview,
                grant: grant.state,
                reasons: grant.reasons,
                // 答复回来时按同一把键记回执（目标集摘要＋配置版本）。
                targetDigest: targetDigestOf(facts.targets),
                configVersion: configVersionOf(config),
                // 补充：类键（或不建键的原因）随这一问一起存，答复回来才建得成类回执。
                classLedger,
                // 判据 5：评审没跑就如实记来源与行名——不许伪造成「评审不可用」。
                // 外项目根闸是事实闸，来源记 fact（不是 floor／rules，也不是评审）。
                verdict: {
                    source: outcome.by === 'floor' ? 'floor'
                            : String(outcome.rule ?? '').startsWith('别的项目根且未点名') ? 'fact'
                                : 'rules',
                    rule: String(outcome.rule ?? ''),
                },
            });
            return {
                kind: 'ask',
                reason: outcome.reason,
                // 候选源目录只挂在纯读的 ask 上（写／删／外传的绑定语义不同，文案不掺）。
                // 补充：同一类沿用到帽时，这一格为什么又回来问人也写进文案。
                displayReason: escalateText(reused.escalate) + askText({
                    by: outcome.by, rule: outcome.rule, source: facts.sourceRoot, command,
                    readOnly: facts.targets.every(target => target?.dynamic === true || String(target?.opClass) === 'read'),
                    targets: facts.targets,
                }, grant),
            };
        }
        // 模式已关闭：本插件不判，交回宿主面板（不是本插件放行的，所以不要求台账可写）。
        if (outcome.kind === 'delegate') return next();
        if (outcome.kind === 'release') {
            // 表里的放行（含「已证明只读」这一行）也是「本插件放行」。台账写不进去就没有可追责的放行，
            // 与快判／深评同一条规矩：降级成人工，而不是悄悄放过去。
            if (releasedWrite?.ok === false)
                return { kind: 'ask', reason: 'auto-approval-frame: audit unwritable', displayReason: '审计台账写入失败，需人工确认' };
            // 本插件放行 ≠ 这次调用真的被执行：waterfall 后面还有别的拥有者，`next` 返回什么才是结局。
            // 过去账上写到 `allowed` 就停，于是"框架说放行了、面板还在弹"这件事没人看得出来（F10/F14）。
            // 这里照原样把下游的返回值交出去，不用无条件 allow 去吞别人的硬约束，只把结局记下来。
            const handed = await next();
            trace({
                category: 'tool',
                eventType: 'tool.handoff',
                decision: handoffKindOf(handed),
                layer: 'host',
                // 这一格也要带上 callId：审计中心按它把同一次调用折成一张卡；机械验收的
                // 「放行都有宿主返回那一格」也是按 callId 配对的（缺了就被算成没那一格）。
                toolName,
                sessionId,
                toolCallId: exec.callId ?? null,
                ...layers,
                // 卡头已经是「已放行」；这里只写宿主那一侧的返回值（F10/F14 要的就是这一格），
                // 不再重复「本插件已放行」。
                message: `宿主返回＝${handoffKindOf(handed)}`,
            });
            return handed;
        }

        // 一份证据、两个档位（F05）：快判过去只看 400 字预览＋前 6 个目标，长写入在第 400 字
        // 之后的差别对它根本不存在，却照样能签字放行。现在两层读同一份投影、同一套操作者规则；
        // 证据装不下＝不做部分评审（快判跳过，深评按 unable 转人工）。
        const projected = projectEvidence({
            facts,
            grant,
            policy: walk.policy,
            // 判据 2：评审读的就是判定链那一份记录（同一个 actionHash／configVersion），
            // 不再拿空 args 现造一个"指纹恰好相同"的副本。
            record: walk.record,
            roots,
            provenance,
            intents: userIntents(authority, { budget: Math.max(1_000, Math.floor(config.evidenceBudget * 0.35)) }),
            background: `tool=${exec.name} model=${sessionModelLabel(authority.session)} trusted=${roots.trusted.length} rejectedTrusted=${JSON.stringify(roots.rejectedTrusted)} no_fast_path_because=${facts.readProofWhy || '—'}`,
            config,
        });
        // 判据 1：只有 `full` 才配自动批准。证据被裁过（正文、参数、块级）就不许自动放行，
        // 也不值得先跑一次快判——它看到的本来就是残片。
        const evidenceComplete = projected.tooLarge !== true && projected.completeness === 'full';
        // §4：卡块（附在证据之后，basis 的逐字引用仍取自 projected.text）。
        const cardBlock = `${projected.text}\n\n【卡】\n已有卡：${stored === undefined ? '无' : JSON.stringify(stored.card)}\n本次新原话：${freshWords ? '有' : '无'}\n`;
        // §4：卡块（附在证据之后，basis 的逐字引用仍取自 projected.text）。
        // 行名（citableRows）与类键（klass）已在判定链那一段按同一份 hits 算好，这里不另算一遍。
                // L2: fast judge — one single write inside the frame's own trust scope.
        let verdict;
        // 判据 6：快判的原话也要留下——升级深评时台账里的两条都在，顺序 fast→deep。
        // 快判自己放行的那条同样要落 reviews（否则「aiCalls 在、reviews 空」正是 B12 尾格）。
        let fastVerdict;
        if (config.fastJudge && grant.state === 'auto' && projected.tooLarge !== true && evidenceComplete === true) {
            // A10：准入收敛到一处（删除必升级，不让快判产生一次必然无收益的调用）。
            const eligible = fastJudgeEligible({ facts, grant, config });
            if (eligible) {
                aiCalls += 1;
                verdict = await runReview({
                    llm,
                    session: authority.session,
                    evidence: cardBlock,
                    config,
                    signal: exec.signal,
                    tier: 'fast',
                });
                fastVerdict = verdict;
                const fastContract = contractOf(verdict);
                const fastBasis = basisCheckOf(verdict, { rows: citableRows, evidence: projected.text, userText: projected.userText });
                // 判据 6（收口）：缺三问应答的 allow 不再自动放行——contract 未知
                // 或不全真 ⇒ fail-closed。verdict.js 本版禁碰，收口在调用点做。
                const fastClear = fastContract?.known === true && fastContract?.allTrue === true;
                if (fastClear && mayRelease(verdict, grant, config.mode, fastContract, fastBasis)) {
                    const released = record({
                        decision: 'allowed', layer: 'fast', ...layers,
                        reasonCode: verdict.reasonCode,
                        durationMs: verdict.durationMs,
                        reviewer: verdict.model,
                        reviewStatus: verdict.status,
                        reviewerDecision: verdict.decision,
                        contract: fastContract,
                        basis: fastBasis,
                        evidenceCompleteness: projected.completeness,
                        visibility: projected.visibility,
                        evidenceChars: projected.size,
                        message: sanitizeText(verdict.summary ?? '', 200),
                        // 与 buildActionRecord 内部同一个 reviewSnapshotOf：同源，不二次构造字段。
                        reviews: [reviewSnapshotOf({
                            raw: verdict.rawOutput ?? '',
                            checks: verdict.checks,
                            level: 'fast',
                            verdict: verdict.decision ?? verdict.status ?? '',
                        })],
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

        // L3: deep review — the only other source of ALLOW besides a rule row.
        // 这条没调模型，只是证据装不下 ⇒ 文案必须说清「没送 AI、直接转人工」，
        // 不许写成「评审无法判断」（人看到会以为自己被模型否了）。
        if (projected.tooLarge === true) {
            verdict = { status: 'unable', unableReason: 'context_too_large', summary: `证据 ${projected.needed} 字超出上限 ${projected.cap} 字，未送 AI 评审，直接转人工确认` };
        }
        else {
            aiCalls += 1;
            verdict = await runReview({
                llm,
                session: authority.session,
                evidence: cardBlock,
                config,
                signal: exec.signal,
                tier: 'deep',
            });
        }
        // 算法已证只读 ⇒ safeguarded 由 verdict.js 代填（模型仍负责 necessary／authorized）。
        // 条3（第 3 行）：代填的事实源交给 verdict.js 按整份 facts 自取——新建目标全不存在
        // 是第二格能量得出的「动不掉任何已有东西」；删／改名／区外／动态一律不代填。
        // 条1：allow 必须有可对证的依据行＋逐字引用；验不出 ⇒ 不释放（不改判成 block）。
        // 依据先验——「授权」这一来源拿它当门槛；AI 只给结论，三问由结论反推。
        const basis = basisCheckOf(verdict, { rows: citableRows, evidence: projected.text, userText: projected.userText });
        verdict = withAlgorithmSafeguard(verdict, facts);
        verdict = withAiConclusion(verdict, { basis, grant, facts, provenance });
        // 判据⑬：收卡。`card===null` ⇒ 沿用旧卡；非空 ⇒ 逐项核引文后按会话覆盖存。
        let cardKept = 0;
        let cardDropped = 0;
        let cardStored = false;
        if (cardKey !== null && verdict !== undefined && verdict !== null && verdict.card !== undefined) {
            if (verdict.card === null) {
                cardDropped = 0;                      // 沿用：不重抽、不计数
            }
            else {
                const screened = screenCard(verdict.card, projected.text);
                cardKept = screened.kept;
                cardDropped = screened.dropped;
                if (screened.card !== null) {
                    CARD_STORE.set(cardKey, { card: screened.card, fingerprint: wordsFingerprint });
                    cardStored = true;
                }
            }
        }
        // 面集合：这次调用碰到的所有动作类别（读／写／删／执行…）。全为读才算「纯读调用」。
        const facesOfCall = [...new Set([...(facts.segments ?? []).map(segment => String(segment.opClass ?? '')),
            ...(facts.targets ?? []).map(target => String(target.opClass ?? ''))])].filter(face => face !== '');
        const readOnlyCall = facesOfCall.length > 0
            && facesOfCall.every(face => face === 'read' || face === 'internal');
        // 「这一步多余」不是「用户不需要」，allow 不再因这个码改判。
        // 但只在纯读时生效——带写／删／改名／执行的同形回答退回旧口径（allow 配非放行码＝按它说的
        // 那一项拒），不让「模型说这步多余、却仍要删」借这一条过关。
        if (verdict?.decision === 'allow' && String(verdict.reasonCode ?? '') === 'not_necessary'
            && readOnlyCall !== true)
            verdict = { ...verdict, decision: 'block' };
        const contract = contractOf(verdict);
        const unableTier = unableTierOf(verdict, facts);
        // 判据 1：证据不完整 ⇒ 自动批准资格失效（`full` 之外的任何一档都只能转人工或拒）。
        // 判据 6（收口）：contract 未知（缺三问应答）⇒ 不放行，与「有一假」同案 fail-closed。
        // 收口放在调用点：评审实现可以换，这里兜得住（verdict.js 里只放判据，不放调用点的缺省值）。
        // AI 的 allow 只有在「算得稳」（非不可逆、无动态目标、无运行时展开）时才走放行门；
        // 算不稳时保留模型原本的三问形状，把这次挡在放行之外。
        const aiStable = verdict.aiStable !== false;
        const release = evidenceComplete === true && aiStable === true
            && (contract?.known === true && contract?.allTrue === true)
            && mayRelease(verdict, grant, config.mode, contract, basis);
        // 判据 5：模型自己把某一问答成 false、却仍写 allow —— 这是它自己的结论，按 block 论。
        // 真机这条由 `parseVerdict` 当场修；这里再兜一层，换掉评审实现也漏不掉。
        const contractSaysBlock = contract.known === true && contract.allTrue !== true;
        const contractCode = contractSaysBlock === true
            ? QUESTION_CODES[contract.failed[0] ?? contract.missing[0] ?? 'necessary']
            : verdict.reasonCode;
        // 判据⑦：评审举不出结论（unable／invalid）而这次调用**全是读面**、且没有任何
        // 机械下界理由时，不再把纯读拖到人面前：终态放行，台账照记 `unableTier` 与原因。
        const unableReadFallback = (verdict.status === 'unable' || verdict.status === 'invalid')
            // 证据装不下（context_too_large）＝模型根本没看到全部证据，这一档仍升人工。
            && verdict.unableReason !== 'context_too_large'
            // 目标集本身不确定（通配没展开／有动态目标）＝「纯读」这句话不成立，仍升人工。
            && !String(facts.readProofWhy ?? '').includes('通配')
            && !(facts.targets ?? []).some(target => target?.dynamic === true)
            && readOnlyCall && grant.state !== 'never' && (grant.reasons ?? []).length === 0;
        // 判据④：blocked 必须带机械理由 id；`other` 等于没给理由，降成一次人工询问。
        const mechanicalReason = typeof contractCode === 'string' && contractCode !== '' && contractCode !== 'other';
        const reviewedBlock = verdict.status === 'reviewed' && verdict.decision === 'block';
        // AI 的 block 就是真拒：auto 档不再把「区外写 block」降成 ask。
        // 「仅建议（advise）」档仍按字面执行——模型意见不构成否决，那是档位语义不是降级。
        const refuse = config.mode === 'auto' && !release && !unableReadFallback && grant.state === 'auto'
            && mechanicalReason
            && (contractSaysBlock === true || reviewedBlock);
        // The entry records what the frame actually did, not just what the model
        // said: a reviewed block in a confirm-grade session still ends in an ask.
        const decision = (release || unableReadFallback) ? 'allowed' : refuse ? 'blocked' : 'ask';
        // 卡片首句与台账读同一份：说清是框架的哪道门没放，不再拿「AI 判不了」兜一切。
        const releaseBlock = decision === 'ask'
            ? releaseBlockerOf({ verdict, grant, config, evidenceComplete, projected, basis, contract, release })
            : undefined;
        const written = record({
            decision,
            layer: 'deep',
            ...layers,
            ...(releaseBlock === undefined ? {} : { releaseBlockers: [releaseBlock] }),
            reviewStatus: verdict.status,
            reviewerDecision: verdict.decision,
            reasonCode: contractCode,
            unableReason: verdict.unableReason,
            // unable 的档位与 safeguarded 的代填来源都要能在台账里指认。
            ...(unableTier === undefined ? {} : { unableTier }),
            ...(verdict.safeguardedBy === undefined ? {} : { safeguardedBy: verdict.safeguardedBy }),
            // 判据②：授权来源要能在台账里指认（user-words+rule-row）。
            ...(verdict.safeguardFact === undefined ? {} : { safeguardFact: verdict.safeguardFact }),
            // 条8（第 10 行）：三问逐格署「谁答的」。代填的格署 `algorithm:<测得的事实>`，
            // 其余署 `ai`——只写一个 `safeguardedBy` 时，台账看不出另两格仍是模型的话。
            checksBy: checksByOf(verdict),
            // 判据⑬：卡只记条数与丢弃数，卡项正文与引文不进台账。
            card: { kept: cardKept, dropped: cardDropped, stored: cardStored },
            message: unableReadFallback
                ? `unable 兜底（${verdict.unableReason ?? verdict.status}）：面集合全为读且无机械下界理由，不升人工`
                : sanitizeText(verdict.summary ?? '', 240),
            rawOutput: verdict.rawOutput,
            durationMs: verdict.durationMs,
            reviewer: verdict.model,
            evidenceChars: projected.size,
            evidenceDropped: projected.dropped,
            // 判据 1／2／3：证据完整度、逐条裁剪账、用的是不是判定链那一份记录。
            evidenceCompleteness: projected.completeness,
            visibility: projected.visibility,
            evidenceIncomplete: projected.incomplete,
            evidenceTruncations: projected.truncations,
            evidenceRecordReused: projected.recordIdentity.reused,
            // 判据 3：证据块那一串版本（evidence.js:222 读 record.identity.configVersion）
            // 也落进同一判定行——一行内即可互证「frame／判定行／证据块」三处口径，不必事后回去猜。
            evidenceConfigVersion: projected.recordIdentity.configVersion ?? null,
            // 口径标签：三处版本均由 configVersionOf(config) 产生（record.js:29／:224），
            // 同一次判定内传入的就是同一个 config 对象，故三串应完全相等。
            versionBasis: 'configVersionOf(config)',
            contract,
            // 条1／条2 的回验结果：只记「它点的那一行在不在本次命中里、它摘的那段在不在证据里」，
            // 引用原文不落台账（证据本身已过脱敏，但没必要再抄一份进可导出的判定行）。
            basis,
            // 脚本 provenance：脚本路径／当前 hash／批准来源（none／rule／human／ai）。
            ...(scriptPath === undefined ? {} : {
                scriptProvenance: {
                    path: scriptPath,
                    hash: scriptHashed?.hash ?? null,
                    source: provenance?.source ?? 'none',
                    at: provenance?.at ?? null,
                },
            }),
            // 判据 6：快判升级来的，两条都在、顺序 fast→deep（fastVerdict 先入数组）。
            // 与 buildActionRecord 内部同一个 reviewSnapshotOf —— 同源，不在这里自拼字段。
            // 原话只进 answerHash／answerChars，判定行里不落明文（凭据因此不会跟着原话进来）。
            reviews: [fastVerdict, verdict]
                .filter(item => item !== undefined && item !== null)
                .map(item => reviewSnapshotOf({
                    raw: item.rawOutput ?? '',
                    checks: item.checks,
                    level: item.tier ?? 'deep',
                    verdict: item.decision ?? item.status ?? '',
                })),
        });
        if (written.ok === false) {
            // No durable trace means no accountable release: ask a human instead.
            return { kind: 'ask', reason: 'auto-approval-frame: audit unwritable', displayReason: '审计台账写入失败，需人工确认' };
        }
        if (release || unableReadFallback)
            return { kind: 'allow' };
        if (refuse) {
            // A reviewed block is decisive: the countdown would only delay the
            // same answer, and the model's reason travels back to the agent.
            // 工具错误面只给中文短句＋理由码：模型原文进台账 `message`，不整段回显到宿主那条红字里。
            // 判据③：summary 与 narrowerScope 要回到执行端——缩范围的「缩到 X」「缺哪条授权」
            // 都在这里；只有一句档位名时，执行端不知道该改什么。
            const why = sanitizeText([verdict.summary, verdict.narrowerScope]
                .filter(text => typeof text === 'string' && text.trim() !== '')
                .join('｜'), 240);
            return {
                kind: 'deny',
                reason: redactSecrets(`auto-approval-frame: AI 拒绝（${contractCode}）${why === '' ? '' : '：' + why}`),
            };
        }
        const reused = reuseByReceipt();
        if (reused.reused === true)
            return { kind: 'allow' };
        pending.put(exec.callId, {
            actionHash: facts.actionHash,
            sessionId,
            commandPreview,
            grant: grant.state,
            reasons: grant.reasons,
            // 答复回来时要按同一把键记回执（目标集摘要＋配置版本）。
            targetDigest: targetDigestOf(facts.targets),
            configVersion: configVersionOf(config),
            // 补充：这一问属于哪一类（不建键时记卡在哪一格），答复回来才建得成类回执。
            classLedger,
            verdict: { status: verdict.status, decision: verdict.decision, reasonCode: verdict.reasonCode, unableReason: verdict.unableReason, summary: verdict.summary },
        });
        return {
            kind: 'ask',
            reason: 'auto-approval-frame: human confirmation required',
            // AI 判不了那一档同样是「人要被问得清」，候选照挂（追加在文案最末，⚠ 句不受影响）。
            // 补充：同一类沿用到帽 ⇒ 这一格重新问人，原因写在文案最前。
            displayReason: escalateText(reused.escalate) + askText({
                by: outcome.by, rule: walk.policy.rule, verdict, source: facts.sourceRoot, command,
                readOnly: facts.targets.every(target => target?.dynamic === true || String(target?.opClass) === 'read'),
                unableTier, readProofWhy: facts.readProofWhy,
                targets: facts.targets,
                releaseBlock,
                evidenceNote: evidenceNoteOf(projected.visibility),
                toolNote: toolNoteOf({ toolName, args: exec.arguments }),
            }, grant),
        };
    });

    // 人工答复只能从会话日志这一侧读。`approval/request` 是跨进程转发的 waterfall：
    // 宿主自己的应答器先把它终结，插件的监听进不去——真机台账里 `approval.answer`
    // 恒为 0 就是这个成因（此前实读：38 次 ask，0 条人工答复）。
    // 而宿主强制 `approval/asked` ＋ `approval/decided` 成对提交，`session/event`
    // 又是「每个监听都跑、没有否决权」的 emit，所以这一侧只观测，不改判。
    anyCtx.on('session/event', (session, event) => {
        if (event?.type === 'approval/asked') {
            // 绑不绑得上要看宿主真给了什么：给了 actionHash 就核，没给就如实记 `hashBound:false`
            // ——不能因为 API 支持核就在台账里假装核过了（F14）。
            const askHash = event.data?.actionHash ?? event.data?.action?.hash;
            const record = pending.take(event.data?.callId, askHash);
            if (record === undefined)
                return;
            // 记下这一问的 callId／工具名：decided 那条只带 id 与结局。
            pending.hold(event.data?.id, {
                ...record,
                callId: event.data.callId ?? null,
                toolName: event.data.toolName ?? null,
                hashBound: askHash !== undefined,
            });
            return;
        }
        if (event?.type !== 'approval/decided')
            return;
        const asked = pending.release(event.data?.id);
        if (asked === undefined)
            return;
        const outcome = event.data?.outcome;
        trace({
            category: 'approval',
            eventType: 'approval.answer',
            decision: ANSWER_DECISION[outcome] ?? 'info',
            layer: 'human',
            sessionId: asked.sessionId ?? null,
            toolCallId: asked.callId ?? null,
            toolName: asked.toolName ?? null,
            commandPreview: asked.commandPreview ?? null,
            grant: asked.grant,
            reasons: asked.reasons,
            // 这一问是不是真的按动作绑过（宿主没给 hash 时＝false，账上如实写）。
            hashBound: asked.hashBound === true,
            message: `人工答复：${ANSWER_TEXT[outcome] ?? outcome}`,
            // 补充：逐格可复核——这一答要么带类键四成分，要么写清哪一类不建键（不回放的那一格）。
            classReceipt: asked.classLedger ?? null,
            advice: asked.verdict,
        });
        // 只有「放行」才记回执——拒绝／取消／没有通道都不记，紧随其后的同一动作照旧问。
        // 宿主给了 actionHash 就按 hash 键（hashBound:true），没给就按退化键入册，不冒充绑过。
        // 补充：同一份人工答复另外建类回执，但只有 classOf 判过排除项的类才有第四个键。
        if (outcome === 'allowed-once' || outcome === 'allowed-always') {
            const klass = asked.classLedger ?? {};
            receipts.put({
                sessionId: asked.sessionId ?? null,
                actionHash: asked.actionHash ?? '',
                hashBound: asked.hashBound === true,
                toolName: asked.toolName ?? null,
                targetDigest: asked.targetDigest ?? '',
                configVersion: asked.configVersion ?? configVersionOf(config),
                classKey: klass.built === true ? klass.key : '',
                classFaces: (klass.faces ?? []).join('+'),
                classRoots: (klass.roots ?? []).join('+'),
                classRows: String((klass.rows ?? []).join('; ')).slice(0, 200),
            });
            if (asked.callId !== null && asked.callId !== undefined) {
                humanAllowedCalls.set(String(asked.callId), Date.now());
                if (humanAllowedCalls.size > 512)
                    humanAllowedCalls.delete(humanAllowedCalls.keys().next().value);
            }
        }
    });

    // Observe the frozen final result: an ask is not an outcome, and a tool that
    // fails after approval otherwise leaves no trace of what actually happened.
    anyCtx.on('tools/result', (exec, result) => {
        const callId = exec?.callId;
        // F07 最后一道投影的诚实账：宿主的 finalizeContent 在本插件的投影**之后**，
        // 插件拦不住那一段；但冻结的最终结果看得见。仍见凭据形状（自铸占位符除外）
        // 就如实记账——不冒充"已遮住"，也不假装这道口不存在。能不能堵，归执行器层。
        if (result !== undefined && result !== null) {
            // 自铸占位符不算裸值：`password=[[SEC-…]]` 仍长着"键=值"的脸，先摘掉再扫，
            // 否则每一笔正常脱敏过的结果都会误报（第一版锁当场抓的就是这个）。
            const stripTokens = (value) => {
                if (typeof value === 'string')
                    return value.replace(TOKEN_PATTERN, '');
                if (Array.isArray(value))
                    return value.map(stripTokens);
                if (value !== null && typeof value === 'object')
                    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, stripTokens(child)]));
                return value;
            };
            const finalScan = scanBlocks(
                [stripTokens(result?.content), stripTokens(result?.additionalContexts)],
                sensitiveRows(config),
            );
            if (finalScan.action !== '') {
                trace({
                    category: 'sensitive',
                    eventType: 'sensitive.final-hit',
                    decision: 'info',
                    layer: 'redact',
                    sessionId: rootSessionId(exec, parentAgent) ?? null,
                    toolCallId: callId ?? null,
                    toolName: exec?.name ?? null,
                    detectors: finalScan.labels,
                    message: '宿主 finalization 之后的最终结果里仍见凭据形状：本插件的遮罩在其之前，拦不住这一段——'
                        + '记账不冒充已遮；要把这类口彻底堵上，得在执行器层做最终投影（能力边界，见 README 隐私节）',
                });
            }
        }
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
        { action: 'deny', label: '拒绝', detail: '这段结果不进模型上下文；动作已经执行过，不回退' },
        { action: 'release', label: '允许', detail: '遮掉凭据后交给模型；明文不进上下文' },
    ];

    // 同一会话里"这类命中怎么处置"问一次就够（F12：已完成安全处置却每格再点一次）。
    // 只缓存**人明确答过**的；没人答／超时不缓存——那不等于人选过。作用域＝会话，销毁即清。
    const dispositions = new Map();
    const dispositionKey = (sessionId, labels) => `${sessionId}|${[...new Set(labels ?? [])].sort().join('、')}`;

    async function askDisposition(exec, labels, detail, options, { reuse = false, sessionId = null } = {}) {
        if (typeof userQuestions?.ask !== 'function')
            return undefined;
        const key = reuse && sessionId !== null ? dispositionKey(sessionId, labels) : null;
        if (key !== null && dispositions.has(key))
            return dispositions.get(key);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), SECRET_ASK_TIMEOUT_MS);
        try {
            const answer = await userQuestions.ask({
                questions: [{
                    id: 'auto-approval-frame-sensitive',
                    question: `结果里检测到「${labels}」，怎么处置？`,
                    detail,
                    options: options.map(option => ({ label: option.label, description: option.detail })),
                }],
                ...(exec.agent !== undefined ? { agent: exec.agent } : {}),
                signal: controller.signal,
            });
            const selected = answer?.answers?.[0]?.selected?.[0];
            const chosen = options.find(option => option.label === selected)?.action;
            if (key !== null && chosen !== undefined) {
                if (dispositions.size > 256)
                    dispositions.delete(dispositions.keys().next().value);
                dispositions.set(key, chosen);
            }
            return chosen;
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
        // F14：待答过期不是"缓存清了"，是一条要入账的结局——没人答的那一问必须留痕，
        // 否则台账里全是开了口没下文的 ask，晚到的答复也成了孤儿。
        const swept = pending.sweep();
        for (const ask of swept.unanswered) {
            trace({
                category: 'approval',
                eventType: 'approval.expired',
                decision: 'expired',
                layer: 'human',
                sessionId: ask.sessionId ?? null,
                toolCallId: ask.callId ?? null,
                toolName: ask.toolName ?? null,
                commandPreview: ask.commandPreview ?? null,
                message: `问了但没人答，超过答案窗口（${Math.round(6 * 60)} 分钟）自动作废；这一问没有结局`,
            });
        }
        const decision = await next();
        const sessionId = rootSessionId(exec, parentAgent) ?? null;
        // 回写腿：模型可能把占位符写进了配置文件。宿主禁止改参数，所以只能在它写完之后
        // 按文件层把**我们自己铸的** token 换回明文。默认开（config.autoRestoreSecrets），但仍要证。
        // 它先于「这段结果给不给模型」：文件已经落地了，结果被拦不等于文件可以不修。
        //
        // F08：这是全帧**唯一会写用户文件**的支路，所以「不该写」的三种情形一次都不许写：
        // 被本帧拒在门外（工具根本没跑）、工具自己失败（半截内容不算落地）、开关没开。
        const prior = exec.callId === undefined || exec.callId === null
            ? undefined : decidedByCall.get(String(exec.callId));
        const landed = prior?.decision !== 'blocked' && result !== undefined && result?.isError !== true;
        // C4：写落地后记 path＋sha256＋来源；人批过一次脚本执行后同 hash 会话内复用。
        if (landed && exec.callId !== undefined && exec.callId !== null) {
            const callIdText = String(exec.callId);
            const byHuman = humanAllowedCalls.has(callIdText);
            const layer = String(prior?.layer ?? '');
            const source = prior?.decision === 'allowed'
                ? (layer === 'rules' || layer === 'floor' ? 'rule' : layer === 'human' ? 'human' : 'ai')
                : (prior?.decision === 'ask' || byHuman) ? 'human' : undefined;
            if (source !== undefined) {
                for (const path of writeTargetsByCall.get(callIdText) ?? []) {
                    const hashed = contentHashOf(path);
                    if (hashed !== undefined)
                        provenanceStore.record({
                            sessionId, path, hash: hashed.hash, source, bytes: hashed.bytes,
                            at: Date.now(), tool: exec.name,
                        });
                }
            }
            const scriptPath = scriptByCall.get(callIdText);
            if (scriptPath !== undefined && (prior?.decision === 'ask' || byHuman)) {
                const hashed = contentHashOf(scriptPath);
                if (hashed !== undefined)
                    provenanceStore.record({
                        sessionId, path: scriptPath, hash: hashed.hash, source: 'human', bytes: hashed.bytes,
                        at: Date.now(), tool: exec.name,
                    });
            }
            writeTargetsByCall.delete(callIdText);
            scriptByCall.delete(callIdText);
            humanAllowedCalls.delete(callIdText);
        }
        // 判据 3：发布授权一次性——只有真落地了才算用掉（上一步挂的 pending 在这里兑现）。
        if (landed && exec.callId !== undefined && exec.callId !== null) {
            const covered = pendingPublish.get(String(exec.callId));
            if (covered !== undefined) {
                for (const target of covered)
                    consumedPublish.add(`${sessionId ?? ''}|${target.remote}|${target.branch}`);
                pendingPublish.delete(String(exec.callId));
                if (consumedPublish.size > 512)
                    consumedPublish.delete(consumedPublish.values().next().value);
            }
        }
        if (landed && config.autoRestoreSecrets === true && vault.size() > 0) {
            const cwd = exec.agent?.session?.header?.cwd ?? process.cwd();
            // 没有会话上下文时无从判断，按「可能铸过」处理（保守记账，不静音）。
            const sessionVaulted = sessionId === null || vaultedSessions.has(sessionId);
            const fixed = restoreVaultedWrites({
                toolName: exec.name,
                args: exec.arguments,
                roots: resolveRoots(cwd, config),
                vault,
                probe: overrides.probe,
                sessionId,
                purpose: RESTORE_PURPOSE,
                // 判据 4：回填必须拿「签发时那一次」的 callId 去消费。
                callId: exec.callId ?? undefined,
            });
            for (const row of fixed) {
                if (row.tokens.length === 0 && row.skipped === undefined)
                    continue;
                // 本会话没铸过占位符：回填照做，账不记——没有占位符能出现在它的写目标里，
                // 这一趟只可能是「读了一遍文件什么也没找到」，记下来只会把真该看的记录淹掉。
                if (sessionVaulted !== true)
                    continue;
                // 两种情况都只是「信息」：换回了是补一笔账，没换回是**没写**，不是拦下了什么。
                // 旧版把跳过记成 `blocked`，页面照判定表渲染成「已拦截」——工具其实跑完了、
                // 文件也在盘上，读台账的人却以为这次调用被拒。
                trace({
                    category: 'sensitive',
                    eventType: row.tokens.length > 0 ? 'sensitive.restored' : 'sensitive.restore-skipped',
                    decision: 'info',
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
        // F07：`additionalContexts` 是宿主递进来的另一张口——扫与遮必须带上它，
        // 否则"content 遮干净、旁边那份原文照递"＝投影只做了一半。
        // A07：宿主 accept 会把 result.additionalContexts 一并合并，两份都算出口。
        const extrasList = [decision.additionalContexts, result?.additionalContexts]
            .filter(value => value !== undefined && value !== null)
            .flatMap(value => (Array.isArray(value) ? value : [value]));
        const extras = extrasList.length === 0 ? undefined : extrasList;
        const rows = sensitiveRows(config);
        // 判据 5：用户行同步进 sanitize 的静态形状出口（证据块／台账／规则行共用一张表）。
        setUserShapes(rows);
        // 判据 2/3：宿主契约（tools/src/index.ts:1804-1811）——accept decision 的
        // `value` 与 `content` 二选一；带 value 时宿主用 value **整建**结果，
        // content 根本不外发。扫与遮必须跟着真正会外发的那一格走。
        const hasValue = Object.hasOwn(decision, 'value') && decision.value !== undefined;
        const scan = scanBlocks(hasValue ? [decision.value, extras] : [blocks, extras], rows);
        const source = sanitizeText(redactSecrets(exec?.name ?? ''), 60);
        if (scan.action === '' && scan.big > 0)
            trace({
                category: 'sensitive', eventType: 'sensitive.unscanned', decision: 'info', layer: 'redact',
                sessionId, toolCallId: exec.callId ?? null, toolName: exec.name ?? null,
                unscanned: scan.big,
                message: `有 ${scan.big} 段结果超过 ${MAX_SCANNED_CHARS} 字，按能力边界未扫描内容（不冒充已遮）`,
            });
        let out = decision;
        // 判据 4：>2MB 块在判定侧是「跳扫」（unscannedBig）——若只在有命中时才投影，
        // 这类块会「跳扫仍交原文」。big>0 时强制走同一道投影：output/maskAny 把
        // 超 2MB 的值裁到上限内扫遮，原文不出门。
        if (scan.action !== '' || scan.big > 0) {
            // 先遮，再按档位决定这段要不要给模型／要不要问人。
            const masked = maskBlocks(hasValue ? [{ type: 'object', value: decision.value }] : blocks, rows, vault, source);
            const action = scan.action === 'ask'
                ? await askDisposition(exec, scan.labels,
                    '命中段落已经换成占位符，磁盘上什么都没动。要把占位符换回明文，去「敏感信息」卡打开自动回写。'
                    + '\n\n同一会话里，同一类命中只问一次；你的选择会被沿用，并计入台账。',
                    DISPOSITION_OPTIONS, { reuse: true, sessionId }) ?? 'release'
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
            // 这个会话从此有占位符在外面了：之后的写操作要检查回填，也要记账。
            if (masked.tokens.length > 0)
                markVaulted(sessionId);
            trace({
                ...layers,
                eventType: 'sensitive.redacted',
                decision: 'info',
                detectors: scan.labels,
                tokens: masked.tokens.length,                action,
                unscanned: masked.unscanned,
                message: `结果已脱敏：${scan.labels}（${masked.tokens.length} 处，占位符已入「敏感信息」表）`
                    + (masked.unscanned > 0
                        ? `；另有 ${masked.unscanned} 格是二进制／编码载荷，本包不扫其内容——遮罩只覆盖能读成文本的部分（能力边界，见 README 隐私节）` : ''),
            });
            if (hasValue) {
                // 判据 2/3：value 出口走与块完全同一把量具（包一层块形状进出，键值同语义、
                // 大响应裁剪、失败计数全在 maskBlocks 里）。宿主 :1804 同时带 content＋value
                // 会直接抛 TypeError ⇒ 不双份外发：以 value 为准，content 丢弃并记账。
                out = { ...decision, value: masked.blocks[0]?.value };
                if (Object.hasOwn(decision, 'content') && decision.content !== undefined) {
                    delete out.content;
                    trace({
                        ...layers,
                        eventType: 'sensitive.delivery-fixed', decision: 'info',
                        message: 'accept decision 同时带了 value 与 content：宿主契约是二选一（tools/src/index.ts:1804 会抛 TypeError）。按 value 分支处理，content 已丢弃，未双份外发。',
                    });
                }
            }
            else {
                out = { ...decision, content: masked.blocks };
            }
            if (extras !== undefined) {
                const maskedExtras = maskBlocks(Array.isArray(extras) ? extras : [extras], rows, vault, source);
                out.additionalContexts = maskedExtras.failed > 0 ? undefined : maskedExtras.blocks;
            }
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
            awaiting: pending.heldSize(),
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
