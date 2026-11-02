// ActionRecord —— 审查报告 §4.2：判定链的单一运行时对象。
// 事实、规则、模拟、提示词和审计都由这一份结构派生；禁止每层各自再猜一次输入。
// 本件只负责把各层已有产物**收进一份结构**并如实标注每个作用项的证据等级；
// "实际由谁批准"（decision）由 walkLadder 在走完链后填——放行出口的两格账
// （本插件结局 vs 宿主最终返回）仍由 index.js 各记各的，这里不替宿主签字。
import { createHash } from 'node:crypto';

/** * 生效规则面的版本号（A13）：凡**改变判定或脱敏结果**的设置都算进版本。
 * 旧形只哈希五张规则表——改 `mode`／`sensitiveDetect`／`reviewRules` 之后，
 * 规则缓存（policy.effectiveRows）与台账都以为"配置没变"，缓存不失效、审计说不清。
 * 只影响排查的键（如 `debug`）不算：版本变了缓存就得重编译，没道理为它付钱。
 */
const VERSION_TABLES = ['commandRules', 'fileRules', 'networkRules', 'toolRules', 'sensitiveRules'];
const VERSION_SETTINGS = [
    'mode', 'enabled', 'sensitiveDetect', 'evidenceBudget', 'blockBudgets', 'reviewRules', 'gatedPresets',
    'reviewerSource', 'reviewerProvider', 'reviewerModel',
    'fastJudge', 'fastJudgeTimeoutMs', 'fastJudgeMaxTokens', 'reviewerTimeoutMs', 'reviewerMaxTokens',
];

/** * 配置语义纪元（判据 3）：AI 档从「本层不拦、继续往下走」变成「终局路由」，
 * 这是**语义**变更而不是内容变更——旧配置一个字没改，判定结果却可能不同。所以版本串
 * 带上纪元号：纪元一升，旧版本串（pending／审批绑定、台账里的 configVersion）自然不再相等，
 * 不会拿旧语义下的批准去套新语义。v1＝12 位纯 hash，v2 起前缀 `2:`。
 */
export const CONFIG_EPOCH = 2;

export function configVersionOf(config, epoch = CONFIG_EPOCH) {
    const tables = VERSION_TABLES.map(key => config?.[key] ?? []);
    const settings = VERSION_SETTINGS.map(key => [key, config?.[key] ?? null]);
    const hash = createHash('sha256')
        .update(JSON.stringify({ tables, settings }))
        .digest('hex')
        .slice(0, 12);
    return `${epoch}:${hash}`;
}

/** 版本串里的纪元号；老格式（纯 hash）按 1 算。 */
export function configEpochOf(version) {
    const match = /^(\d+):/.exec(String(version ?? ''));
    return match === null ? 1 : Number(match[1]);
}

/** * 读到比自己更新的版本时**保留 last-good**，不清空规则（回退不炸）。
 * 返回 { version, forward }：forward＝对方版本比本机语义新，页面据此显示只读提示。
 */
export function acceptConfigVersion(previous, incoming) {
    if (typeof incoming !== 'string' || incoming === '')
        return { version: previous ?? '', forward: false };
    if (configEpochOf(incoming) > CONFIG_EPOCH)
        return { version: previous ?? '', forward: true };
    return { version: incoming, forward: false };
}

/** 配置里还有多少行被设成 AI（含旧写法 allow 折过来的）；告知文案用它给个数。 */
function aiRowCount(config) {
    const keys = ['commandRules', 'fileRules', 'networkRules', 'toolRules'];
    let count = 0;
    for (const key of keys) {
        for (const row of Array.isArray(config?.[key]) ? config[key] : []) {
            if (row === null || typeof row !== 'object' || row.removed === true)
                continue;
            if (row.action === 'ai' || row.action === 'allow'
                || ['read', 'write', 'delete'].some(op => row[op] === 'ai' || row[op] === 'allow'))
                count += 1;
        }
    }
    return count;
}

/** * 把「存下的版本」与「现在的版本」的差翻成一句人话（判据 2，纯函数，接线在 24）。
 * - 相同：不告知（level 'none'）；
 * - 落后：告知一次（level 'notice'）——AI／allow 行的含义已经从「不拦、继续走」变成
 *   「交模型判一次、命中即终局」；行内容不动，只告知；
 * - 更高／认不出：保留 last-good（keep=true），不清空用户规则，也不静默降档
 *   （与 19 的 safeResolve 同口径：解析失败或版本更新都不许把规则当空表处理）。
 */
export function migrationNoticeOf(storedVersion, currentVersion, config) {
    const stored = String(storedVersion ?? '');
    const current = String(currentVersion ?? '');
    if (stored === '' || stored === current)
        return { level: 'none', keep: true, text: '' };
    const storedEpoch = configEpochOf(stored);
    const currentEpoch = configEpochOf(current);
    if (storedEpoch > currentEpoch) {
        return {
            level: 'forward',
            keep: true,
            text: `存下的配置版本更新（v${storedEpoch} > 本机 v${currentEpoch}）：保留当前生效配置，不清空你的规则；请先升级插件再改判定。`,
        };
    }
    const rows = aiRowCount(config);
    return {
        level: 'notice',
        keep: true,
        text: `判定语义已升级（v${storedEpoch} → v${currentEpoch}）：AI 行现在等于「交模型判一次，命中即终局」，`
            + `不再是不拦、继续往下走。当前有 ${rows} 行受影响，行内容没有被自动改写；要不要保留由你决定。`,
    };
}


/** 判据 4／ 判据 7：每一条判定行都要能回答「模型原话是什么、三问各是什么」。
 *  快判与深评**各留一条**（升级路径不许丢前一次）；原话只留摘要与指纹（出口侧脱敏归结果面），
 *  三问按 verdict 契约的三键归成 true／false／unknown（字段名照抄 `verdict.js:18` 的
 *  `REVIEW_QUESTIONS`＝necessary／authorized／safeguarded，不自造也不改写——
 * 24 交付时把第三键写成 `safeguards`，与模型实际吐的那个名字差一个词，真应答会一律落成 unknown）。 */
const CONTRACT_KEYS = ['necessary', 'authorized', 'safeguarded'];
const CONTRACT_ALIASES = { safeguarded: ['safeguarded', 'safeguards'] };

export function reviewSnapshotOf(review) {
    if (review === null || typeof review !== 'object')
        return undefined;
    const text = typeof review.raw === 'string' ? review.raw
        : typeof review.answer === 'string' ? review.answer
            : typeof review.text === 'string' ? review.text : '';
    const checks = review.checks ?? review.contract?.checks ?? {};
    const read = key => (CONTRACT_ALIASES[key] ?? [key])
        .map(name => checks[name])
        .find(value => value !== undefined && value !== null) ?? null;
    const tri = key => {
        const value = read(key);
        return ['true', 'false', true, false].includes(value) ? String(value) : 'unknown';
    };
    const verdict = String(review.verdict ?? review.decision ?? '');
    return {
        level: String(review.level ?? review.kind ?? 'review'),
        verdict: verdict.slice(0, 120),
        verdictChars: verdict.length,
        // 拿不到原话就如实留空：不许填占位文本，也不许让「有条目」冒充「留了档」（判据 7）。
        answerHash: text === '' ? null : createHash('sha256').update(text).digest('hex').slice(0, 16),
        answerChars: text.length,
        answerEmpty: text === '',
        contract: Object.fromEntries(CONTRACT_KEYS.map(key => [key, tri(key)])),
        coveredBy: review.coveredBy ?? null,
    };
}

/** 反向锁：只有计数（`aiCalls: N`）而没有逐次应答的形状不算留档；
 *  条目在但**原话为空**（answerHash 为 null／空串）同样不算——那正是 B12 尾格说的「丢了应答」。 */
export function reviewTraceComplete(reviews) {
    return Array.isArray(reviews) && reviews.length > 0 && reviews.every(item => item !== null
        && typeof item === 'object'
        && item.contract !== undefined
        && CONTRACT_KEYS.every(key => ['true', 'false', 'unknown'].includes(String(item.contract[key])))
        && typeof item.answerHash === 'string' && item.answerHash !== '');
}

/** Map（reason → { op: action }）收成普通对象，进证据块与台账时不再依赖 Map 序列化。 */
const scopeEntries = (map) => {
    const out = {};
    for (const [reason, byOp] of map ?? [])
        out[reason] = { ...byOp };
    return out;
};

/** * @param {object} input { toolName, args, config, roots, facts, grant, session, callId, authorization }
 * `authorization` 是 gate 层 `userIntents` 的产物（来源／时序／范围／排除项／最新撤销）。
 * 传不进来就如实留 null——这个空位必须是显式的，不能用情绪标签或"没看到反对"顶替（F11）。
 */
export function buildActionRecord({ toolName, args, config, roots, facts, grant, session, callId, authorization, reviews }) {
    const effects = [];
    facts.targets.forEach((target, index) => {
        effects.push(target.dynamic === true
            ? {
                kind: 'operand', op: target.opClass, role: target.role ?? 'operand', input: target.input,
                segmentIndex: target.segmentIndex, index,
                evidence: 'unknown', conclusion: scopeEntries(grant?.targetScopes?.[index]),
            }
            : {
                kind: 'fs',
                op: target.opClass,
                role: target.role ?? 'operand',
                input: target.input,
                path: target.path,
                // 真身与字符串分开记（A02）：父目录是链接时两个答案不一样，台账要能看出来。
                realPath: target.realPath ?? null,
                linkEscapes: target.linkEscapes === true,
                program: target.program,
                rootHit: target.rootHit,
                identity: target.identity ?? null,
                exists: target.exists ?? null,
                gitState: target.gitState ?? null,
                bytes: target.bytes ?? null,
                segmentIndex: target.segmentIndex,
                index,
                // 身份／存在性没查出来就写 unknown：不许顶替 absent，也不许顶替 proven。
                evidence: target.gitState === 'unknown' || target.identity === 'unchecked' ? 'unknown' : 'proven',
                conclusion: scopeEntries(grant?.targetScopes?.[index]),
            });
    });
    facts.segments.forEach((segment, index) => {
        effects.push({
            kind: 'segment',
            op: segment.opClass,
            program: segment.program,
            index,
            remote: segment.remote === true,
            hosts: segment.hosts ?? [],
            readProof: segment.readProof ?? null,
            conclusion: scopeEntries(grant?.segmentScopes?.[index]),
        });
    });
    for (const host of facts.remoteHosts ?? [])
        effects.push({ kind: 'network', op: 'remote', host, evidence: 'proven' });
    const unknowns = [
        ...(facts.opaque ? ['opaque-command'] : []),
        ...(facts.truncated ? ['facts-truncated'] : []),
        ...effects
            .filter(effect => effect.evidence === 'unknown')
            .map(effect => `${effect.kind}:${effect.input ?? effect.program ?? effect.host ?? '?'}`),
    ];
    return {
        identity: {
            toolName: facts.toolName,
            isShell: facts.isShell === true,
            isMcp: facts.isMcp === true,
            session: session ?? null,
            callId: callId ?? null,
            actionHash: facts.actionHash,
            configVersion: configVersionOf(config),
            workspace: roots.workspace,
        },
        action: {
            command: facts.command,
            argv: facts.segments.map(segment => segment.argv ?? [segment.program, ...(segment.words ?? [])]),
            payloads: facts.payloads,
            opaque: facts.opaque === true,
        },
        // 逐段完整参数（带 kind 的 word 不再被折成字符串后丢掉）：快判、深评、模拟、台账
        // 都从这一段取输入，指纹（actionHash）只有一个来源（A05）。
        segments: facts.segments.map((segment, index) => ({
            index,
            program: segment.program,
            opClass: segment.opClass,
            baseOpClass: segment.baseOpClass ?? segment.opClass,
            argv: segment.argv ?? [segment.program, ...(segment.words ?? [])],
            words: segment.words ?? [],
            kinds: segment.kinds ?? [],
            redirects: segment.redirects ?? [],
            readProof: segment.readProof ?? null,
            heredocExpanded: segment.heredocExpanded === true,
            fromHeredoc: segment.fromHeredoc === true,
        })),
        effects,
        evidence: {
            provenRead: facts.provenRead === true,
            internalOnly: facts.internalOnly === true,
            readProofWhy: facts.readProofWhy ?? '',
            truncated: facts.truncated === true,
            unknowns,
        },
        authorization: authorization ?? null,
        // 判据 4：每一次评审的应答快照（快判与深评各一条）。
        reviews: (Array.isArray(reviews) ? reviews : []).map(reviewSnapshotOf).filter(item => item !== undefined),
        // 判据 5：裁剪过就如实标——判定行另有 actionHash＋configVersion（含语义纪元）可复算。
        truncation: {
            targets: facts.truncated === true,
            command: String(facts.command ?? '').length > 6_000,
            completeness: facts.completeness ?? 'ok',
            partial: facts.truncated === true
                || String(facts.command ?? '').length > 6_000
                || (facts.completeness !== undefined && facts.completeness !== 'ok'),
        },
        decision: null,
    };
}
