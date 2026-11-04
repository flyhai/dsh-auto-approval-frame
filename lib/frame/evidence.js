// L2 input assembly: bounded, trust-labeled evidence blocks. The reviewer sees
// nothing outside this text, so every fact it needs must be carried here.
import { sanitizeText, redactSecrets } from './sanitize.js';
import { NO_RULE_ROW } from './policy.js';
import { buildActionRecord } from './record.js';
import { authorizationOf } from './gate.js';

const BLOCK_BUDGETS = {
    action_to_review: 8_000,
    trusted_user_intent: 4_000,
    prior_user_context: 1_000,
    background_only: 2_000,
    prior_human_answers: 1_200,
};
// Trim order: lowest evidentiary weight is dropped first.
// 卡片答复排在最后面丢：它只增「人已表过态」这一条事实，权重低于用户原话（A16）。
const TRIM_ORDER = ['prior_human_answers', 'background_only', 'prior_user_context', 'trusted_user_intent', 'action_to_review'];

/** 单字段上限（判据 3）：每一格都得说得出「留了多少、丢了多少原字」。 */
/** 递给评审的判据范围句——只判安全面；项目内部惯例不是拒绝理由。 */
export const REVIEW_SCOPE_LINE = '评审范围：只判安全面（凭据泄露／外传目的地／写区外／权限过大）。项目内部惯例（该走哪个脚本、仓库怎么建、文件命名与流程）不是拒绝理由，不得据此 block。';
export const FIELD_CAPS = { command: 6_000, argv: 512, operand: 512, payload: 4_000 };

const TRUNC_MARK = '\n…[truncated]';

/** * 先投影、再裁剪（A06）：截断必须排在脱敏**之后**。
 * 反过来时，一条私钥的结束标记被切掉，依赖完整起止标记的检测就再也遮不住它的前半段。
 *
 * 判据 3：裁剪必须可解释。过去这里只把 `…[truncated]` 拼进正文，账上什么都不记——
 * 于是一份 4530 字的写入被裁到 4000 字，`incomplete` 仍是空数组，评审在残片上照批。
 * 现在每裁一格都往 `sink` 记一条：哪个字段、留了多少、丢了多少原字。
 */
function clip(value, cap, field, sink) {
    const masked = redactSecrets(String(value ?? ''));
    const normalized = masked.replace(/\n{3,}/g, '\n\n').trim();
    const text = sanitizeText(masked, cap);
    const cut = normalized.length > cap && text.length === cap + TRUNC_MARK.length;
    if (cut === true && Array.isArray(sink) === true)
        sink.push({ field, kept: cap, lost: normalized.length - cap, reason: 'field-cap' });
    return { text, cut, chars: normalized.length, kept: cut ? cap : normalized.length };
}

/** 只要正文时用这句：调用方多数不关心账，但账仍然照记（sink 由 actionBlock 传下来）。 */
const clean = (value, cap, field = 'text', sink) => clip(value, cap, field, sink).text;

/** Map（reason → { op: action }）收成普通对象：证据里不许出现 Map 序列化后的空壳。 */
const scopeOf = (map) => {
    const out = {};
    for (const [reason, byOp] of map ?? [])
        out[reason] = { ...byOp };
    return out;
};

/** * ｜目标去重：同一条命令把同一个事实逐段重复列出来（`cp A scripts/ && cp B scripts/`、
 * 五段同一个记账脚本带同一个文件参数），逐条 1:1 直出会让证据块被自己撑爆 ⇒ 超 8000 帽 ⇒
 * `unable/context_too_large` ⇒ 把本该零弹框的正常命令降成问人。
 *
 * 键＝这一格**在证据里渲染出来的全部字段**（path／realPath／literal／op／role／kind／
 * bytes／root／git／scope）：少任何一维就会把不同的事实折成同一条（判据 2.1／2.4）。
 * 折叠只删「同一句话的第二遍」，并留下 `count` 指认重复了几次；不截断、不丢弃任何目标。
 */
function dedupeTargets(entries) {
    const groups = [];
    const index = new Map();
    for (const entry of entries) {
        const key = JSON.stringify([
            entry.path ?? null, entry.realPath ?? null, entry.literal, entry.op ?? null,
            entry.role ?? null, entry.kind ?? null, entry.bytes ?? null, entry.root ?? null,
            entry.git ?? null, entry.scope,
        ]);
        const at = index.get(key);
        if (at !== undefined) {
            groups[at].count += 1;
            continue;
        }
        index.set(key, groups.length);
        groups.push({ entry, count: 1 });
    }
    return groups.map(group => group.count > 1 ? { ...group.entry, count: group.count } : group.entry);
}


/** * ｜段侧对照折叠：同一段在证据里渲染出来的**全部字段**逐格相同才折，留 count。
 * 任一格不同（program／argv／op／opClass／flags／operands／operandCount／redirects／
 * opaque／readProof／heredocExpanded）就是两条事实，不许合并。
 */
function dedupeSegments(entries) {
    const groups = [];
    const index = new Map();
    for (const entry of entries) {
        const key = JSON.stringify([
            entry.program ?? null, entry.argv ?? null, entry.op ?? null, entry.opClass ?? null,
            entry.flags ?? null, entry.operands ?? null, entry.operandCount ?? null,
            entry.redirects ?? null, entry.opaque ?? null, entry.readProof ?? null,
            entry.heredocExpanded ?? null,
        ]);
        const at = index.get(key);
        if (at !== undefined) {
            groups[at].count += 1;
            continue;
        }
        index.set(key, groups.length);
        groups.push({ entry, count: 1 });
    }
    return groups.map(group => group.count > 1 ? { ...group.entry, count: group.count } : group.entry);
}

/** * ｜证据瘦身：只送模型判案要用的那几件。
 *
 * 症状：证据块是 pretty JSON，每段抄 11 个字段、每目标抄 10 个，同一批事实写三遍
 * （`argv` 含 program／flags／operands，`op` 与 `opClass` 同值，`path` 与 `realPath` 相同），
 * 三个文件的 `for` 循环就到 8219 字、顶穿 8000 的块帽 ⇒ `unable/context_too_large` ⇒ 转人工。
 *
 * 判据：只送模型判案要用的两件事——**这次碰了什么**（路径／真身／根／动作／角色）与
 * **它凭什么判**（命令原文、命中规则行、授权卡）。机器自己的结论（只读举证、动作类重复写法、
 * 操作数个数、heredoc 展开标记）不进证据：档位已经用过它们，模型不需要再看一遍答案。
 */
/** `argv` 只在从「程序名＋操作数」还原不出来时补：`--x=y` 的值被折进旗标、子命令、
 *  分离值这些都会让 operands 少一格，过去正是它们被藏掉后模型判错（A05）。 */
function argvNeeded(entry) {
    const argv = entry.argv ?? [];
    if (argv.length === 0)
        return false;
    const left = new Map();
    for (const operand of entry.operands ?? [])
        left.set(String(operand), (left.get(String(operand)) ?? 0) + 1);
    for (const token of argv.slice(1)) {
        const text = String(token);
        if (text.startsWith('-')) {
            if (text.includes('='))
                return true;
            continue;
        }
        const remain = left.get(text) ?? 0;
        if (remain > 0) {
            left.set(text, remain - 1);
            continue;
        }
        return true;
    }
    return false;
}

const slimSegmentOf = entry => {
    const out = { program: entry.program, op: entry.op, operands: entry.operands };
    if (argvNeeded(entry))
        out.argv = entry.argv;
    if ((entry.redirects ?? []).length > 0)
        out.redirects = entry.redirects;
    if (entry.opaque === true)
        out.opaque = true;
    if (entry.count !== undefined)
        out.count = entry.count;
    return out;
};

const minimalSegmentOf = entry => {
    const out = { program: entry.program, op: entry.op };
    if (entry.count !== undefined)
        out.count = entry.count;
    return out;
};

/** 目标：`root` 必须留（模型判「区外」靠它，过去只给 root 时它把区外读成未授权）；
 *  `realPath` 只在真身与字符串不同的时候才值得占字；`git`／`bytes`／`kind` 空值不占位。 */
const slimTargetOf = entry => {
    const out = { path: entry.path, op: entry.op, role: entry.role };
    if (entry.realPath !== undefined && entry.realPath !== null && entry.realPath !== entry.path)
        out.realPath = entry.realPath;
    if (entry.kind)
        out.kind = entry.kind;
    if (entry.root)
        out.root = entry.root;
    if (entry.git !== undefined && entry.git !== null && entry.git !== '' && entry.git !== 'clean')
        out.git = entry.git;
    if (entry.bytes !== undefined && entry.bytes !== null)
        out.bytes = entry.bytes;
    if (entry.literal === false)
        out.dynamic = true;
    // scope 必须每条都带，空对象也要带：{}＝「没有行对这一格表过态」，缺席＝「这一版根本没算」，
    // 两者对模型的含义正相反（判据 6，由 evidence.test 锁着这一格）。
    out.scope = entry.scope ?? {};
    if (entry.count !== undefined)
        out.count = entry.count;
    return out;
};

/** 摘要形（最后一档）：段只剩程序与动作，目标只剩路径／动作／角色／根。
 *  授权逐行结论（scope）在这一档不附——由 `renderNote` 说明，免得模型把「没附」读成「没授权」。 */
const minimalTargetOf = entry => {
    const out = { path: entry.path, op: entry.op, role: entry.role };
    if (entry.root)
        out.root = entry.root;
    if (entry.count !== undefined)
        out.count = entry.count;
    return out;
};

/** * 目标路径共同前缀折叠：16 个文件同在一目录时，每条 100 多字的绝对路径写 16 遍。
 * 折成「一个基址 ＋ 每条相对部分」，基址照旧给全——模型判区外仍然有绝对归属。
 * 少于两条、或基址不足一个目录（`C:`、`/`）时不折。
 */
function foldTargetPaths(entries) {
    const paths = entries.map(entry => String(entry.path ?? ''));
    if (paths.length < 2)
        return { base: '', entries };
    let common = paths[0];
    for (const text of paths.slice(1)) {
        let at = 0;
        const max = Math.min(common.length, text.length);
        while (at < max && common[at] === text[at])
            at += 1;
        common = common.slice(0, at);
        if (common === '')
            return { base: '', entries };
    }
    const cut = Math.max(common.lastIndexOf('\\'), common.lastIndexOf('/'));
    const base = cut > 0 ? common.slice(0, cut + 1) : '';
    if (base.length < 16)
        return { base: '', entries };
    return {
        base,
        entries: entries.map(entry => {
            const text = String(entry.path ?? '');
            return text.startsWith(base) ? { ...entry, path: text.slice(base.length) } : entry;
        }),
    };
}

/** 评审到底看见了多少：命令原文、写入内容、脚本正文，三格一处算。
 *  卡片、台账、提示词都读这一份，不再各自按 toolName／args 猜。 */
function visibilityOf(facts, sink) {
    const cut = field => Array.isArray(sink) && sink.some(item => item?.field === field);
    const payloads = Array.isArray(facts.payloads) ? facts.payloads : [];
    const scripting = (facts.segments ?? [])
        .filter(segment => ['interpreter', 'inline', 'piped'].includes(String(segment?.execFamily ?? '')));
    const commandCut = cut('command');
    // 脚本正文的可视性按**最差的一段**算：只要有一段是外部脚本或管道喂入，
    // 就不能说“正文都看到了”。heredoc 从 stdin 喂脚本的那一段，正文就在命令里。
    const scriptBody = scripting.length === 0
        ? 'absent'
        : scripting.some(segment => String(segment?.execFamily ?? '') === 'piped')
            ? 'piped'
            : scripting.every(segment => String(segment?.execFamily ?? '') === 'inline'
                || segment?.scriptFromStdin === true)
                ? (commandCut ? 'partial' : 'included')
                : 'not-supplied';
    return {
        command: String(facts.command ?? '') === '' ? 'absent' : commandCut ? 'partial' : 'full',
        writeContent: payloads.length === 0
            ? 'absent'
            : payloads.some((_, index) => cut(`payloads[${index}]`)) ? 'partial' : 'included',
        scriptBody,
    };
}

function actionBlock(facts, grant, policy, record, sink, authorization, provenance) {
    const records = record?.segments ?? [];
    // 判定面也进证据：与最终档位同档的命中行都列出来（含被同档合并的目标结论），
    // 模型引用其中任一条都算有依据；判定仍只显示最严的那条。
    const decidedRows = policy?.cited ?? policy?.hits ?? [];
    // 段与目标先按**全字段**折叠（同一事实的第二遍只留 count），再投影成两档精简体。
    // 顺序不能反：先精简再折叠会把「argv 不同但都无需展示」的两段误并成一段。
    const segmentsFull = dedupeSegments(facts.segments.map((segment, index) => ({
        program: segment.program,
        argv: (records[index]?.argv ?? segment.argv ?? [segment.program])
            .map((item, at) => clean(item, FIELD_CAPS.argv, `segments[${index}].argv[${at}]`, sink)),
        op: segment.opClass,
        opClass: segment.opClass,
        flags: segment.flags,
        // 操作数的**值**（脱敏＋截断），不再只报数量——数量不能告诉模型要动的是哪个文件。
        operands: (segment.operands ?? [])
            .map((text, at) => clean(text, FIELD_CAPS.operand, `segments[${index}].operands[${at}]`, sink)),
        operandCount: (segment.operands ?? []).length,
        redirects: segment.redirects,
        opaque: segment.opaque === true,
        readProof: segment.readProof,
        heredocExpanded: segment.heredocExpanded === true,
    })));
    const targetsFull = dedupeTargets(facts.targets.map((target, index) => ({
        path: target.path ?? target.input,
        // 真身与字符串分开给（A02）：父目录是链接时，规则和模型都要能看见真身那一侧。
        realPath: target.realPath,
        literal: target.dynamic !== true,
        op: target.opClass,
        role: target.role,
        kind: target.kind,
        bytes: target.bytes,
        root: target.rootHit,
        git: target.gitState,
        // 判据 6：授权覆盖是**证据里已有的字段**（判定链按作用项算出来的逐行结论）。
        // 过去这张表只给 `root`，模型只好把「区外」自己读成「未授权」；给了它就不用猜。
        scope: scopeOf(grant?.targetScopes?.[index]),
    })));
    const folded = foldTargetPaths(targetsFull);
    const slimSegments = segmentsFull.map(slimSegmentOf);
    const minimalSegments = segmentsFull.map(minimalSegmentOf);
    const slimTargets = folded.entries.map(slimTargetOf);
    const minimalTargets = folded.entries.map(minimalTargetOf);
    const payloads = (facts.payloads ?? []).map((text, index) => {
        const raw = redactSecrets(String(text ?? ''));
        return { raw, ...clip(raw, FIELD_CAPS.payload, `payloads[${index}]`, sink) };
    });
    // 判据 4：正文没全收时必须给**可验证**的结构化摘要（长度／行数／首尾／diff 头），
    // 让模型知道「这是一份什么形状的正文、丢的是多长一段」，而不是要求它补猜。
    const payloadDigests = payloads
        .map((item, index) => item.cut === false ? undefined : {
            index,
            chars: item.chars,
            lines: item.raw.split('\n').length,
            kept: item.kept,
            omitted: Math.max(0, item.chars - item.kept),
            head: clean(item.raw.slice(0, 160), 160, `payloadDigests[${index}].head`, sink),
            tail: clean(item.raw.slice(-120), 120, `payloadDigests[${index}].tail`, sink),
            diffHeader: /^(diff --git |\+\+\+ |--- )/m.test(item.raw) ? 'present' : 'absent',
        })
        .filter(item => item !== undefined);
    const shared = {
        tool: facts.toolName,
        actionHash: facts.actionHash,
        shell: facts.isShell,
        // 原文（脱敏后）必须在证据里：只给 program＋flags＋operandCount 时，
        // `node -e 'console.log(1)'` 与 `node -e 'process.exit(1)'` 对模型是同一句话（F05）。
        command: clean(facts.command ?? '', FIELD_CAPS.command, 'command', sink),
        // 脚本 provenance：none／rule＝没有人工或 AI 看过的正文，AI 不能替它签字；
        // human／ai＝同 path 同 hash 已有批准来源（人批或 AI 已看过写入内容）。
        scriptProvenance: provenance === undefined || provenance === null
            ? { status: 'none' }
            : {
                status: String(provenance.source ?? 'unknown'),
                hash: String(provenance.hash ?? '').slice(0, 16),
                at: provenance.at ?? null,
            },
        cwd: facts.workspace,
        // 段：程序名、动作、操作数值（argv 仅当还原不出时才补）。`opClass`／`operandCount`／
        // `flags`／`readProof`／`heredocExpanded` 不进证据——前三个是同一事实的另一种写法，
        // 后两个是机器已经算完的结论（档位用过它们，模型不用再看一遍）。
        segments: slimSegments,
        // 目标路径若折叠过，基址给全（模型靠它判区外）；没折叠时整份都是绝对路径。
        ...(folded.base === '' ? {} : {
            targetBase: folded.base,
            targetBaseNote: '下面 targets 的 path 是相对 targetBase 的值；带盘符或分隔符开头的是绝对路径',
        }),
        targets: slimTargets,
        // 非 shell 的正文（写入内容／patch 新串／工具参数）：不给它，深评就是在猜。
        payloads: payloads.map(item => item.text),
        payloadDigests,
        // 范围字段有没有生成过，要单说：空对象既可能是「没有任何行表态」，也可能是
        // 「这一版根本没算」——两种情况的回答不一样，不能让模型自己去分辨。
        scopeFields: {
            targets: Array.isArray(grant?.targetScopes) ? 'present' : 'absent',
            segments: Array.isArray(grant?.segmentScopes) ? 'present' : 'absent',
        },
        remoteHosts: facts.remoteHosts ?? [],
        grant: { state: grant.state, reasons: grant.reasons },
        // 判据 5：凭据读／外传／持久执行要能绑「最小视图／目的端／一次性」，先得让评审看见
        // 这张证绑了什么。证上没有的字段一律 absent，不替它补默认值。
        grantBinding: {
            // A18：这里原来是 `authorization.purpose`，指的是「用户最新那句话想干什么」，
            // 不是这张证绑了什么——证的目的是 grant 自己的，证上没有就标 absent，不借别的格。
            resources: authorization?.resources ?? [],
            // 空数组分不清「用户没授权」和「程序没解析出来」，模型只会读成
            // 前者（`ls -la ~/.workbuddy/` 那次就是被这句带偏的）。解析不出路径资源、但原话里确实
            // 点了名字时，如实标「未解析」，并说明这不是「没授权」——算法不替用户猜名字指什么。
            resourcesNote: (authorization?.resources ?? []).length === 0
                ? ((authorization?.bareNames ?? []).length === 0
                    ? 'absent：原话里既没有路径资源，也没有可对的名字'
                    : `未解析：原话里只有名字（${(authorization?.bareNames ?? []).join('、')}），没对上任何路径——这不等于用户没授权，是程序没算出来；名字指什么，按原话判`)
                : '',
            excludes: authorization?.excludes ?? [],
            latestRevoke: authorization?.latestRevoke || '',
            once: grant?.once === undefined ? 'absent' : grant.once,
            destination: grant?.destination ?? 'absent',
        },
        // A18：整份授权对象不再原样给，「目的」「允许的附属操作」两格必须挡在外面，
        // 否则只删拼装行没用——它们会从这个对象里再漏一遍。
        authorization: authorization === null || authorization === undefined
            ? null
            : Object.fromEntries(Object.entries(authorization)
                .filter(([key]) => key !== 'purpose' && key !== 'allows')),
        disposability: grant.disposability,
        counts: facts.counts,
        // 判定面也进证据：哪一个作用项由哪一行定到什么档、还有什么没定局。
        // 一行都没表态时也要给模型一个真东西可指（条1）：否则它的 allow 永远点不出依据行。
        decidedBy: decidedRows.length === 0
            ? [{ plane: 'chain', op: undefined, action: 'ai', rule: NO_RULE_ROW, layer: 'chain' }]
            : decidedRows.map(hit => ({
                plane: hit.plane, op: hit.op || undefined,
                action: hit.action, rule: hit.text, layer: hit.layer,
            })),
        unknowns: [
            facts.provenRead === false && facts.readProofWhy !== '' ? `只读举证未通过：${facts.readProofWhy}` : '',
            facts.opaque === true ? '有段解析不全（运行时展开／控制流尾巴看不见）' : '',
            facts.truncated === true ? '目标过多已被截断，清单不完整' : '',
            // 判据 4：正文被裁时，摘要只能说明「丢了多长」，不能代替「丢了什么」。
            payloadDigests.length > 0
                ? `正文未全收：${payloadDigests.length} 段被裁（明细见 payloadDigests，未见部分按未知处理）`
                : '',
        ].filter(text => text !== ''),
    };
    // 放在 shared 建好之后再算：command 的截断账是上面 clean() 那一刻才写进 sink 的。
    const visibility = visibilityOf(facts, sink);
    shared.visibility = visibility;
    // 摘要形：段只剩程序与动作，目标只剩路径／动作／角色／根。授权逐行结论（scope）在这一档不附，
    // 必须写明「未附 ≠ 没授权」，否则模型会把省略读成否定（`ls -la ~/.workbuddy/` 就是这样被带偏的）。
    const minimal = {
        ...shared,
        segments: minimalSegments,
        targets: minimalTargets,
        renderLevel: 'minimal',
        renderNote: '摘要形：段只剩程序与动作，目标只剩路径／动作／角色／根；授权逐行结论（scope）未附——未附不等于没授权。',
    };
    return { slim: JSON.stringify(shared, null, 1), minimal: JSON.stringify(minimal, null, 1), visibility };
}

// 送给审查模型的每一块文本都先过同一个脱敏投影（F06）：审查请求是秘密离开本机的出口之一，
// 用户原话里也可能夹着凭据——只遮"结果"挡不住这里。
// 语气与承接**只标注、不删句**（A09）：删句等于让情绪词改写授权范围。
function intentBlock(intents) {
    return intents.map((intent, index) => {
        const marks = [intent.origin,
            intent.continuation === true ? '承接前文，不新开范围' : '',
            intent.tone === 'heated' ? '语气激动，语气不作数' : ''].filter(part => part !== '').join('·');
        return `[${index + 1}] (${marks}) ${redactSecrets(intent.text)}`;
    }).join('\n');
}

/** 任务授权读数（A09 五格 → A18 三格）：目标资源／排除项／最新撤销。
 *
 * 「目的」「允许的附属操作」两格已撤除。它们不是用户说的，是词表从原话里
 * 取词概括：目的＝最新一句（`gate.js` `authorizationOf`），动作＝19 个词的
 * `ALLOW_VERBS` 逐条 test。取词只往窄里错——「把节点全部加上」抽不出写、句尾
 * 「你看，」抽出读——而这份概括送到模型手上时没有任何一句说明它是怎么来的，
 * 模型就当成了授权边界。实际出现过：评审自己写「用户原话授权的是把节点全部
 * 加上（写入操作）」，紧接着因为「系统提取的授权结构未包含 write 权限」判拒。
 * 设计原意是「只取词，不是判据，不拿词表当授权边界」（`ALLOW_VERBS`
 * 上方注释），但这句前提从未抵达模型，前提与效果脱节。
 *
 * 防模型编授权靠的不是程序先概括一遍，是引文核验：模型的 allow 必须给出一条
 * 逐字出现在证据里的原话（`basisCheckOf`），引不出就不成立。程序概括这层既不
 * 防编，还在替用户编。这两格程序自己也不消费（全仓只有本文件读过 `allows`）。
 */
function authorizationBlock(auth) {
    return redactSecrets([
        `目标资源：${auth?.resources?.join('、') || '—'}`,
        `排除项（任何语气下都有效）：${auth?.excludes?.join('；') || '—'}`,
        `最新撤销：${auth?.latestRevoke || '—'}`,
    ].join('｜'));
}

/** 用户在卡片上点过的答案（A16）：这是他表过的态，但不是原话。
 *
 * 过去这一格只进 dispositions／回执两处——只影响「还问不问」，从不影响「怎么判」，
 * 于是用户刚点过「同意」，下一次同类写入评审照样不知道，再判一次授权不足。
 * 这里只把「他点过什么」照录给评审，**不当授权范围用**：卡片是就某个具体动作点的一下，
 * 不是一句覆盖得住别处的话；能拿它当依据的只有「这个动作他已经表过态」这一件事。
 */
function humanAnswerBlock(answers) {
    const list = Array.isArray(answers) ? answers.slice(-6) : [];
    if (list.length === 0)
        return '';
    const lines = list.map((item) => {
        const stamp = String(item?.at ?? '');
        const at = /T\d{2}:\d{2}/.test(stamp) ? stamp.slice(11, 16) : stamp.slice(0, 16);
        const question = String(item?.question ?? '').slice(0, 100);
        const answer = String(item?.answer ?? '').slice(0, 40);
        const targets = (Array.isArray(item?.targets) ? item.targets : [])
            .filter(text => typeof text === 'string' && text !== '').slice(0, 2).join('、');
        const tool = String(item?.toolName ?? '');
        const tail = [tool === '' ? '' : `动作=${tool}`, targets === '' ? '' : `目标=${targets}`]
            .filter(part => part !== '').join('｜');
        return `- ${at}「${question}」→ ${answer}${tail === '' ? '' : `（${tail}）`}`;
    });
    return '以下是用户**在界面上点选**的答复，不是他的原话，不得当授权范围引用；'
        + '能证明的只有「这个动作他已经表过态」这一件事：\n' + lines.join('\n');
}

/** 一条裁剪记录说人话：留了多少、丢了多少、丢在哪个字段（判据 1／3 的读数就是这一段）。 */
export function describeTruncation(item) {
    if (item.reason === 'total-budget')
        return `${item.field} 因总预算被整块丢弃（丢 ${item.lost} 字）`;
    if (item.reason === 'block-cap')
        return `${item.field} 超出块上限，已截断（丢 ${item.lost} 字）`;
    if (item.reason === 'render-minimal')
        return `${item.field} 降为摘要形（省 ${item.lost} 字；段只剩程序与动作、目标只剩路径／动作／角色／根，授权逐行结论未附）`;
    return `${item.field} 未全送达：保留 ${item.kept} 字，另有 ${item.lost} 字未包含`;
}

/** * Build the reviewer payload. Returns `tooLarge` when the action block alone
 * cannot fit its budget — the caller turns that into `unable`, never into a
 * review on partial facts.
 *
 * `record` 可选：给就用它（判定链的那一份），不给就按同一把尺现建一份——
 * 两条路产出同一个指纹（actionHash），模拟／判定／审计不会各说各话（A05）。
 * 判据 2：调用方**必须**把判定链那一份传进来，否则「评审看的那份」与「判过的那份」
 * 是两个不同的对象，只是恰好指纹相同；这里把用没用传进来的那份如实标在 `recordIdentity.reused`。
 */
export function projectEvidence({ facts, grant, intents = [], background = '', config = {}, policy, record, roots, provenance, humanAnswers = [] }) {
    const budget = Math.max(2_000, config.evidenceBudget ?? 16_000);
    const perBlock = config.blockBudgets === undefined ? BLOCK_BUDGETS : { ...BLOCK_BUDGETS, ...config.blockBudgets };
    const actionRecord = record ?? buildActionRecord({
        toolName: facts.toolName,
        args: {},
        config,
        roots: roots ?? { workspace: facts.workspace, trusted: [], dshOpen: [], home: facts.workspace },
        facts,
        grant,
    });
    // A demoted line keeps its words but must not be presented as
    // authorization: it lands in the non-authorizing block instead.
    const authorizing = intents.filter(intent => intent.authorizing !== 'background');
    const demoted = intents.filter(intent => intent.authorizing === 'background');
    const newest = authorizing.slice(-4);
    const older = authorizing.slice(-8, -4);
    // 授权五格只算一次：证据块与结构化字段必须是同一份读数，否则模型看到两套说法。
    const auth = authorizing.length === 0 ? null : authorizationOf(authorizing);
    const truncations = [];
    const backgroundText = [
        clean(background, perBlock.background_only, 'background', truncations),
        demoted.length === 0
            ? ''
            : `以下为用户语气激动的语句，内容照录，但不构成授权或不授权的依据：\n${intentBlock(demoted)}`,
    ].filter(part => part !== '').join('\n\n');
    const recordIdentity = {
        actionHash: actionRecord?.identity?.actionHash ?? null,
        configVersion: actionRecord?.identity?.configVersion ?? null,
        reused: record !== undefined && record !== null,
    };
    // 动作证据只算一次（actionBlock 会往 truncations 记账，重复调用会重复记）。
    // 这里返回两档（精简／摘要）。先精简形；装不下换摘要形；两档都装不下才算超帽——
    // 不再「第一次装不下就交人」（三个文件的 for 循环曾被推给人工）。
    const actionRendered = actionBlock(facts, grant, policy, actionRecord, truncations, auth, provenance);
    const actionBlockCap = perBlock.action_to_review;
    const actionPick = String(actionRendered.slim ?? '').length <= actionBlockCap
        ? { text: actionRendered.slim, level: 'slim' }
        : { text: actionRendered.minimal, level: 'minimal' };
    const blocks = [
        {
            name: 'action_to_review', trust: 'code-computed fact',
            text: actionPick.text,
        },
        {
            name: 'trusted_user_intent', trust: 'user-authored',
            // 授权摘要看**全部**授权句（排除项是累计的），不只是最新的四条。
            text: [intentBlock(newest), auth === null ? '' : authorizationBlock(auth)]
                .filter(part => part !== '').join('\n'),
        },
        { name: 'prior_user_context', trust: 'user-authored, older', text: intentBlock(older) },
        // 用户在卡片上点过的答案（A16）：只证明「这个动作他表过态」，不当授权范围。
        { name: 'prior_human_answers', trust: 'user-authored, clicked', text: humanAnswerBlock(humanAnswers) },
        { name: 'background_only', trust: 'non-authorizing', text: backgroundText },
        // 判据范围单独一块——动作块的块体是 JSON，范围句不得混进去（67 按 JSON 解析）。
        { name: 'review_scope', trust: 'policy scope', text: REVIEW_SCOPE_LINE },
    ];
    const dropped = [];
    // 降到摘要形要留痕：`completeness` 会因此变 `partial`，快判就不许自动放行（深评照常判）。
    if (actionPick.level === 'minimal') {
        truncations.push({
            field: 'action_to_review', kept: String(actionPick.text ?? '').length,
            lost: Math.max(0, String(actionRendered.slim ?? '').length - String(actionPick.text ?? '').length),
            reason: 'render-minimal',
        });
    }
    const tooLarge = (needed, cap, note) => ({
        tooLarge: true, needed, cap, incomplete: [note, ...truncations.map(describeTruncation)],
        truncations, completeness: 'too-large', recordIdentity,
    });
    for (const block of blocks) {
        const cap = perBlock[block.name];
        const text = block.text ?? '';
        if (text.length > cap) {
            if (block.name === 'action_to_review')
                return tooLarge(text.length, cap, 'action_to_review 超出块上限，不做部分评审');
            block.text = `${text.slice(0, cap)}\n…[trimmed]`;
            dropped.push(block.name);
            truncations.push({ field: block.name, kept: cap, lost: text.length - cap, reason: 'block-cap' });
        }
    }
    let total = blocks.reduce((sum, block) => sum + (block.text?.length ?? 0), 0);
    for (const name of TRIM_ORDER) {
        if (total <= budget)
            break;
        if (name === 'action_to_review')
            return tooLarge(total, budget, '总预算不足，动作证据不完整');
        const block = blocks.find(item => item.name === name);
        total -= block.text?.length ?? 0;
        truncations.push({ field: name, kept: 0, lost: block.text?.length ?? 0, reason: 'total-budget' });
        block.text = '';
        if (!dropped.includes(name))
            dropped.push(name);
    }
    const rendered = blocks
        .filter(block => (block.text ?? '') !== '')
        .map(block => `<<${block.name.toUpperCase()} trust=${block.trust}>>\n${block.text}\n<</${block.name}>>`)
        .join('\n\n');
    // 用户原话那两块的**实际送达**原文（可能被块上限截断、也可能因总预算整块丢弃）。
    // 依据校验用它判「这段引用是不是你自己说过的话」——必须取裁剪**之后**的文本，
    // 否则会出现「机器以为送进去了、模型其实没看到」的假依据。
    const userText = ['trusted_user_intent', 'prior_user_context']
        .map(name => blocks.find(block => block.name === name)?.text ?? '')
        .filter(text => text !== '')
        .join('\n');
    // 判据 1：incomplete 由账生成，账非空则它必然非空——两者不会再各说各话。
    const incomplete = truncations.map(describeTruncation);
    return {
        text: rendered, dropped, size: rendered.length, tooLarge: false, incomplete,
        // 用户原话块（送达后的文本）：依据校验判「短引文是不是你的原话」只有这一个来源。
        userText,
        // 判据 1／3：`completeness` 是给调用方看的唯一判据：只有 'full' 才配自动批准。
        completeness: truncations.length === 0 ? 'full' : 'partial',
        truncations, recordIdentity,
        visibility: actionRendered.visibility,
    };
}

export { BLOCK_BUDGETS };
