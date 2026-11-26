// L2 input assembly: bounded, trust-labeled evidence blocks. The reviewer sees
// nothing outside this text, so every fact it needs must be carried here.
import { sanitizeText, redactSecrets } from './sanitize.js';
import { NO_RULE_ROW } from './policy.js';
import { numericFloor } from './config-defaults.js';
import { buildActionRecord } from './record.js';
import { authorizationOf } from './gate.js';

// 证据只有一条规矩：拼起来超过总预算，整份不送、直接问人。
// 不再有分块上限，也不再有「丢一块凑合」——丢掉的那块可能是用户原话，
// 模型拿着没有授权的证据判出来的必然是「未授权」。
/** 一块渲染进证据后的固定开销：`<<NAME trust=…>>` 头、`<</name>>` 尾、块间空行。 */
const blockWireOverhead = (name, trust) => `<<${String(name).toUpperCase()} trust=${trust}>>\n`.length
    + `\n<</${name}>>`.length + 2;

/** 单字段上限（判据 3）：每一格都得说得出「留了多少、丢了多少原字」。 */
/** 递给评审的判据范围句——只判安全面；项目内部惯例不是拒绝理由。 */
export const REVIEW_SCOPE_LINE = '评审范围：只判安全面（凭据泄露／外传目的地／写区外／权限过大）。项目内部惯例（该走哪个脚本、仓库怎么建、文件命名与流程）不是拒绝理由，不得据此 block。';
export const FIELD_CAPS = { command: 6_000, argv: 512, operand: 512, payload: 4_000, script: 6_000 };

const TRUNC_MARK = '\n…[truncated]';

/** * 先投影、再裁剪（A06）：截断必须排在脱敏**之后**。
 * 反过来时，一条私钥的结束标记被切掉，依赖完整起止标记的检测就再也遮不住它的前半段。
 *
 * 判据 3：裁剪必须可解释。过去这里只把 `…[truncated]` 拼进正文，账上什么都不记——
 * 于是一份 4530 字的写入被裁到 4000 字，`incomplete` 仍是空数组，评审在残片上照批。
 * 现在每裁一格都往 `sink` 记一条：哪个字段、留了多少、丢了多少原字。
 */
function clip(value, cap, field, sink, secretValues = []) {
    const masked = redactSecrets(String(value ?? ''), secretValues);
    const normalized = masked.replace(/\n{3,}/g, '\n\n').trim();
    const text = sanitizeText(masked, cap);
    const cut = normalized.length > cap && text.length === cap + TRUNC_MARK.length;
    if (cut === true && Array.isArray(sink) === true)
        sink.push({ field, kept: cap, lost: normalized.length - cap, reason: 'field-cap' });
    return { text, cut, chars: normalized.length, kept: cut ? cap : normalized.length, full: normalized };
}

/** 只要正文时用这句：调用方多数不关心账，但账仍然照记（sink 由 actionBlock 传下来）。 */
const clean = (value, cap, field = 'text', sink) => clip(value, cap, field, sink).text;

/** * `argv`／操作数只是 `command` 的结构化副本。整条命令已完整送达时，同一段正文在副本里被
 * 单字段帽截断，不等于「评审没看到」——模型仍能从 command 逐字读到全文。过去这里照记一条
 * 截断账，于是 `python3 -c "…633 字…"` 被判 partial、AI 说放行也转人工（卡片一边说
 * 「证据没送全」，一边说「评审看到了命令里的代码正文」）。只有 command 自己也被截，
 * 才说明正文真的没送全，照常记账。
 */
/** 副本比对用的归一：argv 里的值已被词法还原（`\$X` → `$X`），command 那边还是 shell 原文，
 *  逐字 `includes` 正好在反斜杠处对不上，于是「同一段正文」被判成「副本里有、command 里没有」。
 *  只摊平 shell 真会吃掉的那几个转义（`\$`\\`\"\'\`\\`），Windows 路径里的 `\U` 这种原样保留。
 */
const flattenEscapes = text => String(text ?? '').replace(/\\([$`"'\\])/g, '$1');

/** 副本是不是 command 的一段。三种比法都要试，因为它们对应三种「副本少了几层转义」：
 *  ① 副本原样就在 command 里（没有要摊平的转义，或不是 shell 口）；
 *  ② 副本已被词法还原过**一层**（`\\` → `\`），所以只把 command 摊平一层去对**原样副本**——
 *     多层反斜杠就是这么漏的：regex 里的 `(?<!\\\\)` 摊平后是 `\\`，副本是 `\`，
 *     而两侧都摊平会把副本再摊一层变成 `\` 与 `\\` 对不上，于是「副本是 command 子串」判假，
 *     512 帽的截断账撤不掉 ⇒ `partial` ⇒ 评审说放行也不自动放行；
 *  ③ 副本一层都没被还原（非 shell 来的结构化参数），两侧都摊平才对得上。
 */
const copyInCommand = (commandFull, copyFull) => commandFull.includes(copyFull)
    || flattenEscapes(commandFull).includes(copyFull)
    || flattenEscapes(commandFull).includes(flattenEscapes(copyFull));

/** 副本是不是「command 的一段原文」。判据优先看词法事实，而不是比字符串。
 *
 * `literal` 由解析器给（`wordsBare`／`operandBare` 的取反）：这个词是字面量，就没有展开、没有通配，
 * 它必然逐字出现在 command 里。于是「送达完整性」只由 command 正本回答——command 没被裁 ⇒ 这一段
 * 一定也送到了，不必再拿字符串去证明。字符串比法（三种转义层数）降级成兜底，只负责非 shell 口、
 * 以及 `$VAR`／`*` 这类展开词（它们本来就不在原文里，只能事后比）。
 *
 * 为什么不再逐形状补：同一个判断先前补过三次（`\$`、解释器正文、只摊平一侧），每次都是新形状——
 * 病根是拿字符串比对去回答一个词法问题。词法器早知道答案，只是没传到这里。
 */
const cleanCopy = (value, cap, field, commandClip, sink, secretValues = [], literal = undefined) => {
    const clipped = clip(value, cap, field, sink, secretValues);
    const inCommand = commandClip.cut === false
        && (literal === true || copyInCommand(commandClip.full, clipped.full));
    if (clipped.cut === true && inCommand === true)
        sink.pop();
    return clipped.text;
};

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
    if (typeof entry.cwdUnknown === 'string' && entry.cwdUnknown !== '')
        out.cwdUnknown = entry.cwdUnknown;
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
    if (entry.literal === false) {
        out.dynamic = true;
        if (typeof entry.dynamicWhy === 'string' && entry.dynamicWhy !== '')
            out.why = entry.dynamicWhy;
        if (typeof entry.area === 'string' && entry.area !== '')
            out.area = entry.area;
        if (typeof entry.areaWhy === 'string' && entry.areaWhy !== '')
            out.areaWhy = entry.areaWhy;
    }
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
    if (entry.area)
        out.area = entry.area;
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
 *  卡片、台账、提示词都读这一份，不再各自按 toolName／args 猜。
 *  `scriptText`＝执行这一刻随动作带过来的脚本文本（装置写入时留住的同一份）；
 *  有它就算看见了正文，没有才按族名判（`-c` 正文／heredoc 的正文本来就在命令里）。 */
function visibilityOf(facts, sink, scriptText) {
    const cut = field => Array.isArray(sink) && sink.some(item => item?.field === field);
    const payloads = Array.isArray(facts.payloads) ? facts.payloads : [];
    const scripting = (facts.segments ?? [])
        .filter(segment => ['interpreter', 'command', 'piped'].includes(String(segment?.execFamily ?? '')));
    const commandCut = cut('command');
    const bodyIncluded = typeof scriptText === 'string' && scriptText !== '';
    // 整份没送（kept=0）就是「一个字都没给评审看」，不许标成 partial——那三个字会让人以为送了一半。
    // 正文只有整份送、整份不送两种去处（`actionBlock` 里那条规矩），这里按账上的 kept 如实落标记。
    const scriptCutItem = Array.isArray(sink) ? sink.find(item => item?.field === 'script') : undefined;
    const scriptDropped = scriptCutItem !== undefined && Number(scriptCutItem.kept ?? 0) === 0;
    // 脚本正文的可视性按**最差的一段**算：只要有一段是外部脚本或管道喂入，
    // 就不能说“正文都看到了”。heredoc 从 stdin 喂脚本的那一段，正文就在命令里；
    // 同串里「刚写完就跑」的那一段（`cat > x.py` 接着 `python x.py`）正文也在命令里。
    const scriptBody = scripting.length === 0
        ? 'absent'
        : scripting.some(segment => String(segment?.execFamily ?? '') === 'piped')
            ? 'piped'
            : bodyIncluded
                ? (scriptDropped ? 'not-supplied' : scriptCutItem === undefined ? 'included' : 'partial')
                : scripting.every(segment => String(segment?.execFamily ?? '') === 'command'
                    || segment?.scriptFromStdin === true
                    || segment?.scriptFromSibling === true)
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

/** 该送进证据的判定行（证据与可引用行必须同源，否则模型引不着、机器认不得）。
 *
 * 三份来源：同档命中行＋文件面允许行一律送（文件面允许行替「目标×动作格」表态，规则行授权的机器核对也用它）。
 *
 * 命令面允许行按「这一段的放行对本次判定有没有信息量」筛：
 * ① 整条命令一个文件目标都没有（`mytool && myai` 这种纯执行）：命令面允许行是模型唯一的可引依据，
 *    全送——不送它，模型想 allow 就无据可引。
 * ② 有文件目标：只送「这一段动了文件」或「这一段不是读类」的允许行。
 *    `cd`（纯导航）、`tail`／`wc`（纯管道）都是读类且没目标，放行行只是噪声，模型读到四行 `release`
 *    容易当成「大半已经放行」；而 `mytool` 这种外部程序的放行是「执行这一格」的授权，必须留。
 */
export function decidedRowsOf(policy, targets = []) {
    const rows = [...(policy?.cited ?? policy?.hits ?? []), ...(policy?.allowHits ?? [])];
    const cmdAllow = policy?.cmdAllowHits ?? [];
    if (cmdAllow.length === 0)
        return rows;
    const list = Array.isArray(targets) ? targets : [];
    if (list.length === 0)
        return [...rows, ...cmdAllow];
    // 只算「真在读内容／写／删」的目标：`directory-container` 是导航与列目录（`cd X`、`ls X`）
    // 产生的，它不说明这一段动了什么，拿它撑放行依据等于用「我进过那个文件夹」证明「删文件没问题」。
    const withFile = new Set(list
        .filter(target => String(target?.role ?? '') !== 'directory-container')
        .map(target => target?.segmentIndex)
        .filter(index => typeof index === 'number'));
    // 段号缺失（手搓 hits 的调用方）时保留：无从判断就不擅自删，宁可多送一行。
    return [...rows, ...cmdAllow.filter(hit => {
        if (typeof hit?.segmentIndex !== 'number')
            return true;
        if (withFile.has(hit.segmentIndex))
            return true;
        return hit.segmentOpClass !== 'read';
    })];
}

/** 给评审看的正文：去掉整行注释与空行。
 *
 * 注释不执行、空行不表意，去掉不改脚本行为；反过来，注释可能骗人（开头写「只读解析」，
 * 中间有 `open(...,'w')`），趁早摘掉。只处理整行：行内 `#` / `//` 要先判引号，纯文本匹配会误伤，
 * 收益也只有一两百字。头两行的 shebang 与编码声明保留——那是解释器要读的。
 */
export function stripForReview(text) {
    const source = String(text ?? '');
    // 跨行字符串里以 `#`／`//` 开头的那一行，会被当成注释删掉——删掉的是**字符串内容**，
    // 不是注释：`doc = """` 里那行 `# 标题一`、JS 模板字符串里那行 `// 说明行` 都会消失，
    // 脚本写出去的东西就少一行。认「哪一行在字符串内」要按语言做词法，
    // 超出这一步的职责；保守做法是整份不去注释、原样照送：多送几十上百字是钱，
    // 删错一行是脚本行为改变，两害取轻。
    if (/"""|'''|`/.test(source))
        return source;
    const lines = source.split(/\r?\n/);
    const kept = [];
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        const trimmed = line.trim();
        if (trimmed === '')
            continue;
        if (trimmed.startsWith('#')) {
            if (index <= 1 && (trimmed.startsWith('#!') || /coding[:=]/i.test(trimmed)))
                kept.push(line);
            continue;
        }
        if (trimmed.startsWith('//'))
            continue;
        kept.push(line);
    }
    return kept.join('\n');
}

function actionBlock(facts, grant, policy, record, sink, authorization, provenance, scriptText, actionBudget) {
    const records = record?.segments ?? [];
    // 判定面也进证据：同档命中行＋文件面允许行＋（仅在整条放行时）命令面允许行，见 decidedRowsOf。
    // 引文能替什么表态由机器核对管（verdict）——命令面行不替文件目标表态，cat 区外越级仍拦。
    const rowSeen = new Set();
    const decidedRows = [];
    for (const hit of decidedRowsOf(policy, facts.targets)) {
        const key = `${hit?.plane}|${hit?.action}|${hit?.text}|${hit?.id ?? ''}`;
        if (rowSeen.has(key))
            continue;
        rowSeen.add(key);
        decidedRows.push(hit);
    }
    // 整条 command 是判定的正本：先算它，副本截断才判得出「是不是只是副本」。
    const commandClip = clip(facts.command ?? '', FIELD_CAPS.command, 'command', sink, facts.secretValues);
    // 段与目标先按**全字段**折叠（同一事实的第二遍只留 count），再投影成两档精简体。
    // 顺序不能反：先精简再折叠会把「argv 不同但都无需展示」的两段误并成一段。
    const segmentsFull = dedupeSegments(facts.segments.map((segment, index) => ({
        program: segment.program,
        argv: (records[index]?.argv ?? segment.argv ?? [segment.program])
            // argv[0] 是程序名，恒为字面；其余词查 wordsBare（`bare === true` ⇒ 展开/通配 ⇒ 走兜底比对）。
            .map((item, at) => cleanCopy(item, FIELD_CAPS.argv, `segments[${index}].argv[${at}]`, commandClip, sink, facts.secretValues,
                at === 0 ? true : segment.wordsBare?.[at - 1] !== true)),
        op: segment.opClass,
        opClass: segment.opClass,
        flags: segment.flags,
        // 操作数的**值**（脱敏＋截断），不再只报数量——数量不能告诉模型要动的是哪个文件。
        operands: (segment.operands ?? [])
            .map((text, at) => cleanCopy(text, FIELD_CAPS.operand, `segments[${index}].operands[${at}]`, commandClip, sink, facts.secretValues,
                segment.operandBare?.[at] !== true)),
        operandCount: (segment.operands ?? []).length,
        redirects: segment.redirects,
        opaque: segment.opaque === true,
        readProof: segment.readProof,
        heredocExpanded: segment.heredocExpanded === true,
        // 工作目录算不死时把来源带出来：模型看见的是「为什么这一段的相对路径没定位」，
        // 不用回猜是插件漏了还是命令本身算不出。
        ...(typeof segment.cwdUnknown === 'string' && segment.cwdUnknown !== ''
            ? { cwdUnknown: segment.cwdUnknown } : {}),
    })));
    const targetsFull = dedupeTargets(facts.targets.map((target, index) => ({
        path: target.path ?? target.input,
        // 真身与字符串分开给（A02）：父目录是链接时，规则和模型都要能看见真身那一侧。
        realPath: target.realPath,
        literal: target.dynamic !== true,
        ...(typeof target.dynamicWhy === 'string' && target.dynamicWhy !== ''
            ? { dynamicWhy: target.dynamicWhy } : {}),
        op: target.opClass,
        role: target.role,
        kind: target.kind,
        bytes: target.bytes,
        root: target.rootHit,
        ...(target.dynamic === true ? {
            area: target.areaHit,
            areaPrefix: target.areaPrefix,
            areaWhy: target.areaBasis,
        } : {}),
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
    // 外项目读：另一个项目根下的目标不属于本次任务的作业面。把「哪个根、点没点名」
    // 直接给评审——授权按用户的话覆盖到哪判，点名只是其中一种证据。
    const foreignProjects = (facts.targets ?? [])
        .filter(target => target?.dynamic !== true && target?.foreignProject === true)
        .map(target => ({
            path: target.path ?? target.input,
            root: target.foreignRoot ?? '',
            namedByUser: target.namedByUser === true,
        }));
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
        command: commandClip.text,
        // 脚本 provenance：none／rule＝没有人工或 AI 看过的正文，AI 不能替它签字；
        // human／ai＝同 path 同 hash 已有批准来源（人批或 AI 已看过写入内容）。
        scriptProvenance: provenance === undefined || provenance === null
            ? { status: 'none' }
            : {
                status: String(provenance.source ?? 'unknown'),
                hash: String(provenance.hash ?? '').slice(0, 16),
                at: provenance.at ?? null,
            },
        // 要执行的脚本文本（装置写入时留住的同一份，指纹对得上才到这里）。
        // 没有这一格时，评审只看得到 `python xx.py` 这一行路径，正文得靠猜。
        // 同串里「刚写完就跑」的那份正文不在命令原文里，也得单独带进来——
        // 只把可见性标成 included 却不给正文，等于告诉模型「你看过了」而它其实没看到。
        // 值在下面按「块帽减掉其他字段的实际占用」算出来再填：先塞固定上限、再回头发现装不下，
        // 会让整块作废（一条几千字的脚本就能把动作块顶过帽，模型一个字都看不到）。
        // 区的唯一口径：会话工作区根。名字必须叫 workspace——叫 cwd 会被模型读成
        // 「执行时的当前目录」，命令里一句 `cd F:` 就把区内写判成区外写。
        workspace: facts.workspace,
        // 结构解析的确定性：用的是文法还是退回手写拆串、为什么。只报事实，不当档位——
        // 「结构没被文法证实」不等于危险、未授权或必须人工，模型据此看哪一步算不出即可。
        parse: {
            mode: facts.parseMode?.mode ?? 'none',
            incomplete: facts.parseMode?.incomplete === true,
            ...(facts.parseMode?.incomplete === true ? { why: facts.parseMode?.why ?? '' } : {}),
        },
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
        // 命中了别的项目根的读目标：根＋点名事实（见 review.js 的外项目读判据）。
        ...(foreignProjects.length === 0 ? {} : { foreignProjects }),
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
                    : `未解析：原话里只有名字（${(authorization?.bareNames ?? []).join('、')}），没有路径——这不等于用户没授权，是名字不构成范围证明；名字指什么，按原话判`)
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
    // 正文按「块帽 − 其他字段实际占用」填：先去整行注释与空行（无损），再按剩余额度截。
    // 顺序不能反——先按固定上限截，等于把额度花在注释上（注释与空行能占掉近一成）。
    const fromSibling = !(typeof scriptText === 'string' && scriptText !== '');
    const bodySource = fromSibling
        ? (typeof facts.siblingScriptBody === 'string' && facts.siblingScriptBody !== ''
            ? redactSecrets(facts.siblingScriptBody) : '')
        : scriptText;
    if (bodySource !== '') {
        const stripped = stripForReview(bodySource);
        // 探底：把空串放进同一个键位，量出「除正文以外」的真实占用（含键名与引号）；
        // 再留 120 字给后面才挂上的 `visibility`（它由 sink 决定，必须先记完账才算得出来）。
        // 额度来自总预算减掉其余几块（`actionBudget`），不是某个写死的块上限。
        const room = Math.max(0, Number(actionBudget ?? 0) - 120
            - JSON.stringify({ ...shared, scriptBody: '' }).length);
        // 正文只有两种去处：整份送，或者整份不送。**绝不送残片**。
        // 从头截的话，脚本的收尾（写文件、上传）通常在后半段，模型看到的是 import 和函数定义，
        // 却能给出「看着像诊断脚本」——这比不送更坏：人看见「AI 看过」就点了。
        if (stripped.length <= room) {
            shared.scriptBody = stripped;
            if (fromSibling)
                shared.scriptBodyFrom = 'same-command';
        }
        else {
            // 整份放不下：一个字都不送，账上写清字数与原因，可见性落到 partial——模型别以为看过。
            sink.push({ field: 'script', kept: 0, lost: stripped.length, reason: 'script-too-large' });
        }
    }
    // 放在 shared 建好之后再算：command 的截断账是上面 clean() 那一刻才写进 sink 的。
    const visibility = visibilityOf(facts, sink, scriptText);
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
    // 不带缩进：`null, 1` 让每个字段独占一行，一条命令就多付一份换行、行首空格、
    // 冒号后空格，实测约占动作块总量的一到两成，信息一个字没多。
    // 证据是给模型读的 JSON，紧凑形它读得惯；这几百字在每条命令上都要付一遍。
    return { slim: JSON.stringify(shared), minimal: JSON.stringify(minimal), visibility };
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

/** 会话任务原话：长期有效，后来的话只能增补或由用户明说收窄。 */
function sessionTaskBlock(task) {
    const text = String(task ?? '').trim();
    return text === '' ? '' : '以下为本会话的用户任务原话（长期任务；后来的话只能在它上面增补，或由用户明说收窄）：\n' + text;
}

/** 用户在本机提问卡上点选的答案：选项原文就是他看到并同意的范围。 */
function questionAnswerBlock(answers) {
    const list = Array.isArray(answers) ? answers.slice(-6) : [];
    if (list.length === 0)
        return '';
    const lines = list.map(item => {
        const at = String(item?.at ?? '');
        const question = String(item?.question ?? '').slice(0, 120);
        const answer = String(item?.answer ?? '').slice(0, 80);
        const detail = String(item?.description ?? '').slice(0, 240);
        return `- ${at}「${question}」→ ${answer}${detail === '' ? '' : `（${detail}）`}`;
    });
    return '以下为用户在本机提问卡上点选的答案（选项原文＝用户看到并同意的范围；只覆盖选项写到的目标；不是 AI 推测，也不是其他工具回传）：\n'
        + lines.join('\n');
}

/** 一条裁剪记录说人话：留了多少、丢了多少、丢在哪个字段（判据 1／3 的读数就是这一段）。 */
export function describeTruncation(item) {
    if (item.reason === 'script-too-large')
        return `脚本正文整份没送（${item.lost} 字）`;
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
export function projectEvidence({ facts, grant, intents = [], background = '', config = {}, policy, record, roots, provenance, scriptText, humanAnswers = [], sessionTask = '', questionAnswers = [] }) {
    const budget = numericFloor('evidenceBudget', config.evidenceBudget);
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
        redactSecrets(String(background ?? '')).replace(/\n{3,}/g, '\n\n').trim(),
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
    // 它不再有自己的块上限：能给正文多少额度，＝总预算减掉其余几块的实际长度（见下）。
    const otherBlocks = [
        { name: 'session_task', trust: 'user-authored, standing', text: sessionTaskBlock(sessionTask) },
        { name: 'question_answers', trust: 'user-clicked, verified', text: questionAnswerBlock(questionAnswers) },
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
    // 其余几块先占掉它们的实际长度（不再各有上限，也不再被整块丢弃）：
    // 剩下多少给动作证据，动作证据再拿剩余里的部分给正文。
    const wireOf = block => {
        const text = String(block.text ?? '');
        return text === '' ? 0 : text.length + blockWireOverhead(block.name, block.trust);
    };
    const reserved = otherBlocks.reduce((sum, block) => sum + wireOf(block), 0);
    const actionRendered = actionBlock(facts, grant, policy, actionRecord, truncations, auth, provenance, scriptText, Math.max(0, budget - reserved));
    const actionText = actionRendered.slim;
    const blocks = [
        { name: 'action_to_review', trust: 'code-computed fact', text: actionText },
        ...otherBlocks,
    ];
    const tooLarge = (needed, cap, note) => ({
        tooLarge: true, needed, cap, incomplete: [note, ...truncations.map(describeTruncation)],
        truncations, completeness: 'too-large', recordIdentity,
    });
    // 只有一条规矩：证据完整就送，不完整就不送。没有「丢一块凑合」——
    // 丢掉的那块可能是用户原话，模型拿着没授权的证据判出来的必然是「未授权」。
    const total = blocks.reduce((sum, block) => sum + wireOf(block), 0);
    if (total > budget)
        return tooLarge(total, budget, `证据总长 ${total} 字，超过预算 ${budget} 字，整份不送`);
    const rendered = blocks
        .filter(block => (block.text ?? '') !== '')
        .map(block => `<<${block.name.toUpperCase()} trust=${block.trust}>>\n${block.text}\n<</${block.name}>>`)
        .join('\n\n');
    // 用户原话那两块的**实际送达**原文（可能被块上限截断、也可能因总预算整块丢弃）。
    // 依据校验用它判「这段引用是不是你自己说过的话」——必须取裁剪**之后**的文本，
    // 否则会出现「机器以为送进去了、模型其实没看到」的假依据。
    const userText = ['session_task', 'question_answers', 'trusted_user_intent', 'prior_user_context']
        .map(name => blocks.find(block => block.name === name)?.text ?? '')
        .filter(text => text !== '')
        .join('\n');
    // 判据 1：incomplete 由账生成，账非空则它必然非空——两者不会再各说各话。
    const incomplete = truncations.map(describeTruncation);
    return {
        text: rendered, dropped: [], size: rendered.length, tooLarge: false, incomplete,
        // 预算实数：卡头与台账都要报「超过预算多少」，不能只在 tooLarge 那一支才带。
        cap: budget,
        // 用户原话块（送达后的文本）：依据校验判「短引文是不是你的原话」只有这一个来源。
        userText,
        // 判据 1／3：`completeness` 是给调用方看的唯一判据：只有 'full' 才配自动批准。
        completeness: truncations.length === 0 ? 'full' : 'partial',
        truncations, recordIdentity,
        visibility: actionRendered.visibility,
    };
}

