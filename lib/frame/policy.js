// L1: the ordered rule tables. One list per plane; inside a list the first
// matching row wins, across lists the strictest row wins (deny > ask > ai > release).
//
// Four tiers on every plane, no fifth: `release` is a real release (the operator
// said so), `ai` means "this row does not hold it, keep judging", `ask` goes to
// the human, `deny` stops it. Masking is not a tier — the sensitive plane masks
// every hit it reports, whatever tier the row carries.
//
// 四个平面共用同一套档位，敏感面**不多出一档**：命中就遮是这一层自己在做的事，
// 不是给人挑的选项。档位只决定遮完之后还要不要再问／再判／整段拦掉。
import { DETECTOR_SHAPES } from './sensitive.js';

export const RULE_ACTIONS = ['release', 'ai', 'ask', 'deny'];
export const RULE_OPS = ['read', 'write', 'delete', 'all'];
/**
 * 内置行清单：判定链里每一条「代码自己会拉高」的理由，在这里就是一行，默认档位是它
 * 今天实际的行为。它们与用户行同表同形制，**全部可改**：改档位、停用都可以。
 *
 * `match` 是给人看的说明，不是匹配式——这些行的命中由 `grant.js` 的事实判断给出，
 * 所以页面上编辑的是档位与开关，不是那串描述（这一点在页面上也要写清，不让人误以为
 * 改了字就能改命中范围）。
 */
export const FLOOR_ROWS = [
    { preset: 'credential-or-client-tree', plane: 'file', label: '凭据与客户端目录', action: 'ask', note: '~/.ssh ~/.gnupg ~/.aws ~/.azure ~/.kube ~/.git ~/.docker ~/.copilot ~/.dsh ~/.workbuddy ~/.qoder ＋ gcloud／azure 凭据子树' },
    { preset: 'credential-material', plane: 'file', label: '凭据文件名', action: 'ask', note: '.env *.pem *.key *.p12 *.kdbx id_ed25519 *token* *password* *secret* .netrc .npmrc .gitconfig .mcp.json' },
    { preset: 'os-critical-tree', plane: 'file', label: '系统关键目录', action: 'ask', note: 'C:\\Windows C:\\Program Files C:\\ProgramData C:\\Boot /etc /usr /bin /sbin /lib /var /opt' },
    { preset: 'filesystem-root', plane: 'file', label: '盘根／POSIX 根', action: 'ask', note: '任何改动盘根或 / 的动作' },
    { preset: 'home-root', plane: 'file', label: '家目录本身', action: 'ask', note: '~ 这一层被改动' },
    { preset: 'workspace-root', plane: 'file', label: '当前工作区根', action: 'ask', note: '工作目录本身被改动' },
    { preset: 'harness-state-tree', plane: 'file', label: '宿主状态树', action: 'ask', note: '~/.dsh/**（允许行按子目录开过口的除外）' },
    { preset: 'unresolved-path', plane: 'file', label: '路径解析不出来', action: 'ask', note: '目标算不出绝对路径，看不见落在哪' },
    { preset: 'unresolvable-operand', plane: 'file', label: '操作数是动态的', action: 'ask', note: '$(…)／变量展开出来的目标，事实层读不到' },
    { preset: 'path-outside-trusted-roots', plane: 'file', label: '落在信任区之外', action: 'ask', note: '改动的工作区外目标' },
    { preset: 'symlink-operand', plane: 'file', label: '目标是符号链接', action: 'ask', note: '链接指向哪儿不确定' },
    { preset: 'delete-of-non-file', plane: 'file', label: '删的不是普通文件', action: 'ask', note: '目录、符号链接、设备节点' },
    { preset: 'unrecoverable-content', plane: 'file', label: '内容没有第二份副本', action: 'ask', note: '非空＋git 未跟踪＋不在信任区' },
    { preset: 'batch-too-large', plane: 'file', label: '一次动得太多', action: 'ask', note: '删除目标超过 20 个，或事实层被截断' },
    { preset: 'elevated-operation:destroy', plane: 'command', label: '不可逆销毁', action: 'ask', note: 'shred dd mkfs fdisk wipefs format cipher' },
    { preset: 'elevated-operation:privilege', plane: 'command', label: '提权执行', action: 'ask', note: 'sudo runas chmod chown cacls icacls reg netsh sc takeown' },
    { preset: 'elevated-operation:history-rewrite', plane: 'command', label: '改写或丢弃历史', action: 'ask', note: 'git push --force ／ reset --hard ／ clean ／ restore' },
    { preset: 'recursive-delete', plane: 'command', label: '递归删除标志', action: 'ask', note: 'rm -r…' },
    { preset: 'unrecognized-delete-flag', plane: 'command', label: '框架解释不了的删除参数', action: 'ask', note: '如 --files0-from（真实操作数集合看不见）' },
    { preset: 'opaque-command', plane: 'command', label: '命令看不懂', action: 'ask', note: '子 shell／eval／管道尾巴解析不出来' },
    { preset: 'unclassified-tool', plane: 'tool', label: '认不出操作类型的工具', action: 'ask', note: '非 shell 且框架无法归类（含 MCP 工具）' },
];

export const FLOOR_BY_PRESET = new Map(FLOOR_ROWS.map(row => [row.preset, row]));

export const RULE_PLANES = ['command', 'file', 'network', 'tool', 'sensitive'];

/**
 * 某个平面的**唯一一张表**：内置行＋用户自己的行。
 * 同 `preset` 的用户行覆盖内置行（档位、开关都听用户的）；没有用户行的内置项按默认档出现。
 * `enabled:false` ＝这一条不再拉高（不删行也能关）。
 * 敏感面自己有一张表（内置形状也在里面），直接复用它。
 */
export function effectiveRows(config, plane) {
    if (plane === 'sensitive')
        return sensitiveRows(config);
    const stored = parseRules(config?.[`${plane}Rules`], plane);
    const overrides = new Map(stored.filter(row => row.preset !== '').map(row => [row.preset, row]));
    const builtins = FLOOR_ROWS.filter(row => row.plane === plane)
        .map((row) => {
            const own = overrides.get(row.preset);
            if (own !== undefined)
                return own;
            return {
                id: `builtin-${row.preset}`, plane, preset: row.preset, label: row.label,
                action: row.action, enabled: true, match: row.note, regex: undefined,
            };
        });
    return [...stored.filter(row => row.preset === ''), ...builtins];
}

/** 内置行的当前档位：`grant.js` 用它决定「这条理由还拉不拉高」。 */
export function floorActions(config) {
    const out = new Map();
    for (const row of FLOOR_ROWS) {
        const merged = effectiveRows(config, row.plane).find(item => item.preset === row.preset);
        out.set(row.preset, merged === undefined || merged.enabled === false ? 'off' : merged.action);
    }
    return out;
}

// Which segment op classes a rule op covers. `exec`/`other` count as a write:
// an unclassified state change must not slip through a "read" row.
const OP_CLASSES = {
    read: new Set(['read']),
    write: new Set(['write', 'rename', 'exec', 'privilege', 'history-rewrite', 'other']),
    delete: new Set(['delete', 'destroy']),
};

// 取最严的那一档：拒绝 > 人工 > 交 AI > 直接放行。
// 「直接放行」压在最后＝任何一行不同意都放不了；它是**真放行**（人自己拍的板）。
// 强弱序只有一处定义：RULE_ACTIONS 的顺序就是强弱顺序（弱 → 强），下面按它算权重。
const STRICTNESS = Object.fromEntries(RULE_ACTIONS.map((action, index) => [action, index + 1]));
const URL_PATTERN = /\bhttps?:\/\/[^\s"'`)]+/gi;

// 词表：旧的 `allow`（本层不拦、继续交 AI）折进 `ai`，`ask` 现在读作「人工」。
// 「放行」这两个字从 allow 挪到 release——用户说的「允许就是直接放行」就是这个意思。
export const ACTION_WORDS = {
    release: ['release', 'permit', '允许', '直接放行', '放行'],
    ai: ['ai', 'allow', '模型', '交ai', '评审'],
    // `redact` 是旧配置里的第四档，已删：命中就遮不是选项，折回「人工」。
    ask: ['ask', 'human', 'confirm', 'redact', '人工', '询问', '确认'],
    deny: ['deny', 'block', '拒绝', '拦截', '禁止'],
};

const OP_WORDS = {
    read: ['read', 'r', '读取', '读'],
    write: ['write', 'w', '写入', '写'],
    delete: ['delete', 'del', 'd', '删除', '删'],
    all: ['all', '*', '全部'],
};

export const OP_LABEL = { read: '读取', write: '写入', delete: '删除' };

function word(value, table) {
    const text = String(value ?? '').trim().toLowerCase();
    for (const [canonical, words] of Object.entries(table))
        if (words.includes(text))
            return canonical;
    return undefined;
}

/** `deny rm -rf` / `ask curl` / `allow ~/.dsh/skills/`; `re:` marks a raw regex. */
function legacyRow(raw) {
    const text = String(raw ?? '').trim();
    if (text === '' || text.startsWith('#'))
        return undefined;
    const match = /^([A-Za-z\u4e00-\u9fff]+)\s+(.+)$/.exec(text);
    if (match === null)
        return undefined;
    const action = word(match[1], ACTION_WORDS);
    if (action === undefined)
        return undefined;
    return { action, match: match[2].trim() };
}

let rowSeq = 0;

export const FILE_OPS = ['read', 'write', 'delete'];

/**
 * One stored row.
 *
 * A file row carries an action **per operation** (`read`/`write`/`delete`, empty
 * = 不表态), which is what the operator actually decides: this tree may be read
 * but never deleted. The older `{action, ops}` shape and `deny <pattern>` strings
 * both fold into it. Every other plane has one action per row.
 */
export function toRule(raw, plane) {
    const source = typeof raw === 'string' ? legacyRow(raw) : raw;
    const preset = String(source?.preset ?? '');
    const pattern = String(source?.match ?? source?.pattern ?? '').trim();
    // 内置行的覆盖只带档位与开关：它的匹配由 `grant.js` 的事实判断给出，
    // 所以它**没有匹配式**，也绝不被当匹配式用（否则那串说明文字会变成一条模式）。
    if (pattern === '' && preset === '')
        return undefined;
    if (preset !== '' && pattern === '')
        return {
            id: String(source?.id ?? `builtin-${preset}`),
            plane, preset, label: String(source?.label ?? ''),
            action: word(source?.action, ACTION_WORDS) ?? FLOOR_BY_PRESET.get(preset)?.action ?? 'ask',
            match: '', regex: undefined,
            enabled: source?.enabled !== false,
        };
    const id = String(source?.id ?? `rule-${plane}-${rowSeq += 1}`);
    const regex = pattern.startsWith('re:') ? compile(pattern.slice(3)) : undefined;
    if (plane !== 'file') {
        const action = word(source?.action, ACTION_WORDS);
        if (action === undefined)
            return undefined;
        // `preset` 非空＝这一行是内置项的用户副本（换档位／关掉它）；
        // `enabled:false` 只是这一行不表态——不删行也能关。
        return {
            id, plane, action, match: pattern, regex,
            preset,
            label: String(source?.label ?? ''),
            enabled: source?.enabled !== false,
        };
    }
    const legacyAction = word(source?.action, ACTION_WORDS);
    const legacyOps = Array.isArray(source?.ops) && source.ops.length > 0
        ? [...new Set(source.ops.map(item => word(item, OP_WORDS)).filter(Boolean))]
        : null;
    const row = {
        id, plane, match: pattern, regex,
        preset, label: String(source?.label ?? ''), enabled: source?.enabled !== false,
    };
    for (const op of FILE_OPS) {
        const explicit = word(source?.[op], ACTION_WORDS) ?? '';
        const folded = legacyAction !== undefined
            && (legacyOps === null || legacyOps.includes('all') || legacyOps.includes(op))
            ? legacyAction
            : '';
        row[op] = explicit !== '' ? explicit : folded;
    }
    return FILE_OPS.some(op => row[op] !== '') ? row : undefined;
}

export function parseRules(list, plane) {
    const out = [];
    for (const raw of Array.isArray(list) ? list : []) {
        const rule = toRule(raw, plane);
        if (rule !== undefined)
            out.push(rule);
    }
    return out;
}

function compile(source) {
    try {
        return new RegExp(source, 'i');
    }
    catch {
        return undefined;
    }
}

function globToRegex(glob) {
    let out = '';
    for (let index = 0; index < glob.length; index += 1) {
        const char = glob[index];
        if (char === '*') {
            if (glob[index + 1] === '*') {
                out += '.*';
                index += 1;
            }
            else
                out += '[^/]*';
        }
        else if (char === '?')
            out += '.';
        else
            out += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp(`^${out}$`, 'i');
}

const isGlob = pattern => pattern.includes('*') || pattern.includes('?');
const slashes = text => String(text ?? '').replaceAll('\\', '/');

/** Text matcher shared by the tool, network and sensitive planes. */
function matchText(rule, value) {
    const text = slashes(value);
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(text);
    const pattern = slashes(rule.match);
    // 空模式不是「匹配一切」：只有档位、没有条件的行（内置覆盖行）不该命中任何文本，
    // 否则清空一次条件输入就会把整段结果都算成敏感。
    if (pattern === '')
        return false;
    if (pattern === '*')
        return true;
    if (isGlob(pattern))
        return globToRegex(pattern).test(text);
    return text.toLowerCase() === pattern.toLowerCase()
        || text.toLowerCase().includes(pattern.toLowerCase());
}

/**
 * 敏感平面的**唯一一张表**：内置形状＋用户自己的行。
 * 内置形状不是硬编码的第二套检测——它铺成行，用户改的就是同一行（同 `preset` 的行
 * 覆盖内置行），关掉它就是把那一行 `enabled:false`。`sensitiveDetect` 是卡头总闸。
 */
export function sensitiveRows(config) {
    if (config?.sensitiveDetect === false)
        return [];
    const stored = parseRules(config?.sensitiveRules, 'sensitive');
    const overrides = new Map(stored.filter(row => row.preset !== '').map(row => [row.preset, row]));
    const builtins = DETECTOR_SHAPES.map((shape) => {
        const own = overrides.get(shape.id);
        if (own !== undefined)
            return own;
        return {
            id: `builtin-${shape.id}`, plane: 'sensitive', preset: shape.id, label: shape.label,
            action: 'ask', enabled: true, match: `re:${shape.source}`, regex: compile(shape.source),
        };
    });
    return [...stored.filter(row => row.preset === ''), ...builtins];
}

/**
 * 一行在一段文本里命中的所有区间。
 * 定位不到就不遮：通配行（`pass*`）与 `*` 表达的是「这段文本算敏感」，不是「哪一段」，
 * 拿整条结果去铸 token 等于毁掉整条输出——所以这类行只参与 拒绝/询问/允许。
 */
function matchRanges(rule, value) {
    const text = String(value ?? '');
    if (text === '')
        return [];
    if (rule.regex !== undefined) {
        const flags = rule.regex.flags.includes('g') ? rule.regex.flags : `${rule.regex.flags}g`;
        const re = new RegExp(rule.regex.source, flags);
        const out = [];
        let found;
        while ((found = re.exec(text)) !== null) {
            if (found[0] === '') {
                re.lastIndex += 1;
                continue;
            }
            out.push([found.index, found.index + found[0].length]);
        }
        return out;
    }
    const pattern = String(rule.match ?? '');
    if (pattern === '' || pattern === '*' || isGlob(pattern))
        return [];
    const hay = text.toLowerCase();
    const needle = pattern.toLowerCase();
    const out = [];
    for (let index = hay.indexOf(needle); index !== -1; index = hay.indexOf(needle, index + needle.length))
        out.push([index, index + needle.length]);
    return out;
}

/**
 * 扫一段文本（结果侧用它决定遮哪些、出参侧用它决定拦不拦）。
 * 动作取最严：任一 `deny` 命中就整段不给模型；否则按 ask／ai／release 排。
 * **所有档位都先遮**——遮是这一层自己的事，不是选项：命中就换成占位符，
 * 档位只决定遮完之后还要不要再问／再判／整段拦掉。
 * `ranges` 是所有档位的命中区间（`{from,to,label,detector}`，重叠只留先命中的
 * 那一行，且已按起点降序——替换用它做）。
 */
export function scanSensitive(text, rows) {
    const hits = [];
    for (const row of rows) {
        if (row.enabled === false)
            continue;
        const ranges = matchRanges(row, text);
        if (ranges.length > 0 || matchText(row, text))
            hits.push({ row, ranges });
    }
    if (hits.length === 0)
        return { action: '', hits: [], ranges: [] };
    let action = 'release';
    for (const hit of hits)
        if (STRICTNESS[hit.row.action] > STRICTNESS[action])
            action = hit.row.action;
    const merged = [];
    // 命中就遮：任何一档（含「允许」）都先遮；只有拒绝那一档由处置侧整段拦掉，遮不遮已无意义。
    for (const hit of hits) {
        if (hit.row.enabled === false)
            continue;
        for (const [from, to] of hit.ranges) {
            if (merged.some(range => from < range.to && range.from < to))
                continue;
            merged.push({
                from, to,
                detector: hit.row.preset || hit.row.id,
                label: hit.row.label || hit.row.preset || hit.row.match,
            });
        }
    }
    merged.sort((a, b) => b.from - a.from);
    return { action, hits, ranges: merged, rules: [...new Set(hits.map(hit => hit.row.id))] };
}

function programName(text) {
    const base = slashes(String(text ?? '')).split('/').filter(Boolean).pop() ?? '';
    return base.toLowerCase().replace(/\.exe$/, '');
}

/** `git push` matches `git push origin main`, not `git pull`. */
export function matchCommand(rule, segment) {
    const text = slashes(segment?.program ?? '');
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test([segment.program, ...(segment.words ?? [])].join(' '));
    const tokens = rule.match.split(/\s+/).filter(Boolean);
    if (programName(tokens[0]) !== programName(segment.program))
        return false;
    const words = (segment.words ?? []).map(String);
    for (let index = 1; index < tokens.length; index += 1) {
        const want = tokens[index];
        const got = words[index - 1];
        if (got === undefined)
            return false;
        if (want === '*')
            continue;
        if (want !== got && !(isGlob(want) && globToRegex(want).test(got)))
            return false;
    }
    return true;
}

/** Which file operation a segment class falls under (undefined = none). */
export function opOf(opClass) {
    for (const op of FILE_OPS)
        if (OP_CLASSES[op].has(String(opClass)))
            return op;
    return undefined;
}

/** The action this row takes on one operation; `''` = 这一行对它不表态。 */
export function actionFor(rule, opClass) {
    const op = opOf(opClass);
    if (op === undefined)
        return '';
    return rule?.[op] !== undefined && rule[op] !== '' ? rule[op] : '';
}

function pathMatches(rule, path) {
    const target = slashes(path);
    if (target === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(target);
    const pattern = slashes(rule.match);
    if (pattern === '*')
        return true;
    if (isGlob(pattern))
        return globToRegex(pattern).test(target);
    const trimmed = pattern.replace(/\/+$/, '');
    return target.toLowerCase() === trimmed.toLowerCase()
        || target.toLowerCase().startsWith(`${trimmed.toLowerCase()}/`);
}

/** Path matcher used by the trust floor: does this row excuse `opClass` here? */
export function matchPath(rule, path, opClass) {
    return pathMatches(rule, path) && actionFor(rule, opClass) !== '';
}

function matchHost(rule, value) {
    const text = String(value ?? '').toLowerCase();
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(text);
    const pattern = rule.match.toLowerCase().replace(/^\*\./, '.');
    if (pattern === '*' || pattern === 'http://' || pattern === 'https://')
        return true;
    const bare = text.replace(/^https?:\/\//, '').split('/')[0];
    if (isGlob(rule.match))
        return globToRegex(rule.match).test(bare) || globToRegex(rule.match).test(text);
    return bare === pattern || bare.endsWith(`.${pattern}`);
}

function matchTool(rule, toolName) {
    return matchText(rule, toolName);
}

/** URLs and bare hosts mentioned by the action, for the network plane. */
export function networkTargets(command) {
    const text = typeof command === 'string' ? command : '';
    const urls = text.match(URL_PATTERN) ?? [];
    const hosts = [];
    for (const url of urls) {
        try {
            hosts.push(new URL(url).hostname);
        }
        catch {
            // A malformed URL still matched the plane's text pattern below.
        }
    }
    return [...new Set([...urls, ...hosts])];
}

function firstHit(rules, test) {
    for (const rule of rules)
        if (rule.enabled !== false && test(rule))
            return rule;
    return undefined;
}

function planeHit(plane, rules, test) {
    const rule = firstHit(rules, test);
    return rule === undefined
        ? undefined
        : { plane, action: rule.action, rule: rule.match, text: `${rule.action} ${rule.match}` };
}

/**
 * Evaluate every plane over one action. `segments` and `targets` come from the
 * fact layer (targets carry `path` and `opClass`); `urls` are optional.
 */
export function evaluatePolicies({ toolName, command, segments, targets, urls, config }) {
    const hits = [];
    const toolRules = parseRules(config?.toolRules, 'tool');
    hits.push(planeHit('tool', toolRules, rule => matchTool(rule, toolName)));

    const commandRules = parseRules(config?.commandRules, 'command');
    const segmentList = Array.isArray(segments) && segments.length > 0
        ? segments
        : [{ program: String(command ?? '').split(/\s+/)[0] ?? '', words: String(command ?? '').split(/\s+/).slice(1) }];
    hits.push(planeHit('command', commandRules, rule => command !== undefined && rule.regex !== undefined
        ? rule.regex.test(String(command))
        : segmentList.some(segment => matchCommand(rule, segment))));

    const fileRules = parseRules(config?.fileRules, 'file');
    const targetList = (Array.isArray(targets) ? targets : [])
        .filter(target => target !== undefined && target !== null)
        .map(target => typeof target === 'string' ? { path: target, opClass: 'other' } : target);
    // 每个目标各自由「第一条对它这个操作表态的行」决定；行对别的操作沉默不算命中，
    // 所以 `~/.dsh/skills` 只开读取，不会把后面那条禁止删除同一目录的行盖掉。
    for (const target of targetList) {
        if (target.dynamic === true)
            continue;
        const hit = firstHit(fileRules, rule => pathMatches(rule, target.path ?? target.input)
            && actionFor(rule, target.opClass) !== '');
        if (hit === undefined)
            continue;
        const op = opOf(target.opClass);
        hits.push({
            plane: 'file',
            action: hit[op],
            rule: hit.match,
            text: `${OP_LABEL[op]}·${hit[op]} ${hit.match}`,
        });
    }

    const hosts = Array.isArray(urls) && urls.length > 0 ? urls : networkTargets(command);
    const networkRules = parseRules(config?.networkRules, 'network');
    hits.push(planeHit('network', networkRules, rule => hosts.some(host => matchHost(rule, host))));

    const sensitiveText = [String(command ?? ''), ...targetList.map(target => String(target.path ?? target.input ?? ''))].join(' ');
    // 出参侧改不了命令本身（宿主禁止插件改写参数），所以这一侧的遮只发生在结果上；
    // 档位照常参与取最严。
    const sensitiveScan = scanSensitive(sensitiveText, sensitiveRows(config));
    if (sensitiveScan.action !== '') {
        const names = [...new Set(sensitiveScan.hits.map(hit => hit.row.label || hit.row.preset || hit.row.match))];
        hits.push({
            plane: 'sensitive',
            action: sensitiveScan.action,
            rule: names.join('、'),
            text: `敏感：${names.join('、')}`,
            detectors: sensitiveScan.hits.map(hit => hit.row.preset || hit.row.id),
        });
    }

    // Strictest plane wins: a `deny` elsewhere is not cancelled by an `allow`.
    let best;
    for (const hit of hits.filter(Boolean)) {
        if (best === undefined || STRICTNESS[hit.action] > STRICTNESS[best.action])
            best = hit;
    }
    return best === undefined
        ? { decision: 'pass', plane: null, rule: null, sensitiveHits: [], hits }
        : {
            decision: best.action, plane: best.plane, rule: best.text, hit: best,
            sensitiveHits: hits.find(hit => hit?.plane === 'sensitive')?.detectors ?? [], hits,
        };
}

/** Rows that declare trust: a file row that does not stop this operation (gate.js reads these). */
export function trustRules(config) {
    const out = [];
    for (const rule of parseRules(config?.fileRules, 'file')) {
        if (rule.enabled === false)
            continue;
        // 旧的 `allow` 现在折进 `ai`；`release`（允许＝直接放行）同样声明信任。
        const allowed = FILE_OPS.filter(op => rule[op] === 'ai' || rule[op] === 'release');
        if (allowed.length === 0)
            continue;
        const entry = { ...rule };
        for (const op of FILE_OPS)
            if (!allowed.includes(op))
                entry[op] = '';
        out.push(entry);
    }
    return out;
}

