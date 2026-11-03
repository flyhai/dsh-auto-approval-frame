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

/** * Shape guard for an `allow` row that is being used as a trust root. Rows under
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
        // 用户显式文件行是「已点名」的第二路来源；这里只带原始表，解析留给
        // 需要它的那一层（facts.js 按同一把 parseRules 解，不另造一套匹配语义）。
        fileRules: config?.fileRules,
        // 源根搜索的补充目录（出厂空＝今天的扫描面逐字不变）；解析在 facts.js。
        sourceRootDirs: config?.sourceRootDirs,
    };
}

/** The durable raw permission identity, never the folded current. */
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

// 语气不是授权。旧形把「只骂人、不带限制词」的句子整句降成非授权背景——于是一句
// 带情绪的有效指令（「你他妈倒是把这个文件改完」）被抹掉授权效力（A09）。
// 现在语气只做**标注**（`tone`），它不进授权判定；授权与否只看这句话本身说了什么。
const TONE_PATTERN = /(傻[逼叉子屄]|蠢货|蠢材|白痴|废物|脑子有病|有病|去死|滚开|他妈|妈的|妈了个|狗屎|智障|fuck|shit|stupid|idiot|dumb|useless|damn|wtf)/i;

// 明确否令：无论语气如何都要保留成排除项（A09 判据 2）。中西两套写法都收。
const EXCLUDE_PATTERN = /(不许|不准|不要|不能|禁止|严禁|不得|别再|先别|别写|别动|别碰|勿动|只做|只改|仅限|DO NOT|DON'T|don'?t|never|must not|avoid|no changes to)/i;
// 撤销：让此前某项授权作废的那一句。最新一句撤销要单独能查。
const REVOKE_PATTERN = /(取消|撤回|撤销|作废|停手|停下|算了|不做了|别做了|cancel|revoke|abort|revert that)/i;
// 「继续」不新开范围：它承接前一条实质指令，本身既不扩大也不缩小授权（A09）。
const CONTINUE_PATTERN = /^(继续|接着|往下|下一步|照做|就这么办|go on|continue|proceed|carry on)/i;

// 「允许的附属操作」＝这句话点到的动作类。它只是**取词**，不是判据：
// 表里没有的词就不表态，由模型按上下文判，不拿词表当授权边界。
const ALLOW_VERBS = [
    ['delete', /(删|移除|清掉|清空|remove|delete)/i],
    ['write', /(改|编辑|写入|新增|补上|修复|创建|生成|提交|commit|write|edit|create)/i],
    ['run', /(跑|执行|运行|测试|构建|安装|启动|test|build|install|run)/i],
    ['read', /(读|看|查|搜|检索|打开|cat |grep |read|search|inspect)/i],
    ['publish', /(推|推送|发布|发版|push|publish|deploy)/i],
];
const PATHISH = /(?:[A-Za-z]:[\\/][^\s"'，。；、）]+|\/[\w.-]+(?:\/[\w.-]+)+|~\/[\w.-]+|[\w.-]+\.(?:js|mjs|cjs|ts|json|md|txt|py|yml|yaml|ps1|sh|mjs))/g;
// 裸名候选（「这个原项目在workbuddy」只有名字、没有路径形状）。这里只做**抽取**，
// 不碰 IO——名字能不能解析成目录由事实层按有界 readdir 做（facts.js），解析不出唯一目录就不绑。
const BARE_NAME = /[A-Za-z][A-Za-z0-9_-]{2,}/g;

function bareNamesOf(text) {
    const value = String(text ?? '');
    const spans = [];
    for (const match of value.matchAll(PATHISH)) {
        const start = match.index ?? 0;
        spans.push([start, start + match[0].length]);
    }
    const out = [];
    for (const match of value.matchAll(BARE_NAME)) {
        const start = match.index ?? 0;
        const end = start + match[0].length;
        // 已经落在 PATHISH 命中里的词不再当裸名：那条路径已经整条进了 resources。
        if (spans.some(([from, to]) => start < to && end > from))
            continue;
        out.push(match[0]);
    }
    return [...new Set(out)].slice(0, 20);
}

function allowsOf(text) {
    const value = String(text ?? '');
    return ALLOW_VERBS.filter(([, re]) => re.test(value)).map(([name]) => name);
}

function resourcesOf(text) {
    return [...new Set(String(text ?? '').match(PATHISH) ?? [])].slice(0, 20);
}

/** 按句切分，收带禁止词的句子（原话照录，不改写成「已禁止」）。 */
function excludesOf(text) {
    return String(text ?? '')
        .split(/[。；;!！?？\n]/)
        .map(line => line.trim())
        .filter(line => line !== '' && EXCLUDE_PATTERN.test(line))
        .slice(0, 6);
}

/** * 授权里点名的**发布目标**：「允许推 origin/main」「发布到 ghcr.io」这类话
 * 要能落到「远端 + 分支」两格，否则 exfil 行只能一律问人。
 */
function publishTargetsOf(text) {
    const out = [];
    const re = /(?:git\s+push|push|推送|推到|推|发布到|发布)\s+([^\s，。；、,]+)(?:\s+([^\s，。；、,]+))?/gi;
    let matched;
    while ((matched = re.exec(String(text ?? ''))) !== null) {
        const first = matched[1] ?? '';
        if (first === '' || first.startsWith('-'))
            continue;
        const parts = first.split('/');
        const remote = parts[0].toLowerCase();
        const branch = (parts.length > 1 ? parts.slice(1).join('/')
            : (matched[2] !== undefined && !matched[2].startsWith('-') ? matched[2] : '')).toLowerCase();
        out.push({ remote, branch });
    }
    return out;
}

/** 一句话的五格：目的／允许的附属操作／目标资源／排除项／是否撤销＋语气与承接标注。 */
function intentShape(text) {
    const value = String(text ?? '');
    const continuation = CONTINUE_PATTERN.test(value.trim());
    const revoke = REVOKE_PATTERN.test(value);
    return {
        tone: TONE_PATTERN.test(value) ? 'heated' : 'neutral',
        continuation,
        revoke,
        // 承接句与撤销句没有独立的「目的」——它们的意义挂在前一条上。
        purpose: continuation || revoke ? '' : sanitizeText(value, 300),
        allows: continuation || revoke ? [] : allowsOf(value),
        resources: resourcesOf(value),
        // 裸名与路径资源同一时间轴，撤销句不新开范围。
        bareNames: continuation || revoke ? [] : bareNamesOf(value),
        excludes: excludesOf(value),
        publish: continuation || revoke ? [] : publishTargetsOf(value),
    };
}

/** * What the user actually asked for, newest first: session events plus anything
 * still sitting in the agent inbox (steered prompts arrive after the last
 * event). Plugin-injected messages are never authorization evidence.
 *
 * Each entry carries an `authorizing` class. A line whose class is `background`
 * must never reach the reviewer as authorization — evidence.js enforces that by
 * routing it into the non-authorizing block.
 */
/** * 判据 6（B03）：**谁说的话能当授权**。当前只有「用户自己打的字」算。
 * 这个集合是给将来留的结构位：宿主的「计划批准」若要被认可，先把它的来源登记进来，
 * 再由 `userIntents` 收——`tool/result` 里的 `answers`（工具回传的问答记录）永远不在其中，
 * 它是**结果**，不是批准；远端工具可以伪造它。
 */
export const AUTHORIZING_SOURCES = new Set(['user']);

export function authorizingClassOf(source) {
    const kind = String(source?.kind ?? '');
    return AUTHORIZING_SOURCES.has(kind) ? 'authorizing' : 'background';
}

export function userIntents(authority, { maxMessages = 8, budget = 6_000 } = {}) {
    const found = [];
    const events = typeof authority?.session?.snapshotEvents === 'function' ? authority.session.snapshotEvents() : [];
    for (let index = (events?.length ?? 0) - 1; index >= 0 && found.length < maxMessages; index -= 1) {
        const event = events[index];
        if (event?.type !== 'user/message' || event.data?.source?.kind !== 'user')
            continue;
        const text = String(textOf(event.data.content) ?? '').trim();
        if (text !== '')
            found.push({
                seq: index, origin: 'user-message', text: sanitizeText(text, 1_500),
                // 语气只标注；授权效力不因脏话改变（A09）。分类由来源决定，不由措辞决定。
                authorizing: authorizingClassOf(event.data?.source), ...intentShape(text),
            });
    }
    const inbox = authority?.inbox;
    for (const [at, batch] of [...(inbox?.nextStep ?? []), ...(inbox?.nextTurn ?? [])].entries()) {
        const message = Array.isArray(batch) ? batch[0] : batch;
        if (message?.source?.kind !== 'user')
            continue;
        const text = String(textOf(message.content) ?? '').trim();
        if (text !== '')
            // 事件流之后到达的转向消息＝比任何事件都新，序号要接在事件后面（F11）。
            found.push({
                seq: (events?.length ?? 0) + at, origin: 'inbox', text: sanitizeText(text, 1_500),
                authorizing: authorizingClassOf(message?.source), ...intentShape(text),
            });
    }
    let used = 0;
    const admitted = [];
    // 单一时间轴：按 seq 从新到旧取，预算不够时**先丢最旧的**——
    // 过去是先排好"新→旧"再整体 reverse，于是排在末尾的 inbox 反而变成最旧，
    // 用户最新那句叫停的话正好是被裁掉的那条。
    for (const intent of found.sort((a, b) => b.seq - a.seq)) {
        if (used + intent.text.length > budget)
            break;
        used += intent.text.length;
        admitted.push(intent);
    }
    return admitted.reverse();
}

/** * 把逐条意图汇总成一份任务授权（A09 五格）：目的／允许的附属操作／目标资源／
 * 排除项／最新撤销。列表按「旧→新」，所以反向找＝最新一句。
 * 明确否令**累计保留**（任何语气都算），只有用户自己说撤销才作废。
 */
export function authorizationOf(intents = [], { consumed = [] } = {}) {
    const list = Array.isArray(intents) ? intents : [];
    const newest = [...list].reverse();
    const purpose = newest.find(intent => intent.continuation !== true && intent.revoke !== true
        && String(intent.purpose ?? '') !== '');
    const latestRevoke = newest.find(intent => intent.revoke === true && String(intent.text ?? '') !== '');
    // 判据 2：撤销的**时序位置**。`list` 是旧→新，取最后一条撤销句的下标；
    // 撤销之前签出去的发布授权当场作废，只有它之后再明确说一遍才恢复。
    // 消费方（grant.js 的 publishAuthorized）按 `entry.seq > revokeSeq` 判——不看台账、不看模型。
    let revokeSeq = -1;
    list.forEach((intent, index) => {
        if (intent.revoke === true && String(intent.text ?? '') !== '')
            revokeSeq = index;
    });
    const postRevokePublish = list
        .map((intent, index) => ({ intent, index }))
        .filter(({ intent, index }) => index > revokeSeq && intent.revoke !== true)
        .flatMap(({ intent, index }) => (intent.publish ?? []).map(target => ({ ...target, seq: index })));
    // 裸名同样只认**最后一次撤销之后**的句子——说了撤销，此前点过的名当场失效。
    const bareNames = [...new Set(list
        .map((intent, index) => ({ intent, index }))
        .filter(({ intent, index }) => index > revokeSeq && intent.revoke !== true)
        .flatMap(({ intent }) => intent.bareNames ?? []))].slice(0, 20);
    // 判据 3：已经成功用过的「远端＋分支」不再授权。记账在调用方（谁执行谁记），
    // 这里只按传入的集合过滤，保持本函数是纯函数、可复算。
    const usedKeys = new Set(consumed.map(row => (typeof row === 'string'
        ? row : `${row?.remote ?? ''}|${row?.branch ?? ''}`)));
    const freshPublish = postRevokePublish
        .filter(target => usedKeys.has(`${target.remote}|${target.branch}`) === false);
    return {
        purpose: purpose?.purpose ?? '',
        allows: [...new Set(list.flatMap(intent => intent.allows ?? []))],
        resources: [...new Set(list.flatMap(intent => intent.resources ?? []))].slice(0, 20),
        // 消息里的裸名（没有路径形状的名字）——事实层据此解析唯一存在的目录。
        bareNames,
        excludes: [...new Set(list.flatMap(intent => intent.excludes ?? []))],
        // 发布目标：同一远端＋分支只留一格（后来的覆盖先前的）；每条带 `seq` 供消费方对齐撤销位置。
        publish: [...new Map(freshPublish
            .map(target => [`${target.remote}|${target.branch}`, target])).values()],
        latestRevoke: latestRevoke?.text ?? '',
        // -1＝这一串意图里没有撤销句，所有发布授权照旧有效。
        revokeSeq,
        continuations: list.filter(intent => intent.continuation === true).length,
    };
}

export function sessionModelLabel(session) {
    const config = typeof session?.requestHeader === 'function' ? session.requestHeader()?.config : undefined;
    return config?.provider !== undefined ? `${config.provider}/${config.model}` : 'unknown';
}
