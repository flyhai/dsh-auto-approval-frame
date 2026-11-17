// Text hygiene for anything that travels into a model prompt.
// 形状表只有一份（`sensitive.js`）：结果侧与台账侧必须遮同样的东西，否则台账这条
// 就成了更窄的那一面——写进哈希链的明文永远无法追回。
import { DETECTOR_SHAPES } from './sensitive.js';
import { highEntropyRanges } from './entropy.js';

const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/g;

/** Strip control characters, collapse absurd whitespace runs, hard-cap length. */
export function sanitizeText(input, maxChars = 4_000) {
    const text = String(input ?? '').replace(CONTROL, ' ').replace(/\n{3,}/g, '\n\n').trim();
    if (text.length <= maxChars)
        return text;
    return `${text.slice(0, maxChars)}\n…[truncated]`;
}

/** * Never let a path or command leak a token-shaped substring into the log.
 * 顺序是判据的一部分：先按「赋值」与 `sk-` 遮（这两条留下键名，页面才看得出遮了什么），
 * 再铺形状表——否则 `Bearer sk-xxx` 会被 bearer 形状整段吞掉，台账里连 `sk-***` 都不剩。
 */
const SHAPES = DETECTOR_SHAPES.map(shape => ({
    id: shape.id, keyed: shape.keyed === true, keep: shape.keep ?? 0,
    valueOnly: shape.valueOnly === true,
    re: new RegExp(shape.source, 'gi'),
}));

/** * 台账侧不再有第二张私有正则表。旧版这里有三条自写正则（authorization／通用赋值／
 * `sk-`），与 `DETECTOR_SHAPES` 各管一段——结果侧改了形状、台账侧忘记跟，漏遮就是这么来的。
 * 现在：赋值族（含复合键名）与 `sk-` 都走同一张表，渲染规则只有三条：
 * - `keyed`：留下「键名＋分隔符」，值换成 `***`（页面看得出遮了什么）；
 * - `api-key` 的 `sk-` 短形沿用旧文案 `sk-***`（A08 的读数与断言都以它为准）；
 * - 其余：整段换成 `[已遮罩:id]`。
 * Authorization 是**唯一特例**：它的值允许带空格（`Bearer <token>`），与赋值形状的
 * 「值段不含空格」不是同一套语法，塞进表里会把 `Bearer` 之后的令牌漏在外面。
 */
const AUTHORIZATION = /\b((?:proxy-)?authorization)(["'\s:=]+)[^\r\n"'&,;]+/gi;

function renderShape(shape, match, groups) {
    if (shape.keyed)
        return `${groups.slice(0, shape.keep).join('')}***`;
    if (shape.id === 'api-key' && /^sk-/i.test(match))
        return 'sk-***';
    return `[已遮罩:${shape.id}]`;
}

/** * 用户敏感行的注入点（判据 5）：`redactSecrets` 是**同步纯替换**，被证据块、
 * 台账、verdict 规则行等静态形状出口共用——这些调用方有的拿不到 config（evidence.js、
 * verdict.js 本版禁碰），所以由入口在每次取到用户行时同步进来，静态出口因此与结果遮罩
 * 共用**同一张**用户表；不注入时行为与从前完全一致（只有预设形状）。
 * 测试用 `resetUserShapes` 还原，避免跨用例串味。
 */
let userShapes = [];
export function setUserShapes(rows) {
    userShapes = [];
    for (const row of Array.isArray(rows) ? rows : []) {
        if (row?.enabled === false)
            continue;
        const id = row?.preset || row?.id || 'user';
        if (row?.regex !== undefined) {
            userShapes.push({ id, re: new RegExp(row.regex.source, 'gi') });
            continue;
        }
        // 非 re: 的字面行（含 glob 去掉通配后的字面部分）在静态出口按「包含即遮」处理。
        const pattern = String(row?.match ?? '');
        if (pattern === '' || pattern === '*' || pattern.startsWith('re:'))
            continue;
        if (pattern.includes('*') || pattern.includes('?'))
            continue;
        const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        userShapes.push({ id, re: new RegExp(escaped, 'gi') });
    }
}
export function resetUserShapes() {
    userShapes = [];
}

export function redactSecrets(input) {
    let text = String(input ?? '')
        // Authorization 必须先遮：通用赋值规则会把 `Bearer` 当值先吃掉，真正的令牌
        // 无人认领（A08：`Authorization: Bearer AuditValue123` → `authorization: *** AuditValue123`）。
        .replace(AUTHORIZATION, '$1$2***');
    for (const shape of SHAPES)
        text = text.replace(shape.re, (...args) => {
            const match = args[0];
            const groups = args.slice(1, -2); // 去掉 offset 与整串入参
            return renderShape(shape, match, groups);
        });
    // 判据 5：用户自己的行与预设形状同台——证据块／台账／规则行不再「只认预设形状」。
    for (const shape of userShapes)
        text = text.replace(shape.re, `[已遮罩:${shape.id}]`);
    // 高熵令牌：台账侧**恒开**，与内置正则形状同口径（F10：总闸只关判定，结果脱敏照常）。
    // 行开关只影响结果侧——这条不对称是有意的：明文一旦写进哈希链台账就追不回。
    const entropy = highEntropyRanges(text);
    for (let index = entropy.length - 1; index >= 0; index -= 1) {
        const { from, to } = entropy[index];
        text = `${text.slice(0, from)}[已遮罩:high-entropy]${text.slice(to)}`;
    }
    return text;
}
