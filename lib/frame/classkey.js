// 补充｜类键：同一会话里同一「类」刚被人放行过 ⇒ 第二回合不再问（只抵「问」，不抵「拒」）。
// 四成分钉死＝工具｜本次真命中的规则行｜面集合（读／写／删）｜目标根类别；
// 会话与配置版本作界沿用 那两把键的口径，不在这里另立。
// 排除项（这些类一次放行只抵那一次动作，不许借给同类）＝删除／改名／区外（读写皆）／网络上行／
// 远端执行／进程／装包／提权／破坏族／历史改写／跨项目读／凭据形状／认不出的程序／目标抠不出／证据被裁。
import { createHash } from 'node:crypto';
import { opOf } from './policy.js';

/** 同一类键最多沿用几次，到帽回到问人。与 TTL／条数帽同形＝常量，不建配置键。 */
export const CLASS_REUSE_CAP = 8;

const INNER_ROOTS = new Set(['workspace', 'trusted', 'dsh-open']);
// `exec`／`other` 是「认不出的程序」：第 17 条已裁它不得按类复用；
// `privilege`／`history-rewrite`／`internal` 同族走硬闸，一次放行不许扩成类。
const EXCLUDED_OP_CLASSES = new Set(['delete', 'destroy', 'rename', 'exec', 'privilege', 'history-rewrite', 'internal', 'other']);
const EXCLUDED_EXEC_FAMILIES = new Set(['process', 'package']);
const EXCLUDED_REASON_PREFIXES = ['elevated:', 'destroy:', 'exfil:', 'credential-', 'remote-'];
// 文件面尾部 8 行条目撤出表、`grant.js` 也不再发那八条理由：这里跟着删掉七个死名字
// （路径解析不出来／操作数是动态的／目标是符号链接／删的不是普通文件／删的是可重建目录／
// 内容没有第二份副本／一次删得太多／事实层看不全）——留着就是"表里没这行、名单里还认它"。
const EXCLUDED_REASONS = new Set(['recursive-delete', 'unrecognized-delete-flag',
    'path-outside-trusted-roots', 'opaque-command',
    'unclassified-tool', 'mcp-tool']);

const sortedUnique = values => [...new Set(values)].sort();

/** * 这一调用够不够格建类键。不够格时把原因原样带回去（要能落台账逐格复核，不许只回一个 false）。
 * @returns `key` 有值＝可建类键；否则 `why` 说明卡在哪一格。
 */
export function classOf({ toolName = null, rows = [], targets = [], reasons = [], segments = [] } = {}) {
    const skip = why => ({ key: undefined, why, faces: [], roots: [], rows: [] });
    const tool = String(toolName ?? '');
    if (tool === '')
        return skip('no-tool-name');
    const targetList = Array.isArray(targets) ? targets : [];
    // 目标集为空＝「根类别」这一维读不出来，就没法保证同类＝同范围。
    if (targetList.length === 0)
        return skip('no-target-facts');
    for (const segment of Array.isArray(segments) ? segments : []) {
        const opClass = String(segment?.opClass ?? '');
        if (EXCLUDED_OP_CLASSES.has(opClass))
            return skip(`excluded-segment:${opClass}`);
        const family = String(segment?.execFamily ?? '');
        if (EXCLUDED_EXEC_FAMILIES.has(family))
            return skip(`exec-family:${family}`);
    }
    const faces = new Set();
    const roots = [];
    for (const target of targetList) {
        const opClass = String(target?.opClass ?? '');
        if (EXCLUDED_OP_CLASSES.has(opClass))
            return skip(`excluded-target:${opClass || 'unknown'}`);
        if (target?.dynamic === true)
            return skip('dynamic-operand');
        if (target?.foreignProject === true)
            return skip('foreign-project');
        const root = String(target?.rootHit ?? 'unknown');
        if (!INNER_ROOTS.has(root))
            return skip(`outside-target:${root}`);
        faces.add(opOf(opClass) ?? 'write');
        roots.push(root);
    }
    for (const reason of Array.isArray(reasons) ? reasons : []) {
        const text = String(reason ?? '');
        if (EXCLUDED_REASONS.has(text) || EXCLUDED_REASON_PREFIXES.some(prefix => text.startsWith(prefix)))
            return skip(`excluded-reason:${text || 'unknown'}`);
    }
    const rowTexts = sortedUnique((Array.isArray(rows) ? rows : [])
        .map(row => String(row ?? '').trim()).filter(text => text !== ''));
    if (rowTexts.length === 0)
        return skip('no-hit-rows');
    const faceList = sortedUnique(faces);
    const rootList = sortedUnique(roots);
    const shape = [tool, faceList.join('+'), rootList.join('+'), rowTexts.join(';')].join('::');
    return { key: createHash('sha256').update(shape).digest('hex').slice(0, 16),
        tool, faces: faceList, roots: rootList, rows: rowTexts, why: '' };
}
