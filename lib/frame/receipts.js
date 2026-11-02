// ｜判定回执：同一会话里，同一个动作刚被人放行过一次之后，第二回合不再问。
// 回执只抵「问」——不抵「拒」（拒绝／取消／没有通道一律不记），不跨会话，
// 不跨配置版本，也不活过 TTL。内存态：重启即忘（落盘不是本版的事）。
//
// 键（钉死的三种形）：
// hashBound＝true  ⇒ sessionId|actionHash
// 宿主没给 actionHash（真机存在 hashBound:false）⇒ 退化键
// sessionId|toolName|目标集摘要|configVersion
// 补充 ⇒ sessionId|#class#类键（四成分＝工具｜命中行｜面集合｜目标根类别，见 classkey.js）
// 三种键都带会话：跨会话复用会把 A 会话的批准借给 B 会话，这正是判据 2 要挡的。
// 类键另带沿用帽：同一类连续沿用满 CLASS_REUSE_CAP 次就不再复用，把这一格交回人（重复调用升级）。
import { createHash } from 'node:crypto';
import { CLASS_REUSE_CAP } from './classkey.js';

const TTL_MS = 30 * 60 * 1000;
const MAX_ENTRIES = 128;

const pad = value => String(value).padStart(2, '0');
const stampOf = (ms) => {
    const d = new Date(ms);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} `
        + `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
};

/** 退化键里的「目标集摘要」：排序后的目标路径串，取前 12 位 hash。 */
export function targetDigestOf(targets) {
    const keys = (Array.isArray(targets) ? targets : [])
        .map(target => String(target?.path ?? target?.input ?? ''))
        .filter(key => key !== '')
        .sort();
    return createHash('sha256').update(keys.join('\n')).digest('hex').slice(0, 12);
}

// 空目标集的摘要＝所有「没有路径的命令」共用的同一个值（`git push`／`systemctl`／`npm install`／
// `aws ec2 terminate-instances` 全都算出这一串）。11-01 对照实测：退化键撞上它，
// 一次放行就让这些互不相干的命令互相顶替——这一格不能当「同一个动作」的证据。
export const EMPTY_TARGET_DIGEST = targetDigestOf([]);

const sessionOf = (value) => {
    const sid = value === undefined || value === null ? '' : String(value);
    return sid === '' ? undefined : sid;
};

export function createReceiptStore() {
    const map = new Map();
    const hashKey = (sid, actionHash) => (actionHash === undefined || actionHash === null || String(actionHash) === ''
        ? undefined
        : `${sid}|${String(actionHash)}`);
    const fallbackKey = (sid, fields) => (String(fields.targetDigest ?? '') === EMPTY_TARGET_DIGEST
        // 目标集为空＝这一格没有信息量：不许把任意两条无路径命令折成同一把键。
        ? undefined
        : `${sid}|${String(fields.toolName ?? '')}`
            + `|${String(fields.targetDigest ?? '')}|${String(fields.configVersion ?? '')}`);
    // 类键单独一个命名空间：`#` 打头，工具名不可能长成这样，与退化键不会撞。
    const classKey = (sid, digest) => (digest === undefined || digest === null || String(digest) === ''
        ? undefined
        : `${sid}|#class#${String(digest)}`);
    const dropExpired = (now) => {
        const gone = [];
        for (const [key, entry] of map)
            if (now - entry.at > TTL_MS) {
                map.delete(key);
                gone.push(key);
            }
        return gone;
    };
    return {
        size: () => map.size,
        /** 记一条回执：只有人工放行才调用；sessionId 缺省时不记（键会串台）。 */
        put(fields = {}, now = Date.now()) {
            dropExpired(now);
            const sid = sessionOf(fields.sessionId);
            if (sid === undefined)
                return;
            const key = fields.hashBound === true
                ? hashKey(sid, fields.actionHash)
                : fallbackKey(sid, fields);
            if (key !== undefined) {
                // 同一键再记＝以最近一次的答复时刻为准（后答的覆盖先答的）。
                map.delete(key);
                map.set(key, {
                    via: 'action',
                    hash: String(fields.actionHash ?? ''),
                    answeredAt: stampOf(now),
                    at: now,
                    version: String(fields.configVersion ?? ''),
                });
            }
            // 补充：同一份人工答复另外建一条类回执。类键由调用方算好传进来
            // （classkey.js 判过排除项才有值）；每次新批准都把沿用计数归零。
            const ck = classKey(sid, fields.classKey);
            if (ck !== undefined) {
                map.delete(ck);
                map.set(ck, {
                    via: 'class',
                    classKey: String(fields.classKey),
                    hash: String(fields.actionHash ?? ''),
                    answeredAt: stampOf(now),
                    at: now,
                    version: String(fields.configVersion ?? ''),
                    uses: 0,
                    faces: String(fields.classFaces ?? ''),
                    roots: String(fields.classRoots ?? ''),
                    rows: String(fields.classRows ?? ''),
                });
            }
            while (map.size > MAX_ENTRIES)
                map.delete(map.keys().next().value);
        },
        /** 查一条回执：先试 hash 键（命中再核配置版本），再试退化键（版本已在键里）。 */
        check(fields = {}, now = Date.now()) {
            dropExpired(now);
            const sid = sessionOf(fields.sessionId);
            if (sid === undefined)
                return undefined;
            const version = String(fields.configVersion ?? '');
            if (fields.hashBound !== false) {
                const strong = hashKey(sid, fields.actionHash);
                const hit = strong === undefined ? undefined : map.get(strong);
                // hash 键里没有版本这一格 ⇒ 命中时再核一次：旧配置下答的「同意」不许套新规则。
                if (hit !== undefined && hit.version === version)
                    return hit;
            }
            if (fields.hashBound !== true) {
                // 退化键含 configVersion：版本一变，键就变了，旧回执自然不再命中。
                // 键算不出来（目标集为空）＝这一动作没有退化键可用，照旧问。
                const weak = fallbackKey(sid, fields);
                const hit = weak === undefined ? undefined : map.get(weak);
                if (hit !== undefined)
                    return hit;
            }
            const ck = classKey(sid, fields.classKey);
            const classHit = ck === undefined ? undefined : map.get(ck);
            // 类键没把版本折进键里 ⇒ 命中时自己再核一次，与 hash 键同一处理。
            if (classHit !== undefined && classHit.version === version) {
                if (classHit.uses >= CLASS_REUSE_CAP)
                    return { ...classHit, capped: true };
                classHit.uses += 1;
                return { ...classHit, capped: false };
            }
            return undefined;
        },
        /** TTL 到期清掉（判据 3 的读法：sweep 后照旧问）。 */
        sweep(now = Date.now()) {
            return dropExpired(now).length;
        },
        dropSession(sessionId) {
            const sid = sessionOf(sessionId);
            if (sid === undefined)
                return;
            const prefix = `${sid}|`;
            for (const key of [...map.keys()])
                if (key.startsWith(prefix))
                    map.delete(key);
        },
    };
}
