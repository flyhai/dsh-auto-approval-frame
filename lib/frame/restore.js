// 把 token 换回明文的**唯一**落点：文件层。
//
// 为什么不是执行前：宿主契约明写「Input rewriting is excluded because arguments are
// already logged and presented」——参数改不得，所以模型用 token 写出的那份文件，
// 只能在它写完之后由我们把里面的 token 换回明文。也因此两条边界要说死：
// · 只覆盖**落到文件里**的 token；命令参数里的（`--token [[SEC-…]]`）执行时不会变明文；
// · 只换**这张表铸出来**的 token，别的方括号文本一概不碰。
// 写回是「读→换→原子重写」，且跳过凭据／系统关键树：往 `~/.ssh` 里回填明文不是修正。
//
// F08 后半：回填不是「看到 token 就换」，是一次**受控使用**——先向秘密表消费一张授权
// （会话＋目的文件＋用途＋有效期＋版本，见 vault.consumeGrant），拿不到就一个字节都不写。
// 没有会话上下文（sessionId 缺省）的调用拿不到任何授权，所以直调也绕不过这道闸。
import { chmodSync, closeSync, fstatSync, lstatSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';
import { collectFacts } from './facts.js';
import { neverReasonFor } from './grant.js';
import { reasonText } from './policy.js';

const MAX_FILE_BYTES = 4 * 1024 * 1024;

/** * 删掉临时文件；删不掉也不许把异常抛出去（清理失败不该让一次回填变成工具异常），
 * 但要如实返回有没有删成——调用方据此说「这里可能留了含明文的后缀文件」。
 * 判据 7：`unlink` 可注入，只为让「删除被拒」这一态可测（生产路径就是 unlinkSync）。
 */
function discard(tmp, unlink = unlinkSync) {
    try {
        unlink(tmp);
        return true;
    }
    catch {
        return false;
    }
}

/** * 判据 5：目标版本口径与 vault 里那份一致（mtime＋size），用来在 rename 前复检
 * 「采样之后有没有人改过这个文件」。
 */
function sampleVersion(path) {
    try {
        const info = statSync(path);
        return { mtimeMs: info.mtimeMs, size: info.size };
    }
    catch {
        return null;
    }
}

function sameSample(left, right) {
    if (left === null && right === null)
        return true;
    if (left === null || right === null)
        return false;
    return Number(left.mtimeMs) === Number(right.mtimeMs) && Number(left.size) === Number(right.size);
}

/** * 从目标自身一路向上找链接，直到信任根为止（A12 判据 2）。
 * 判据 6：三种结论分清楚，不能都折成「没事」——
 *  · `{kind:'link', path}`：命中了链接／junction，重写会落到区外的真身；
 *  · `{kind:'unverified', path, error}`：这一层 lstat 读不出来，往上也无从判断 ⇒ **未验证**；
 *  · `{kind:'none'}`：一路查到信任根，没有链接。
 */
function firstLinkAncestor(target, roots, probe = lstatSync) {
    const stops = new Set();
    for (const root of [roots?.workspace, roots?.home])
        if (typeof root === 'string' && root !== '')
            stops.add(root.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase());
    let cursor = String(target).replace(/\\/g, '/').replace(/\/+$/, '');
    let guard = 0;
    // 上限 64 层：路径再有病也不许把一次回填变成死循环。
    while (cursor !== '' && guard < 64) {
        guard += 1;
        try {
            if (probe(cursor).isSymbolicLink())
                return { kind: 'link', path: cursor };
        }
        catch (error) {
            // 查不到＝「未验证」，不是「安全」。旧实现返回 undefined，调用处当成无事发生。
            return { kind: 'unverified', path: cursor, error: String(error?.code ?? error?.message ?? error) };
        }
        const lower = cursor.toLowerCase();
        if (stops.has(lower))
            return { kind: 'none' };
        const parent = dirname(cursor);
        if (parent === cursor)
            return { kind: 'none' };   // 已经到根
        const parentLower = parent.toLowerCase();
        if (stops.has(parentLower))
            return { kind: 'none' };
        cursor = parent;
    }
    return { kind: 'unverified', path: cursor, error: 'ancestor-walk-limit' };
}

// 搬运族的「要动哪个文件」只有一个答案：最后一个操作数。其余都是被搬走的东西——
// 往源文件里回填明文等于改了模型根本没打算改的那个文件（F08 的硬负例之一）。
const COPY_FAMILY = new Set(['cp', 'copy', 'mv', 'move', 'install', 'rsync', 'rename-item', 'move-item', 'copy-item']);

/** * @returns rows 每个目标一条：`{path, tokens}` 真的回写了什么，或 `{path, skipped, reason?}` 为什么没动。
 *          调用方必须给 `sessionId` 与 `purpose`——它们就是授权域的两维，缺了谁也拿不到通行证。
 */
/** * 判据 4：执行体的「效果指纹」。签发时把这份 hash 写进证，回填时按**同一次调用的事实**再算一遍；
 * 两边不等就不是同一件事。算法只此一处，签发方与回填方都 import 它，不许各写一份。
 */
export function effectHashOf(facts) {
    const rows = (facts?.targets ?? [])
        .map(item => [item.program ?? '', item.opClass ?? '', item.role ?? '', String(item.path ?? item.raw ?? '')].join('\u0001'))
        .sort();
    return createHash('sha256').update(rows.join('\n')).digest('hex').slice(0, 16);
}

export function restoreVaultedWrites({ toolName, args, roots, vault, probe, sessionId, purpose, callId, deps = {} }) {
    const facts = collectFacts({ toolName, args, roots, probe });
    const effectHash = effectHashOf(facts);
    const unlink = typeof deps.unlink === 'function' ? deps.unlink : unlinkSync;
    // 判据 6 的可测性钩子：生产路径就是 lstatSync；测试用它造「查不通＝未验证」。
    const linkProbe = typeof deps.lstat === 'function' ? deps.lstat : lstatSync;
    const out = [];
    // 先按「程序＋段序」把操作数排好，才知道哪个是最后一个（目的地）。
    const lastOf = new Map();
    for (const [index, target] of facts.targets.entries()) {
        if (target.dynamic === true || typeof target.path !== 'string')
            continue;
        const group = `${target.program ?? ''}|${target.opClass ?? ''}`;
        if (COPY_FAMILY.has(String(target.program ?? '').toLowerCase()))
            lastOf.set(group, index);
    }
    for (const [index, target] of facts.targets.entries()) {
        if (target.opClass !== 'write' || target.dynamic === true || typeof target.path !== 'string')
            continue;
        const group = `${target.program ?? ''}|${target.opClass ?? ''}`;
        if (COPY_FAMILY.has(String(target.program ?? '').toLowerCase()) && lastOf.get(group) !== index)
            continue;   // 源文件：它不是这次写入的落点
        const never = neverReasonFor(target, roots);
        if (never !== undefined) {
            out.push({ path: target.path, tokens: [], skipped: `不回填到${reasonText(never)}` });
            continue;
        }
        let text;
        let sampled;
        let sampledMode;
        try {
            // 链接要查**整条祖先链**，不是只看目标自己和它的直接父亲：A12 判据 2。
            // 旧实现只查一层（`target` 与 `dirname(target)`），`~/work/link/README.md` 这类
            // 「祖父以上是链接」的路径会被当成普通文件重写——而重写会落到链接指向的另一处，
            // 那一处从来没进过判定。一直向上查到信任根（workspace／home）为止。
            const linkAncestor = firstLinkAncestor(target.path, roots, linkProbe);
            if (linkAncestor.kind === 'link') {
                out.push({
                    path: target.path, tokens: [],
                    skipped: `目标或它的祖先 ${linkAncestor.path} 是链接／junction，重写会落到区外的真身`,
                });
                continue;
            }
            // 判据 6：查不通＝未验证，不是安全。回填是往文件里写明文，看不见就一个字节都不动。
            if (linkAncestor.kind !== 'none') {
                out.push({
                    path: target.path, tokens: [],
                    skipped: `链接祖先查不通（${linkAncestor.error}＠${linkAncestor.path}），未验证不动`,
                    linkUnverified: true,
                });
                continue;
            }
            // 版本与内容取同一刻：用同一个 fd 的 fstat，而不是读完再按路径 stat
            //（两次之间文件被换掉，会变成「读到旧内容、记下新版本」）。
            const fd = openSync(target.path, 'r');
            let raw;
            try {
                const info = fstatSync(fd);
                sampled = { mtimeMs: info.mtimeMs, size: info.size };
                // 判据 8：权限位跟着这一次采样走，rename 之后按它复原。
                sampledMode = info.mode;
                raw = readFileSync(fd);
            }
            finally {
                closeSync(fd);
            }
            if (raw.length > MAX_FILE_BYTES) {
                out.push({ path: target.path, tokens: [], skipped: '文件超过 4 MB' });
                continue;
            }
            text = raw.toString('utf8');
            // 回写是「按 UTF-8 重新编一遍」：非 UTF-8 的字节会先被替换字符吃掉，再原样写回去＝内容损坏。
            // 判据 8：比**字节**不比长度——替换字符能让长度正好抵消，长度相等而字节不同照样是损坏。
            if (Buffer.compare(Buffer.from(text, 'utf8'), raw) !== 0) {
                out.push({ path: target.path, tokens: [], skipped: '不是 UTF-8 文本，回写会改坏字节' });
                continue;
            }
        }
        catch {
            // 读不到＝文件还没落地（目标 absent）／不是文件／无权限：不去猜，也不建、不碰。
            out.push({ path: target.path, tokens: [], skipped: '读不出文本内容（文件不存在或不是普通文件）' });
            continue;
        }
        const found = vault.containsToken(text);
        if (found.length === 0)
            continue;
        // F08 后半：每一枚 token 都要一张活的授权（会话＋目的文件＋用途＋有效期＋版本）。
        // 一枚不匹配就只跳过这一枚——同一文件里别的枚有自己的通行证，不能连坐。
        const granted = [];
        const denied = [];
        for (const token of found) {
            const verdict = vault.consumeGrant(token, {
                sessionId, destination: target.path, purpose, expectedVersion: sampled,
                // 判据 4：带上「哪一次调用、什么效果」——证只对签发时那一次成立。
                callId, effectHash,
            });
            if (verdict.ok === true)
                granted.push(token);
            else
                denied.push(verdict.reason);
        }
        if (granted.length === 0) {
            out.push({
                path: target.path, tokens: [],
                skipped: `没有可用授权（${[...new Set(denied)].join('、')}）`,
                reason: denied[0] ?? 'grant.none',
            });
            continue;
        }
        const restored = vault.restoreText(text, { only: granted });
        if (restored.restored.length === 0) {
            out.push({ path: target.path, tokens: [], skipped: '这几条的回写开关是关的' });
            continue;
        }
        // A12 判据 3：这个临时文件里是**明文**——写坏、rename 失败、中途崩，
        // 都必须在原地把它删掉，不能留一份带明文的后缀文件躺在目标旁边。
        const tmp = `${target.path}.dsa-${process.pid}.tmp`;
        try {
            writeFileSync(tmp, restored.text);
        }
        catch (error) {
            const cleaned = discard(tmp, unlink);
            // A12 判据 3 后半：一次性授权已经在这次调用里被消费，文件却没换成 ⇒ 退回授权，
            // 让下一次「同一目的、同一用途」还有机会重试；否则一次磁盘抖动就永久烧掉证。
            const released = granted.map(token => vault.releaseGrant(token));
            out.push({
                path: target.path, tokens: [],
                skipped: `写入临时文件失败：${String(error?.message ?? error)}`,
                // 判据 7：这里以前固定写 false——没删掉的那份明文就这么被报成"没留下"。
                plaintextLeftBehind: cleaned ? false : 'unknown',
                grantedReleased: released.some(Boolean),
            });
            continue;
        }
        // 判据 5：采样与 rename 之间第三方改了目标 ⇒ 放弃回填，不拿我们的整份内容去盖别人刚写的。
        // `beforeRename` 只为让这一瞬可复现（生产调用方不传）：不注入就只能靠竞态，测不出稳定读数。
        if (typeof deps.beforeRename === 'function')
            deps.beforeRename(target.path);
        const current = sampleVersion(target.path);
        if (sameSample(sampled, current) !== true) {
            const cleaned = discard(tmp, unlink);
            const released = granted.map(token => vault.releaseGrant(token));
            out.push({
                path: target.path, tokens: [],
                skipped: '目标已变（采样后被外部改过），放弃回填',
                targetChanged: true,
                plaintextLeftBehind: cleaned ? false : 'unknown',
                grantedReleased: released.some(Boolean),
            });
            continue;
        }
        try {
            renameSync(tmp, target.path);
        }
        catch (error) {
            const cleaned = discard(tmp, unlink);
            const released = granted.map(token => vault.releaseGrant(token));
            out.push({
                path: target.path, tokens: [],
                skipped: `原子替换失败：${String(error?.message ?? error)}`,
                // 判据 7：删掉了才敢说没有残留；删不掉只能说「不知道」（可能就躺在目标旁边）。
                plaintextLeftBehind: cleaned ? false : 'unknown',
                grantedReleased: released.some(Boolean),
            });
            continue;
        }
        // 判据 8：rename 换上来的是临时文件的权限位，按采样时那份复原（Windows 上 chmod 基本空操作，
        // ACL 来自同目录继承，RESULTS 里给 icacls 的前后两串）。
        try {
            if (typeof sampledMode === 'number')
                chmodSync(target.path, sampledMode);
        }
        catch {
            // 复原不了不让这次回填变成失败：内容已经正确落盘，权限面在 RESULTS 里如实记。
        }
        discard(tmp, unlink);   // rename 成功时 tmp 已被移走；再来一次只是兜住"移动后仍有残留"的异常形状
        out.push({
            path: target.path, tokens: restored.restored,
            ...(denied.length > 0 ? { denied } : {}),
        });
    }
    return out;
}
