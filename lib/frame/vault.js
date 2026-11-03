// 明文↔token 映射表。可逆脱敏必然在本机多落一份明文——这是这一档换来的代价，
// 所以围着它有四条限制：只落插件自己的状态目录（`secrets.json`）、上限 200 条、
// 30 天不用就丢、台账里永远只写 token 与字符数（绝不写明文）。
//
// token ＝ `[[SEC-` ＋ HMAC(pepper, 明文) 前 12 位 ＋ `]]`。pepper 与表同目录，
// 所以即便有人拿到别人的凭据也算不出我们表里的 token；删掉 pepper 文件＝整表作废。
// 落盘是密文（`secretbox.js`，AES-256-GCM）：挡的是「干活时顺手读到文件」，
// 不是操作系统级密钥保护——钥匙跟着源码走，拿到代码并肯跑一遍的人能还原。
// 封印过的表打不开时一律停写、不覆盖：宁可脱敏走不动，也不拿空表冲掉真表。
import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, closeSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync, writeSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { CURRENT_KEY_ID, isSealed, openSealed, sealText } from './secretbox.js';
import { TOKEN_PATTERN } from './sensitive.js';

const FILE = 'secrets.json';
const MAX_ENTRIES = 200;
// 判据 2：墓碑单独配额。它不占活条目的名额（否则删 200 次就把表填死），
// 但也必须有上限——墓碑只负责挡住「旧快照复活」，挡住 30 天足够。
const MAX_GRAVES = 50;
const TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TOKEN_CHARS = 12;

const TOKENIZE_LIMIT = 64 * 1024;
// A12 判据 4：进程间互斥用的锁文件与耐心上限（与 audit 同款）。
const LOCK_FILE = '.vault.lock';
const LOCK_TRIES = 12;
const LOCK_SLEEP_MS = 100;
const LOCK_STALE_MS = 10_000;

// 一次「秘密使用授权」的默认寿命：它是回填那一下的通行证，不是长期凭证。
const GRANT_TTL_MS = 10 * 60 * 1000;

/** 目标文件的版本口径（写死在这里）：mtime＋size。 */
function versionOfFile(path) {
    try {
        const info = statSync(path);
        return { mtimeMs: info.mtimeMs, size: info.size };
    }
    catch {
        return null;   // 还不存在／读不到：记成空版本，回填时只要不是空版本就算被动过
    }
}

function sameVersion(left, right) {
    if (left === null && right === null)
        return true;
    if (left === null || right === null)
        return false;
    return Number(left.mtimeMs) === Number(right.mtimeMs) && Number(left.size) === Number(right.size);
}

/** 路径比较口径：先解析成绝对路径；Windows 上不区分大小写。 */
function keyOf(value) {
    const text = typeof value === 'string' ? value : String(value ?? '');
    if (text === '')
        return '';
    const resolved = resolve(text);
    return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function createSecretVault({ dir, now = () => Date.now() }) {
    const path = join(dir, FILE);
    // 上次读到的盘面镜像与版本号：据此算出"本实例动过哪些条目"，合并时不冤枉对方的新东西。
    // 这几个必须先于 `load` 声明——load 会给它们赋值，晚一步就是 TDZ。
    let diskMirror = new Map();
    let diskRev = 0;
    // 最近一次落盘的结果：读侧（秘密页 GET）拿它说「这张表现在写不下去」，
    // 不靠调用方猜——register 失败时返回 undefined 只是半句实话。
    let writable = true;
    // 盘上是密文却打不开（文件损坏／钥匙换了）＝停写：不覆盖、不清空。
    let locked = false;
    // 旧版本留下的明文表：读到就改写成密文。
    let plainOnDisk = false;
    // 盘上是旧编号的密文：能解开，但要用当前钥匙重新封一次（旧钥匙继续留着解老文件）。
    let needsReseal = false;
    let state = load();
    // 明文表或旧钥匙封的表，第一次读到即改写；写不进去（锁冲突等）只记 writable=false，下次 save 再试。
    if (plainOnDisk === true || needsReseal === true)
        save();

    function readDisk() {
        let text;
        try {
            text = readFileSync(path, 'utf8');
        }
        catch (error) {
            // 不存在＝空表起步；存在却读不动（权限／IO）＝不能当成空表，
            // 否则下一次保存会拿空表把一份可能完好的表冲掉。
            if (error?.code === 'ENOENT')
                return { status: 'missing' };
            return { status: 'unreadable' };
        }
        const body = text.trim();
        const sealed = isSealed(body);
        try {
            const opened = sealed ? openSealed(body) : { text, keyId: CURRENT_KEY_ID };
            const raw = JSON.parse(opened.text);
            if (typeof raw?.pepper !== 'string' || !Array.isArray(raw.entries))
                throw new Error('bad shape');
            return {
                status: 'ok',
                sealed,
                keyId: opened.keyId,
                pepper: raw.pepper,
                entries: raw.entries,
                rev: Number.isFinite(raw.rev) ? raw.rev : 0,
            };
        }
        catch {
            return { status: 'bad', sealed };
        }
    }

    function load() {
        const disk = readDisk();
        if (disk.status === 'ok') {
            diskMirror = new Map(disk.entries.map(entry => [entry.token, entry]));
            diskRev = disk.rev;
            plainOnDisk = disk.sealed !== true;
            needsReseal = disk.sealed === true && disk.keyId !== CURRENT_KEY_ID;
            return { pepper: disk.pepper, entries: disk.entries };
        }
        diskMirror = new Map();
        diskRev = 0;
        // 封印过的表打不开、或文件存在却读不动：**不拿空表覆盖**——读不出不等于表是空的，
        // 这一支宁可让脱敏走不动，也不把真表冲掉。
        if ((disk.status === 'bad' && disk.sealed === true) || disk.status === 'unreadable') {
            locked = true;
            writable = false;
            return { pepper: randomBytes(32).toString('hex'), entries: [] };
        }
        // 旧明文表坏了：沿用原来的恢复口径（新 pepper＋空表），它没有「钥匙不对」这一说。
        return { pepper: randomBytes(32).toString('hex'), entries: [] };
    }

    /** * 判据 3：条目的生命状态用一张状态机定死，不再用「取更严格的对象」代替状态机。
     * 顺序＝谁更不可逆：墓碑 > 已消费 > 已撤销 > 有证未用 > 无证 > 不存在。
     *  · 条目不存在／明文已被清掉 ⇒ absent（reason `grant.none`）；
     *  · `use === undefined`（字段缺失）＝从未签发过证 ⇒ gap，与无证同档（`grant.none`）；
     *  · `use === null` ＝ **显式撤销**（revoke／过期写的），与「从未签发」不是一回事（`grant.revoked`）；
     *  · `use.consumedAt` 是数字 ⇒ 已消费（`grant.consumed`）；是 null 或缺失 ⇒ 还没用（老数据按未用）。
     */
    const LIFE_RANK = { absent: 0, gap: 1, granted: 2, revoked: 3, expired: 3, consumed: 4, deleted: 5 };

    function lifecycleOf(entry) {
        if (entry === undefined || entry === null || typeof entry !== 'object')
            return 'absent';
        if (entry.tombstone !== undefined && entry.tombstone !== null)
            return 'deleted';
        const use = entry.use;
        // 撤销与过期都清成 `use = null`，但过期会留 `expiredAt`：两者都不可用，
        // 台账上却是两件事（「这个人撤了」vs「时间到了」），不能混成一个 reason。
        if (use === null)
            return entry.expiredAt === undefined || entry.expiredAt === null ? 'revoked' : 'expired';
        if (use === undefined)
            return 'gap';
        if (use.consumedAt !== null && use.consumedAt !== undefined)
            return 'consumed';
        return 'granted';
    }

    /** A12 判据 4／B10 判据 2：把本实例改过的条目重放到最新盘面。 */
    function mergeOntoDisk(disk) {
        const latest = new Map(disk.entries.map(entry => [entry.token, entry]));
        const mine = new Map(state.entries.map(entry => [entry.token, entry]));
        const touched = new Set();
        for (const token of diskMirror.keys())
            touched.add(token);
        for (const token of mine.keys())
            touched.add(token);

        for (const token of touched) {
            const wasInDisk = diskMirror.get(token);
            const isInMine = mine.get(token);
            const peer = latest.get(token);
            if (isInMine === undefined) {
                // 本实例里查无此条：只有当对方也没动过它时才算「我删了它」。
                // 判据 2 起删除改写成墓碑，这条分支只兜住「墓碑被裁掉」的老形状。
                const peerIsNewer = peer !== undefined
                    && Number(peer.lastAt) > Number(wasInDisk?.lastAt ?? -Infinity);
                if (peer !== undefined && peerIsNewer === true)
                    continue;
                latest.delete(token);
                continue;
            }
            if (peer === undefined) {
                latest.set(token, isInMine);
                continue;
            }
            if (wasInDisk !== undefined && JSON.stringify(wasInDisk) === JSON.stringify(isInMine))
                continue;   // 本实例没动过它：对方的版本说了算
            // 判据 2／3：按状态机的档位择一，**不是**把对方的 `use` 拼回我的对象——
            // 拼法会让「我这边是墓碑／已消费、对方是旧快照」两边各说一半。
            const peerRank = LIFE_RANK[lifecycleOf(peer)];
            const mineRank = LIFE_RANK[lifecycleOf(isInMine)];
            if (peerRank > mineRank) {
                latest.set(token, peer);   // 更高的档不可逆：墓碑压过旧快照，已消费压过可用
                continue;
            }
            if (mineRank > peerRank) {
                latest.set(token, isInMine);
                continue;
            }
            // 同档才比新旧：同一档里没有不可逆差异，后写的那个说了算。
            latest.set(token, Number(peer.lastAt) > Number(isInMine.lastAt) ? peer : isInMine);
        }
        return [...latest.values()];
    }

    /** * 判据 1：真事务。取锁 → **重读盘面** → 在盘面副本上判并改 → 一次写回。
     * 旧实现把「判」放在内存快照上、只在写盘时合并：两个实例各判各的都能过，合并时只有一份落盘，
     * 于是「一次性」变成「两边都以为自己用掉了」。
     *
     * mutator 拿到的是盘面深拷贝，返回 `{ commit: true, ... }` 才写；不 commit 时内存镜像也
     * 对齐到刚读到的盘面（别人的新条目要看得见，否则下一次判又基于旧账）。
     */
    function transact(mutator) {
        try {
            mkdirSync(dir, { recursive: true });
            if (acquireSaveLock() !== true) {
                writable = false;
                return { ok: false, reason: 'vault.locked' };
            }
            try {
                const disk = readDisk();
                // 读不出不等于空表：封印过的表打不开、或文件在却读不动，一律停手，一个字节不写。
                // 旧写法判 `disk === undefined`，可 readDisk 从不返回 undefined ⇒ 那是条死分支；
                // 真碰上文件不在时反而拿到 entries=undefined 的草稿，mutator 一碰就抛，
                // 被外层 catch 吞成 `vault.unwritable`——理由是假的，那张表其实写得下去。
                if ((disk.status === 'bad' && disk.sealed === true) || disk.status === 'unreadable') {
                    locked = true;
                    writable = false;
                    return { ok: false, reason: 'vault.locked' };
                }
                // 剩下两态按空表起步：missing＝文件不在（被别处删了／还没建）；
                // bad 且未封印＝明文表已损坏，与 load() 同口径（这一支本来就允许被覆盖）。
                // pepper 用内存里那份：已经发出去的 token 靠它才算得回明文。
                const base = disk.status === 'ok'
                    ? { pepper: disk.pepper, entries: disk.entries, rev: disk.rev }
                    : { pepper: state.pepper, entries: [], rev: diskRev };
                const draft = { pepper: base.pepper, entries: structuredClone(base.entries), rev: base.rev };
                const result = mutator(draft) ?? {};
                if (result.commit === true) {
                    draft.rev = (Number(base.rev) || 0) + 1;
                    writeBody(draft);
                    state = draft;
                    diskRev = draft.rev;
                    diskMirror = new Map(draft.entries.map(entry => [entry.token, entry]));
                    writable = true;
                }
                else {
                    // 没提交：不写盘，但把盘面（可能是别人刚写的）纳入视野。
                    state = { pepper: draft.pepper, entries: base.entries, rev: base.rev };
                    diskRev = state.rev;
                    diskMirror = new Map(state.entries.map(entry => [entry.token, entry]));
                }
                return result;
            }
            finally {
                releaseSaveLock();
            }
        }
        catch {
            writable = false;
            return { ok: false, reason: 'vault.unwritable' };
        }
    }

    /** * 落盘。失败不抛：抛出会把一次脱敏变成工具异常，而它本该是「这段遮不住」。
     *
     * A12 判据 4：旧实现把内存里的 `state` 整份写到目标文件——**写前不重读**。
     * 两个 vault 实例同时开着（本进程与另一 profile／CLI／页面）时，旧实例那份快照里
     * 没有新实例刚登记的条目、也没有它的撤销与一次性消费，save 一下就把三样全盖没了。
     * 现在改成「取锁 → 重读盘 → 按条目差量合并 → 写盘（rev+1）」：
     *  · 只有本实例动过的条目参与重放，对方的新条目原样留下；
     *  · 终止态（已消费 `consumedAt`／已撤销 `use === null`）**不回退**——谁更严格谁留下，
     *    因为「撤回已经发出去的通行证」比「多留一条登记」重要得多；
     *  · 本实例因过期裁掉的条目，若对方刚刚才碰过它（lastAt 更新）就不裁。
     */
    function save() {
        if (locked === true) {
            writable = false;
            return false;   // 盘上是打不开的密文表：停写，绝不拿空表/半表覆盖它
        }
        try {
            mkdirSync(dir, { recursive: true });
            const held = acquireSaveLock();
            if (held !== true) {
                writable = false;
                return false;   // 拿不到锁就不写：写了就是又一次整份覆盖的事故
            }
            try {
                const disk = readDisk();
                if (disk.status !== 'ok' || disk.rev <= diskRev) {
                    // 没人抢先（或本来就是空档）：照本实例的样子写，rev 自增。
                    state.rev = (disk.status === 'ok' ? disk.rev : diskRev ?? 0) + 1;
                }
                else {
                    const merged = mergeOntoDisk(disk);
                    state.entries = merged;
                    state.pepper = disk.pepper;   // pepper 换了＝所有 token 失效，绝不能被偷偷换掉
                    state.rev = disk.rev + 1;
                }
                diskRev = state.rev;
                diskMirror = new Map(state.entries.map(entry => [entry.token, entry]));
                writeBody(state);
                writable = true;
                return true;
            }
            finally {
                releaseSaveLock();
            }
        }
        catch {
            writable = false;
            return false;
        }
    }

    function writeBody(body) {
        const tmp = `${path}.${process.pid}.tmp`;
        const text = `${sealText(JSON.stringify(body))}\n`;
        // mode 只在支持它的文件系统上有意义（Windows 上基本是空操作）：
        // 真正的保护是把内容封起来，权限位只是第二道顺手的门。
        try {
            writeFileSync(tmp, text, { mode: 0o600 });
        }
        catch {
            writeFileSync(tmp, text);
        }
        renameSync(tmp, path);
        plainOnDisk = false;
    }

    /** 同一份表上的进程间互斥（与 audit 的 .append.lock 同形，只是文件名不同）。 */
    function acquireSaveLock() {
        const lockPath = join(dir, LOCK_FILE);
        for (let attempt = 0; attempt < LOCK_TRIES; attempt += 1) {
            try {
                const handle = openSync(lockPath, 'wx');
                try {
                    writeSync(handle, `${JSON.stringify({ pid: process.pid, at: Number(now()) })}\n`);
                }
                finally {
                    closeSync(handle);
                }
                return true;
            }
            catch (error) {
                if (error?.code !== 'EEXIST')
                    return false;
                if (isStaleSaveLock(lockPath) === true) {
                    try {
                        rmSync(lockPath, { force: true });
                        continue;
                    }
                    catch {
                        sleepSync(LOCK_SLEEP_MS);
                    }
                }
                else
                    sleepSync(LOCK_SLEEP_MS);
            }
        }
        return false;
    }

    function releaseSaveLock() {
        try {
            rmSync(join(dir, LOCK_FILE), { force: true });
        }
        catch {
            // 锁删不掉也让流程继续：下一轮 acquire 会因超时接管它。
        }
    }

    function isStaleSaveLock(lockPath) {
        let meta;
        try {
            meta = JSON.parse(readFileSync(lockPath, 'utf8'));
        }
        catch {
            return true;
        }
        const at = Number(meta?.at);
        if (Number.isFinite(at) === false)
            return true;
        if (Number(meta?.pid) === process.pid)
            return false;
        return Number(now()) - at > LOCK_STALE_MS;
    }

    function sleepSync(ms) {
        try {
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(1, ms));
        }
        catch {
            // 没有 Atomics.wait 的环境：靠重试次数兜住。
        }
    }

    function tokenFor(plain) {
        return `[[SEC-${createHmac('sha256', state.pepper).update(plain).digest('hex').slice(0, TOKEN_CHARS)}]]`;
    }

    /** * 过期与超限都在这一步收口；纯函数，调用方决定要不要落盘。
     * 判据 2：活条目与墓碑各自算配额——墓碑挤掉真凭据等于用一次删除换一次误删。
     */
    function pruned(entries, stamp) {
        const alive = entries.filter(entry => lifecycleOf(entry) !== 'deleted');
        const graves = entries.filter(entry => lifecycleOf(entry) === 'deleted');
        const kept = alive
            // 缺 lastAt 的老条目不能按「过期」裁掉：NaN 一进比较就被判成超龄，条目会静默消失。
            .filter(entry => !Number.isFinite(Number(entry.lastAt)) || stamp - entry.lastAt <= TTL_MS)
            .sort((a, b) => b.lastAt - a.lastAt)
            .slice(0, MAX_ENTRIES);
        const keptGraves = graves
            .filter((entry) => {
                const at = Number(entry.tombstone?.deletedAt ?? entry.lastAt);
                return !Number.isFinite(at) || stamp - at <= TTL_MS;
            })
            .sort((a, b) => Number(b.tombstone?.deletedAt ?? 0) - Number(a.tombstone?.deletedAt ?? 0))
            .slice(0, MAX_GRAVES);
        return [...kept, ...keptGraves];
    }

    /** 登记一段明文，回它对应的确定性 token（同明文同 token，重复命中只加次数）。 */
    function register(plain, { detector = 'custom', label = '', source = '' } = {}) {
        const text = String(plain ?? '');
        if (text === '' || text.length > TOKENIZE_LIMIT || isKnownToken(text))
            return undefined;
        const token = tokenFor(text);
        const stamp = now();
        const previous = state.entries;
        const entries = previous.slice();
        const index = entries.findIndex(entry => entry.token === token);
        const fresh = {
            token, detector, label, plain: text, chars: text.length,
            at: stamp, lastAt: stamp, hits: 1, restore: true, source,
        };
        if (index === -1)
            entries.push(fresh);
        // 判据 2：同一段明文被重新登记＝它又被用到了，墓碑作废（墓碑挡的是旧快照，不是新意图）。
        else if (lifecycleOf(entries[index]) === 'deleted')
            entries[index] = fresh;
        else {
            const found = entries[index];
            entries[index] = {
                ...found, lastAt: stamp, hits: found.hits + 1,
                label: label || found.label, source: source || found.source,
            };
        }
        state.entries = pruned(entries, stamp);
        // 表落不下去＝这张表兑不出「换回明文」：撤掉这次改动，回 undefined，
        // 让结果侧按「遮不住就别给模型」处理，而不是揣着一个换不回明文的 token 继续走。
        if (!save()) {
            state.entries = previous;
            return undefined;
        }
        return token;
    }

    function isKnownToken(text) {
        return typeof text === 'string' && new RegExp(`^${TOKEN_PATTERN.source}$`).test(text);
    }

    function entryOf(token) {
        const entry = state.entries.find(item => item.token === token);
        // 判据 2：墓碑不是条目——它只负责在合并时挡住旧快照，不进任何可用面。
        return lifecycleOf(entry) === 'deleted' ? undefined : entry;
    }

    /** 先验期再返回：过期条目既换不出明文，也不该留在表里——裁掉就立即落盘（页面与盘一份数）。 */
    function pruneNow() {
        const stamp = now();
        const kept = pruned(state.entries, stamp);
        if (kept.length === state.entries.length)
            return false;
        state.entries = kept;
        save();
        return true;
    }

    /** * 签发一次「秘密使用授权」：一个会话、一个目的文件、一种用途、一段有效期。
     * 授权域落在条目上（一次一条），再次签发会替换旧授权——同一时刻只有一张活的通行证。
     * 版本在签发这一刻取样（mtime＋size）：回填时若文件已经变过，`grant.stale`。
     */
    function grantUse(token, { sessionId, destination, purpose, ttlMs = GRANT_TTL_MS, once = true, callId, effectHash } = {}) {
        pruneNow();
        // 三项缺一不可：没有会话就叫「谁都能用」，没有目的文件就叫「写哪都行」，没有用途就无从追责。
        if (typeof sessionId !== 'string' || sessionId === '')
            return { ok: false, reason: 'grant.session' };
        if (typeof destination !== 'string' || destination === '')
            return { ok: false, reason: 'grant.destination' };
        if (typeof purpose !== 'string' || purpose === '')
            return { ok: false, reason: 'grant.purpose' };
        // 判据 4：签发时把「哪一次调用、什么效果」一起写进证里——
        // 证只对那一次调用成立，换一个执行体就不是同一件事了。
        const result = transact((draft) => {
            const entry = draft.entries.find(item => item.token === token);
            if (lifecycleOf(entry) === 'absent' || lifecycleOf(entry) === 'deleted')
                return { ok: false, reason: 'grant.none' };
            const stamp = now();
            entry.use = {
                sessionId,
                destination,
                purpose,
                expiresAt: stamp + Math.max(1, Number(ttlMs) || GRANT_TTL_MS),
                once: once !== false,
                version: versionOfFile(destination),
                consumedAt: null,
                ...(callId === undefined || callId === null ? {} : { callId: String(callId) }),
                ...(effectHash === undefined || effectHash === null ? {} : { effectHash: String(effectHash) }),
            };
            entry.lastAt = stamp;
            // 新证覆盖旧账：重新签发后这一条不再是「过期」状态。
            delete entry.expiredAt;
            return { ok: true, commit: true };
        });
        // 授权写不进表＝这张通行证不存在：如实回「没签成」，不揣一张只在内存里的证。
        return result.ok === true ? { ok: true } : { ok: false, reason: result.reason ?? 'grant.unwritable' };
    }

    /** * 消费一次授权。检查顺序固定：会话 → 目的 → 用途 → 过期 → 已用 → 版本。
     * 顺序就是台账里那个 reason 的来源：一处不匹配就停，后面的不再猜。
     *
     * 版本有两层，别混：
     *  · 签发时存的那份是**兜底**——调用方说不出「我看到的版本」时，就拿它比；
     *  · 回填腿会在读目标文件定位 token 的同一刻取样，作为 `expectedVersion` 传进来。
     *    真实时序是「签发 → 被授权的那次工具写盘 → 回填」，工具的写本来就会改版本；
     *    拿签发时的旧版本去比必然 stale，那不是防并发修改，那是把正常路径当异常。
     *    真正要防的是「取样之后、重写之前有人改了文件」——那才是这一格的用途。
     */
    function consumeGrant(token, { sessionId, destination, purpose, expectedVersion, callId, effectHash } = {}) {
        pruneNow();
        const result = transact((draft) => {
            const entry = draft.entries.find(item => item.token === token);
            const life = lifecycleOf(entry);
            if (life === 'absent' || life === 'gap')
                return { ok: false, reason: 'grant.none' };
            if (life === 'deleted')
                return { ok: false, reason: 'grant.deleted' };
            if (life === 'revoked')
                return { ok: false, reason: 'grant.revoked' };
            if (life === 'expired')
                return { ok: false, reason: 'grant.expired' };
            const use = entry.use;
            if (use.sessionId !== sessionId)
                return { ok: false, reason: 'grant.session' };
            if (keyOf(use.destination) !== keyOf(destination))
                return { ok: false, reason: 'grant.destination' };
            if (use.purpose !== purpose)
                return { ok: false, reason: 'grant.purpose' };
            if (now() > use.expiresAt) {
                // 过期的通行证不再可用：清成 `use = null`，但留 `expiredAt` 与「撤销」分档。
                const stamp = now();
                entry.use = null;
                entry.expiredAt = stamp;
                entry.lastAt = stamp;
                return { ok: false, reason: 'grant.expired', commit: true };
            }
            if (life === 'consumed')
                return { ok: false, reason: 'grant.consumed' };
            // 判据 4：证绑的是「被批准的那一次」。签发版写了 callId／效果 hash 时，
            // 执行体对不上就不是同一件事——`expectedVersion` 只比文件版本，不能顶替这两项。
            if (use.callId !== undefined && String(use.callId) !== String(callId))
                return { ok: false, reason: 'grant.call' };
            if (use.effectHash !== undefined && String(use.effectHash) !== String(effectHash))
                return { ok: false, reason: 'grant.effect' };
            const baseline = expectedVersion === undefined ? use.version : expectedVersion;
            if (!sameVersion(baseline, versionOfFile(use.destination)))
                return { ok: false, reason: 'grant.stale' };
            if (use.once !== false) {
                const stamp = now();
                use.consumedAt = stamp;
                entry.lastAt = stamp;
                // 一次性标记与「谁用掉了」在同一次写里落盘：判与写都在锁内，另一方进锁只会看见已消费。
                return { ok: true, commit: true };
            }
            return { ok: true };
        });
        // `commit` 是事务内部用语，不外泄给调用方（index.js 只认 ok／reason）。
        const { commit, ...verdict } = result;
        return verdict;
    }

    /** * A12 判据 3 后半：一次性授权在「已消费、文件没换成」时退回。
     * 只清 consumedAt，不复活过期／已撤销的证；落不了盘就不退（fail-closed）。
     */
    function releaseGrant(token) {
        // 只清 consumedAt，不复活过期／已撤销的证；落不了盘就不退（fail-closed）。
        const result = transact((draft) => {
            const entry = draft.entries.find(item => item.token === token);
            if (lifecycleOf(entry) !== 'consumed')
                return { changed: false };
            entry.use.consumedAt = null;
            entry.lastAt = now();
            return { changed: true, commit: true };
        });
        return result.changed === true && result.commit === true;
    }

    /** 显式撤销：条目还在，通行证作废（`use = null`，与「从未签发」的 `undefined` 分档）。 */
    function revokeGrant(token) {
        const result = transact((draft) => {
            const entry = draft.entries.find(item => item.token === token);
            const life = lifecycleOf(entry);
            if (life !== 'granted' && life !== 'consumed')
                return { changed: false };
            entry.use = null;
            entry.lastAt = now();
            return { changed: true, commit: true };
        });
        return result.changed === true && result.commit === true;
    }

    function plainOf(token) {
        // 读一次**不给续命**：寿命由「最后一次真的被写进表」决定，
        // 否则每查一次就把 30 天推回去，README 承诺的 TTL 成了摆设。
        pruneNow();
        const entry = entryOf(token);
        if (entry === undefined)
            return undefined;
        entry.hits += 1;
        save();
        return entry.plain;
    }

    /** 页面用的形状：明文默认不出表（`reveal` 单条要点开才给）。 */
    function list() {
        pruneNow();
        return state.entries
            .filter(entry => lifecycleOf(entry) !== 'deleted')
            .slice()
            .sort((a, b) => b.lastAt - a.lastAt)
            .map(entry => ({
                token: entry.token,
                detector: entry.detector,
                label: entry.label || entry.detector,
                chars: entry.chars,
                head: entry.plain.slice(0, 4),
                at: entry.at,
                lastAt: entry.lastAt,
                hits: entry.hits,
                restore: entry.restore !== false,
                source: entry.source,
            }));
    }

    function setRestore(token, on) {
        const entry = entryOf(token);
        if (entry === undefined)
            return false;
        entry.restore = on === true;
        save();
        return true;
    }

    /** * 判据 2：删除写成墓碑，不再物理抹掉。
     * 物理删的后果是「谁没看见我删就对」：一个持旧快照的实例再 save 一次，
     * 合并逻辑看见「盘上没有、我有」就当成新条目塞回去——删掉的明文又回到表里。
     * 墓碑让「删过」本身成为一条不可逆的账，合并按档位取严，旧快照压不过它。
     */
    function remove(token) {
        const result = transact((draft) => {
            const index = draft.entries.findIndex(entry => entry.token === token);
            if (index === -1)
                return { changed: false };
            const found = draft.entries[index];
            if (lifecycleOf(found) === 'deleted')
                return { changed: false };
            const stamp = now();
            draft.entries[index] = {
                token,
                tombstone: { deletedAt: stamp, version: Number(found.version ?? 0) + 1 },
                at: found.at, lastAt: stamp,
                chars: found.chars, detector: found.detector, label: found.label,
                // 明文不随墓碑保留：墓碑只回答「这个 token 不存在了」。
            };
            return { changed: true, commit: true };
        });
        return result.changed === true && result.commit === true;
    }

    function clear() {
        const stamp = now();
        // 换 pepper：即便有残留副本，旧 token 也再也换不出明文。
        const pepper = randomBytes(32).toString('hex');
        // 判据 2：整表清空也要留墓碑，否则旧实例一 save 就把上百条明文带回表里。
        const result = transact((draft) => {
            const alive = draft.entries.filter(entry => lifecycleOf(entry) !== 'deleted');
            if (alive.length === 0)
                return { commit: false, cleared: 0 };
            const graves = alive.map(entry => ({
                token: entry.token,
                tombstone: { deletedAt: stamp, version: Number(entry.version ?? 0) + 1 },
                at: entry.at, lastAt: stamp,
                chars: entry.chars, detector: entry.detector, label: entry.label,
            }));
            draft.entries = [...draft.entries.filter(entry => lifecycleOf(entry) === 'deleted'), ...graves];
            draft.pepper = pepper;
            return { commit: true, cleared: alive.length };
        });
        return result.cleared ?? 0;
    }

    function restoreText(text, { only } = {}) {
        // 同 reveal：先验期，过期 token 原样留着（它已经换不回明文了）；也不给续命。
        pruneNow();
        // `only`＝这次只换这几枚（回填腿先逐枚消费授权，没授权的枚不碰）。
        const allowed = only === undefined ? undefined : new Set(only);
        const value = typeof text === 'string' ? text : String(text ?? '');
        const restored = [];
        const replaced = value.replace(new RegExp(TOKEN_PATTERN.source, 'g'), (token) => {
            if (allowed !== undefined && !allowed.has(token))
                return token;
            const entry = entryOf(token);
            if (entry === undefined || entry.restore === false)
                return token;
            entry.hits += 1;
            restored.push(token);
            return entry.plain;
        });
        if (restored.length > 0)
            save();
        return { text: replaced, restored };
    }

    /** 文本里有没有**这张表认得**的 token——回写腿用它决定要不要碰这个文件。 */
    function containsToken(text) {
        const found = String(text ?? '').match(new RegExp(TOKEN_PATTERN.source, 'g')) ?? [];
        return found.filter(token => entryOf(token) !== undefined);
    }

    return {
        path,
        register,
        plainOf,
        grantUse,
        consumeGrant,
        releaseGrant,
        revokeGrant,
        list,
        setRestore,
        remove,
        clear,
        restoreText,
        containsToken,
        size: () => state.entries.filter(entry => lifecycleOf(entry) !== 'deleted').length,
        // F15：这原来是**一个对象**，而 `index.js` 按 `vault.limits` 调 ⇒ 每次读秘密表
        // 都 TypeError（500 就是这么来的）。接口与调用点现在同一形状。
        limits: () => ({ maxEntries: MAX_ENTRIES, ttlDays: Math.round(TTL_MS / 86_400_000) }),
        // 页面据此说明「这张表此刻写不下去」——只给状态与路径，绝不回明文。
        storage: () => ({
            writable, path,
            // sealed＝盘上是密文；locked＝密文打不开（已停写，原文件一个字节没动）。
            atRest: locked ? 'locked' : 'sealed',
            locked,
        }),
    };
}
