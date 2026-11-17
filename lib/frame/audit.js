// L4 audit store: day-segmented, hash-chained JSONL with a manifest that
// carries a per-segment sha256 and counts, retention pruning with tombstones,
// and a verifier that checks chain, sequence and manifest in one pass.
//
// Layout (all under `dir`):
// state.json                 running pointer: sequence/lastHash/current segment
// manifest.jsonl             segment-closed / retention-pruned / audit-cleared
// verify-cache.json          per-segment memo of "these exact bytes verified so"
// YYYY-MM-DD[.N].jsonl       the entries themselves
// legacy/                    imported pre-0.5 ledger files, kept as evidence
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, closeSync, existsSync, linkSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, renameSync, rmSync, statSync, unlinkSync, writeFileSync, writeSync } from 'node:fs';
import { basename, join } from 'node:path';
import { numericDefault } from './config-defaults.js';

const GENESIS = '0'.repeat(64);
const SEGMENT_PATTERN = /^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$/;
const MANIFEST = 'manifest.jsonl';
const STATE = 'state.json';
const VERIFY_CACHE = 'verify-cache.json';
const VERIFY_CACHE_VERSION = 1;
const SCHEMA_VERSION = 1;
// A14：进程间互斥用的锁文件与耐心上限。等待总时长＝60×50ms＝3s：第一版给 1.2s，
// 在套跑与磁盘忙时会耗尽 ⇒ 一次**正常的**追加被判 lock-busy 丢掉（wiring 里表现为
// 台账少一行、断言红；单独复跑又绿＝典型偶发）。等待够久，才配说「真的抢不到」。
const LOCK_FILE = '.append.lock';
const LOCK_TRIES = 60;
const LOCK_SLEEP_MS = 50;
const LOCK_STALE_MS = 10_000;
// 建锁与写 pid 之间的真实停顿（判据 3）：空锁文件在这段窗口里**不算 stale**，
// 窗口过了才按「创建者可能崩在写之前」处理。取 15s：必须明显大于一次 append 的等待预算
// （60×50ms＋抖动≈5s），否则「等到一半窗自然过期」会被误当成可接管。
// 实测副产物（**不在本版改**，另记）：窗 15s ＞ 重试预算满额 12.58s ⇒ 若真崩在
// 写 pid 之前，紧随其后的那一次追加会等满次数后 `audit-lock-busy` 被拒、**丢掉这一条**。
// 缩短窗会与既有判据 3 断言（窗内 ok=0）直接冲突，属"改断言凑绿"，故只报不改。
const LOCK_WRITE_GRACE_MS = 15_000;

export const DECISION_TEXT = {
    allowed: '已放行', ask: '转人工确认', blocked: '已拦截', delegated: '未接管',
    approved: '已批准', rejected: '已拒绝', cancelled: '没答（取消／关窗）', unavailable: '没有应答通道',
    failed: '失败', info: '信息',
};
export const CATEGORY_TEXT = {
    tool: '工具调用', command: '命令安全', file: '文件安全', network: '网络安全',
    sensitive: '敏感保护', approval: '审批', config: '配置变更', lifecycle: '生命周期', audit: '审计',
};
export const LAYER_TEXT = {
    floor: '预设行', rules: '你的规则', fact: '事实闸', host: '宿主组合点',
    fast: 'AI 快判', deep: 'AI 深评',
    human: '人工', redact: '结果脱敏', lifecycle: '生命周期', config: '配置变更', none: '未判定',
};

export function chainHash(prevHash, bodyText) {
    return createHash('sha256').update(`${prevHash}|${bodyText}`).digest('hex');
}

export function bodyTextOf(entry) {
    const { prevHash, hash, ...rest } = entry;
    return JSON.stringify(rest);
}

const sha256 = buffer => createHash('sha256').update(buffer).digest('hex');

function dayStamp(ts) {
    const date = new Date(ts);
    return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

function parseLines(text) {
    const entries = [];
    for (const line of text.split('\n')) {
        if (line.trim() === '')
            continue;
        try {
            entries.push(JSON.parse(line));
        }
        catch {
            // A corrupt line is reported by verify; query just skips it.
        }
    }
    return entries;
}

/** One-line human rendering, used by the Markdown export. */
export function renderEntry(entry) {
    const time = new Date(entry.timestamp ?? 0).toLocaleString('zh-CN', { hour12: false });
    const parts = [
        DECISION_TEXT[entry.decision] ?? entry.decision ?? '-',
        CATEGORY_TEXT[entry.category] ?? entry.category ?? '-',
    ];
    if (entry.toolName)
        parts.push(`工具 ${entry.toolName}`);
    if (entry.commandPreview)
        parts.push(`动作 ${entry.commandPreview}`);
    // 规则路线的文案自 13:0x 起自带「命中规则…｜规则结果…」整句，不再重复挂「规则」前缀。
    if (entry.rule)
        parts.push(String(entry.rule).startsWith('命中规则') ? String(entry.rule) : `规则 ${entry.rule}`);
    if (entry.layer)
        parts.push(`层级 ${LAYER_TEXT[entry.layer] ?? entry.layer}`);
    if (entry.message)
        parts.push(`备注 ${entry.message}`);
    return `[${time}] ${parts.join(' · ')}`;
}

export function createAuditStore({ dir, now = () => Date.now(),
    maxSegmentBytes = numericDefault('maxSegmentBytes'),
    retentionDays = numericDefault('retentionDays'),
    maxTotalBytes = numericDefault('maxTotalBytes') }) {
    const statePath = join(dir, STATE);
    const manifestPath = join(dir, MANIFEST);
    const verifyCachePath = join(dir, VERIFY_CACHE);
    let state = { sequence: 0, lastHash: GENESIS, currentSegment: undefined, closedSegments: [] };
    let loaded = false;
    // A14 判据 6：落盘失败要有个**能问的地方**——上层据此决定"需批准的动作转人工"，
    // 而不是对着静默失败继续走"自动放行"。读侧拿它说"这条账现在写不下去"。
    let writable = true;

    // `2026-10-27.10.jsonl` must sort after `2026-10-27.9.jsonl`; a plain
    // string sort would put `.1` before the base segment and break the chain.
    const segmentOrder = name => {
        const match = SEGMENT_PATTERN.exec(name);
        return match === null ? name : `${match[1]}#${String(Number(match[2] ?? 0)).padStart(6, '0')}`;
    };
    const segmentFiles = () => {
        try {
            return readdirSync(dir).filter(name => SEGMENT_PATTERN.test(name))
                .sort((left, right) => segmentOrder(left).localeCompare(segmentOrder(right)));
        }
        catch {
            return [];
        }
    };

    function saveState() {
        try {
            const temporary = `${statePath}.tmp`;
            writeFileSync(temporary, JSON.stringify(state, null, 2));
            renameSync(temporary, statePath);
        }
        catch {
            // The store stays usable; verify will report a missing segment if
            // the pointer and the files diverge.
        }
    }

    function appendManifest(record) {
        try {
            mkdirSync(dir, { recursive: true });
            appendFileSync(manifestPath, `${JSON.stringify({ ...record, timestamp: record.timestamp ?? now() })}\n`);
        }
        catch {
            // Manifest writes are best effort; the segments remain authoritative.
        }
    }

    function load() {
        loaded = true;
        try {
            const parsed = JSON.parse(readFileSync(statePath, 'utf8'));
            if (Number.isFinite(parsed?.sequence) && typeof parsed?.lastHash === 'string') {
                state = {
                    sequence: parsed.sequence,
                    lastHash: parsed.lastHash,
                    currentSegment: typeof parsed.currentSegment === 'string' ? parsed.currentSegment : undefined,
                    closedSegments: Array.isArray(parsed.closedSegments) ? parsed.closedSegments.filter(name => typeof name === 'string') : [],
                };
                if (state.currentSegment !== undefined) {
                    const currentPath = join(dir, state.currentSegment);
                    // 只为对一次尾指针 ⇒ 走段尾几 KB，不把整段读进内存（50MB 段＝开机白等一趟）。
                    const tail = existsSync(currentPath) ? tailRecord(currentPath, statSync(currentPath).size) : undefined;
                    if (tail !== undefined && tail.sequence === state.sequence && tail.hash === state.lastHash)
                        return;
                }
                else if (state.currentSegment === undefined)
                    return;
            }
        }
        catch {
            // fall through to segment recovery
        }
        const files = segmentFiles();
        if (files.length === 0) {
            state = { sequence: 0, lastHash: GENESIS, currentSegment: undefined, closedSegments: [] };
            return;
        }
        const current = files[files.length - 1];
        // 恢复分支照旧整段读＋宽口径解析：末行被截断时要**跳过坏行取最后一条好行**，
        // 而段尾读（`tailRecord`）的判据是「凑不出完整末行就算看不清」——那是追加侧要的严，
        // 不是开机恢复要的宽。这条是冷路径（state.json 缺失或与段尾不符才走），不值当为它换语义。
        const entries = parseLines(readFileSync(join(dir, current), 'utf8'));
        const last = entries[entries.length - 1];
        state = {
            sequence: Number.isFinite(last?.sequence) ? last.sequence : 0,
            lastHash: typeof last?.hash === 'string' ? last.hash : GENESIS,
            currentSegment: current,
            closedSegments: files.slice(0, -1),
        };
    }

    /** * 判据 1(b) 修因：`load` 发生在**拿锁之前**，两进程同时起步时都读到
     * 「目录里没有段、序号 0」；先拿锁的建出 `day.jsonl`，后拿锁的内存里
     * `currentSegment` 仍是 undefined ⇒ `nextSegmentPath` 见 `day.jsonl` 已存在就取
     * `day.1.jsonl`；新段的尾是 absent ⇒ 拿着本进程的 0 去铸号 ⇒ 双段、两段各从 1 起、
     * 链从这里分叉（实测 3/3 轮：两个段各 1..5，verify 报 sequence-gap／prev-hash-mismatch）。
     * 拿锁之后再读一遍 state.json（只读指针，不扫段），后手才会落到同一个段、接着真尾号。
     */
    function reloadPointer() {
        try {
            const parsed = JSON.parse(readFileSync(statePath, 'utf8'));
            if (Number.isFinite(parsed?.sequence) === false || typeof parsed?.lastHash !== 'string')
                return;
            if (parsed.sequence <= state.sequence)
                return;
            state = {
                sequence: parsed.sequence,
                lastHash: parsed.lastHash,
                currentSegment: typeof parsed.currentSegment === 'string' ? parsed.currentSegment : undefined,
                closedSegments: Array.isArray(parsed.closedSegments)
                    ? parsed.closedSegments.filter(name => typeof name === 'string')
                    : state.closedSegments,
            };
        }
        catch {
            // 没有 state.json／读不清：保持本进程指针，readTail 的 fresh 分支还会兜一次。
        }
    }

    function nextSegmentPath(day) {
        let index = 0;
        let name = `${day}.jsonl`;
        while (existsSync(join(dir, name))) {
            index += 1;
            name = `${day}.${index}.jsonl`;
        }
        return join(dir, name);
    }

    function closeSegment() {
        const name = state.currentSegment;
        if (name === undefined)
            return;
        const path = join(dir, name);
        state.currentSegment = undefined;
        if (!existsSync(path)) {
            saveState();
            return;
        }
        // 一次读盘喂两件事：行数／首尾行要有条目数（口径＝可解析的行数，坏行不算，
        // 与 `verify` 的 `manifest-count` 同一把尺），段指纹也用同一份字节算——
        // 旧写法在这里读第二遍整段（一次 `readFileSync` 数行、再一次 `readFileSync` 算指纹），
        // 50MB 段就多一趟全量 IO。
        const buffer = readFileSync(path);
        const entries = parseLines(buffer.toString('utf8'));
        if (entries.length === 0) {
            rmSync(path, { force: true });
            saveState();
            return;
        }
        const first = entries[0];
        const last = entries[entries.length - 1];
        appendManifest({
            event: 'segment-closed',
            segment: name,
            entryCount: entries.length,
            firstSequence: first.sequence ?? null,
            lastSequence: last.sequence ?? null,
            firstHash: first.hash ?? null,
            lastHash: last.hash ?? null,
            fileSha256: sha256(buffer),
        });
        if (!state.closedSegments.includes(name))
            state.closedSegments.push(name);
        saveState();
        prune();
    }

    function pickSegment(ts) {
        mkdirSync(dir, { recursive: true });
        const day = dayStamp(ts);
        if (state.currentSegment !== undefined) {
            const currentPath = join(dir, state.currentSegment);
            const sameDay = state.currentSegment === `${day}.jsonl` || state.currentSegment.startsWith(`${day}.`);
            const size = existsSync(currentPath) ? statSync(currentPath).size : 0;
            if (sameDay && size < maxSegmentBytes)
                return currentPath;
            closeSegment();
        }
        const path = nextSegmentPath(day);
        state.currentSegment = basename(path);
        return path;
    }

    /** Drop whole closed segments past the age or size budget; each drop leaves a tombstone. */
    function prune() {
        try {
            const files = segmentFiles().filter(name => name !== state.currentSegment);
            if (files.length === 0)
                return;
            const nowMs = now();
            const cutoff = nowMs - Math.max(1, retentionDays) * 24 * 60 * 60 * 1000;
            const rows = files.map(name => {
                const path = join(dir, name);
                return { name, path, size: statSync(path).size, dateMs: new Date(`${name.slice(0, 10)}T00:00:00`).getTime() };
            });
            let total = rows.reduce((sum, row) => sum + row.size, 0);
            const removed = new Set();
            for (const row of rows) {
                if (Number.isFinite(row.dateMs) && row.dateMs < cutoff) {
                    removed.add(row.name);
                    total -= row.size;
                }
            }
            for (const row of rows.slice().sort((left, right) => segmentOrder(left.name).localeCompare(segmentOrder(right.name)))) {
                if (total <= maxTotalBytes)
                    break;
                if (removed.has(row.name))
                    continue;
                removed.add(row.name);
                total -= row.size;
            }
            for (const name of removed) {
                const path = join(dir, name);
                const entries = parseLines(readFileSync(path, 'utf8'));
                const last = entries[entries.length - 1];
                appendManifest({
                    event: 'retention-pruned',
                    segment: name,
                    entryCount: entries.length,
                    lastSequence: last?.sequence ?? null,
                    lastHash: last?.hash ?? null,
                    reason: 'retention',
                });
                rmSync(path, { force: true });
                state.closedSegments = state.closedSegments.filter(item => item !== name);
            }
            if (removed.size > 0)
                saveState();
        }
        catch {
            // Retention must never break an append.
        }
    }

    /** * 多实例共用同一个目录时的尾指针重读（F14）：本进程的 `state` 只在启动时读一次，
     * 第二个 profile／进程往同一条链追加后，第一个进程仍拿着旧的 sequence／lastHash——
     * 两边都会从旧尾铸号 ⇒ 重复序号、链分叉。每次追加前只读**尾部几 KB**（不整档重读，
     * 那会把 50 MB 段读成热点），尾比我们的指针新就adopt。
     *
     * A14：返回值改成**四态**——旧实现只有「有/没有」，读不到就照本进程指针写，
     * 于是「段尾看不清」和「段尾本来就不存在」被压成同一种结果 ⇒ 尾不可确认时也敢铸号。
     * 现在区分：`absent`(真的没有，可用指针)／`stale`(尾不比指针新，用指针)／`fresh`(adopt)
     * ／`unconfirmed`(有内容但末行读不清 ⇒ **不许铸号**)。
     */
    /** * 段尾 ≤8KB 里的最后一条**完整**行——`readTail`（追加前的尾比对）与 `load`
     * （开机对指针／恢复指针）共用这一把尺，都不必为了一条记录把整段读进内存。
     * 返回 `undefined`＝这一段凑不出可解析的末行（空段／起点落在半行之后没有整行／
     * 打开失败／末行不是带 sequence＋hash 的对象）⇒ 由调用方决定「看不清」怎么处理。
     */
    function tailRecord(path, size) {
        try {
            const from = Math.max(0, size - 8_192);
            const handle = openSync(path, 'r');
            let text;
            try {
                const buffer = Buffer.alloc(size - from);
                readSync(handle, buffer, 0, buffer.length, from);
                text = buffer.toString('utf8');
            }
            finally {
                closeSync(handle);
            }
            const lines = text.split('\n').filter(line => line.trim() !== '');
            if (from > 0)
                lines.shift();  // 起点落在半行上：丢掉那半行
            const last = lines[lines.length - 1];
            if (last === undefined)
                return undefined;
            const parsed = JSON.parse(last);
            return Number.isFinite(parsed?.sequence) && typeof parsed?.hash === 'string' ? parsed : undefined;
        }
        catch {
            return undefined;
        }
    }

    function readTail(path) {
        let size;
        try {
            size = statSync(path).size;
        }
        catch {
            // 查不到 size＝文件不存在（新段）；有文件却查不到 size＝拦不住的情况 ⇒ 不许铸号。
            return existsSync(path) ? { kind: 'unconfirmed' } : { kind: 'absent' };
        }
        if (size === 0)
            // 空段却带着非零指针＝有人清过这段，指针与文件已经分家 ⇒ 不可确认。
            return state.sequence > 0 ? { kind: 'unconfirmed' } : { kind: 'absent' };
        const parsed = tailRecord(path, size);
        if (parsed === undefined)
            return { kind: 'unconfirmed' };   // 有字节却凑不出一行＝读到半行，属于看不清
        return parsed.sequence > state.sequence
            ? { kind: 'fresh', sequence: parsed.sequence, hash: parsed.hash }
            : { kind: 'stale', sequence: parsed.sequence, hash: parsed.hash };
    }

    /** * A14 判据 5：追加必须互斥。旧实现「读尾 → 铸号 → append」三步之间没有锁——
     * 两个进程同时读到同一个尾 ⇒ 铸出同一个号码、链从这里分叉，`verify` 事后才发现。
     * 这里用 `<dir>/.append.lock`（`wx` 即排他创建）把三步关进一段临界区；
     * 锁文件本身带 pid 与时间戳，持有者已死或超时即视为 stale 并接管（避免一次崩溃永久卡死）。
     * @returns true 拿到锁；false 拿不到（此时调用方必须拒绝写，不得退化成"照旧写"）。
     */
    function acquireLock() {
        const lockPath = join(dir, LOCK_FILE);
        try {
            mkdirSync(dir, { recursive: true });
        }
        catch {
            return false;
        }
        for (let attempt = 0; attempt < LOCK_TRIES; attempt += 1) {
            try {
                // 判据 3：**内容先落齐再原子露面**。旧形 `openSync(wx)` 之后才写 pid，
                // 两者之间锁文件是空的——另一进程读到空锁会当 stale 删掉，竞态窗就长在这条缝里。
                // 现在写临时文件再 `linkSync`（目标已存在即 EEXIST，原子、没有空壳中间态）。
                const meta = `${JSON.stringify({ pid: process.pid, at: Number(now()) })}\n`;
                if (createLockAtomically(lockPath, meta) === true)
                    return true;
                if (isStaleLock(lockPath) === true) {
                    const stale = lockMetaOf(lockPath);
                    try {
                        rmSync(lockPath, { force: true });
                        noteLockReclaim(stale);
                        sleepSync(jitter(LOCK_SLEEP_MS / 4));   // 抢完抖一下再试，避免两边同时抢同一把失效锁
                        continue;
                    }
                    catch {
                        sleepSync(jitter(LOCK_SLEEP_MS));
                    }
                }
                else
                    sleepSync(jitter(LOCK_SLEEP_MS));
            }
            catch (error) {
                // 建不了锁＝目录不可写：直说，不偷偷退化成无锁追加。
                if (error?.code !== 'EEXIST')
                    return false;
                sleepSync(jitter(LOCK_SLEEP_MS));
            }
        }
        return false;
    }

    function releaseLock() {
        try {
            rmSync(join(dir, LOCK_FILE), { force: true });
        }
        catch {
            // 锁删不掉也要让调用方继续：下一次 acquire 会因 stale 接管它。
        }
    }

    /** * 原子建锁：先把内容写进临时文件，再 `linkSync` 到锁名（已存在即 EEXIST）。
     * 文件系统不支持硬链接（FAT／部分网络盘）时退回 `writeFileSync(flag:'wx')`——
     * 那条路仍有极小的空壳窗口，由 isStaleLock 的空锁宽限窗兜住。
     */
    function createLockAtomically(lockPath, meta) {
        const tmp = `${lockPath}.${process.pid}.${Math.floor(Math.random() * 1e9)}.tmp`;
        try {
            writeFileSync(tmp, meta);
            try {
                linkSync(tmp, lockPath);
                return true;
            }
            catch (error) {
                if (error?.code === 'EEXIST')
                    return false;
                if (['EPERM', 'ENOSYS', 'EOPNOTSUPP', 'EXDEV'].includes(String(error?.code ?? '')))
                    writeFileSync(lockPath, meta, { flag: 'wx' });
                else
                    throw error;
                return true;
            }
        }
        catch (error) {
            if (error?.code === 'EEXIST')
                return false;
            throw error;
        }
        finally {
            try {
                unlinkSync(tmp);
            }
            catch {
                // 临时文件已被消费（或环境不允许删）：不影响主流程。
            }
        }
    }

    /** 判活（判据 2）：能发 0 号信号＝活着；EPERM＝活着但无权发信号；其余（ESRCH…）＝死。 */
    function isPidAlive(pid) {
        if (Number.isInteger(pid) === false || pid <= 0)
            return false;
        if (pid === process.pid)
            return true;
        try {
            process.kill(pid, 0);
            return true;
        }
        catch (error) {
            // 只有 `ESRCH`（找不到该进程）才算死。旧写法把「非 EPERM 的一切」都当死，
            // 于是 EACCES／EINVAL／宿主代理抛的怪码都会被读成"持有者不在了"⇒ 抢活锁 ⇒
            // 并发双写。实测 audit-lock 判据 2 偶发 ok=2（活锁被抢），就是这个兜底太宽。
            // 判不准时一律当活着：宁可等一把真失效的锁，也不能抢活锁。
            return String(error?.code ?? '') !== 'ESRCH';
        }
    }

    /** * 锁是否失效：超时**且**持有者确实不在了才接管（判据 2）。只看时间戳会在
     * 「另一进程正好在长任务里」时把活锁删掉（双方互踩）；Windows 上
     * `process.kill(pid, 0)` 的异常形状按实测处理（ESRCH＝死、EPERM＝活）。
     * 空／半截锁文件给创建者 LOCK_WRITE_GRACE_MS 的宽限窗，过了才按「崩在写之前」处理。
     */
    function isStaleLock(lockPath) {
        let text;
        let info;
        try {
            text = readFileSync(lockPath, 'utf8');
            info = statSync(lockPath);
        }
        catch (error) {
            // 只有"锁文件确实不存在"才可抢。旧写法把读不到／查不到（EBUSY、EPERM、
            // 杀软占用、宿主代理抛错）也当成"可以抢"——文件明明在，却被判成没有，
            // 于是活锁被接管。实测 audit-lock 判据 3（空锁宽限窗）偶发 ok=1 就是这个口子。
            if (String(error?.code ?? '') !== 'ENOENT')
                return false;
            // 代理层偶发把存在的文件报成 ENOENT，再确认一次：还在就不算可抢。
            return existsSync(lockPath) === false;
        }
        let meta = null;
        try {
            meta = JSON.parse(text);
        }
        catch {
            meta = null;
        }
        const at = Number(meta?.at);
        if (Number.isFinite(at) === false) {
            // 空壳窗口：建锁与写 pid 之间，**不许**被读成 stale。
            return Number(now()) - Number(info.mtimeMs) > LOCK_WRITE_GRACE_MS;
        }
        const pid = Number(meta?.pid);
        if (pid === process.pid)
            return false;
        if (Number(now()) - at <= LOCK_STALE_MS)
            return false;
        return isPidAlive(pid) === false;
    }

    /** 判据 2：接管失效锁要留痕。删之前先把持有者信息读出来——删掉就查不到了。 */
    function lockMetaOf(lockPath) {
        try {
            const info = statSync(lockPath);
            let meta = null;
            try {
                meta = JSON.parse(readFileSync(lockPath, 'utf8'));
            }
            catch {
                meta = null;
            }
            const pid = Number(meta?.pid);
            const at = Number(meta?.at);
            return {
                pid: Number.isFinite(pid) ? pid : null,
                at: Number.isFinite(at) ? at : null,
                mtimeMs: Math.round(info.mtimeMs),
            };
        }
        catch {
            return { pid: null, at: null, mtimeMs: null };
        }
    }

    function noteLockReclaim(meta) {
        appendManifest({
            category: 'lifecycle',
            eventType: 'audit.lock-reclaimed',
            decision: 'info',
            layer: 'audit',
            reason: meta.pid === null ? 'empty-lock-grace-expired' : 'holder-gone',
            holderPid: meta.pid,
            holderAt: meta.at,
            lockMtimeMs: meta.mtimeMs,
            reclaimer: process.pid,
        });
    }

    function jitter(base) {
        return base + Math.floor(Math.random() * base);
    }

    function sleepSync(ms) {
        try {
            Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.max(1, ms));
        }
        catch {
            // 没有 Atomics.wait 的环境：退化为不做等待，靠重试次数兜住。
        }
    }

    function append(record) {
        try {
            if (!loaded)
                load();
            const acquired = acquireLock();
            if (acquired !== true) {
                // 拿不到锁就**不写**：宁可丢一条账，也不许写一条可能对不上链的号。
                writable = false;
                appendManifest({ category: 'lifecycle', eventType: 'audit.append-refused',
                    decision: 'info', layer: 'audit', reason: 'lock-busy' });
                return { ok: false, reason: 'audit-lock-busy', terminal: true };
            }
            try {
                // 临界区里先对齐指针——拿锁前读到的 state 可能已被前一个持锁者推走。
                reloadPointer();
                const timestamp = Number.isFinite(record?.timestamp) ? record.timestamp : now();
                const path = pickSegment(timestamp);
                const tail = readTail(path);
                if (tail.kind === 'unconfirmed') {
                    // A14 判据 5 的后半：尾确认不了 ⇒ 拒绝铸号，并给出**终态**（不是"以后再说"）。
                    writable = false;
                    appendManifest({ category: 'lifecycle', eventType: 'audit.append-refused',
                        decision: 'info', layer: 'audit', reason: 'tail-unconfirmed', segment: basename(path) });
                    return { ok: false, reason: 'tail-unconfirmed', terminal: true };
                }
                if (tail.kind === 'fresh') {
                    state.sequence = tail.sequence;
                    state.lastHash = tail.hash;
                }
                const body = { ...record, timestamp };
                delete body.id;
                delete body.schemaVersion;
                delete body.sequence;
                delete body.prevHash;
                delete body.hash;
                // A14 判据 7：四类出口（判决／交接／人工答复／最终结果）写同一条链，靠 callId 配对。
                // callId 空就写显式 null——"不知道是哪次调用"不能被写成"没有调用"。
                const callId = typeof body.callId === 'string' && body.callId !== '' ? body.callId : null;
                const line = { id: randomUUID(), schemaVersion: SCHEMA_VERSION, sequence: state.sequence + 1, ...body, callId };
                const text = JSON.stringify(line);
                const hash = chainHash(state.lastHash, text);
                appendFileSync(path, `${JSON.stringify({ ...line, prevHash: state.lastHash, hash })}\n`);
                state = { ...state, sequence: line.sequence, lastHash: hash, currentSegment: basename(path) };
                saveState();
                writable = true;
                return { ok: true, sequence: line.sequence, hash, callId };
            }
            finally {
                releaseLock();
            }
        }
        catch (error) {
            writable = false;
            return { ok: false, reason: String(error?.message ?? error), terminal: true };
        }
    }

    /** A14 判据 7：按 callId 把一次调用的四类出口捞出来，判"这一条链是否齐"由调用方做。 */
    function entriesByCallId(callId) {
        if (typeof callId !== 'string' || callId === '')
            return [];
        const out = [];
        for (const name of segmentFiles()) {
            const rows = parseLines(readFileSync(join(dir, name), 'utf8'));
            for (const row of rows) {
                // parseLines 直接返回已解析的条目数组（没有 {entry} 这一层包装）。
                // 四类出口在台账里统一写 `toolCallId`（index.js:956 判决／1060 交接／
                // 1216 人工答复／1284 最终结果），`callId` 只是内部与测试用的别名
                // ⇒ 两者都要认，否则真机数据上一条也配不上（判据 7 就成空话）。
                const id = row?.callId ?? row?.toolCallId;
                if (id !== undefined && id !== null && String(id) === callId)
                    out.push(row);
            }
        }
        return out;
    }

    // 段名就是日期 ⇒ 带 `from`／`to` 的筛选可以整段跳过，不在区间里的字节不必进内存。
    // 判据保守：算不出这一段的日期（非标准段名）就当它在区间内，照旧读。
    function segmentOutsideRange(name, filters) {
        const match = SEGMENT_PATTERN.exec(name);
        if (match === null)
            return false;
        const date = new Date(Number(match[1].slice(0, 4)), Number(match[1].slice(5, 7)) - 1, Number(match[1].slice(8, 10)));
        const dayStart = date.getTime();
        const dayEnd = new Date(date.getFullYear(), date.getMonth(), date.getDate() + 1).getTime();
        if (Number.isFinite(filters.to) && filters.to < dayStart)
            return true;
        if (Number.isFinite(filters.from) && filters.from >= dayEnd)
            return true;
        return false;
    }

    function readAll(filters = {}) {
        const files = segmentFiles().filter(name => segmentOutsideRange(name, filters) === false);
        const entries = [];
        for (const name of files) {
            try {
                entries.push(...parseLines(readFileSync(join(dir, name), 'utf8')));
            }
            catch {
                // verify reports the unreadable segment.
            }
        }
        return entries;
    }

    // 筛选谓词的唯一所有者：`query` 的融合遍历与 `filterEntries`、`exportText` 都走它，
    // 免得「页面看到的」与「计数算的」长两副面孔。
    function prepareFilters(filters = {}) {
        const keyword = typeof filters.q === 'string' ? filters.q.trim().toLowerCase() : '';
        // 会话标签只认自己那一本账：判据是逐字相等，不是「包含」——会话 id 是整串，
        // 前缀相同是另一场会话。没有会话的记录（启动／配置变更）不属于任何会话，一律不进来。
        const sessionId = typeof filters.sessionId === 'string' ? filters.sessionId.trim() : '';
        const hidden = Array.isArray(filters.hide)
            ? filters.hide
            : (typeof filters.hide === 'string' ? filters.hide.split(',').map(item => item.trim()).filter(Boolean) : []);
        return entry => {
            if (sessionId !== '' && String(entry.sessionId ?? '') !== sessionId)
                return false;
            if (hidden.includes(entry.eventType))
                return false;
            if (Number.isFinite(filters.from) && entry.timestamp < filters.from)
                return false;
            if (Number.isFinite(filters.to) && entry.timestamp > filters.to)
                return false;
            if (typeof filters.decision === 'string' && filters.decision !== '' && entry.decision !== filters.decision)
                return false;
            // 层级是「谁判的」：AI 快判／AI 深评／预设行／你的规则……。一次调用里各行层级不同，
            // 所以它只能单独筛，不能折进 decision 里。
            if (typeof filters.layer === 'string' && filters.layer !== '' && entry.layer !== filters.layer)
                return false;
            if (typeof filters.category === 'string' && filters.category !== '' && entry.category !== filters.category)
                return false;
            if (keyword !== '') {
                const haystack = [entry.toolName, entry.commandPreview, entry.message, entry.rule,
                    Array.isArray(entry.reasons) ? entry.reasons.join(' ') : '', entry.eventType]
                    .filter(Boolean).join(' ').toLowerCase();
                if (!haystack.includes(keyword))
                    return false;
            }
            return true;
        };
    }

    function filterEntries(entries, filters = {}) {
        const passes = prepareFilters(filters);
        return entries.filter(entry => passes(entry));
    }

    /** * 一次调用在账本里是多行（命中→判定→答复→结果）。页面按调用折成一张卡，
     * 计数也必须同一口径，否则卡片数与「共 N 条」对不上（一条审批算一个）。
     * 折键与页面 groupEntries 逐字相同：`toolCallId` 优先，其次 `actionHash`；
     * 两个都没有的簿记行（启动／清空）各自算一条。
     */
    const approvalKeyOf = entry => entry?.toolCallId ?? entry?.actionHash;

    function groupApprovals(entries) {
        const groups = [];
        const at = new Map();
        for (const entry of entries) {
            const key = approvalKeyOf(entry);
            if (key === undefined || key === null) {
                groups.push([entry]);
                continue;
            }
            const found = at.get(key);
            if (found !== undefined) {
                groups[found].push(entry);
                continue;
            }
            at.set(key, groups.length);
            groups.push([entry]);
        }
        return groups;
    }

    /** 与 `groupApprovals(...).length` 逐字同口径，但不建二维数组（「共 N 条」只要个数）。 */
    function countApprovals(entries) {
        const keys = new Set();
        let keyless = 0;
        for (const entry of entries) {
            const key = approvalKeyOf(entry);
            if (key === undefined || key === null)
                keyless += 1;
            else
                keys.add(key);
        }
        return keys.size + keyless;
    }

    function query(filters = {}) {
        const offset = Number.isInteger(filters.offset) && filters.offset > 0 ? filters.offset : 0;
        const limit = Number.isInteger(filters.limit) && filters.limit > 0 ? Math.min(filters.limit, 500) : 50;
        // 「全机共 N 条」是全账口径（界面原话＝`全机共 ${total} 条审批`），带日期筛选时也不许
        // 缩成区间内 ⇒ 这里必须读全量；省下来的只有第二遍二维分组（改走 `countApprovals`）。
        const all = readAll();
        // 分页按「组」走：同一调用的几行必须留在同一页，不能被截成半张卡。
        // 组内仍按旧的「新→旧」给行：recent 与按 callId 取末态的都靠这个顺序。
        const groups = groupApprovals(filterEntries(all, filters)).reverse();
        return {
            entries: groups.slice(offset, offset + limit).flatMap(group => group.slice().reverse()),
            matched: groups.length,
            total: countApprovals(all),
            segments: segmentFiles().length,
        };
    }

    function exportText(filters = {}, format = 'jsonl') {
        const rows = filterEntries(readAll(filters), filters);
        if (format === 'md')
            return `${rows.map(renderEntry).join('\n')}\n`;
        return `${rows.map(entry => JSON.stringify(entry)).join('\n')}\n`;
    }

    // verify 的段内结论＝这一段字节的纯函数 ⇒ 文件 sha256 逐字没变就能原样复用
    //（已封段不再变＝命中；当天段每次新写入都变＝不命中，照旧全走这一段）。
    // 不能复用的只有**段与段的接头**：那比的是前一段的链尾 ⇒ 命中分支照样现比。
    // 缓存被伪造也不比全量重走更弱：篡改者要连文件带缓存写成自洽的一条新链，
    // 而全量 verify 对「整条链被一致改写」同样查不出（没有外部锚）。
    function readVerifyCache() {
        let raw;
        try {
            raw = readFileSync(verifyCachePath, 'utf8');
        }
        catch {
            return { raw: undefined, segments: {} };
        }
        try {
            const parsed = JSON.parse(raw);
            if (parsed?.version !== VERIFY_CACHE_VERSION || (parsed.segments ?? null) === null)
                return { raw: undefined, segments: {} };
            return { raw, segments: parsed.segments };
        }
        catch {
            return { raw: undefined, segments: {} };
        }
    }

    function writeVerifyCache(previousRaw, segments) {
        const text = JSON.stringify({ version: VERIFY_CACHE_VERSION, segments });
        if (previousRaw === text)
            return;
        try {
            // 先落临时文件再改名 ⇒ 读者只会看到整份旧或整份新（同 append 的写法）。
            const tmp = `${verifyCachePath}.tmp`;
            writeFileSync(tmp, text);
            renameSync(tmp, verifyCachePath);
        }
        catch {
            // 加速件写不进去就这次不缓存，verify 的结论不受影响。
        }
    }

    function verify() {
        const issues = [];
        const files = segmentFiles();
        const manifest = new Map();
        try {
            for (const record of parseLines(readFileSync(manifestPath, 'utf8')))
                if (typeof record?.segment === 'string')
                    manifest.set(record.segment, record);
        }
        catch {
            // A missing manifest is reported per segment below.
        }
        const ordered = [...new Set([...manifest.keys(), ...files])]
            .sort((left, right) => segmentOrder(left).localeCompare(segmentOrder(right)));
        const cache = readVerifyCache();
        const nextSegments = {};
        let reused = 0;
        let prevHash = GENESIS;
        let prevSequence = 0;
        let lines = 0;
        // 尾指针要跟**落盘的** state.json 比，不能跟本实例内存里的指针比——
        // 多实例交错写时内存指针天然落后一格，那样比出来的是假阳性（我自己第一版就踩了）。
        // 它取决于 state.json 的当下内容，不是段字节的函数 ⇒ **两条路径都现查，绝不进缓存**。
        const tailCheck = (name, last) => {
            if (last === null || last === undefined)
                return;
            let persisted;
            try {
                persisted = JSON.parse(readFileSync(statePath, 'utf8'));
            }
            catch {
                return;
            }
            if (persisted?.currentSegment !== name || !Number.isFinite(persisted.sequence))
                return;
            // 尾指针与文件末尾对不上＝有人半路写坏了（末行被截断、外部改过段文件、
            // 或 state.json 没写成功）。这一格只有在这里查得出来，序号连续性查不到"最后一条"。
            if (last.sequence !== persisted.sequence || last.hash !== persisted.lastHash)
                issues.push({
                    type: 'tail-pointer-mismatch', segment: name,
                    expected: `${persisted.sequence}/${String(persisted.lastHash).slice(0, 8)}`,
                    actual: `${last.sequence}/${String(last.hash).slice(0, 8)}`,
                });
        };
        // 段间接头＝本段第一条接不接得上**前一段的链尾**。它不是本段字节的函数
        //（前一段被改写时接头就变了）⇒ 命中缓存也现比，且绝不写进缓存的 issues。
        // 必须在走链之前调用：走链会把 prev 推进到本段末尾。
        const linkCheck = (name, head) => {
            if (head === null || head === undefined)
                return;
            if (head.sequence !== prevSequence + 1)
                issues.push({ type: 'sequence-gap', segment: name, sequence: head.sequence, expected: prevSequence + 1 });
            if (head.prevHash !== prevHash)
                issues.push({ type: 'prev-hash-mismatch', segment: name, sequence: head.sequence });
        };
        for (const name of ordered) {
            const path = join(dir, name);
            const record = manifest.get(name);
            if (!existsSync(path)) {
                if (record?.event === 'retention-pruned') {
                    prevHash = record.lastHash ?? prevHash;
                    prevSequence = record.lastSequence ?? prevSequence;
                    continue;
                }
                if (record?.event !== 'audit-cleared')
                    issues.push({ type: 'missing-segment', segment: name });
                continue;
            }
            // 一次 read 喂两件事（段指纹与逐行走链），不再读两遍整段。
            const buffer = readFileSync(path);
            const sha = sha256(buffer);
            const memo = cache.segments[name];
            const segIssues = [];
            let count;
            let first;
            let last;
            if (memo?.fileSha256 === sha) {
                count = memo.count;
                first = memo.first;
                last = memo.last;
                linkCheck(name, first);
                issues.push(...(memo.issues ?? []));
                nextSegments[name] = memo;
                reused += 1;
            }
            else {
                const raw = buffer.toString('utf8');
                // 坏行以前只被 `parseLines` 悄悄丢掉：丢掉的那行若是段尾最后一条，
                // 序号没有"下一行"去跳、哈希也没人算 ⇒ `verify.ok` 照样为真，账面看起来是完整的
                //（F14）。这里逐行数一次原始行，把解析不出来的行按位置报出来，
                // 并把它计入"这一段少了多少条"。
                let position = 0;
                for (const line of raw.split('\n')) {
                    position += 1;
                    if (line.trim() === '')
                        continue;
                    try {
                        JSON.parse(line);
                    }
                    catch {
                        segIssues.push({ type: 'corrupt-line', segment: name, line: position });
                    }
                }
                const entries = parseLines(raw);
                count = entries.length;
                first = count > 0 ? { sequence: entries[0].sequence, prevHash: entries[0].prevHash } : null;
                last = count > 0 ? { sequence: entries[count - 1].sequence, hash: entries[count - 1].hash } : null;
                linkCheck(name, first);
                let index = 0;
                for (const entry of entries) {
                    // 段首那条已由 linkCheck 比过（跨段事实，不进缓存）；
                    // 段内每条比的是本文件自己记的 prevHash／hash＝本段字节的纯函数 ⇒ 进缓存。
                    if (index > 0) {
                        if (entry.sequence !== prevSequence + 1)
                            segIssues.push({ type: 'sequence-gap', segment: name, sequence: entry.sequence, expected: prevSequence + 1 });
                        if (entry.prevHash !== prevHash)
                            segIssues.push({ type: 'prev-hash-mismatch', segment: name, sequence: entry.sequence });
                    }
                    if (chainHash(entry.prevHash, bodyTextOf(entry)) !== entry.hash)
                        segIssues.push({ type: 'hash-mismatch', segment: name, sequence: entry.sequence });
                    prevHash = entry.hash;
                    prevSequence = entry.sequence;
                    index += 1;
                }
                issues.push(...segIssues);
                nextSegments[name] = { fileSha256: sha, count, first, last, issues: segIssues };
            }
            if (record?.event === 'segment-closed') {
                if (sha !== record.fileSha256)
                    issues.push({ type: 'manifest-sha256', segment: name });
                if (count !== record.entryCount)
                    issues.push({ type: 'manifest-count', segment: name, expected: record.entryCount, actual: count });
                if (last?.hash !== record.lastHash)
                    issues.push({ type: 'manifest-last-hash', segment: name });
            }
            tailCheck(name, last);
            lines += count;
            if (last !== null && last !== undefined) {
                prevHash = last.hash;
                prevSequence = last.sequence;
            }
        }
        writeVerifyCache(cache.raw, nextSegments);
        // 「链在第 N 处断了」要的是**序号**：界面读 `chain.brokenAt`，而这个字段此前
        // 从没被产出过（坏的时候永远显示 `?`）。三类断链里取第一条命中的序号。
        const broken = issues.find(issue => issue.type === 'sequence-gap'
            || issue.type === 'prev-hash-mismatch' || issue.type === 'hash-mismatch');
        return {
            ok: issues.length === 0,
            issues: issues.slice(0, 20),
            brokenAt: broken?.sequence ?? null,
            lines,
            segments: files.length,
            verifyReused: reused,
        };
    }

    function clear() {
        const files = segmentFiles();
        const entries = readAll();
        const previous = { entries: entries.length, segments: files.length, lastSequence: state.sequence, lastHash: state.lastHash };
        for (const name of files) {
            try {
                rmSync(join(dir, name), { force: true });
            }
            catch {
                // A locked segment stays; the cleared marker still records intent.
            }
        }
        // The manifest belongs to the cleared chain; a lone marker keeps the
        // fact (counts + tail hash) without leaving verify chasing dead files.
        try {
            rmSync(manifestPath, { force: true });
        }
        catch {
            // Manifest is best effort.
        }
        appendManifest({
            event: 'audit-cleared',
            clearedSegments: files,
            clearedEntries: previous.entries,
            lastSequence: previous.lastSequence,
            lastHash: previous.lastHash,
        });
        state = { sequence: 0, lastHash: GENESIS, currentSegment: undefined, closedSegments: [] };
        saveState();
        append({
            category: 'audit',
            eventType: 'audit.clear',
            decision: 'info',
            layer: 'human',
            clearedEntries: previous.entries,
            clearedSegments: previous.segments,
            message: `清空本机审计：${previous.entries} 条 / ${previous.segments} 段（清空前链尾 ${String(previous.lastHash).slice(0, 12)}…）`,
        });
    }

    /** Import a pre-0.5 single-file ledger, keeping its bytes as evidence. */
    function migrateLegacy(legacyPath) {
        try {
            if (!existsSync(legacyPath))
                return { ok: true, imported: 0 };
            const buffer = readFileSync(legacyPath);
            const rows = parseLines(buffer.toString('utf8'));
            const sha = sha256(buffer);
            let imported = 0;
            for (const row of rows) {
                const mapped = mapLegacyRow(row);
                if (mapped === undefined)
                    continue;
                const written = append(mapped);
                if (written.ok !== false)
                    imported += 1;
            }
            append({
                category: 'lifecycle',
                eventType: 'lifecycle.migrate',
                decision: 'info',
                layer: 'lifecycle',
                legacySha256: sha,
                legacyLines: rows.length,
                imported,
                message: `导入旧台账 ${imported} 条（原文件 sha256 ${sha.slice(0, 12)}…）`,
            });
            const legacyDir = join(dir, 'legacy');
            mkdirSync(legacyDir, { recursive: true });
            renameSync(legacyPath, join(legacyDir, `decisions-${dayStamp(now())}-${sha.slice(0, 8)}.jsonl`));
            return { ok: true, imported, legacyLines: rows.length, sha256: sha };
        }
        catch (error) {
            return { ok: false, reason: String(error?.message ?? error) };
        }
    }

    return {
        paths: { dir, statePath, manifestPath },
        append,
        query,
        exportText,
        verify,
        clear,
        prune,
        migrateLegacy,
        // A14 新增：写侧终态供上层判"要不要转人工"（判据 6）；按次调用配对四类出口（判据 7）。
        writable: () => writable,
        entriesByCallId,
    };
}

function mapLegacyRow(row) {
    if (row === null || typeof row !== 'object')
        return undefined;
    const timestamp = Number.isFinite(row.at) ? row.at : undefined;
    if (row.event === 'boot') {
        return {
            timestamp,
            category: 'lifecycle',
            eventType: 'lifecycle.boot',
            decision: 'info',
            layer: 'lifecycle',
            message: typeof row.summary === 'string' ? row.summary : '启动',
            source: 'migration',
            legacySequence: row.sequence,
        };
    }
    if (row.event === 'human-answer') {
        return {
            timestamp,
            category: 'approval',
            eventType: 'approval.answer',
            decision: row.outcome === 'approved' ? 'approved' : 'rejected',
            layer: 'human',
            toolName: row.toolName,
            message: typeof row.summary === 'string' ? row.summary : undefined,
            source: 'migration',
            legacySequence: row.sequence,
        };
    }
    if (row.event !== 'decision')
        return undefined;
    const outcome = String(row.outcome ?? '');
    const decision = outcome.startsWith('unable:') ? 'failed'
        : outcome === 'block' ? 'blocked'
            : outcome === 'ask' ? 'ask' : 'allowed';
    return {
        timestamp,
        category: 'tool',
        eventType: `tool.${decision}`,
        decision,
        layer: row.decidedBy === 'ai' ? 'deep' : 'floor',
        toolName: row.toolName,
        commandPreview: typeof row.action === 'string' ? row.action : undefined,
        grant: row.grant,
        reasons: Array.isArray(row.reasons) ? row.reasons : [],
        targets: Array.isArray(row.targets) ? row.targets : [],
        decidedBy: row.decidedBy,
        reasonCode: row.reasonCode,
        durationMs: row.durationMs,
        message: typeof row.summary === 'string' ? row.summary : undefined,
        source: 'migration',
        legacySequence: row.sequence,
    };
}
