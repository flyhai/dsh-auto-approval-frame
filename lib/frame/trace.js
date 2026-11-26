// 判定存根：给「为什么这么判」留一份能查的现场。
//
// 台账回答「发生了什么」（碰了哪些文件、命中哪条行、最后问没问人），不回答「为什么」。
// 判定中间结论——每个目标被判成读还是写、依据是脚本正文还是兜底默认——算完就丢了，
// 于是排查只能靠反推（两条同形命令给出相反结论，排查很费时间）。
//
// 这里的取舍：
//   1. 只在「走了弯路」时写（问人／被拒），放行的判定不写——大部分时候一条都不落。
//   2. 只留三天。排查窗口就是今天和昨天出的问题，更早的没有价值。
//   3. 不进台账、不进导出、不进哈希链。它是排查材料，不是审计证据。
//   4. 与台账分工：台账存结论与评审侧（决策、拦截点、评审引用与校验、证据账），按
//      会话＋调用编号关联；存根只存台账缺的输入侧——分段、目标判定、命中行文字、
//      送审实际带上的卡与实际送入的用户原话。不存脚本正文、不存密钥；所有文本过
//      调用方给的 `safe`（与台账同一个 `ledgerSafe`，遮掉已知密钥）。
//   5. 写失败一律吞掉：存根坏了不许影响判定本身。
import { existsSync, mkdirSync, readdirSync, readFileSync, appendFileSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';

const TRACE_DIR = 'trace';
const KEEP_DAYS = 3;

const dayOf = (at = Date.now()) => {
    const d = new Date(at);
    const pad = n => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
};

/** 这次判定值不值得留现场：放行／交给下游的不留，问人与被拒的留。 */
export function traceWorthy({ decision, releaseBlockers }) {
    if (Array.isArray(releaseBlockers) && releaseBlockers.length > 0)
        return true;
    return decision === 'ask' || decision === 'blocked';
}

/** 删掉超出保留期的存根（按文件名日期，删的是整天，不做逐行裁剪）。 */
export function pruneTraces(stateDir, keepDays = KEEP_DAYS) {
    const dir = join(stateDir, TRACE_DIR);
    if (!existsSync(dir))
        return 0;
    const cutoff = dayOf(Date.now() - keepDays * 86_400_000);
    let removed = 0;
    for (const name of readdirSync(dir)) {
        if (!/^\d{4}-\d{2}-\d{2}\.jsonl$/.test(name))
            continue;
        if (name.slice(0, 10) >= cutoff)
            continue;
        try {
            unlinkSync(join(dir, name));
            removed += 1;
        }
        catch {}
    }
    return removed;
}

/**
 * 写一条判定存根。`safe` 由调用方给（与台账同一套脱敏）；其余字段全部是判定链的现成产物。
 * 返回写入的路径，写不成返回空串——调用方不需要关心。
 */
export function writeTrace(stateDir, entry, safe = value => String(value ?? '')) {
    try {
        const dir = join(stateDir, TRACE_DIR);
        mkdirSync(dir, { recursive: true });
        const at = Number(entry?.at ?? Date.now());
        // 与台账的分工：台账存结论与评审侧（决策、拦截点、评审引用与校验、证据账），
        // 按 会话＋调用编号 关联；存根只存台账没有的输入侧，不复制、不成第二本账。
        const cardOf = value => {
            if (value === null || value === undefined || typeof value !== 'object')
                return null;
            const out = {};
            let count = 0;
            for (const field of ['canDo', 'where', 'cannot', 'separate']) {
                const items = Array.isArray(value[field]) ? value[field] : [];
                out[field] = items.slice(0, 12).map(item => ({
                    text: safe(String(item?.text ?? '')).slice(0, 200),
                    quote: safe(String(item?.quote ?? '')).slice(0, 500),
                }));
                count += out[field].length;
            }
            return count === 0 ? null : out;
        };
        const row = {
            v: 2,
            at,
            session: safe(entry?.session ?? ''),
            call: safe(entry?.call ?? ''),
            actionHash: safe(entry?.actionHash ?? ''),
            // 台账深评行不存命中行文字，这里补；其余结论回台账取。
            rule: safe(entry?.rule ?? ''),
            // 段：程序、动作、执行族。段数通常 < 8，超了截断——存根是排查用，不是全量快照。
            segments: (Array.isArray(entry?.segments) ? entry.segments : []).slice(0, 12).map(item => ({
                i: Number(item?.i ?? 0),
                prog: safe(item?.prog ?? ''),
                op: safe(item?.op ?? ''),
                family: safe(item?.family ?? ''),
            })),
            // 目标：台账只存路径数组；读／写／删、根、依据只有这里有。
            targets: (Array.isArray(entry?.targets) ? entry.targets : []).slice(0, 24).map(item => ({
                path: safe(item?.path ?? ''),
                op: safe(item?.op ?? ''),
                role: safe(item?.role ?? ''),
                root: safe(item?.root ?? ''),
                why: safe(item?.why ?? ''),
                dynamic: item?.dynamic === true,
                identity: safe(item?.identity ?? ''),
            })),
            // 送审实际带上的卡（每格摘要与原话成对）与实际送入的用户原话：
            // 依据校验就是拿这两份比，台账不存，缺了只能反推。
            card: cardOf(entry?.card),
            userWords: safe(String(entry?.userWords ?? '')).slice(0, 4000),
        };
        const file = join(dir, `${dayOf(at)}.jsonl`);
        appendFileSync(file, `${JSON.stringify(row)}\n`, 'utf8');
        pruneTraces(stateDir);
        return file;
    }
    catch {
        return '';
    }
}

/** 读某一天的存根（排查入口用）。 */
export function readTraces(stateDir, day = dayOf()) {
    const file = join(stateDir, TRACE_DIR, `${day}.jsonl`);
    if (!existsSync(file))
        return [];
    const rows = [];
    for (const line of readFileSync(file, 'utf8').split('\n')) {
        if (line.trim() === '')
            continue;
        try {
            rows.push(JSON.parse(line));
        }
        catch {}
    }
    return rows;
}
