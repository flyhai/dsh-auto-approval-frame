// 脚本 provenance：
// 写入落地后记 path＋sha256＋来源（人批／规则放／AI 放）；执行脚本时按同 path 同 hash 查。
// 只有人批过的内容（或 AI 已看过正文并放行的写入）才让 AI 对脚本执行拍板；
// 规则自动放行不升成人批，但执行时正文可见仍交给 AI 判；同 hash 在会话内复用。
//
// 元数据（path／hash／source／at）跨进程重启保留：DSH 重启后仍是同一会话 ID 时，
// 脚本没改就能重新算到同一 hash，正文再按当前磁盘内容读一次给评审。
// 正文本身不落盘（脚本可能有敏感内容），只活在本进程内存里；新会话仍不复用。
//
// 脚本正文留存（判据：只送「经手过、指纹对得上」的那份正文）：写入落地那一次，正文本来
// 就在手上（算 sha256 已经把文件读进内存），留一份到记录里，执行时随那次已有的模型调用
// 一起送审——不额外读盘、不新增调用。重启后没有内存正文，则按同一指纹从磁盘重读。
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const MAX_ENTRIES = 4096;
/** 整会话留存的正文总量上限：到顶就不再留，后来的按「没留」处理（转人工）。 */
const MAX_TEXT_TOTAL = 8 * 1024 * 1024;
/** 只有这些扩展名才算「脚本」，别的文件一个字都不留。 */
const SCRIPT_EXTENSIONS = new Set([
    '.py', '.pyw', '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.js', '.mjs', '.cjs', '.ts', '.rb', '.pl', '.php', '.lua', '.r',
]);

export function isScriptPath(path) {
    const text = String(path ?? '');
    const at = text.lastIndexOf('.');
    return at >= 0 && SCRIPT_EXTENSIONS.has(text.slice(at).toLowerCase());
}

export function contentHashOf(path, options) {
    try {
        const bytes = readFileSync(path);
        const hash = createHash('sha256').update(bytes).digest('hex');
        if (options?.withText !== true)
            return { hash, bytes: bytes.length };
        // 同一次读里顺手留正文（不是第二次读盘）：指纹与正文出自同一份字节，天然同源。
        // 不在这里按字数截——留存只吃内存，送不送、送多少由证据层按总预算判：
        // 装得下就整份送，装不下就整份不送。留存先掐尾等于替证据层做决定，而它本来可能装得下。
        const full = bytes.toString('utf8');
        return { hash, bytes: bytes.length, text: full };
    }
    catch {
        return undefined;
    }
}

function pathKey(path) {
    const text = String(path ?? '');
    return process.platform === 'win32' ? text.toLowerCase() : text;
}

export function createProvenanceStore({ dir } = {}) {
    const file = dir === undefined ? undefined : join(dir, 'script-provenance.json');
    const entries = new Map();
    let textTotal = 0;
    const keyOf = (sessionId, path, hash) => `${sessionId ?? ''}\u0000${pathKey(path)}\u0000${hash}`;
    const load = () => {
        if (file === undefined)
            return;
        let parsed;
        try {
            parsed = JSON.parse(readFileSync(file, 'utf8'));
        }
        catch {
            return;
        }
        for (const row of Array.isArray(parsed?.entries) ? parsed.entries : []) {
            if (row === null || typeof row !== 'object' || row.path === undefined || row.hash === undefined)
                continue;
            if (entries.size >= MAX_ENTRIES)
                break;
            const sessionId = row.sessionId ?? '';
            entries.set(keyOf(sessionId, row.path, row.hash), {
                sessionId,
                path: row.path,
                source: row.source,
                hash: row.hash,
                at: row.at ?? Date.now(),
                tool: row.tool ?? null,
                bytes: row.bytes,
            });
        }
    };
    const save = () => {
        if (file === undefined)
            return;
        const temp = `${file}.${process.pid}.${Date.now()}.tmp`;
        try {
            mkdirSync(dirname(file), { recursive: true });
            const rows = [...entries.values()].map(entry => ({
                sessionId: entry.sessionId ?? '',
                path: entry.path,
                hash: entry.hash,
                source: entry.source,
                at: entry.at,
                tool: entry.tool,
                bytes: entry.bytes,
            }));
            writeFileSync(temp, JSON.stringify({ version: 1, entries: rows }), 'utf8');
            renameSync(temp, file);
        }
        catch {
            try {
                unlinkSync(temp);
            }
            catch {}
        }
    };
    load();
    return {
        record(entry) {
            if (entry === null || entry === undefined || entry.path === undefined || entry.hash === undefined)
                return;
            const key = keyOf(entry.sessionId, entry.path, entry.hash);
            const prior = entries.get(key);
            // 人批过的事实不被「规则放／AI 放」降级；反过来，人批覆盖同 hash 的任何旧来源。
            if (prior?.source === 'human' && entry.source !== 'human')
                return;
            const priorText = typeof prior?.text === 'string' ? prior.text : undefined;
            let text = typeof entry.text === 'string' && entry.text !== '' ? entry.text : undefined;
            // 后一条记录不带正文时（例如人批执行的落地记录）沿用前一条留下的那份，不抹掉。
            if (text === undefined)
                text = priorText;
            if (text !== undefined) {
                const grew = text.length - (priorText?.length ?? 0);
                if (textTotal + grew > MAX_TEXT_TOTAL) {
                    // 到顶：不留，按「没留」处理——执行时照旧问人，不假装看过。
                    textTotal -= priorText?.length ?? 0;
                    text = undefined;
                }
                else
                    textTotal += grew;
            }
            entries.set(key, {
                sessionId: entry.sessionId ?? '',
                path: entry.path,
                source: entry.source,
                hash: entry.hash,
                at: entry.at ?? Date.now(),
                tool: entry.tool ?? null,
                bytes: entry.bytes,
                ...(text === undefined ? {} : { text }),
            });
            if (entries.size > MAX_ENTRIES) {
                const oldest = entries.keys().next().value;
                textTotal -= typeof entries.get(oldest)?.text === 'string' ? entries.get(oldest).text.length : 0;
                entries.delete(oldest);
            }
            save();
        },
        lookup({ sessionId, path, hash }) {
            return entries.get(keyOf(sessionId, path, hash));
        },
        size() {
            return entries.size;
        },
        textChars() {
            return textTotal;
        },
    };
}
