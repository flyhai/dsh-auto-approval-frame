// 脚本 provenance：
// 写入落地后记 path＋sha256＋来源（人批／规则放／AI 放）；执行脚本时按同 path 同 hash 查。
// 只有人批过的内容（或 AI 已看过正文并放行的写入）才让 AI 对脚本执行拍板；
// 规则自动放行的写入第一次执行仍问人，人放行后同 hash 会话内复用。
// 会话内态：重启即清，不做跨会话记忆；同 hash 只在会话内复用。
//
// 脚本正文留存（判据：只送「经手过、指纹对得上」的那份正文）：写入落地那一次，正文本来
// 就在手上（算 sha256 已经把文件读进内存），留前 SCRIPT_TEXT_CAP 字到记录里，执行时随那次
// 已有的模型调用一起送审——不额外读盘、不新增调用。留多少由证据格决定，超出部分送了也会被裁。
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const MAX_ENTRIES = 4096;
/** 证据里脚本正文那一格的上限；留更多没有意义。 */
export const SCRIPT_TEXT_CAP = 6_000;
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
        // 超过上限的部分留不下，但要记下「没留多少」——执行时照实标 partial，不假装看全了。
        const full = bytes.toString('utf8');
        return {
            hash, bytes: bytes.length,
            text: full.slice(0, SCRIPT_TEXT_CAP),
            textCut: full.length > SCRIPT_TEXT_CAP,
            textLost: Math.max(0, full.length - SCRIPT_TEXT_CAP),
        };
    }
    catch {
        return undefined;
    }
}

function pathKey(path) {
    const text = String(path ?? '');
    return process.platform === 'win32' ? text.toLowerCase() : text;
}

export function createProvenanceStore() {
    const entries = new Map();
    let textTotal = 0;
    const keyOf = (sessionId, path, hash) => `${sessionId ?? ''}\u0000${pathKey(path)}\u0000${hash}`;
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
            let text = typeof entry.text === 'string' && entry.text !== ''
                ? entry.text.slice(0, SCRIPT_TEXT_CAP)
                : undefined;
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
                source: entry.source,
                hash: entry.hash,
                at: entry.at ?? Date.now(),
                tool: entry.tool ?? null,
                bytes: entry.bytes,
                ...(text === undefined ? {} : { text }),
                // 原文比上限长：执行时只能是 partial，不许说「正文都看到了」。
                ...(text !== undefined && (entry.textCut === true || prior?.textCut === true)
                    ? { textCut: true, textLost: Math.max(entry.textLost ?? 0, prior?.textLost ?? 0) }
                    : {}),
            });
            if (entries.size > MAX_ENTRIES) {
                const oldest = entries.keys().next().value;
                textTotal -= typeof entries.get(oldest)?.text === 'string' ? entries.get(oldest).text.length : 0;
                entries.delete(oldest);
            }
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
