// 脚本 provenance：
// 写入落地后记 path＋sha256＋来源（人批／规则放／AI 放）；执行脚本时按同 path 同 hash 查。
// 只有人批过的内容（或 AI 已看过正文并放行的写入）才让 AI 对脚本执行拍板；
// 规则自动放行的写入第一次执行仍问人，人放行后同 hash 会话内复用。
// 会话内态：重启即清，不做跨会话记忆；同 hash 只在会话内复用。
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const MAX_ENTRIES = 4096;

export function contentHashOf(path) {
    try {
        const bytes = readFileSync(path);
        return { hash: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length };
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
            entries.set(key, {
                source: entry.source,
                hash: entry.hash,
                at: entry.at ?? Date.now(),
                tool: entry.tool ?? null,
                bytes: entry.bytes,
            });
            if (entries.size > MAX_ENTRIES)
                entries.delete(entries.keys().next().value);
        },
        lookup({ sessionId, path, hash }) {
            return entries.get(keyOf(sessionId, path, hash));
        },
        size() {
            return entries.size;
        },
    };
}
