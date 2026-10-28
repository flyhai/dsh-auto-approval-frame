// 明文↔token 映射表。可逆脱敏必然在本机多落一份明文——这是这一档换来的代价，
// 所以围着它有四条限制：只落插件自己的状态目录（`secrets.json`）、上限 200 条、
// 30 天不用就丢、台账里永远只写 token 与字符数（绝不写明文）。
//
// token ＝ `[[SEC-` ＋ HMAC(pepper, 明文) 前 12 位 ＋ `]]`。pepper 与表同目录，
// 所以即便有人拿到别人的凭据也算不出我们表里的 token；删掉 pepper 文件＝整表作废。
// Windows 上 chmod 基本是空操作，不要把它当防线：这一档的保护是「不外传、不进台账、
// 可随时一键清空」，不是「操作系统级加密」。
import { createHmac, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { TOKEN_PATTERN } from './sensitive.js';

const FILE = 'secrets.json';
const MAX_ENTRIES = 200;
const TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TOKEN_CHARS = 12;

const TOKENIZE_LIMIT = 64 * 1024;

export function createSecretVault({ dir, now = () => Date.now() }) {
    const path = join(dir, FILE);
    let state = load();

    function load() {
        try {
            const raw = JSON.parse(readFileSync(path, 'utf8'));
            if (typeof raw?.pepper !== 'string' || !Array.isArray(raw.entries))
                throw new Error('bad shape');
            return { pepper: raw.pepper, entries: raw.entries };
        }
        catch {
            // 读不出来＝重新生成 pepper：旧 token 全部作废（换不回明文），
            // 但绝不拿空表去覆盖一份好表以外的东西。
            return { pepper: randomBytes(32).toString('hex'), entries: [] };
        }
    }

    function save() {
        mkdirSync(dir, { recursive: true });
        const tmp = `${path}.${process.pid}.tmp`;
        // mode 只在支持它的文件系统上有意义（Windows 上基本是空操作）：
        // 这一档真正的保护是不外传、不进台账、可一键清空，不要把它当加密。
        try {
            writeFileSync(tmp, `${JSON.stringify(state, null, 1)}\n`, { mode: 0o600 });
        }
        catch {
            writeFileSync(tmp, `${JSON.stringify(state, null, 1)}\n`);
        }
        renameSync(tmp, path);
    }

    function tokenFor(plain) {
        return `[[SEC-${createHmac('sha256', state.pepper).update(plain).digest('hex').slice(0, TOKEN_CHARS)}]]`;
    }

    function prune() {
        const stamp = now();
        state.entries = state.entries
            .filter(entry => stamp - entry.lastAt <= TTL_MS)
            .sort((a, b) => b.lastAt - a.lastAt)
            .slice(0, MAX_ENTRIES);
    }

    /** 登记一段明文，回它对应的确定性 token（同明文同 token，重复命中只加次数）。 */
    function register(plain, { detector = 'custom', label = '', source = '' } = {}) {
        const text = String(plain ?? '');
        if (text === '' || text.length > TOKENIZE_LIMIT || isKnownToken(text))
            return undefined;
        const token = tokenFor(text);
        const stamp = now();
        const existing = state.entries.find(entry => entry.token === token);
        if (existing === undefined) {
            state.entries.push({
                token, detector, label, plain: text, chars: text.length,
                at: stamp, lastAt: stamp, hits: 1, restore: true, source,
            });
        }
        else {
            existing.lastAt = stamp;
            existing.hits += 1;
            if (existing.label !== label || existing.source === '') {
                existing.label = label || existing.label;
                existing.source = source || existing.source;
            }
        }
        prune();
        save();
        return token;
    }

    function isKnownToken(text) {
        return typeof text === 'string' && new RegExp(`^${TOKEN_PATTERN.source}$`).test(text);
    }

    function entryOf(token) {
        return state.entries.find(entry => entry.token === token);
    }

    function plainOf(token) {
        const entry = entryOf(token);
        if (entry === undefined)
            return undefined;
        entry.lastAt = now();
        entry.hits += 1;
        save();
        return entry.plain;
    }

    /** 页面用的形状：明文默认不出表（`reveal` 单条要点开才给）。 */
    function list() {
        prune();
        return state.entries
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

    function remove(token) {
        const before = state.entries.length;
        state.entries = state.entries.filter(entry => entry.token !== token);
        save();
        return before !== state.entries.length;
    }

    function clear() {
        const cleared = state.entries.length;
        // 换 pepper：即便有残留副本，旧 token 也再也换不出明文。
        state = { pepper: randomBytes(32).toString('hex'), entries: [] };
        save();
        return cleared;
    }

    function restoreText(text) {
        const value = typeof text === 'string' ? text : String(text ?? '');
        const restored = [];
        const replaced = value.replace(new RegExp(TOKEN_PATTERN.source, 'g'), (token) => {
            const entry = entryOf(token);
            if (entry === undefined || entry.restore === false)
                return token;
            entry.lastAt = now();
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
        list,
        setRestore,
        remove,
        clear,
        restoreText,
        containsToken,
        size: () => state.entries.length,
        limits: { maxEntries: MAX_ENTRIES, ttlDays: Math.round(TTL_MS / 86_400_000) },
    };
}
