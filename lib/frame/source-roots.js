// 会话级源根绑定。用户在多义 ask 里补出完整路径后，本次会话内同目录读直接按源根放行；
// 键＝sessionId|目录归一化路径，只活在进程内存里——不写文件、不进配置、不进 vault。
// 宿主重启即忘（含「关掉软件再打开、接着同一对话」）：要跨重启保留，正确去处是配置项／用户规则行。
const DEFAULT_TTL_MS = 30 * 60 * 1000;
const DEFAULT_MAX = 32;

export function createSourceRootStore({ ttlMs = DEFAULT_TTL_MS, max = DEFAULT_MAX, now = () => Date.now() } = {}) {
    const map = new Map();
    const keyOf = (sessionId, dir) => `${sessionId}|${dir}`;
    const dropExpired = (at = now()) => {
        for (const [key, entry] of map) {
            if (at - entry.at > ttlMs)
                map.delete(key);
        }
        return at;
    };
    return {
        /** 该会话当前的绑定目录；''＝没绑。取到即刷新最近使用时间（滑动过期）。 */
        get(sessionId) {
            const id = String(sessionId ?? '');
            if (id === '')
                return '';
            const at = dropExpired();
            const prefix = `${id}|`;
            let hit = '';
            for (const key of map.keys()) {
                if (key.startsWith(prefix))
                    hit = key;
            }
            if (hit === '')
                return '';
            const entry = map.get(hit);
            map.delete(hit);
            entry.at = at;
            map.set(hit, entry);
            return entry.dir;
        },
        /** 记一条绑定；超过上限按最近使用淘汰最旧的一条。返回落下的目录（''＝没绑）。 */
        put(sessionId, dir, { at = now() } = {}) {
            const id = String(sessionId ?? '');
            const path = String(dir ?? '');
            if (id === '' || path === '')
                return '';
            dropExpired(at);
            const key = keyOf(id, path);
            map.delete(key);
            map.set(key, { dir: path, at });
            while (map.size > max)
                map.delete(map.keys().next().value);
            return path;
        },
        /** 撤销句：该会话的所有绑定当场清空。 */
        clear(sessionId) {
            const prefix = `${String(sessionId ?? '')}|`;
            if (prefix === '|')
                return 0;
            let dropped = 0;
            for (const key of [...map.keys()]) {
                if (!key.startsWith(prefix))
                    continue;
                map.delete(key);
                dropped += 1;
            }
            return dropped;
        },
        size() {
            return map.size;
        },
        dropExpired(at = now()) {
            dropExpired(at);
        },
    };
}
