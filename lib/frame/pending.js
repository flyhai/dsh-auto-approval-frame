// L1→L2 hand-off: the pre-execute plane decides, the approval plane only reads.
// Keyed by callId and verified against actionHash, so an ask that does not match
// the action this record was made for cannot inherit its verdict.
//
// Two lanes, one lifetime rule:
// pending — callId → the verdict context, handed over when the human is asked.
// held    — approval id → the same context, waiting for `approval/decided`.
// The host answers on its own answerer, so a plugin never sees the waterfall
// return; the answer only becomes observable through the session log, which
// pairs `approval/asked` with `approval/decided` by an id we hold here.
// 两条道各自的寿命，不能共用一把扫帚（F14）：
// `pending`＝已经决定要问、但 `approval/asked` 还没到的交接件——它是缓存，短 TTL 合理；
// `held`＝**人正在想**的那一条。用 5 分钟把它静默扫掉，等于"问过了但没人答"
// 在账上不存在，晚来的答复成了孤儿。所以 held 走一个明确的答案窗口，
// 过期不是删除，而是由 `sweep` 交回调用方入账（`approval.expired`）。
const ENTRY_TTL_MS = 5 * 60 * 1000;
const ANSWER_WINDOW_MS = 6 * 60 * 60 * 1000;
const MAX_ENTRIES = 512;

export function createPendingStore() {
    const pending = new Map();
    const held = new Map();
    const lane = map => ({
        set(key, record) {
            map.set(key, { ...record, at: Date.now() });
            if (map.size > MAX_ENTRIES) {
                const oldest = [...map.entries()].sort((a, b) => a[1].at - b[1].at)[0];
                if (oldest !== undefined)
                    map.delete(oldest[0]);
            }
        },
        pop(key) {
            const found = map.get(key);
            map.delete(key);
            return found;
        },
    });
    const byCall = lane(pending);
    const byAsk = lane(held);
    const dropExpired = (map, now, ttl) => {
        const expired = [];
        for (const [key, record] of map)
            if (now - record.at > ttl) {
                map.delete(key);
                expired.push({ key, ...record });
            }
        return expired;
    };
    const keyOf = value => value === undefined || value === null ? undefined : String(value);
    return {
        size: () => pending.size,
        heldSize: () => held.size,
        put(callId, record) {
            const key = keyOf(callId);
            if (key === undefined)
                return;
            byCall.set(key, record);
        },
        take(callId, actionHash) {
            const key = keyOf(callId);
            if (key === undefined)
                return undefined;
            const found = byCall.pop(key);
            if (found === undefined)
                return undefined;
            if (actionHash !== undefined && found.actionHash !== undefined && found.actionHash !== actionHash)
                return undefined;
            return found;
        },
        /** Hold one ask so its answer can be tied back when the log commits it. */
        hold(id, record) {
            const key = keyOf(id);
            if (key === undefined)
                return;
            byAsk.set(key, record);
        },
        release(id) {
            const key = keyOf(id);
            return key === undefined ? undefined : byAsk.pop(key);
        },
        dropSession(sessionId) {
            for (const map of [pending, held])
                for (const [entryKey, record] of map)
                    if (record.sessionId === sessionId)
                        map.delete(entryKey);
        },
        // 返回过期条目＝让调用方把"问了没人答"写成一条账，而不是当缓存清了就算完。
        sweep(now = Date.now()) {
            const stale = dropExpired(pending, now, ENTRY_TTL_MS);
            const unanswered = dropExpired(held, now, ANSWER_WINDOW_MS);
            return { stale, unanswered };
        },
    };
}
