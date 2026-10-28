// L1→L2 hand-off: the pre-execute plane decides, the approval plane only reads.
// Keyed by callId and verified against actionHash, so an ask that does not match
// the action this record was made for cannot inherit its verdict.
const ENTRY_TTL_MS = 5 * 60 * 1000;
const MAX_ENTRIES = 512;

export function createPendingStore() {
    const entries = new Map();
    return {
        size: () => entries.size,
        put(callId, record) {
            if (callId === undefined || callId === null)
                return;
            entries.set(String(callId), { ...record, at: Date.now() });
            if (entries.size > MAX_ENTRIES) {
                const oldest = [...entries.entries()].sort((a, b) => a[1].at - b[1].at)[0];
                if (oldest !== undefined)
                    entries.delete(oldest[0]);
            }
        },
        take(callId, actionHash) {
            if (callId === undefined || callId === null)
                return undefined;
            const key = String(callId);
            const found = entries.get(key);
            entries.delete(key);
            if (found === undefined)
                return undefined;
            if (actionHash !== undefined && found.actionHash !== undefined && found.actionHash !== actionHash)
                return undefined;
            return found;
        },
        dropSession(sessionId) {
            for (const [key, record] of entries)
                if (record.sessionId === sessionId)
                    entries.delete(key);
        },
        sweep(now = Date.now()) {
            for (const [key, record] of entries)
                if (now - record.at > ENTRY_TTL_MS)
                    entries.delete(key);
        },
    };
}
