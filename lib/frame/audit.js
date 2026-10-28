// L4 audit store: day-segmented, hash-chained JSONL with a manifest that
// carries a per-segment sha256 and counts, retention pruning with tombstones,
// and a verifier that checks chain, sequence and manifest in one pass.
//
// Layout (all under `dir`):
//   state.json                 running pointer: sequence/lastHash/current segment
//   manifest.jsonl             segment-closed / retention-pruned / audit-cleared
//   YYYY-MM-DD[.N].jsonl       the entries themselves
//   legacy/                    imported pre-0.5 ledger files, kept as evidence
import { createHash, randomUUID } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { basename, join } from 'node:path';

const GENESIS = '0'.repeat(64);
const SEGMENT_PATTERN = /^(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.jsonl$/;
const MANIFEST = 'manifest.jsonl';
const STATE = 'state.json';
const SCHEMA_VERSION = 1;

export const DECISION_TEXT = {
    allowed: '已放行', ask: '转人工确认', blocked: '已拦截', delegated: '未接管',
    approved: '已批准', rejected: '已拒绝', failed: '失败', info: '信息',
};
export const CATEGORY_TEXT = {
    tool: '工具调用', command: '命令安全', file: '文件安全', network: '网络安全',
    sensitive: '敏感保护', approval: '审批', config: '配置变更', lifecycle: '生命周期', audit: '审计',
};
export const LAYER_TEXT = {
    floor: '内置行', rules: '你的规则', fact: '事实门', fast: 'AI 快判', deep: 'AI 深评',
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
const fileSha256 = path => sha256(readFileSync(path));

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
            // A corrupt line is reported by verify(); query just skips it.
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
    if (entry.rule)
        parts.push(`规则 ${entry.rule}`);
    if (entry.layer)
        parts.push(`层级 ${LAYER_TEXT[entry.layer] ?? entry.layer}`);
    if (entry.message)
        parts.push(`备注 ${entry.message}`);
    return `[${time}] ${parts.join(' · ')}`;
}

export function createAuditStore({ dir, now = () => Date.now(), maxSegmentBytes = 50 * 1024 * 1024, retentionDays = 90, maxTotalBytes = 512 * 1024 * 1024 }) {
    const statePath = join(dir, STATE);
    const manifestPath = join(dir, MANIFEST);
    let state = { sequence: 0, lastHash: GENESIS, currentSegment: undefined, closedSegments: [] };
    let loaded = false;

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
            // The store stays usable; verify() will report a missing segment if
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
                if (state.currentSegment !== undefined && existsSync(join(dir, state.currentSegment))) {
                    const lines = parseLines(readFileSync(join(dir, state.currentSegment), 'utf8'));
                    const last = lines[lines.length - 1];
                    if (last !== undefined && last.sequence === state.sequence && last.hash === state.lastHash)
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
        const entries = parseLines(readFileSync(join(dir, current), 'utf8'));
        const last = entries[entries.length - 1];
        state = {
            sequence: Number.isFinite(last?.sequence) ? last.sequence : 0,
            lastHash: typeof last?.hash === 'string' ? last.hash : GENESIS,
            currentSegment: current,
            closedSegments: files.slice(0, -1),
        };
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
        const entries = parseLines(readFileSync(path, 'utf8'));
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
            fileSha256: fileSha256(path),
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

    function append(record) {
        try {
            if (!loaded)
                load();
            const timestamp = Number.isFinite(record?.timestamp) ? record.timestamp : now();
            const path = pickSegment(timestamp);
            const body = { ...record, timestamp };
            delete body.id;
            delete body.schemaVersion;
            delete body.sequence;
            delete body.prevHash;
            delete body.hash;
            const line = { id: randomUUID(), schemaVersion: SCHEMA_VERSION, sequence: state.sequence + 1, ...body };
            const text = JSON.stringify(line);
            const hash = chainHash(state.lastHash, text);
            appendFileSync(path, `${JSON.stringify({ ...line, prevHash: state.lastHash, hash })}\n`);
            state = { ...state, sequence: line.sequence, lastHash: hash, currentSegment: basename(path) };
            saveState();
            return { ok: true, sequence: line.sequence, hash };
        }
        catch (error) {
            return { ok: false, reason: String(error?.message ?? error) };
        }
    }

    function readAll() {
        const files = segmentFiles();
        const entries = [];
        for (const name of files) {
            try {
                entries.push(...parseLines(readFileSync(join(dir, name), 'utf8')));
            }
            catch {
                // verify() reports the unreadable segment.
            }
        }
        return entries;
    }

    function filterEntries(entries, filters = {}) {
        const keyword = typeof filters.q === 'string' ? filters.q.trim().toLowerCase() : '';
        const hidden = Array.isArray(filters.hide)
            ? filters.hide
            : (typeof filters.hide === 'string' ? filters.hide.split(',').map(item => item.trim()).filter(Boolean) : []);
        return entries.filter(entry => {
            if (hidden.includes(entry.eventType))
                return false;
            if (Number.isFinite(filters.from) && entry.timestamp < filters.from)
                return false;
            if (Number.isFinite(filters.to) && entry.timestamp > filters.to)
                return false;
            if (typeof filters.decision === 'string' && filters.decision !== '' && entry.decision !== filters.decision)
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
        });
    }

    function query(filters = {}) {
        const all = readAll();
        const matched = filterEntries(all, filters);
        const offset = Number.isInteger(filters.offset) && filters.offset > 0 ? filters.offset : 0;
        const limit = Number.isInteger(filters.limit) && filters.limit > 0 ? Math.min(filters.limit, 500) : 50;
        return {
            entries: matched.slice().reverse().slice(offset, offset + limit),
            matched: matched.length,
            total: all.length,
            segments: segmentFiles().length,
        };
    }

    function exportText(filters = {}, format = 'jsonl') {
        const rows = filterEntries(readAll(), filters);
        if (format === 'md')
            return `${rows.map(renderEntry).join('\n')}\n`;
        return `${rows.map(entry => JSON.stringify(entry)).join('\n')}\n`;
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
        let prevHash = GENESIS;
        let prevSequence = 0;
        let lines = 0;
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
            const entries = parseLines(readFileSync(path, 'utf8'));
            lines += entries.length;
            if (record?.event === 'segment-closed') {
                if (fileSha256(path) !== record.fileSha256)
                    issues.push({ type: 'manifest-sha256', segment: name });
                if (entries.length !== record.entryCount)
                    issues.push({ type: 'manifest-count', segment: name, expected: record.entryCount, actual: entries.length });
                const last = entries[entries.length - 1];
                if (last?.hash !== record.lastHash)
                    issues.push({ type: 'manifest-last-hash', segment: name });
            }
            for (const entry of entries) {
                if (entry.sequence !== prevSequence + 1)
                    issues.push({ type: 'sequence-gap', segment: name, sequence: entry.sequence, expected: prevSequence + 1 });
                if (entry.prevHash !== prevHash)
                    issues.push({ type: 'prev-hash-mismatch', segment: name, sequence: entry.sequence });
                if (chainHash(entry.prevHash, bodyTextOf(entry)) !== entry.hash)
                    issues.push({ type: 'hash-mismatch', segment: name, sequence: entry.sequence });
                prevHash = entry.hash;
                prevSequence = entry.sequence;
            }
        }
        return { ok: issues.length === 0, issues: issues.slice(0, 20), lines, segments: files.length };
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
        // fact (counts + tail hash) without leaving verify() chasing dead files.
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
