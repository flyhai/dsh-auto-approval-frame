/**
 * Reading the profile's model configuration.
 *
 * The settings page needs a picker of models the user has already configured. The
 * obvious host call — `llm.listModels(provider)` — answers from the adapter's own
 * registry only for routes the adapter knows, and probes the endpoint for every
 * other route. One unreachable provider then blocks the whole read for tens of
 * seconds (real incident, 2026-10-28). The profile files are what the user actually
 * configures, they cost no network, and they cannot hang — so that is the source.
 *
 * This is a bounded, structure-specific scan (providers → models), not a YAML
 * parser: it only recognises `providers:` blocks, the keys directly under them,
 * their `displayName`, and `- id:` entries inside a `models:` list. Anything it does
 * not understand is skipped, and an unreadable file yields no groups — the caller
 * then keeps the manual provider/model fields.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const MAX_PROVIDERS = 24;
const MAX_MODELS = 40;

const indentOf = line => line.length - line.trimStart().length;
const unquote = value => value.trim().replace(/^["'](.*)["']$/, '$1');
const isBlank = line => line.trim() === '' || line.trimStart().startsWith('#');

/** One `providers:` block: the keys at its first deeper indent are the providers. */
function readProvidersBlock(lines, start) {
    let cursor = start + 1;
    while (cursor < lines.length && isBlank(lines[cursor])) cursor += 1;
    if (cursor >= lines.length) return [start, []];
    const keyIndent = indentOf(lines[cursor]);
    const providers = [];
    let current = null;
    for (; cursor < lines.length; cursor += 1) {
        const line = lines[cursor];
        if (isBlank(line)) continue;
        const indent = indentOf(line);
        if (indent < keyIndent) break;
        const key = /^([A-Za-z0-9_.-]+):\s*(.*)$/.exec(line.trim());
        if (indent > keyIndent) {
            if (current === null) continue;
            if (key?.[1] === 'displayName' && key[2] !== '') current.name = unquote(key[2]);
            // `models:` belongs to the provider we are inside; the list is read here
            // so the outer scan does not have to rewind over lines already consumed.
            if (key?.[1] === 'models' && key[2] === '') {
                const [end, found] = readModelsList(lines, cursor);
                current.models = found.slice(0, MAX_MODELS);
                cursor = end;
            }
            continue;
        }
        if (key === null || key[2] !== '') continue;
        current = { id: key[1], name: key[1], models: [] };
        providers.push(current);
        continue;
    }
    // `cursor` stopped on the first line dedented past the block; `providers:` keys
    // end at the block level, so step back one line for the caller's scan.
    return [cursor - 1, providers];
}

/** A `models:` list under one provider: `- id: x` entries plus their sibling `name:`. */
function readModelsList(lines, start) {
    let cursor = start + 1;
    while (cursor < lines.length && isBlank(lines[cursor])) cursor += 1;
    if (cursor >= lines.length) return [start, []];
    const itemIndent = indentOf(lines[cursor]);
    if (!lines[cursor].trimStart().startsWith('- ')) return [start, []];
    const models = [];
    let current = null;
    for (; cursor < lines.length; cursor += 1) {
        const line = lines[cursor];
        if (isBlank(line)) continue;
        const indent = indentOf(line);
        if (indent < itemIndent) break;
        const item = /^-\s+([A-Za-z0-9_.-]+):\s*(.*)$/.exec(line.trim());
        if (indent === itemIndent && item) {
            if (item[1] !== 'id') continue;
            current = { id: unquote(item[2]), name: unquote(item[2]) };
            models.push(current);
            continue;
        }
        if (indent === itemIndent) break;
        if (current === null || indent !== itemIndent + 2) continue;
        const field = /^([A-Za-z0-9_.-]+):\s*(.*)$/.exec(line.trim());
        if (field?.[1] === 'name' && field[2] !== '') current.name = unquote(field[2]);
    }
    return [cursor - 1, models];
}

/** Providers declared in one profile document. */
export function profileProviders(text) {
    const lines = String(text ?? '').split(/\r?\n/);
    const providers = [];
    for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index];
        if (isBlank(line)) continue;
        if (line.trim() === 'providers:') {
            const [end, found] = readProvidersBlock(lines, index);
            providers.push(...found);
            index = end;
            continue;
        }
        if (line.trim() === 'models:' && providers.length > 0) {
            const [end, found] = readModelsList(lines, index);
            providers[providers.length - 1].models = found.slice(0, MAX_MODELS);
            index = end;
        }
    }
    return providers.slice(0, MAX_PROVIDERS);
}

/**
 * Every profile under `<home>/profiles`, later files winning per provider id.
 * @returns groups (provider with at least one model) plus a note when nothing was found.
 */
export function readModelGroups(home) {
    const root = join(home, 'profiles');
    const merged = new Map();
    let files = 0;
    let dirs = [];
    try {
        dirs = readdirSync(root, { withFileTypes: true })
            .filter(entry => entry.isDirectory()).map(entry => entry.name);
    }
    catch {
        return { groups: [], note: `读不到 profile 目录（${root}）` };
    }
    for (const dir of dirs) {
        for (const file of ['cordis.yml', 'cordis.patch.yml']) {
            let text;
            try { text = readFileSync(join(root, dir, file), 'utf8'); files += 1; }
            catch { continue; }
            for (const provider of profileProviders(text)) {
                const previous = merged.get(provider.id);
                if (previous === undefined || provider.models.length > 0) merged.set(provider.id, provider);
                else if (previous.name === previous.id && provider.name !== provider.id)
                    merged.set(provider.id, { ...previous, name: provider.name });
            }
        }
    }
    const groups = [...merged.values()].filter(provider => provider.models.length > 0);
    return {
        groups,
        note: groups.length === 0
            ? `profile 里没有声明带 models 的提供方（扫了 ${dirs.length} 个 profile、${files} 个文件）`
            : '',
    };
}
