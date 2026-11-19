// aaf_secret：把占位符换成真值，落进一个文件，或交给一条子进程。
//
// 为什么要有这个工具：宿主不许改工具入参（参数已记录、已展示），所以「命令里要真值」与
// 「文件里要真值」都只能在一次显式调用里发生。谁开口比一张弹窗猜准——模型知道磁盘此刻
// 是什么，弹窗不知道。
//
// 两条硬边界：
//  · 一次调用只做一件事：给 command 就代跑，给 target 就落盘，两个都给＝拒。
//  · 真值不出这个函数：返回值里只有「几枚、落在哪、几处、失败原因」，一字节明文都不回。
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import {
    chmodSync, closeSync, fstatSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { firstLinkAncestor, MAX_FILE_BYTES, sameSample, sampleVersion } from './restore.js';
import { neverReasonFor } from './grant.js';
import { reasonText } from './policy.js';
import { redactSecrets } from './sanitize.js';
import { TOKEN_PATTERN } from './sensitive.js';

const MAX_OUTPUT_BYTES = 256 * 1024;
const ENV_PREFIX = 'DSH_SECRET_';
/** 工具名：写后回填腿要按它跳过自己（自己已经落过盘，别再走一遍）。 */
export const SECRET_TOOL_NAME = 'aaf_secret';
/** 命令分支的落点身份：没有文件可落，用命令摘要当目的，台账与证都能对齐同一件事。 */
const commandTargetOf = command => `command:${createHash('sha256').update(command).digest('hex').slice(0, 16)}`;

/**
 * 把值按占位符出现的位置替换成环境变量展开式：单引号内不展开，所以那里直接拒绝执行，
 * 而不是悄悄塞一个字面量进去；裸位置用双引号包住，免得值里的空格被拆成两个词。
 */
function substituteInto(text, tokens) {
    const plan = new Map(tokens.map((token, index) => [token, `${ENV_PREFIX}${index + 1}`]));
    const at = new Map();
    for (const match of text.matchAll(TOKEN_PATTERN)) {
        if (plan.has(match[0]) && match.index !== undefined)
            at.set(match.index, match[0]);
    }
    let out = '';
    let quote = null;
    for (let i = 0; i < text.length;) {
        const token = at.get(i);
        if (token !== undefined) {
            if (quote === 'single')
                return { error: `占位符 ${token} 在单引号里，单引号内不做展开；把它挪到引号外再试` };
            out += quote === null ? `"\${${plan.get(token)}}"` : `\${${plan.get(token)}}`;
            i += token.length;
            continue;
        }
        const ch = text[i];
        if (ch === '\\' && quote !== 'single') {
            out += ch + (text[i + 1] ?? '');
            i += 2;
            continue;
        }
        if (ch === '\'' && quote !== 'double')
            quote = quote === 'single' ? null : 'single';
        else if (ch === '"' && quote !== 'single')
            quote = quote === 'double' ? null : 'double';
        out += ch;
        i += 1;
    }
    return { text: out };
}

/** 默认执行体：一条 bash 命令，输出有上限，超时由宿主与调用方各自的 signal 收口。 */
function runShell(command, { env, signal }) {
    return new Promise((resolve) => {
        let stdout = '';
        let stderr = '';
        let truncated = false;
        const child = spawn('bash', ['-c', command], { env, windowsHide: true, ...(signal === undefined ? {} : { signal }) });
        const take = (current, chunk) => {
            if (current.length >= MAX_OUTPUT_BYTES) {
                truncated = true;
                return current;
            }
            return current + chunk.toString('utf8');
        };
        child.stdout?.on('data', (chunk) => { stdout = take(stdout, chunk); });
        child.stderr?.on('data', (chunk) => { stderr = take(stderr, chunk); });
        child.on('error', error => resolve({ code: -1, stdout, stderr: `${stderr}${String(error?.message ?? error)}`, truncated }));
        child.on('close', code => resolve({ code: code ?? -1, stdout, stderr, truncated }));
    });
}

/** 单文件受控回填：与写后回填同一套检查（链接祖先／版本／原子替换／权限位／凭据树）。 */
function restoreOneFile({ path, found, vault, roots, probe, sessionId, purpose, callId }) {
    const never = neverReasonFor({ path, opClass: 'write', program: '' }, roots);
    if (never !== undefined)
        return { ok: false, reason: `不回填到${reasonText(never)}` };
    const link = firstLinkAncestor(path, roots, probe ?? lstatSync);
    if (link.kind === 'link')
        return { ok: false, reason: `目标或它的祖先 ${link.path} 是链接／junction，重写会落到区外的真身` };
    if (link.kind !== 'none')
        return { ok: false, reason: `链接祖先查不通（${link.error}＠${link.path}），未验证不动` };
    let raw;
    let sampled;
    let sampledMode;
    try {
        const fd = openSync(path, 'r');
        try {
            const info = fstatSync(fd);
            sampled = { mtimeMs: info.mtimeMs, size: info.size };
            sampledMode = info.mode;
            raw = readFileSync(fd);
        }
        finally {
            closeSync(fd);
        }
    }
    catch (error) {
        return { ok: false, reason: `读不到目标文件：${String(error?.code ?? error?.message ?? error)}` };
    }
    if (raw.length > MAX_FILE_BYTES)
        return { ok: false, reason: `文件超过 ${Math.round(MAX_FILE_BYTES / 1024 / 1024)} MB，不动` };
    const text = raw.toString('utf8');
    // 非 UTF-8 的文件按 UTF-8 重编会吃掉字节，写回去就是损坏：比字节不比长度。
    if (Buffer.compare(Buffer.from(text, 'utf8'), raw) !== 0)
        return { ok: false, reason: '目标不是 UTF-8 文本，重写会损坏内容，不动' };
    const present = found.filter(token => text.includes(token));
    if (present.length === 0)
        return { ok: false, reason: '文件里没有这几枚占位符，一个字节都没动' };
    const granted = [];
    const denied = [];
    for (const token of present) {
        const issued = vault.grantUse(token, { sessionId, destination: path, purpose, callId });
        if (issued.ok !== true) {
            denied.push(String(issued.reason ?? 'grant.none'));
            continue;
        }
        const verdict = vault.consumeGrant(token, {
            sessionId, destination: path, purpose, expectedVersion: sampled, callId,
        });
        if (verdict.ok === true)
            granted.push(token);
        else
            denied.push(String(verdict.reason ?? 'grant.none'));
    }
    if (granted.length === 0)
        return { ok: false, reason: `没有可用授权（${[...new Set(denied)].join('、')}）` };
    const restored = vault.restoreText(text, { only: granted });
    if (restored.restored.length === 0)
        return { ok: false, reason: '这几条的回写开关是关的' };
    const tmp = `${path}.aaf-secret-${process.pid}.tmp`;
    try {
        writeFileSync(tmp, restored.text);
    }
    catch (error) {
        try {
            unlinkSync(tmp);
        }
        catch {
            // 删不掉只是一份临时文件留在原地，不改变这次没有落盘的事实。
        }
        granted.forEach(token => vault.releaseGrant(token));
        return { ok: false, reason: `写入临时文件失败：${String(error?.message ?? error)}` };
    }
    // 采样与替换之间被第三方改过 ⇒ 放弃，不拿我们这份去盖别人刚写的。
    if (sameSample(sampled, sampleVersion(path)) !== true) {
        try {
            unlinkSync(tmp);
        }
        catch {
            // 同上。
        }
        granted.forEach(token => vault.releaseGrant(token));
        return { ok: false, reason: '目标在读取之后被改过，放弃这次回填' };
    }
    try {
        renameSync(tmp, path);
    }
    catch (error) {
        try {
            unlinkSync(tmp);
        }
        catch {
            // 同上。
        }
        granted.forEach(token => vault.releaseGrant(token));
        return { ok: false, reason: `原子替换失败：${String(error?.message ?? error)}` };
    }
    try {
        if (typeof sampledMode === 'number')
            chmodSync(path, sampledMode);
    }
    catch {
        // 权限位复原不了不改变内容已正确落盘的事实。
    }
    return { ok: true, path, count: restored.restored.length, tokens: restored.restored };
}

/**
 * 造这个工具的注册定义。宿主只要求 name／description／parameters／output／execute 几个身形，
 * 不需要 defineTool 的类型机器——插件是纯 JS，参数校验在这里自己做，报错也说人话。
 */
export function createSecretTool({ vault, trace, toolName = SECRET_TOOL_NAME, purpose = 'secret-tool', rootsOf, sessionIdOf, probe, runChild = runShell }) {
    return {
        name: toolName,
        description: 'Replace [[SEC-…]] placeholders with the real value where it is actually needed. `command`: run one shell command on this machine with the placeholders replaced; that command text is what the approval card and the rules judge, the value reaches only that process, and its output comes back masked. `target`: replace the placeholders inside that existing file. One call is one use — one command or one file, never both, and nothing is echoed back. Credential trees, system trees, symlinked targets and files changed since the read are refused rather than forced. Editing a line that holds a placeholder fails on the plaintext mismatch: write the whole file, then call this. A value passed as an argument stays visible to same-user processes for as long as that command runs; prefer a program\'s own file or stdin option when it has one.',
        parameters: {
            command: {
                type: 'string',
                description: 'One shell command to run on this machine, placeholders left exactly as they are. Mutually exclusive with target.',
            },
            target: {
                type: 'string',
                description: 'Existing file whose placeholders should be replaced with the real value. Mutually exclusive with command.',
            },
            tokens: {
                type: 'array',
                items: { type: 'string' },
                description: 'Which placeholders this call may use, copied exactly as they appear. Omit to use every placeholder found in command or target.',
            },
            why: {
                type: 'string',
                required: true,
                description: 'One line shown on the approval card and kept in the ledger: what this value is for. It must not contain the value itself.',
            },
        },
        output: {
            schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                    ok: { type: 'boolean' },
                    what: { type: 'string', enum: ['command', 'file'] },
                    tokens: { type: 'array', items: { type: 'string' } },
                    path: { type: 'string' },
                    count: { type: 'integer' },
                    code: { type: 'integer' },
                    output: { type: 'string' },
                    reason: { type: 'string' },
                },
            },
            render: (_args, value) => [{ type: 'text', text: describe(value) }],
        },
        timeoutMs: 120000,
        async execute(args, exec) {
            const command = typeof args?.command === 'string' ? args.command.trim() : '';
            const target = typeof args?.target === 'string' ? args.target.trim() : '';
            const why = typeof args?.why === 'string' ? args.why.trim() : '';
            if (command === '' && target === '')
                throw new Error('给 command（要代跑的命令）或 target（要落真的文件），二选一');
            if (command !== '' && target !== '')
                throw new Error('一次只做一件事：command 与 target 不能同时给');
            if (why === '')
                throw new Error('why 必填：一句话说明这枚值要用在哪，它上审批卡和台账');
            const sessionId = sessionIdOf(exec);
            if (typeof sessionId !== 'string' || sessionId === '')
                throw new Error('没有会话上下文，签不出这一次的使用证');
            void trace({
                category: 'sensitive', eventType: 'sensitive.use-requested', decision: 'info', layer: 'redact',
                sessionId, toolCallId: exec.callId ?? null, toolName,
                path: target === '' ? null : target,
                message: `要用真值：${command === '' ? `写进 ${target}` : '代跑一条命令'}（用途：${why}）`,
            });
            if (target !== '') {
                const found = typeof args?.tokens === 'object' && Array.isArray(args.tokens) && args.tokens.length > 0
                    ? args.tokens.map(token => String(token))
                    : vault.containsToken(readTextOrEmpty(target));
                const unknown = found.filter(token => !vault.containsToken(token).includes(token));
                if (unknown.length > 0)
                    throw new Error(`这几枚不是本表铸的，不能用：${unknown.join('、')}`);
                const result = restoreOneFile({
                    path: target, found, vault, roots: rootsOf(exec), probe, sessionId, purpose, callId: exec.callId,
                });
                void trace({
                    category: 'sensitive', eventType: result.ok === true ? 'sensitive.used' : 'sensitive.use-refused',
                    decision: 'info', layer: 'redact', sessionId,
                    toolCallId: exec.callId ?? null, toolName: toolName, path: target,
                    message: result.ok === true
                        ? `把 ${result.count} 枚秘密写进文件（用途：${why}）`
                        : `没写：${result.reason}（用途：${why}）`,
                });
                if (result.ok !== true)
                    return { ok: false, what: 'file', tokens: [], path: target, count: 0, reason: result.reason };
                return { ok: true, what: 'file', tokens: result.tokens, path: target, count: result.count };
            }
            const inCommand = vault.containsToken(command);
            const use = typeof args?.tokens === 'object' && Array.isArray(args.tokens) && args.tokens.length > 0
                ? args.tokens.map(token => String(token)).filter(token => inCommand.includes(token))
                : inCommand;
            if (use.length === 0)
                return {
                    ok: false, what: 'command', tokens: [], count: 0,
                    reason: '这条命令里没有占位符；要跑一条不含秘密的命令，直接走原命令就行',
                };
            const destination = commandTargetOf(command);
            const granted = [];
            for (const token of use) {
                const issued = vault.grantUse(token, { sessionId, destination, purpose, callId: exec.callId });
                const verdict = issued.ok === true
                    ? vault.consumeGrant(token, { sessionId, destination, purpose, callId: exec.callId })
                    : issued;
                if (verdict.ok === true)
                    granted.push(token);
            }
            if (granted.length === 0)
                return { ok: false, what: 'command', tokens: [], count: 0, reason: '签不出这一次的使用证（会话或用途缺失）' };
            const substituted = substituteInto(command, granted);
            if (substituted.error !== undefined)
                return { ok: false, what: 'command', tokens: [], count: 0, reason: substituted.error };
            const env = { ...process.env };
            const missing = [];
            granted.forEach((token, index) => {
                const plain = vault.plainOf(token);
                if (typeof plain === 'string')
                    env[`${ENV_PREFIX}${index + 1}`] = plain;
                else
                    missing.push(token);
            });
            // 取不到明文就不执行：让它展开成空字符串，命令会带着一个空密码跑出去。
            if (missing.length > 0)
                return {
                    ok: false, what: 'command', tokens: [], count: 0,
                    reason: `取不到这几枚的明文：${missing.join('、')}`,
                };
            const ran = await runChild(substituted.text, { env, signal: exec.signal });
            const shown = redactSecrets(vault.maskKnown(`${ran.stdout ?? ''}${ran.stderr ?? ''}`));
            void trace({
                category: 'sensitive', eventType: 'sensitive.used', decision: 'info', layer: 'redact',
                sessionId, toolCallId: exec.callId ?? null, toolName, path: destination,
                message: `用 ${granted.length} 枚秘密代跑了一条命令，退出码 ${ran.code}（用途：${why}）`,
            });
            return {
                ok: ran.code === 0,
                what: 'command',
                tokens: granted,
                count: granted.length,
                code: ran.code,
                output: ran.truncated === true ? `${shown}\n[输出已截断]` : shown,
            };
        },
    };
}

/** 给模型看的结算话术：只说做了什么，永远不含明文。 */
function describe(value) {
    if (value?.ok === true && value.what === 'file')
        return `已把 ${value.count} 枚秘密写进 ${value.path}（${value.count} 处），文件其余内容未动。`;
    if (value?.ok === true && value.what === 'command')
        return `已执行（退出码 ${value.code}）。\n${value.output ?? ''}`.trim();
    if (value?.ok === false && value.what === 'command')
        return `执行了，退出码 ${value.code}。\n${value.output ?? ''}`.trim();
    if (value?.ok === false)
        return `没做：${value.reason ?? '未知原因'}`;
    return '完成。';
}

/** 只用来判断「文件里现在有哪几枚」，读不出来就当空——真正的读在同一次回填里再做。 */
function readTextOrEmpty(path) {
    try {
        return readFileSync(path, 'utf8');
    }
    catch {
        return '';
    }
}
