// Wiring regression: the decision chain as apply() actually runs it. The model
// call and the filesystem probe are the only seams; everything else is real.
// Usage: node test/wiring.test.mjs <fixture-dir>
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import { apply } from '../lib/index.js';

const root = resolve(process.argv[2] ?? join(homedir(), 'Documents/ai/垃圾桶/frame-wiring'));
rmSync(root, { recursive: true, force: true });
// 测试只准写自己的临时 DSH_HOME：真实状态目录里是在役台账，删一次就丢一次事故证据。
process.env.DSH_HOME = join(root, 'dsh-home');
const ws = join(root, 'ws');
mkdirSync(ws, { recursive: true });
writeFileSync(join(ws, 'junk0.txt'), '');
writeFileSync(join(ws, 'content.txt'), 'hello');
mkdirSync(join(ws, 'emptydir'), { recursive: true });

// 模型目录的真源头＝profile 里的 providers.<id>.models[]；测试自带一份，免得去读真实 ~/.dsh。
const profileDir = join(process.env.DSH_HOME, 'profiles', 'desktop');
mkdirSync(profileDir, { recursive: true });
writeFileSync(join(profileDir, 'cordis.patch.yml'), [
    '- id: llm-pi-ai',
    '  name: "@deepseek-ai/dsh-llm-pi-ai"',
    '  config:',
    '    providers:',
    '      nodeb4603:',
    '        displayName: 生产 vLLM',
    '        baseURL: http://127.0.0.1:8090/v1',
    '        models:',
    '          - id: qwen3.8-27b',
    '            name: qwen3.8-27b',
    '            contextWindow: 256000',
    '            input:',
    '              - text',
    '              - image',
    '      test:',
    '        displayName: 测试 vLLM',
    '        models:',
    '          - id: qwen3.8-27b',
    '            name: qwen3.8-27b-vllm',
    '      nosettings:',
    '        displayName: 没声明模型的提供方',
    '',
].join('\n'));

const session = (cwd) => ({
    id: 'session-1',
    header: { cwd, origin: 'main' },
    snapshotEvents: () => [
        { type: 'user/message', data: { source: { kind: 'user' }, content: [{ type: 'text', text: '把工作区里的垃圾空文件删掉' }] } },
    ],
    requestHeader: () => ({ config: { provider: 'stub', model: 'stub-model' } }),
});
const exec = (command, callId = 'call-1', cwd = ws) => ({
    callId,
    name: 'bash',
    arguments: { command },
    agent: { session: session(cwd), inbox: {} },
    signal: new AbortController().signal,
});

function harness({ preset = 'auto-approval', review, config = {}, stored = { row: null },
    knownPresets = ['auto-approval', 'workspace-write', 'danger-full-access'] } = {}) {
    const handlers = new Map();
    const listenerOptions = new Map();
    const calls = { review: 0 };
    const routes = [];
    const ctx = {
        get: (service) => ({
            approval: { config: { policy: 'ask' } },
            permissionPresets: {
                names: knownPresets,
                optionOf: (name) => {
                    if (!knownPresets.includes(name))
                        throw new Error(`unknown permission preset: ${name}`);
                    return { name };
                },
                permissionState: () => ({ preset }),
            },
            // 只给评审用的 prepareCall：模型目录不再走 llm 服务（那是网络路径）。
            llm: { prepareCall: async () => {
                calls.review += 1;
                return { config: {}, stream: async function* () { yield { type: 'text', text: '{"x":1}' }; } };
            } },
            tools: { schemas: () => [] },
            settings: { describe: () => (stored.row === null ? [] : [{ ns: 'auto-approval-frame', value: stored.row, revision: 1 }]) },
            agents: { get: () => undefined },
            connection: { fetch: { register: route => { routes.push(route); return async () => { }; } } },
        }[service]),
        on: (event, handler, options) => { handlers.set(event, handler); listenerOptions.set(event, options); },
        effect: factory => factory(),
    };
    const api = apply(ctx, {
        enabled: true,
        mode: 'auto',
        gatedPresets: ['auto-approval'],
        reviewerSource: 'session',
        reviewerTimeoutMs: 1000,
        ...config,
    }, {
        review: review === undefined ? undefined : async (options) => {
            calls.review += 1;
            return review(options);
        },
    });
    const next = async (marker) => marker ?? 'delegated';
    return {
        calls,
        routes,
        stored,
        api,
        listenerOptions,
        fire: (event, ...args) => handlers.get(event)(...args),
        preExecute: async (command, callId) => handlers.get('tools/pre-execute')(exec(command, callId), next),
        preExecuteTool: async (name, args, callId) => {
            const base = exec('', callId);
            return handlers.get('tools/pre-execute')({ ...base, name, arguments: args }, next);
        },
        approvalRequest: async (callId, toolName = 'bash') => handlers.get('approval/request')(
            { callId, toolName, agent: { session: session(ws) }, signal: new AbortController().signal },
            async () => 'rejected',
        ),
        dispose: async () => handlers.get('session/disposed')({ id: 'session-1' }),
    };
}
const ALLOW = async () => ({ status: 'reviewed', decision: 'allow', reasonCode: 'no_material_risk', summary: 'disposable', durationMs: 1, model: 'stub/stub-model', tier: 'deep' });const BLOCK = async () => ({ status: 'reviewed', decision: 'block', reasonCode: 'unauthorized_by_user', summary: 'user did not ask', durationMs: 1, model: 'stub/stub-model', tier: 'deep' });
const UNABLE = async () => ({ status: 'unable', unableReason: 'timeout', summary: 'no answer', durationMs: 1, tier: 'deep' });

// 0. 跨作用域监听：宿主的 approval/request 与 tools/result 都按 agent 作用域分发，
// 根上下文注册必须带 global，否则被作用域过滤掉（真机 0 条人工答复的成因）。
{
    const h = harness({ review: ALLOW });
    assert.deepEqual(h.listenerOptions.get('approval/request'), { global: true }, '人工答复监听必须全局注册');
    assert.deepEqual(h.listenerOptions.get('tools/result'), { global: true }, '结果观测监听必须全局注册');
    console.log('OK wiring: approval/request 与 tools/result 以 global 注册');
}

// 1. 内置行（第一道）拒绝把动作交给模型，也不给它起个第二个名字
{
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute(`rm -f "${join(homedir(), '.ssh', 'id_ed25519')}"`);
    assert.equal(decision.kind, 'ask');
    assert.equal(h.calls.review, 0, 'a never action must not reach the reviewer');
    assert.ok(decision.displayReason.includes('内置行'), decision.displayReason);
    assert.ok(!decision.displayReason.includes('代码下界'), `页面上已经没有「代码下界」这个名字：${decision.displayReason}`);
    console.log('OK wiring: never floor is terminal before the model');
}
// 2. ALLOW releases an auto action, with the trace written first
{
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute('rm -f junk0.txt');
    assert.deepEqual(decision, { kind: 'allow' });
    assert.equal(h.calls.review, 1);
    const audit = h.api.inspect().audit;
    assert.equal(audit.ok, true, JSON.stringify(audit.issues));
    assert.ok(audit.lines >= 2, 'boot + decision rows');
    console.log('OK wiring: grant=auto × ALLOW → release, ledger chain intact');
}
// 3. a reviewed block is decisive, no countdown
{
    const h = harness({ review: BLOCK });
    const decision = await h.preExecute('rm -f junk0.txt');
    assert.equal(decision.kind, 'deny');
    assert.ok(decision.reason.includes('unauthorized_by_user'), decision.reason);
    console.log('OK wiring: grant=auto × BLOCK → decisive deny');
}
// 4. confirm state: ALLOW is advice only, the ask carries it
{
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute('rm -rf emptydir', 'call-confirm');
    assert.equal(decision.kind, 'ask');
    assert.ok(decision.displayReason.includes('AI: allow'), decision.displayReason);
    const outcome = await h.approvalRequest('call-confirm');
    assert.equal(outcome, 'rejected', 'the human answer still decides');
    assert.equal(h.api.inspect().pending, 0, 'the ask consumed its record');
    const approvals = h.api.inspect().recent(10).filter(entry => entry.eventType === 'approval.answer');
    assert.equal(approvals.length, 1, '人工答复必须入账');
    assert.equal(approvals[0].decision, 'rejected');
    console.log('OK wiring: confirm keeps ALLOW powerless and hands the human the advice');
}
// 5. an unavailable review never becomes a silent allow
{
    const h = harness({ review: UNABLE });
    const decision = await h.preExecute('rm -f junk0.txt', 'call-unable');
    assert.equal(decision.kind, 'ask');
    assert.ok(decision.displayReason.includes('AI 评审不可用'), decision.displayReason);
    console.log('OK wiring: unable → human, with the reason shown');
}
// 6. mode off delegates; ungated presets never enter the chain
{
    const off = harness({ review: ALLOW, config: { mode: 'off' } });
    assert.equal(await off.preExecute('rm -f junk0.txt'), 'delegated');
    const other = harness({ review: ALLOW, preset: 'workspace-write' });
    assert.equal(await other.preExecute('rm -f junk0.txt'), 'delegated');
    assert.equal(other.calls.review, 0);
    console.log('OK wiring: mode=off and ungated preset delegate');
}
// 7. no durable trace means no release
{
    const blocked = join(root, 'blocked-home');
    writeFileSync(blocked, 'not a directory');
    process.env.DSH_HOME = blocked;
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute('rm -f junk0.txt');
    assert.equal(decision.kind, 'ask');
    assert.ok(decision.displayReason.includes('台账'), decision.displayReason);
    process.env.DSH_HOME = join(root, 'dsh-home');
    console.log('OK wiring: an unwritable ledger downgrades every ALLOW to a human ask');
}
// 8. an ask that outlives its session is dropped, not inherited
{
    const h = harness({ review: ALLOW });
    await h.preExecute('rm -rf emptydir', 'call-stale');
    await h.dispose();
    const outcome = await h.approvalRequest('call-stale');
    assert.equal(outcome, 'rejected', 'a dropped record simply delegates');
    console.log('OK wiring: session disposal clears pending asks');
}

// 9. 只读命令走快路：不送模型，但必须留一条事实门记录
// 真机台账实证：每条 `cd … && grep -rn 'a|b' … | head -20` 都被送去评审，
// 付了 2.4—2.9 秒却只得到「这是只读命令」的结论。新帧要求全事件可审计，
// 所以放行照旧不付模型钱，但要能回答「这条命令来过」。
{
    const h = harness({ review: ALLOW });
    const before = h.api.inspect().audit.lines;
    const decision = await h.preExecute(`cd "${ws}" && grep -rn "x" . | head -20`);
    assert.equal(decision, 'delegated', '只读命令应当直接放行，不进判定');
    assert.equal(h.calls.review, 0, '只读命令不该付一次模型调用');
    assert.equal(h.api.inspect().audit.lines, before + 1, '只读快路也必须留一条记录');
    const [last] = h.api.inspect().recent(1);
    assert.equal(last.decision, 'allowed');
    assert.equal(last.layer, 'fact');
    assert.ok(last.commandPreview.includes('grep'), last.commandPreview);
}
{
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute(`sed -i.bak 's/a/b/' "${join(ws, 'content.txt')}"`);
    assert.notEqual(decision, 'delegated', '原地改写不是只读，必须进判定');
    assert.equal(h.calls.review, 1);
}
console.log('OK wiring: 只读命令走快路（0 次模型调用，留事实门记录），写操作仍进判定链');

// 9b. 会话内部工具（compress 等）只改会话、无对外副作用：事实门放行，不送模型
{
    const h = harness({ review: ALLOW });
    const decision = await h.preExecuteTool('compress', {
        content: [{ startId: 'm00001', endId: 'm00008', summary: 'folded' }],
    }, 'call-compress');
    assert.equal(decision, 'delegated', '内部工具直接放行');
    assert.equal(h.calls.review, 0, '内部工具不付模型调用');
    const [last] = h.api.inspect().recent(1);
    assert.equal(last.decision, 'allowed');
    assert.equal(last.layer, 'fact');
    assert.ok(last.message.includes('会话内部工具'), last.message);
    // 同一条调用跑完（例如 compress 被保护区驳回）也要能看到结局
    await h.fire('tools/result', { ...exec('', 'call-compress'), name: 'compress' }, {
        isError: true, content: [{ type: 'text', text: 'Error: Compression FAILED: batch rejected' }],
    });
    const result = h.api.inspect().recent(1)[0];
    assert.equal(result.eventType, 'tool.result');
    assert.equal(result.decision, 'failed');
    assert.ok(result.message.includes('Compression FAILED'), result.message);
}
console.log('OK wiring: compress 等会话内部工具走事实门');

// 9c. 事实门放行也是「本插件放行」：台账写不进去就没有可追责的放行，降级成人工。
// 快判／深评早就守这条规矩，放行出口曾经漏了它——只读命令在坏台账上会悄悄过去。
{
    const blocked = join(root, 'blocked-home-fact');
    writeFileSync(blocked, 'not a directory');
    process.env.DSH_HOME = blocked;
    const h = harness({ review: ALLOW });
    const decision = await h.preExecute('ls');
    assert.equal(decision.kind, 'ask', '坏台账下只读放行必须转人工，不能交回宿主悄悄执行');
    assert.ok(decision.displayReason.includes('台账'), decision.displayReason);
    assert.equal(h.calls.review, 0, '降级成人工不该付模型调用');
    process.env.DSH_HOME = join(root, 'dsh-home');
    console.log('OK wiring: 事实门放行同样要求台账可写');
}

// 9c. 最终结果入账：放行后成功/失败都留一条 tool.result，接上 ask 的结局
{
    const h = harness({ review: ALLOW });
    await h.preExecute('rm -f junk0.txt', 'call-result-ok');
    await h.fire('tools/result', exec('rm -f junk0.txt', 'call-result-ok'), {
        isError: false, content: [{ type: 'text', text: 'done' }],
    });
    const ok = h.api.inspect().recent(1)[0];
    assert.equal(ok.eventType, 'tool.result');
    assert.equal(ok.decision, 'info');
    assert.ok(ok.message.includes('done'), ok.message);

    const rejected = harness({ review: ALLOW, config: { commandRules: ['ask rm'] } });
    await rejected.preExecute('rm -f junk0.txt', 'call-result-fail');
    await rejected.fire('tools/result', exec('rm -f junk0.txt', 'call-result-fail'), {
        isError: true, content: [{ type: 'text', text: 'Error: the user rejected tool "bash"' }],
    });
    const failed = rejected.api.inspect().recent(1)[0];
    assert.equal(failed.decision, 'failed');
    assert.ok(failed.message.includes('rejected'), failed.message);
}
console.log('OK wiring: 工具结果成功/失败都入账，ask 不再断尾');

// 11. 规则平面：deny 直接拦，ask 转人工，两者都不付模型钱
{
    const h = harness({ review: ALLOW, config: { commandRules: ['deny rm -rf'] } });
    const decision = await h.preExecute('rm -rf emptydir', 'call-rule-deny');
    assert.equal(decision.kind, 'deny');
    assert.ok(decision.reason.includes('规则拦截'), decision.reason);
    assert.equal(h.calls.review, 0, '规则命中不送模型');
    const [last] = h.api.inspect().recent(1);
    assert.equal(last.decision, 'blocked');
    assert.equal(last.layer, 'rules');
    assert.equal(last.rule, 'deny rm -rf');
}
{
    const h = harness({ review: ALLOW, config: { commandRules: ['ask rm'] } });
    const decision = await h.preExecute('rm -f junk0.txt', 'call-rule-ask');
    assert.equal(decision.kind, 'ask');
    assert.ok(decision.displayReason.includes('规则命中'), decision.displayReason);
    assert.equal(h.calls.review, 0);
    await h.approvalRequest('call-rule-ask');
    const decisions = h.api.inspect().recent(6).map(entry => `${entry.category}:${entry.decision}`);
    assert.ok(decisions.includes('tool:ask'), decisions.join(','));
    assert.ok(decisions.includes('approval:rejected'), decisions.join(','));
}
{
    // 「AI」档只让这一层不拦，调用仍要走模型——旧配置里存的 `allow` 折到这一档（上面那行就是旧名）。
    const h = harness({ review: ALLOW, config: { commandRules: [{ action: 'allow', match: 'rm' }] } });
    assert.deepEqual(await h.preExecute('rm -f junk0.txt', 'call-rule-allow'), { kind: 'allow' });
    assert.equal(h.calls.review, 1, 'AI 档不能代替模型调用');
    const rows = h.api.inspect().recent(4);
    assert.ok(rows.some(entry => entry.layer === 'rules' && entry.decision === 'info' && entry.rule === 'ai rm'),
        rows.map(entry => `${entry.layer}:${entry.decision}:${entry.rule}`).join(','));
    assert.ok(rows.some(entry => entry.layer === 'fast' || entry.layer === 'deep'), '真正放行的是 AI 层');
}
{
    // 「允许」是真放行：不调模型、不弹面板，但必须留一条可追责的行。
    const h = harness({ review: ALLOW, config: { commandRules: [{ action: 'release', match: 'rm' }] } });
    assert.equal(await h.preExecute('rm -f junk0.txt', 'call-release'), 'delegated', '直接放行＝交回宿主执行');
    assert.equal(h.calls.review, 0, '允许档不调模型');
    const [last] = h.api.inspect().recent(1);
    assert.equal(last.decision, 'allowed');
    assert.equal(last.layer, 'rules', '放行记在规则层，指认得出是哪一行放的');
    assert.equal(last.rule, 'release rm', last.rule);
}
{
    // 真放行也要求台账可写：写不进去就没有可追责的放行，降级人工（与事实门、快判深评同一条规矩）。
    const blocked = join(root, 'blocked-home-release');
    writeFileSync(blocked, 'not a directory');
    process.env.DSH_HOME = blocked;
    const h = harness({ review: ALLOW, config: { commandRules: [{ action: 'release', match: 'rm' }] } });
    const decision = await h.preExecute('rm -f junk0.txt', 'call-release-blocked');
    assert.equal(decision.kind, 'ask', '坏台账下「允许」不许悄悄放行');
    assert.ok(decision.displayReason.includes('台账'), decision.displayReason);
    process.env.DSH_HOME = join(root, 'dsh-home');
    console.log('OK wiring: 允许＝真放行（0 次模型调用、记规则层）且同样要求台账可写');
}
{
    // 内置行全部可改：把「凭据文件名」这一条停用，就是一次普通的改档位，不是绕过。
    const h = harness({
        review: ALLOW,
        config: { fileRules: [{ preset: 'credential-material', action: 'ai', enabled: true }] },
    });
    const decision = await h.preExecute(`rm -f "${join(ws, '.npmrc')}"`, 'call-floor-row');
    assert.notEqual(decision.kind, 'ask', '内置行改成 AI 后不再必人工（危险名单后议，现在不设特例）');
    const off = harness({
        review: ALLOW,
        config: {
            fileRules: [
                { preset: 'credential-or-client-tree', action: 'ask', enabled: false },
                { preset: 'credential-material', action: 'ask', enabled: false },
            ],
        },
    });
    const offDecision = await off.preExecute(`rm -f "${join(ws, '.ssh', 'id_ed25519')}"`, 'call-floor-off');
    assert.notEqual(offDecision.kind, 'ask', '两条都停用＝这条路不再拉高');
    console.log('OK wiring: 内置行可改可停用，停用与降档都照用户的行算');
}
{
    // 文件行按操作维度命中：只写「删」的规则管不住读。
    const denyDelete = harness({ review: ALLOW, config: { fileRules: [{ action: 'deny', match: `${ws}/`, ops: ['delete'] }] } });
    assert.equal((await denyDelete.preExecute('rm -f junk0.txt', 'call-file-deny')).kind, 'deny');
    assert.equal(denyDelete.calls.review, 0);
    const readOnly = harness({ review: ALLOW, config: { fileRules: [{ action: 'deny', match: `${ws}/`, ops: ['delete'] }] } });
    assert.ok((await readOnly.preExecute('cat junk0.txt', 'call-file-read')) !== undefined);
    assert.equal(readOnly.calls.review, 0, '只读命令走事实门，本就不送模型');
    assert.ok(readOnly.api.inspect().recent(1)[0].layer === 'fact', '读操作没被删除行误伤');
}
console.log('OK wiring: 规则表拦/问不付模型钱、allow 只放行到 AI、文件行按操作维度命中；人工答复独立入账');

// 12. 快判与深评：快判只可放行或升级，升级后才有深评
{
    const tiers = [];
    const h = harness({ review: async options => {
        tiers.push(options.tier);
        return { status: 'reviewed', decision: 'allow', reasonCode: 'no_material_risk', summary: 'trivial', durationMs: 1, model: 'stub' };
    } });
    assert.deepEqual(await h.preExecute('rm -f junk0.txt', 'call-fast'), { kind: 'allow' });
    assert.deepEqual(tiers, ['fast'], '单段写入 × grant=auto 先走快判，不付深评');
    assert.equal(h.api.inspect().recent(1)[0].layer, 'fast');
}
{
    const tiers = [];
    const h = harness({ review: async options => {
        tiers.push(options.tier);
        return { status: 'reviewed', decision: 'block', reasonCode: 'unauthorized_by_user', summary: 'no', durationMs: 1, model: 'stub' };
    } });
    assert.equal((await h.preExecute('rm -f junk0.txt', 'call-fast-block')).kind, 'deny');
    assert.deepEqual(tiers, ['fast', 'deep'], '快判的 block 只是升级信号，最终裁决来自深评');
}
{
    const h = harness({ review: ALLOW, config: { fastJudge: false } });
    await h.preExecute('rm -f junk0.txt', 'call-deep-only');
    assert.equal(h.api.inspect().recent(1)[0].layer, 'deep', '关掉快判后同一动作走深评');
}
console.log('OK wiring: 快判放行/升级两态，深评兜底，层级入账');

// 13. 结果脱敏：命中就遮成占位符，与档位无关；明文只进本机映射表，绝不进台账
{
    const h = harness({ review: ALLOW });
    const result = { content: [{ type: 'text', text: 'token=abcdef123456' }] };
    const decision = await h.fire('tools/post-execute', exec('cat .env', 'call-redact'), result,
        async () => ({ kind: 'accept', content: result.content }));
    assert.equal(decision.content[0].text.includes('abcdef123456'), false, '凭据不得回到模型');
    const token = /\[\[SEC-[0-9a-f]{12}\]\]/.exec(decision.content[0].text)?.[0];
    assert.ok(token, `要换成确定性占位符：${decision.content[0].text}`);
    const entry = h.api.inspect().secrets();
    assert.equal(entry.entries.some(item => item.token === token), true, '占位符要能在「敏感信息」表里找到');
    assert.equal(entry.entries.some(item => item.plain !== undefined), false, '列表默认不出明文');
    assert.equal(JSON.stringify(h.api.inspect().recent(3)).includes('abcdef123456'), false, '台账里不许出现明文');
    // 同一串明文再出现一次，还是同一个占位符（随机串会漂，回写与再脱敏就对不上）。
    const again = { content: [{ type: 'text', text: 'token=abcdef123456' }] };
    const second = await h.fire('tools/post-execute', exec('cat .env', 'call-redact-2'), again,
        async () => ({ kind: 'accept', content: again.content }));
    assert.equal(second.content[0].text.includes(token), true, '确定性：同明文同占位符');
    assert.equal(h.api.inspect().recent(1)[0].eventType, 'sensitive.redacted');
    assert.equal(h.api.inspect().recent(1)[0].layer, 'redact', '脱敏记录的层级要落在链上第 6 步，不是混进「安全规则」');
}
{
    // 遮与档位无关：这一行设成「允许」（真放行）也照样遮——放的是那次调用，不是明文。
    const h = harness({ review: ALLOW, config: { commandRules: [{ action: 'release', match: 'cat' }] } });
    const result = { content: [{ type: 'text', text: 'token=abcdef987654' }] };
    const decision = await h.fire('tools/post-execute', exec('cat .env', 'call-redact-release'), result,
        async () => ({ kind: 'accept', content: result.content }));
    assert.equal(decision.content[0].text.includes('abcdef987654'), false, '「允许」档不解除遮');
}
{
    const h = harness({ review: ALLOW, config: { sensitiveDetect: false } });
    const result = { content: [{ type: 'text', text: 'token=abcdef123456' }] };
    const decision = await h.fire('tools/post-execute', exec('cat .env', 'call-redact-off'), result,
        async () => ({ kind: 'accept', content: result.content }));
    assert.equal(decision.content[0].text, 'token=abcdef123456', '关闭脱敏后原样放行');
}
console.log('OK wiring: 结果脱敏同表、凭据不回模型、开关可关');

// 13b. 自动回写：模型把占位符写进配置文件，写完之后在文件层换回明文
// （参数改不了——宿主契约；文件能改。只换这张表铸出来的 token，别的一概不碰。）
{
    const target = join(ws, 'note.txt');
    const h = harness({ review: ALLOW, config: { autoRestoreSecrets: true } });
    const minted = { content: [{ type: 'text', text: 'token=abcdef123456' }] };
    const masked = await h.fire('tools/post-execute', exec('cat .env', 'call-mint'), minted,
        async () => ({ kind: 'accept', content: minted.content }));
    const token = /\[\[SEC-[0-9a-f]{12}\]\]/.exec(masked.content[0].text)[0];
    // 文件里还有一枚不是这张表铸的占位符：回写只碰自己认得的那一枚。
    writeFileSync(target, `${masked.content[0].text}\nkeep [[SEC-0123456789ab]]\n`);
    await h.fire('tools/post-execute', exec(`cat > "${target}"`, 'call-restore'),
        { content: [{ type: 'text', text: 'ok' }] },
        async () => ({ kind: 'accept', content: [{ type: 'text', text: 'ok' }] }));
    const after = readFileSync(target, 'utf8');
    assert.ok(after.includes('token=abcdef123456'), `占位符要换回明文：${after}`);
    assert.ok(after.includes('[[SEC-0123456789ab]]'), '不是这张表铸的方括号串一概不碰');
    assert.equal(after.includes(token), false, '自己那枚占位符不再留在文件里');
    assert.equal(h.api.inspect().recent(4).some(row => row.eventType === 'sensitive.restored'), true, '回写要留台账');
}
console.log('OK wiring: 自动回写只换自己铸的占位符，文件本身落地后修正');

// 14. 旧单文件台账在启动时迁移，原文件留作证据
{
    const home = join(root, 'migrate-home');
    mkdirSync(join(home, 'auto-approval-frame'), { recursive: true });
    writeFileSync(join(home, 'auto-approval-frame', 'decisions.jsonl'),
        `${JSON.stringify({ event: 'decision', at: Date.now(), sequence: 1, toolName: 'bash', grant: 'auto', outcome: 'allowed-once', decidedBy: 'ai', action: 'rm -f x' })}\n`);
    process.env.DSH_HOME = home;
    const h = harness({ review: ALLOW });
    const entries = h.api.inspect().recent(10);
    assert.ok(entries.some(entry => entry.eventType === 'lifecycle.migrate'), '迁移事件必须入账');
    assert.ok(entries.some(entry => entry.eventType === 'tool.allowed'), '旧判定行必须导入');
    assert.equal(existsSync(join(home, 'auto-approval-frame', 'decisions.jsonl')), false);
    assert.equal(existsSync(join(home, 'auto-approval-frame', 'audit', 'legacy')), true);
    assert.equal(h.api.inspect().audit.ok, true);
    process.env.DSH_HOME = join(root, 'dsh-home');
}
console.log('OK wiring: 旧台账迁移一次，原文件移入 legacy/');

// 10. 审计路由＋判定链读侧：查询 / 导出 / 清空 / frame（同源、非回环拒绝）
{
    const h = harness({
        review: ALLOW,
        config: {
            fileRules: [
                { action: 'allow', match: join(root, 'trash'), ops: ['all'] },
                { action: 'allow', match: join(process.env.DSH_HOME, 'skills'), ops: ['all'] },
                { action: 'allow', match: process.env.DSH_HOME, ops: ['all'] },
                { action: 'deny', match: 'D:/build/**', ops: ['delete'] },
            ],
        },
    });
    await h.preExecute('rm -f junk0.txt', 'call-route');
    assert.equal(h.routes.length, 7, '查询/导出/清空/判定链/模拟审批/模型目录/敏感信息 七条路由');
    const byPath = Object.fromEntries(h.routes.map(route => [route.path, route]));
    const query = byPath['/api/auto-approval-frame/audit'];
    const exportRoute = byPath['/api/auto-approval-frame/audit/export'];
    const clearRoute = byPath['/api/auto-approval-frame/audit/clear'];
    const frameRoute = byPath['/api/auto-approval-frame/frame'];
    const explainRoute = byPath['/api/auto-approval-frame/explain'];
    assert.ok(query && exportRoute && clearRoute && frameRoute && explainRoute, Object.keys(byPath).join(','));
    assert.deepEqual(clearRoute.methods, ['POST']);
    const frame = await (await frameRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/frame'))).json();
    assert.equal(frame.ok, true);
    assert.deepEqual(frame.missingGatedPresets, [], '受管档在宿主目录里时不出缺失告警');
    // 内置行由宿主一处给出（页面只渲染它，不再自己拼第二份清单）。
    assert.ok(frame.rows.file.filter(row => row.preset !== '').length >= 8, '文件面要读得到内置行');
    assert.ok(frame.rows.command.filter(row => row.preset !== '').length >= 5, '命令面也要有内置行');
    assert.equal(Object.values(frame.rows).flat().filter(row => row.preset !== '')
        .every(row => row.action === 'ask'), true, '内置行默认全人工，页面读到的与判定用的同一份');
    assert.deepEqual(frame.trusted.map(row => row.match), [join(root, 'trash').toLowerCase()], '表外信任行进读侧');
    assert.deepEqual(frame.dshOpen.map(row => row.match), [join(process.env.DSH_HOME, 'skills').toLowerCase()],
        '状态树子目录行按开口报告');
    assert.deepEqual(frame.rejected.map(row => row.reason), ['whole-state-tree'],
        '整棵 ~/.dsh 的允许行要被拒并说明原因');
    const frameDenied = await frameRoute.fetch(new Request('http://198.51.100.9:4321/api/auto-approval-frame/frame'));
    assert.equal(frameDenied.status, 403, '判定链读侧同样只接回环');
    const noTier = harness({ knownPresets: ['workspace-write'] });
    await noTier.preExecute('rm -f junk0.txt', 'call-missing-tier');
    const noTierFrameRoute = noTier.routes.find(route => route.path === '/api/auto-approval-frame/frame');
    const noTierFrame = await (await noTierFrameRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/frame'))).json();
    assert.deepEqual(noTierFrame.missingGatedPresets, ['auto-approval'],
        '受管档不在宿主目录时 /frame 要报出来（页面红字依赖它）');
    // 模型目录只读 profile 配置：不调 llm 服务、不碰网络（上一版调 listModels 卡了十几秒还没结果）。
    const modelsRoute = byPath['/api/auto-approval-frame/models'];
    const models = await (await modelsRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/models'))).json();
    assert.equal(models.ok, true);
    assert.deepEqual(models.groups.map(group => group.id), ['nodeb4603', 'test'], '按 profile 里声明的顺序列提供方');
    assert.deepEqual(models.groups.map(group => group.name), ['生产 vLLM', '测试 vLLM'], '组名用 displayName，不是内部 id');
    assert.deepEqual(models.groups[0].models, [{ id: 'qwen3.8-27b', name: 'qwen3.8-27b' }], '选项写 id，选中直接写回两枚配置键');
    assert.ok(!models.groups.some(group => group.id === 'nosettings'), '没声明 models 的提供方不进列表');
    assert.equal(models.note, '', '读到了就不该带抱怨');
    assert.equal((await modelsRoute.fetch(new Request('http://198.51.100.9:4321/api/auto-approval-frame/models'))).status, 403, '模型目录同样只接回环');
    // 试算：一条命令走完整条链，逐步回落点；不调模型，也不执行任何东西。
    const reviewsBefore = h.calls.review;
    const askExplain = async q => (await explainRoute.fetch(new Request(
        `http://127.0.0.1:4321/api/auto-approval-frame/explain?q=${encodeURIComponent(q)}`))).json();
    const tried = await askExplain('rm -rf emptydir');
    assert.equal(tried.steps.length, 6, '六个关卡：是否接管／安全规则（内置行＋你的行）／事实门／AI 审查／人工／结果脱敏');
    assert.equal(tried.steps.find(step => step.step === '6').name, '结果脱敏',
        '第 6 步与页面判定链同名；它发生在执行之后，不参与这次让不让执行');
    // 你的行没命中，但内置行有话要说（垃圾桶那条例外管的是另一个目录）⇒ 这一步落在「内置行」上。
    assert.equal(tried.steps.find(step => step.step === '1').state, 'confirm', '工作区外的删除：内置行让 AI 只能给建议');
    assert.ok(tried.steps.find(step => step.step === '1').why.startsWith('内置行：'), tried.steps[0].why);
    assert.ok(tried.verdict.includes('内置行'), tried.verdict);
    assert.equal(tried.steps.find(step => step.step === '2').state, 'skip', '内置行的 confirm 不截断链：后面关卡照常列出来');
    // 落在信任目录里的可弃文件：内置行没意见、你的行是「允许」（不算命中）⇒ 一路走到 AI 审查那格。
    const inside = await askExplain(`rm -f "${join(root, 'trash', 'junk.txt')}"`);
    assert.equal(inside.steps.find(step => step.step === '1').state, 'pass', '允许行只表示这一层不拦，不等于这一步定了');
    assert.ok(inside.verdict.includes('AI 审查'), inside.verdict);
    // 命中拦截行时：决定步之后全部标成「不再走」，页面不会让人以为还会往下放行。

    const blocked = await askExplain('rm -rf D:/build/out');
    assert.equal(blocked.steps.find(step => step.step === '1').state, 'deny', '文件规则的删除列命中');
    assert.ok(blocked.steps.find(step => step.step === '1').why.startsWith('你的行命中：'), blocked.steps[0].why);
    assert.ok(blocked.steps.find(step => step.step === '1').why.includes('D:/build/**'), blocked.steps[0].why);
    assert.equal(blocked.steps.find(step => step.step === '2').state, 'n/a', '决定步之后不再往下走');
    assert.equal(blocked.steps.find(step => step.step === '6').state, 'n/a', '被拒绝的调用没有结果可遮');
    assert.ok(blocked.verdict.includes('安全规则'), blocked.verdict);
    // 踩到下界的路径轮不到规则：.git 属于客户端树，第 1 步就定死。
    const gitDir = await askExplain('rm -rf D:/repo/.git/objects');
    assert.equal(gitDir.steps.find(step => step.step === '1').state, 'never', '内置行先定（.git 属于客户端树）');
    assert.ok(gitDir.steps.find(step => step.step === '1').why.startsWith('内置行：'), gitDir.steps[0].why);
    assert.equal(gitDir.steps.find(step => step.step === '2').state, 'n/a', '内置行定掉之后你的行不再走');
    const credential = await askExplain('cat ~/.ssh/id_ed25519');
    assert.equal(credential.steps.find(step => step.step === '1').state, 'never', '凭据文件由内置行定住');
    assert.ok(credential.verdict.includes('内置行'), credential.verdict);
    assert.equal(credential.steps.find(step => step.step === '2').state, 'n/a', '下界之后规则与 AI 都不再走');
    assert.equal(h.calls.review, reviewsBefore, '试算不调模型');
    // 自证：模拟审批读的是宿主手里那份配置。explain 回的规则数就是页面上那行「共 N 行」的来源。
    assert.equal(tried.ruleTotal, 4, `回的是当前生效的行数：${tried.ruleTotal}`);
    assert.deepEqual(tried.rules, { command: 0, file: 4, network: 0, tool: 0, sensitive: 0 }, JSON.stringify(tried.rules));
    const stored = { row: { fileRules: [{ match: 'D:/logs/**', read: '', write: '', delete: 'deny' }] } };
    const late = harness({ review: ALLOW, config: { fileRules: stored.row.fileRules }, stored });
    const lateRoute = late.routes.find(route => route.path === '/api/auto-approval-frame/explain');
    const askLate = async q => (await lateRoute.fetch(new Request(
        `http://127.0.0.1:4321/api/auto-approval-frame/explain?q=${encodeURIComponent(q)}`))).json();
    const first = await askLate('rm -rf D:/logs/a.txt');
    assert.equal(first.ruleTotal, 1, '启动时就在配置里的行算进来');
    assert.equal(first.steps.find(step => step.step === '1').state, 'deny', first.steps[0].why);
    // 存一条新行 → 宿主发 settings/document-updated → 规则数与判定都要立刻跟着变。
    stored.row = {
        fileRules: [
            { match: 'D:/logs/**', read: '', write: '', delete: 'deny' },
            { match: 'E:/cache/**', read: '', write: '', delete: 'ask' },
        ],
    };
    await late.fire('settings/document-updated', 'auto-approval-frame');
    const after = await askLate('rm -rf E:/cache/x.txt');
    assert.equal(after.ruleTotal, 2, '新存的行要立刻进规则数');
    assert.equal(after.steps.find(step => step.step === '1').state, 'ask', '自定义规则存完就该被模拟到');
    assert.ok(after.steps.find(step => step.step === '1').why.includes('E:/cache/**'), after.steps[0].why);
    // 别的命名空间刷新不该触发我们重读。
    await late.fire('settings/document-updated', 'something-else');
    assert.equal((await askLate('rm -rf E:/cache/x.txt')).ruleTotal, 2);

    const blankTry = await explainRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/explain?q='));
    assert.equal(blankTry.status, 400, '空输入不试算');
    const farTry = await explainRoute.fetch(new Request('http://198.51.100.9:4321/api/auto-approval-frame/explain?q=ls'));
    assert.equal(farTry.status, 403, '试算也只接回环');
    const ok = await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit?decision=allowed'));
    assert.equal(ok.status, 200);
    const body = await ok.json();
    assert.equal(body.ok, true);
    assert.ok(body.entries.length > 0, '至少应含一条 allowed 记录');
    assert.equal(body.entries.every(entry => entry.decision === 'allowed'), true);
    assert.equal(body.chain.ok, true);
    const noBoot = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit?hide=lifecycle.boot'))).json();
    assert.equal(noBoot.entries.some(entry => entry.eventType === 'lifecycle.boot'), false, 'hide 参数排除启动记录');
    const exported = await exportRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit/export?format=jsonl'));
    assert.equal(exported.status, 200);
    assert.match(exported.headers.get('content-type'), /ndjson/);
    const text = await exported.text();
    assert.ok(text.includes('"decision":"allowed"'), text.slice(0, 200));
    const markdown = await (await exportRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit/export?format=md'))).text();
    assert.ok(markdown.includes('已放行'), markdown.slice(0, 200));
    // 启动行的层级该是「生命周期」：冒充内置行会让人以为插件在启动时判过什么东西。
    assert.ok(markdown.includes('层级 生命周期'), markdown.slice(0, 400));
    assert.ok(!markdown.includes('代码下界'), '导出件与页面同一套层级名字，不许两套');
    // 分页的界只由 store 负责：越界参数要归到边界值，而不是变成「空结果」或倒数切片。
    const paged = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit'))).json();
    const hugeLimit = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit?limit=999999'))).json();
    assert.ok(hugeLimit.entries.length <= 500, `limit 有上界：${hugeLimit.entries.length}`);
    assert.equal(hugeLimit.matched, paged.matched, '超界参数不许改变命中总数，只夹页大小');
    const zeroLimit = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit?limit=0'))).json();
    assert.ok(zeroLimit.entries.length >= 1, 'limit=0 不等于一条都不给（回到默认页）');
    const negativeOffset = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit?offset=-9'))).json();
    assert.equal(negativeOffset.entries.length, paged.entries.length, '负 offset 夹到 0');
    // 模拟审批的输入也要有界：它是用户粘进来的原文，直接喂进判定链。
    const hugeTry = await explainRoute.fetch(new Request(`http://127.0.0.1:4321/api/auto-approval-frame/explain?q=${'x'.repeat(2001)}`));
    assert.equal(hugeTry.status, 400, '超长输入要在进链之前挡掉');
    assert.match((await hugeTry.json()).error, /2000/);
    const denied = await query.fetch(new Request('http://198.51.100.9:4321/api/auto-approval-frame/audit'));
    assert.equal(denied.status, 403, '非回环地址必须 403');
    const cleared = await clearRoute.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit/clear', { method: 'POST' }));
    assert.equal(cleared.status, 200);
    const afterClear = await (await query.fetch(new Request('http://127.0.0.1:4321/api/auto-approval-frame/audit'))).json();
    assert.equal(afterClear.total, 1, '清空后只留清空事件');
    assert.equal(afterClear.entries[0].eventType, 'audit.clear');
}
// ── 差分锁：同一份配置，模拟审批的答案必须与真判定逐条对得上 ──────────────
// 这条用例是「彻底根除两套实现」的那道闸：explain 与 tools/pre-execute 现在共用
// walkLadder，谁要是再分叉（比如把「允许」行算成命中或不算命中），这里立刻红。
{
    const diffConfig = {
        commandRules: [
            { action: 'deny', match: 'rm -rf D:/build/**' },
            { action: 'ask', match: 'git push --force' },
            { action: 'allow', match: 'ls' },
        ],
        fileRules: [
            { match: join(root, 'trash'), read: 'allow', write: 'allow', delete: 'allow' },
            { match: 'D:/logs/**', read: '', write: '', delete: 'deny' },
        ],
    };
    const dh = harness({ review: ALLOW, config: diffConfig });
    const explainRoute = dh.routes.find(route => route.path === '/api/auto-approval-frame/explain');
    const ask = async q => (await explainRoute.fetch(new Request(
        `http://127.0.0.1:4321/api/auto-approval-frame/explain?q=${encodeURIComponent(q)}`))).json();
    // 模拟侧：链上第一个决定步（never／deny／ask／release）折算成同一个词表。
    const saidBy = body => {
        const step = body.steps.find(item => ['never', 'deny', 'ask', 'release'].includes(item.state));
        if (step === undefined) return 'ai';
        if (step.step === '2') return 'fact';
        return step.state === 'never' ? 'floor' : step.state;
    };
    // 真判定侧：台账里第一条真正定了结局的行。
    const decidedBy = callId => {
        const rows = dh.api.inspect().recent(60).filter(row => row.toolCallId === callId);
        const row = rows.find(item => ['blocked', 'ask', 'allowed'].includes(item.decision));
        if (row === undefined) return 'ai';
        if (row.layer === 'floor') return 'floor';
        if (row.layer === 'fact') return 'fact';
        if (row.layer === 'rules') return row.decision === 'blocked' ? 'deny' : row.decision === 'allowed' ? 'release' : 'ask';
        return 'ai';
    };
    const table = [
        ['ls', 'fact', '允许行不算决定，但 ls 是纯只读 ⇒ 由事实门放行'],
        ['ls -a', 'fact', '带参数的只读命令同样落在事实门'],
        ['rm -rf D:/build/out', 'deny', '拦截行命中：两边都必须是 deny'],
        ['git push --force origin main', 'ask', '询问行命中：两边都必须是 ask'],
        ['rm -rf D:/repo/.git/objects', 'floor', '内置行先定：只能由你确认'],
        ['cat ~/.ssh/id_ed25519', 'floor', '凭据文件由内置行定住'],
        ['rm -f D:/logs/a.txt', 'deny', '文件行的删除列拦截要能被模拟出来'],
    ];
    for (const [index, [command, expected, note]] of table.entries()) {
        const body = await ask(command);
        const said = saidBy(body);
        assert.equal(said, expected, `模拟对 ${command} 的落点：${note}｜${JSON.stringify(body.steps.map(step => [step.step, step.state]))}`);
        await dh.preExecute(command, `diff-${index}`);
        const decided = decidedBy(`diff-${index}`);
        assert.equal(decided, said, `${command}：模拟说 ${said}，真判定台账说 ${decided}——两条实现又分叉了`);
    }
    console.log('OK wiring: 差分锁——模拟审批与真判定逐条对账（七条命令，落点一致）');
}

{
    const src = readFileSync(new URL('../lib/index.js', import.meta.url), 'utf8');
    for (const name of ['collectFacts', 'grantFor', 'evaluatePolicies', 'networkTargets'])
        assert.ok(!src.includes(name + '('),
            `index.js 里又出现了 ${name}( —— 判定链被重新分叉成第二套实现，模拟审批会与真判定说两套话`);
    console.log('OK wiring: 链条只有一份实现——index.js 不再自己走下界／规则／事实门');
}

console.log('OK wiring: 审计路由查询/导出/清空＋判定链读侧报告保护、信任、开口与被拒行，非回环 403');

// 10b. 旧的三个范围键自动迁成文件规则行，行为不降级、也不留第二份真相
{
    const trash = join(root, 'trash');
    mkdirSync(trash, { recursive: true });
    writeFileSync(join(trash, 'l10.txt'), '');
    const migrated = harness({
        review: ALLOW,
        config: { trustedDirs: [trash], dshOpen: [join(process.env.DSH_HOME, 'skills')], neverAutoExtra: [ws] },
    });
    const view = migrated.api.inspect().config;
    assert.equal(view.trustedDirs, undefined, '旧键不再出现在生效配置里');
    assert.equal(view.dshOpen, undefined);
    assert.equal(view.neverAutoExtra, undefined);
    const matches = view.fileRules.map(row => `${row.read}:${row.match}`);
    assert.ok(matches.includes(`ai:${trash}`), `信任目录要迁成「AI」行：${matches.join(',')}`);
    assert.ok(matches.includes(`ai:${join(process.env.DSH_HOME, 'skills')}`), '开口同样迁成「AI」行');
    assert.ok(matches.includes(`ask:${ws}`), '额外禁放迁成询问行（原语义是必人工）');
    // 禁放行排在允许行之前：宽信任不能把自己的禁放覆盖掉。
    assert.ok(view.fileRules.findIndex(row => row.read === 'ask') < view.fileRules.findIndex(row => row.read === 'ai'),
        '禁放行必须排在 AI 行之前');
    const decision = await migrated.preExecute(`rm -f ${join(ws, 'junk0.txt')}`, 'call-legacy-ask');
    assert.equal(decision.kind, 'ask', '旧 neverAutoExtra 的目录迁完后仍然必人工');
    assert.equal(migrated.calls.review, 0, '询问行不付模型钱');
    const outside = await migrated.preExecute(`rm -f ${join(trash, 'l10.txt')}`, 'call-legacy-trust');
    assert.deepEqual(outside, { kind: 'allow' }, '迁成 AI 行后，垃圾桶里的空文件仍可被 AI 放行');
    // 迁移只做一次：表已经有自己的行时，旧键不得再复制一遍，也不得复活被删掉的行。
    const again = harness({
        review: ALLOW,
        config: {
            trustedDirs: [trash],
            fileRules: [{ action: 'deny', match: join(trash, 'gone.txt'), ops: ['delete'] }],
        },
    });
    const rowsAgain = again.api.inspect().config.fileRules;
    assert.equal(rowsAgain.length, 1, `旧键不能往已有的表里塞行：${JSON.stringify(rowsAgain)}`);
    assert.equal(rowsAgain[0].delete, 'deny', '行内容按原样保留（删除列＝拦截）');
}
console.log('OK wiring: trustedDirs/dshOpen/neverAutoExtra 一次性迁成文件规则行，语义与优先级不变');

console.log(`\nALL WIRING CASES PASS (ledger dir ${harness({}).api.inspect().stateDir})`);
rmSync(root, { recursive: true, force: true });
