/** * The decision ladder — ONE implementation, two consumers.
 *
 * `tools/pre-execute` runs it to decide a live call; `GET /api/auto-approval-frame/explain`
 * (the settings page's 模拟审批) runs the same function to explain a call without
 * executing it. Before this module the two paths were written out twice, and they
 * drifted: an `allow` row that really matched was reported as "你的行也没命中" by the
 * simulator. Nothing here prevents drift by convention — the simulator cannot disagree
 * because there is nothing else to disagree with, and `test/wiring.test.mjs` compares
 * the two entry points on a table of commands.
 */
import { collectFacts } from './facts.js';
import { grantFor } from './grant.js';
import { effectiveRows, evaluatePolicies, floorActions, networkTargets, reasonText } from './policy.js';
import { buildActionRecord } from './record.js';

/** 模拟页「第 1 步」沿用既有措辞「你的行」（既有断言锁在 steps 上）；结论句用「你的规则」。 */
function stepSpeakerOf(by, rule) {
    const speaker = speakerOf(by, rule);
    return speaker === '你的规则' ? '你的行' : speaker;
}

/** 一张结论的说话人：预设行／你的规则／事实闸（事实闸独立一档）。
 *  依据＝实测：60 的事实闸 policy.layer='fact'，但台账行与 outcome.by 都写 'rules'，
 *  与用户规则行同层 —— 只能靠 rule 前缀「别的项目根且未点名」区分，不许照 PLAN 文案硬编。 */
const FOREIGN_RULE_PREFIX = '别的项目根且未点名';
function speakerOf(by, rule = '') {
    if (by === 'floor')
        return '预设行';
    if (String(rule ?? '').startsWith(FOREIGN_RULE_PREFIX))
        return '外项目闸';
    // 判据 3：与 index.js 的 askText（禁改侧）对齐——不再叫「你的行」。
    return '你的规则';
}

/** Pure read / session-internal calls cannot change anything outside the session. */
function factGateOf(facts) {
    // 只读不再是「程序名在表里」的推论，而是事实层的举证结果（A1：特权换证据）。
    // A2：这里只**报告证据**，不再放行——放不放由表里的「已证明只读／会话内部工具」两行拍板。
    return { readOnly: facts.provenRead === true, internalOnly: facts.internalOnly === true };
}

/** * Walk one call through 事实（取证）→ 一张有序表（预设行＋你的行）→ 模式 → AI 审查.
 * @returns outcome: deny | ask | release | delegate | review, plus the audit rows
 *          the caller must write and everything the simulator needs to narrate.
 */
export function walkLadder({ toolName, args, config, roots, probe, env, session, callId, authorization }) {
    const command = typeof args?.command === 'string' ? args.command : '';
    const facts = collectFacts({ toolName, args, roots, probe, env });
    const grant = grantFor(facts, roots, floorActions(config), authorization);
    // 一次构建、**先于判定**（A05）：证据块、模拟、台账都读这一份，不再各层重猜输入。
    // "实际由谁批准"稍后由这里填；宿主最终返回仍由 index.js 的两格账单独记。
    const record = buildActionRecord({ toolName, args, config, roots, facts, grant, session, callId, authorization });
    const policy = evaluatePolicies({
        toolName,
        command,
        segments: facts.segments,
        targets: facts.targets,
        urls: [...networkTargets(command), ...(facts.remoteHosts ?? [])],
        payloads: facts.payloads,
        config,
        roots,
        hits: grant.hits,
        segmentScopes: grant.segmentScopes,
        targetScopes: grant.targetScopes,
    });
    const { readOnly, internalOnly } = factGateOf(facts);
    const emits = [];
    if (policy.decision === 'ai') {
        // 卡片头已经是「命中规则 N 名字 ｜ 规则结果 AI」；这行原来又写「命中：本层不拦，继续交模型判」，
        // 同一件事说两遍，而且「本层不拦」是 之前的旧语义（AI 档现在是终局路由）。
        // 记录留着——规则名靠这条带进台账——只是不再写 message。
        emits.push({
            decision: 'info', layer: policy.layer ?? 'rules', rule: policy.rule, plane: policy.plane,
        });
    }
    // 一张表、一套顺序：预设行与用户行谁先给出结论谁算，AI 档只是不拍板。
    const by = policy.layer === 'fact' ? 'fact'
        : policy.layer === 'floor' ? 'floor' : 'rules';
    // 事实闸（policy.layer='fact'）在落账那一格保留 fact——by 仍按既有三档（66 的锁不动），
    // 只让台账「这一行是谁说的」靠字段读得出来；判定与文案一字不改。
    const auditLayer = policy.layer === 'fact' ? 'fact' : by;
    const said = speakerOf(by, policy.rule);
    const label = (policy.rule ?? '').trim();
    let outcome;
    // 模式＝关闭 时**一切交回宿主**：本插件不拦也不判。这条必须在表之前——
    // 过去 off 仍让表里的 deny／ask 行先定局，等于"我明明关了它还是在拦我"（F10）。
    if (config.mode === 'off') {
        outcome = {
            kind: 'delegate', by: 'mode',
            audit: { decision: 'ask', layer: 'none', message: '模式已关闭：交回宿主面板' },
        };
    }
    else if (policy.decision === 'deny') {
        outcome = {
            kind: 'deny', by, layer: by, rule: policy.rule, plane: policy.plane,
            reason: `auto-approval-frame: ${said}拦截（${policy.plane}）${label}`,
            displayReason: `${said}拦截：${label}`,
            audit: { decision: 'blocked', layer: auditLayer, rule: policy.rule, plane: policy.plane },
        };
    }
    else if (policy.decision === 'ask') {
        outcome = {
            kind: 'ask', by, layer: by, rule: policy.rule, plane: policy.plane,
            reason: `auto-approval-frame: ${said} requires a human`,
            displayReason: `${said}需要你确认：${label}`,
            audit: {
                decision: 'ask', layer: auditLayer, rule: policy.rule, plane: policy.plane,
                // 卡片首句读的是 rule；台账也留同一份，复盘时不用从文案反推是谁没放。
                releaseBlockers: [{ id: by, text: policy.rule }],
            },
        };
    }
    // 「允许」是真放行：不调模型、不弹面板，但必须留下可追责的一行（写不进去就转人工）。
    else if (policy.decision === 'release') {
        outcome = {
            kind: 'release', by, layer: by,
            message: `${said}直接放行：${label}`,
            // 卡片上已有「规则结果 允许」，再写一句「允许＝直接放行」是同一件事说两遍。
            audit: { decision: 'allowed', layer: auditLayer, rule: policy.rule, plane: policy.plane },
        };
    }
    else {
        outcome = { kind: 'review', by: 'ai' };
    }
    // 逐项结论收进同一份 ActionRecord（审查报告 §4.2）：证据块、模拟、台账都读它，
    // 不再各层重新猜输入。"实际由谁批准"在这里落本插件的结局；宿主最终返回仍由
    // index.js 的两格账单独记（tool.handoff，layer:'host'）。
    // 说话人单独一格——台账不必靠猜文案就知道是谁在说话（不改 decision 序列）。
    outcome.speaker = said;
    record.decision = {
        kind: outcome.kind,
        by: outcome.by,
        layer: outcome.layer ?? null,
        rule: outcome.rule ?? null,
        plane: outcome.plane ?? null,
        reasons: [...grant.reasons],
        hits: Object.fromEntries([...grant.hits].map(([reason, byOp]) => [reason, { ...byOp }])),
        factGate: { readOnly, internalOnly },
    };
    return { command, facts, grant, policy, record, readOnly, internalOnly, emits, outcome };
}

/** 第 1 步：一张有序表里，谁先给出结论谁算；AI 档只是不拍板。 */
function rulesStep(walk) {
    const decision = walk.policy.decision;
    const by = walk.policy.layer;
    const state = decision === 'deny' ? 'deny'
        : decision === 'ask' ? 'ask'
            : decision === 'release' ? 'release' : 'pass';
    const said = [];
    if (decision === 'deny' || decision === 'ask' || decision === 'release') {
        const who = stepSpeakerOf(by, walk.policy.rule);
        said.push(`${who}命中：${walk.policy.rule ?? ''}${decision === 'release' ? '（允许＝直接放行，不调模型）' : ''}`);
    }
    else if (decision === 'ai')
        // 判据 1：AI 不是「本层不拦，继续往下找」，而是**终局路由**。
        said.push(`命中：${walk.policy.rule ?? ''}（AI 档＝终局路由：直接交模型判，后面的行不再表态）`);
    if (walk.grant.reasons.length > 0 && walk.grant.state === 'confirm')
        said.push(`另需你确认：${walk.grant.reasons.map(reasonText).join('、')}`);
    return {
        step: '1', name: '安全规则', state,
        why: said.length > 0 ? said.join('；') : '预设没踩到，你的行也没命中',
        detail: walk.grant.disposability ?? null,
    };
}

/** * The ladder as the settings page narrates it. Derived from the same walk, so a step
 * can never claim something the decision did not do.
 */
export function ladderSteps(walk, { enabled, gatedPresets }) {
    const steps = [{
        step: '0',
        name: '是否接管',
        state: enabled === true ? 'pass' : 'stop',
        why: enabled === true
            ? `只有权限档在 ${(gatedPresets ?? []).join('、')} 里的会话才判`
            : '插件已关闭，全部交回宿主面板',
    }, rulesStep(walk)];
    if (enabled !== true) {
        steps.push(
            { step: '2', name: 'AI 审查', state: 'stop', why: '本插件不判定' },
            { step: '3', name: '人工', state: 'stop', why: '本插件不判定' },
            { step: '4', name: '结果脱敏', state: 'stop', why: '本插件不判定' },
        );
        return steps;
    }
    steps.push({
        step: '2',
        name: 'AI 审查',
        state: 'pending',
        why: walk.outcome.by === 'mode' ? '模式已关闭，直接轮到你'
            : walk.policy.decision === 'ai'
                ? '规则表命中 AI 档（终局路由）：这一步一定会跑；模拟审批不调模型，只说明落点'
                : '模拟审批不调模型；这里由快判／深评决定',
    });
    steps.push({ step: '3', name: '人工', state: 'fallback', why: '以上没给出放行，就弹宿主审批面板' });
    // 链是一步定掉就停：决定步之后标成「不再走」。规则层的「AI／不表态」不算决定（state 落 pass），
    // 只有真会执行的放行（表里的「允许」行，含「已证明只读」）才截断。
    const decider = steps.findIndex(step => ['never', 'deny', 'ask', 'release'].includes(step.state));
    if (decider >= 0) {
        for (let index = decider + 1; index < steps.length; index += 1) {
            steps[index].state = 'n/a';
            steps[index].why = '前面已定，不再往下走';
        }
    }
    // 脱敏这一格在调用**执行之后**才发生：它不参与「这次让不让执行」的决定，
    // 所以上面那圈「决定步之后不再走」不能把它标成 n/a。被拒绝的调用没有结果可遮。
    steps.push({
        step: '4', name: '结果脱敏',
        state: walk.outcome.kind === 'deny' ? 'n/a' : 'info',
        why: walk.outcome.kind === 'deny'
            ? '调用已被拒绝，没有结果可遮'
            : '调用执行后，结果回到模型前按检测规则遮成占位符（命中就遮，与档位无关）',
    });
    return steps;
}

/** One human-readable conclusion, from the same outcome the handler acts on. */
export function ladderVerdict(walk, { enabled }) {
    if (enabled !== true) return '本插件不判定（已关闭）';
    const who = speakerOf(walk.outcome.by, walk.policy.rule);
    switch (walk.outcome.kind) {
        case 'deny': return `第 1 步 安全规则·${who}：直接拦截，工具收到拒绝`;
        case 'ask': return `第 1 步 安全规则·${who}：直接问你，不调模型`;
        case 'release': return `第 1 步 安全规则·${who}：直接放行，不调模型（${walk.outcome.message}）`;
        case 'delegate': return '模式已关闭：交回宿主审批面板';
        default: return '第 2 步 AI 审查：由模型决定，否决或没把握时转人工';
    }
}

/** 生效中的规则行数——页面用它自证"我读的是哪份配置"。 */
export function ladderRuleCounts(config) {
    const keys = {
        command: 'commandRules', file: 'fileRules', network: 'networkRules',
        tool: 'toolRules', sensitive: 'sensitiveRules',
    };
    const counts = Object.fromEntries(Object.entries(keys).map(([plane, key]) => [
        plane, Array.isArray(config?.[key]) ? config[key].length : 0,
    ]));
    return { counts, total: Object.values(counts).reduce((sum, value) => sum + value, 0) };
}
