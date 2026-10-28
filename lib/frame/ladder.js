/**
 * The decision ladder — ONE implementation, two consumers.
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
import { effectiveRows, evaluatePolicies, floorActions, networkTargets } from './policy.js';

/** Pure read / session-internal calls cannot change anything outside the session. */
function factGateOf(facts) {
    const readOnly = facts.segments.length > 0
        && facts.segments.every(segment => segment.opClass === 'read')
        && facts.opaque === false;
    const internalOnly = facts.segments.length > 0
        && facts.segments.every(segment => segment.opClass === 'internal');
    return { readOnly, internalOnly };
}

/**
 * Walk one call through 事实 → 内置行 → 你的规则 → 事实门.
 * @returns outcome: deny | ask | release | delegate | review, plus the audit rows
 *          the caller must write and everything the simulator needs to narrate.
 */
export function walkLadder({ toolName, args, config, roots, probe }) {
    const command = typeof args?.command === 'string' ? args.command : '';
    const facts = collectFacts({ toolName, args, roots, probe });
    const grant = grantFor(facts, roots, floorActions(config));
    const policy = evaluatePolicies({
        toolName,
        command,
        segments: facts.segments,
        targets: facts.targets,
        urls: networkTargets(command),
        config,
    });
    const { readOnly, internalOnly } = factGateOf(facts);
    const emits = [];
    if (policy.decision === 'ai') {
        emits.push({
            decision: 'info', layer: 'rules', rule: policy.rule, plane: policy.plane,
            message: '命中：本层不拦，继续走事实门与 AI 审查',
        });
    }
    let outcome;
    if (grant.state === 'deny') {
        outcome = {
            kind: 'deny', by: 'floor', layer: 'floor',
            reason: `auto-approval-frame: 内置行拦下（${grant.reasons.join('、')}）`,
            displayReason: `内置行拦下：${grant.reasons.join('、')}`,
            audit: { decision: 'blocked', layer: 'floor', message: '内置行的档位是拒绝' },
        };
    }
    else if (grant.state === 'never') {
        outcome = {
            kind: 'ask', by: 'floor', layer: 'floor',
            reason: 'auto-approval-frame: builtin row requires a human',
            displayReason: `auto-approval-frame: 内置行（${grant.reasons.join('、') || '凭据·系统目录·宿主状态'}）需要你确认`,
            audit: { decision: 'ask', layer: 'floor' },
        };
    }
    else if (policy.decision === 'deny') {
        outcome = {
            kind: 'deny', by: 'rules', layer: 'rules', rule: policy.rule, plane: policy.plane,
            reason: `auto-approval-frame: 规则拦截（${policy.plane}）${policy.rule}`,
            displayReason: `规则拦截：${policy.rule}`,
            audit: { decision: 'blocked', layer: 'rules', rule: policy.rule, plane: policy.plane },
        };
    }
    else if (policy.decision === 'ask') {
        outcome = {
            kind: 'ask', by: 'rules', layer: 'rules', rule: policy.rule, plane: policy.plane,
            reason: 'auto-approval-frame: rule requires a human',
            displayReason: `规则命中：${policy.rule}`,
            audit: { decision: 'ask', layer: 'rules', rule: policy.rule, plane: policy.plane },
        };
    }
    // 「允许」是真放行：不调模型、不弹面板，但必须留下可追责的一行（写不进去就转人工）。
    else if (policy.decision === 'release') {
        outcome = {
            kind: 'release', by: 'rules', layer: 'rules',
            message: `你的行直接放行：${policy.rule ?? ''}`,
            audit: { decision: 'allowed', layer: 'rules', rule: policy.rule, plane: policy.plane, message: '允许＝直接放行' },
        };
    }
    else if (readOnly || internalOnly) {
        const message = internalOnly ? '会话内部工具（无对外副作用）' : '只读快路';
        outcome = {
            kind: 'release', by: 'fact', layer: 'fact', message,
            audit: { decision: 'allowed', layer: 'fact', message },
        };
    }
    else if (config.mode === 'off') {
        outcome = {
            kind: 'delegate', by: 'mode',
            audit: { decision: 'ask', layer: 'none', message: '插件已关闭：交回宿主面板' },
        };
    }
    else {
        outcome = { kind: 'review', by: 'ai' };
    }
    return { command, facts, grant, policy, readOnly, internalOnly, emits, outcome };
}

/** 内置行与你的行合起来是链上的第 1 步；「AI／不表态」这一档算命中但不算决定。 */
function rulesStep(walk) {
    const never = walk.grant.state === 'never';
    const decidedByMine = walk.policy.decision === 'deny' || walk.policy.decision === 'ask'
        || walk.policy.decision === 'release';
    const state = walk.grant.state === 'deny' ? 'deny'
        : never ? 'never'
            : walk.policy.decision === 'deny' ? 'deny'
                : walk.policy.decision === 'ask' ? 'ask'
                    : walk.policy.decision === 'release' ? 'release'
                        : walk.grant.state === 'confirm' ? 'confirm' : 'pass';
    const said = [];
    if (walk.grant.state === 'deny') said.push(`内置行：${walk.grant.reasons.join('、')}｜你把这一条设成了拒绝`);
    else if (never) said.push(`内置行：${walk.grant.reasons.join('、') || '凭据·系统目录·宿主状态'}｜只能由你确认`);
    else if (decidedByMine) said.push(`你的行命中：${walk.policy.rule ?? ''}${walk.policy.decision === 'release' ? '（允许＝直接放行，不调模型）' : ''}`);
    else if (walk.policy.decision === 'ai')
        said.push(`你的行命中：${walk.policy.rule ?? ''}（这一档＝本层不拦，继续往下判）`);
    if (walk.grant.state === 'confirm' && walk.grant.reasons.length > 0)
        said.push(`内置行：${walk.grant.reasons.join('、')}`);
    return {
        step: '1', name: '安全规则', state,
        why: said.length > 0 ? said.join('；') : '内置没踩到，你的行也没命中',
        detail: walk.grant.disposability ?? null,
    };
}

/**
 * The ladder as the settings page narrates it. Derived from the same walk, so a step
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
            { step: '2', name: '事实门', state: 'stop', why: '本插件不判定' },
            { step: '3/4', name: 'AI 审查', state: 'stop', why: '本插件不判定' },
            { step: '5', name: '人工', state: 'stop', why: '本插件不判定' },
            { step: '6', name: '结果脱敏', state: 'stop', why: '本插件不判定' },
        );
        return steps;
    }
    steps.push({
        step: '2',
        name: '事实门',
        state: walk.outcome.by === 'fact' ? 'release' : 'skip',
        why: walk.readOnly ? '纯只读，不调模型'
            : walk.internalOnly ? '会话内部工具，无对外副作用'
                : '有对外副作用，过不了事实门',
    });
    steps.push({
        step: '3/4',
        name: 'AI 审查',
        state: 'pending',
        why: walk.outcome.by === 'mode' ? '模式已关闭，直接轮到你' : '模拟审批不调模型；这里由快判／深评决定',
    });
    steps.push({ step: '5', name: '人工', state: 'fallback', why: '以上没给出放行，就弹宿主审批面板' });
    // 链是一步定掉就停：决定步之后标成「不再走」。规则层的「AI／不表态」不算决定（state 落 pass），
    // 只有真会执行的放行（你的行「允许」或事实门）才截断。
    const decider = steps.findIndex(step => ['never', 'deny', 'ask', 'release'].includes(step.state));
    if (decider >= 0) {
        for (let index = decider + 1; index < steps.length; index += 1) {
            steps[index].state = 'n/a';
            steps[index].why = '前面已定，不再往下走';
        }
    }
    // 第 6 步在调用**执行之后**才发生：它不参与「这次让不让执行」的决定，
    // 所以上面那圈「决定步之后不再走」不能把它标成 n/a。被拒绝的调用没有结果可遮。
    steps.push({
        step: '6', name: '结果脱敏',
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
    switch (walk.outcome.kind) {
        case 'deny': return '第 1 步 安全规则：直接拦截，工具收到拒绝';
        case 'ask': return walk.outcome.by === 'floor'
            ? '第 1 步 安全规则·内置行：只能由你确认，AI 不参与'
            : '第 1 步 安全规则：直接问你，不调模型';
        case 'release': return walk.outcome.by === 'rules'
            ? `第 1 步 安全规则：你的行写了「允许」，直接放行，不调模型（${walk.outcome.message}）`
            : `第 2 步 事实门：直接放行，不调模型（${walk.outcome.message}）`;
        case 'delegate': return '模式已关闭：交回宿主审批面板';
        default: return walk.grant.state === 'confirm'
            ? '第 1 步 安全规则·内置行：AI 只能给建议，最终仍由你确认'
            : '第 3/4 步 AI 审查：由模型决定，否决或没把握时转人工';
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
