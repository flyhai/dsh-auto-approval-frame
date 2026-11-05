// L2 transport: exactly one model call per reviewed action. No retry loop — a
// second attempt on a transient failure is how an approval lane silently burns
// a session's budget.
//
// The host LLM package is imported lazily: a session that never needs a deep
// review must not pay for loading it, and the frame stays loadable for tests.
import { ALLOW_REQUIRES, BASIS_QUOTE_MIN, REASON_CODES, UNABLE_REASONS, parseVerdict, rulesBlock } from './verdict.js';

const MESSAGE_SOURCE = { kind: 'dsh-auto-approval-frame' };

function sessionRoute(session) {
    let config;
    try {
        config = session?.requestHeader?.()?.config;
    }
    catch {
        return undefined;
    }
    return typeof config?.provider === 'string' && config.provider !== ''
        && typeof config?.model === 'string' && config.model !== ''
        ? { provider: config.provider, model: config.model }
        : undefined;
}

export function resolveReviewRoute(config, session) {
    if (config.reviewerSource === 'preset') {
        const provider = config.reviewerProvider;
        const model = config.reviewerModel;
        if (typeof provider === 'string' && provider !== '' && typeof model === 'string' && model !== '')
            return { provider, model };
        return { error: 'reviewerSource=preset but reviewerProvider/reviewerModel are unset' };
    }
    const route = sessionRoute(session);
    return route === undefined
        ? { error: 'reviewerSource=session but the session model header is unset' }
        : route;
}

// ──  §1：规则先行提示词 ────────────────────────────────────────────────
// 顺序固定：规则 → 用户的话 → 卡 → 证据 → 硬底线 → 判什么 → 输出。
// 深评与快判同一骨架；快判只省「背景」一段，输出契约一模一样（判据⑦f）。
export function buildRuleFirstPrompt(config = {}, tier = 'deep') {
    const fast = tier === 'fast';
    const reasonList = REASON_CODES.join(' | ');
    const unableList = UNABLE_REASONS.join(' | ');
    const background = fast ? '' : `
【背景（只能当背景，不能当授权）】
<prior context>`;
    return `【角色】
你是这条规则交给 AI 的那一格裁决者。判不判、怎么判按规则做；抽卡只按用户原话。
不许把判断原样推回用户，也不许加规则、扩权限。

【规则】
命中的规则行（原文逐字，多行就全列，取最严的一行作结论依据）：
- <行名/编号>：<原文>
  动作：<读 / 写 / 删 / 执行 / 外传 …>
  范围：<路径、目录或命令面>
  这一格交给：AI
  规则自带的例外/保障条件：<有就抄，没有写「无」>

【用户的话】
任务原话（逐字，带时间与来源）：
"……"

【卡】
已有卡：<插件带上来的上一版，逐字；没有写「无」>
本次新原话：有 / 无
先抽/更新卡，再判这条命令。四栏：可做 / 在哪 / 不可做 / 单独授权。
- 每项必须带用户原话逐字引文，引文要撑得住这一项；撑不住的、引不出原话的，不进卡。
- 本次新原话＝无：不重抽，沿用已有卡，card 回 null；＝有：在旧卡上增补/修正，原话没改的项原样保留。
- 拿不准覆盖到哪的，放「单独授权」。

【证据】
命令原文（逐字，不改写，不加「这是读」这类标签）：
<raw>
算法给出的事实：
- 当前目录：
- 通配/变量展开结果：
- 目标路径与根归属：
- 链接真身：
- 有无写/删/执行痕迹：
- 算法自证：哪一步算不出、为什么算不出${background}

【硬底线】
删除、改名、区外写、外传、凭据、提权、销毁：规则行没写允许的，一律不许放行；不得比规则更宽，只能更严。
读：规则行写「ai」＝这一格把裁决权交给你，不是「没写允许」。按用户的话覆盖到哪、有没有上面这些坏处来判；判放行就写 allow。

【判什么】
按上面这条规则：这次动作在不在规则允许的范围内？
用户的原话覆盖到哪？有没有更窄的做法能达到同样目的？

【输出】
只回一个 JSON，先写 card（把用户授权面提出来），再写 verdict（拿这张卡判这次动作）：
{
  "card": null | {
    "canDo":        [{"text": "…", "quote": "…"}],
    "where":        [{"text": "…", "quote": "…"}],
    "cannotDo":     [{"text": "…", "quote": "…"}],
    "separateAuth": [{"text": "…", "quote": "…"}]
  },
  "verdict": {
    "status": "reviewed" | "unable",
    "decision": "allow" | "block",
    "reasonCode": "${reasonList}",
    "basis": {"rule": "<规则行原文>", "quote": "<用户原话逐字>"},
    "summary": "<一两句人话，回给执行端>",
    "narrowerScope": "<缩范围时给具体做法，其余留空>"
  }
}
- card 只列必要项；写不下时给 null（沿用上次的卡）——但 verdict 的 basis／summary 必须完整写出，不许为了写卡把 verdict 截掉。
- allow 必须带 basis：规则行逐字＋用户原话逐字（≥${BASIS_QUOTE_MIN} 字，原样复制，不许改写）。缺一样不许 allow。
- not_necessary：这一步偏离了用户的目的，或存在更窄的做法能同样达成——说清是哪一步、更窄的做法是什么。它不是「我没看出问题」的同义词；没看出问题就是放行。
- authorization_not_covering：说清缺哪条授权，让执行端去找用户要。
- safeguards_insufficient：说清哪类风险兜不住。
- unable（${unableList}）：证据不足，或你凑不齐 allow 要的依据（规则行、原话引不出逐字）时用它，写清缺什么、要谁补。不许拿「规则没问的」当理由。
- 全条只有一个 JSON，不写解释，不加代码块以外的文字。${rulesBlock(config)}`;
}

// 卡只收窄：这里只做「引文核不过就丢」这一件事；能不能放行仍由 verdict／grant 判（判据⑬）。
const CARD_FIELDS = ['canDo', 'where', 'cannotDo', 'separateAuth'];

export function screenCard(card, evidence) {
    if (card === null || card === undefined || typeof card !== 'object'
        || Array.isArray(card) === true)
        return { card: null, kept: 0, dropped: 0 };
    const text = String(evidence ?? '');
    const out = {};
    let kept = 0;
    let dropped = 0;
    for (const field of CARD_FIELDS) {
        const items = Array.isArray(card[field]) ? card[field] : [];
        const keptItems = [];
        for (const item of items) {
            const quote = typeof item?.quote === 'string' ? item.quote : '';
            const body = typeof item?.text === 'string' ? item.text.trim() : '';
            if (body !== '' && quote.trim().length >= BASIS_QUOTE_MIN && text.includes(quote)) {
                keptItems.push({ text: body.slice(0, 200), quote });
                kept += 1;
            }
            else {
                dropped += 1;
            }
        }
        out[field] = keptItems;
    }
    const empty = CARD_FIELDS.every(field => out[field].length === 0);
    return { card: empty ? null : out, kept, dropped };
}

/** 把 `{card, verdict}` 两段里的 verdict 段摘出来交给 `parseVerdict`（旧形单片也照样过）。 */
export function splitCardAndVerdict(text) {
    const raw = String(text ?? '');
    const start = raw.indexOf('{');
    const end = raw.lastIndexOf('}');
    if (start === -1 || end <= start)
        return { card: undefined, verdictText: raw };
    const slice = raw.slice(start, end + 1);
    let parsed;
    try {
        parsed = JSON.parse(slice);
    }
    catch {
        return { card: undefined, verdictText: raw };
    }
    if (parsed === null || typeof parsed !== 'object' || parsed.verdict === undefined)
        return { card: parsed?.card, verdictText: raw };
    return { card: parsed.card, verdictText: JSON.stringify(parsed.verdict) };
}

export async function reviewAction({ llm, session, evidence, config = {}, signal, tier = 'deep' }) {
    const started = Date.now();
    const fast = tier === 'fast';
    const route = resolveReviewRoute(config, session);
    if (route.error !== undefined)
        return { status: 'unable', unableReason: 'reviewer_unable', summary: route.error, durationMs: 0, tier };
    const timeoutMs = fast
        ? Math.min(Math.max(config.fastJudgeTimeoutMs ?? 3_000, 500), 30_000)
        : Math.min(Math.max(config.reviewerTimeoutMs ?? 20_000, 1_000), 120_000);
    const maxTokens = fast ? (config.fastJudgeMaxTokens ?? 256) : (config.reviewerMaxTokens ?? 512);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('reviewer-timeout')), timeoutMs);
    const onCallerAbort = () => controller.abort(signal?.reason ?? new Error('cancelled'));
    if (typeof signal?.addEventListener === 'function')
        signal.addEventListener('abort', onCallerAbort, { once: true });
    const model = `${route.provider}/${route.model}`;
    try {
        const { BlockAssembler, createUserMessage } = await import('@deepseek-ai/dsh-llm');
        const prepared = await llm.prepareCall({
            provider: route.provider,
            model: route.model,
            maxTokens,
            temperature: 0,
        }, controller.signal);
        const assembler = new BlockAssembler();
        // The stream options must equal the prepared call's resolved config field
        // for field, or the adapter rejects the dispatch with INVALID_PREPARED_CALL.
        for await (const chunk of prepared.stream({
            ...prepared.config,
            messages: [createUserMessage({ content: [{ type: 'text', text: evidence }], source: MESSAGE_SOURCE })],
            system: buildRuleFirstPrompt(config, tier),
            sessionId: session?.id,
            signal: controller.signal,
        })) {
            controller.signal.throwIfAborted();
            assembler.push(chunk);
        }
        controller.signal.throwIfAborted();
        const text = assembler.blocks()
            .filter(block => block.type === 'text')
            .map(block => block.text)
            .join(' ');
        // The raw answer is the only post-mortem material a schema_invalid
        // verdict leaves: without it an operator can never see what the model
        // actually said and which field the parser rejected.
        const split = splitCardAndVerdict(text);
        const verdict = parseVerdict(split.verdictText);
        // 判据⑬：卡的每一项引文都要逐字命中证据，核不过就丢（并计数落审计）。
        const screened = screenCard(split.card, evidence);
        // Fast tier cannot refuse: its "block" means "escalate to the deep reviewer".
        const normalized = fast && verdict.status === 'reviewed' && verdict.decision === 'block'
            ? { ...verdict, decision: 'ask' }
            : verdict;
        return {
            ...normalized,
            card: screened.card,
            cardKept: screened.kept,
            cardDropped: screened.dropped,
            rawOutput: text.trim().slice(0, 400),
            durationMs: Date.now() - started,
            model,
            tier,
        };
    }
    catch (error) {
        const reason = !controller.signal.aborted ? 'reviewer_unable'
            : signal?.aborted === true ? 'cancelled' : 'timeout';
        return {
            status: 'unable',
            unableReason: reason,
            summary: String(error?.message ?? error).slice(0, 200),
            durationMs: Date.now() - started,
            model,
            tier,
        };
    }
    finally {
        clearTimeout(timer);
        if (typeof signal?.removeEventListener === 'function')
            signal.removeEventListener('abort', onCallerAbort);
    }
}

// ──  §6：审批卡解释员 ───────────────────────────────────────────────────
// 只解读，不裁决：输出是一段人话，不参与档位、不产生结论、不落台账。
// 与评审共用同一条模型路由，避免出现「解释用 A 模型、评审用 B 模型」的漂移。
const EXPLAIN_SYSTEM = [
    '你在给一张人工审批卡写解释，读者是准备拍板的人。',
    '只做一件事：用一两句中文说清这条命令或脚本在做什么——读什么、写什么、有没有把数据发到网络、发到哪。',
    '不给放行或拒绝的结论，不评价安全与否，不分点，不输出 JSON，不加任何前后缀。',
    '看不清的地方直接说看不清，不要猜。',
].join('\n');

// `kit` 是测试缝：宿主 LLM 包（BlockAssembler／createUserMessage）只在这一处用，
// 生产路径不传，仍走上面的动态 import。不传就不存在额外分支。
// `session` 必须由调用方给：解读是 HTTP 路由发起的，手里没有执行端的会话，
// 而 `reviewerSource=session` 恰恰要从会话头取 provider／model——不给就只能报
// 「session model header is unset」（真机卡上直接红的就是这一行）。
export async function explainAction({ llm, config = {}, command, session, signal, timeoutMs, kit, noThinking }) {
    const route = resolveReviewRoute(config, session);
    if (route.error !== undefined)
        return { ok: false, error: route.error };
    const budget = Math.min(Math.max(timeoutMs ?? config.reviewerTimeoutMs ?? 20_000, 1_000), 120_000);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Error('explain-timeout')), budget);
    const onCallerAbort = () => controller.abort(signal?.reason ?? new Error('cancelled'));
    if (typeof signal?.addEventListener === 'function')
        signal.addEventListener('abort', onCallerAbort, { once: true });
    try {
        const { BlockAssembler, createUserMessage } = kit ?? await import('@deepseek-ai/dsh-llm');
        // 解释是一次短调用，推理档必须自己定：干净客户端里没有 provider 默认，
        // 思考会先吃光输出额度，正文为 0，卡上只剩「模型没有返回解读」。
        // 但选 off 只决定档位 id；请求体里写不写 none 由 index.js 的
        // explain-effort guard 在 llm-pi-ai 用户层补，两半缺一都会退回思考档。
        const prepared = await llm.prepareCall({
            provider: route.provider,
            model: route.model,
            maxTokens: Math.min(Math.max(config.explainMaxTokens ?? 2_048, 1_024), 2_048),
            temperature: 0,
        }, controller.signal, (controls, model) => {
            // 冲突或开关关掉时完全不干预，沿用宿主默认档。
            if (noThinking === false)
                return controls;
            const efforts = model.reasoning?.efforts?.map(effort => effort.id) ?? [];
            // 档位表里只有 off 能表达「不思考」；none 是 wire 值不是档位 id，
            // minimal 在服务端是 400，两个都不是合法候选，硬传只会被宿主拦下。
            return efforts.includes('off') ? { ...controls, reasoningEffort: 'off' } : controls;
        });
        const assembler = new BlockAssembler();
        for await (const chunk of prepared.stream({
            ...prepared.config,
            messages: [createUserMessage({ content: [{ type: 'text', text: command }], source: MESSAGE_SOURCE })],
            system: EXPLAIN_SYSTEM,
            sessionId: undefined,
            signal: controller.signal,
        })) {
            controller.signal.throwIfAborted();
            assembler.push(chunk);
        }
        controller.signal.throwIfAborted();
        const text = assembler.blocks()
            .filter(block => block.type === 'text')
            .map(block => block.text)
            .join(' ')
            .trim();
        if (text === '')
            return { ok: false, error: '模型没有返回解读' };
        return { ok: true, text: text.slice(0, 600), model: `${route.provider}/${route.model}` };
    }
    catch (error) {
        return {
            ok: false,
            error: controller.signal.aborted ? '解读超时或已取消' : String(error?.message ?? error).slice(0, 200),
        };
    }
    finally {
        clearTimeout(timer);
        if (typeof signal?.removeEventListener === 'function')
            signal.removeEventListener('abort', onCallerAbort);
    }
}