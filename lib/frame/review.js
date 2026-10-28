// L2 transport: exactly one model call per reviewed action. No retry loop — a
// second attempt on a transient failure is how an approval lane silently burns
// a session's budget.
//
// The host LLM package is imported lazily: a session that never needs a deep
// review must not pay for loading it, and the frame stays loadable for tests.
import { buildFastPrompt, buildSystemPrompt, parseVerdict } from './verdict.js';

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
            system: fast ? buildFastPrompt() : buildSystemPrompt(config),
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
        const verdict = parseVerdict(text);
        // Fast tier cannot refuse: its "block" means "escalate to the deep reviewer".
        const normalized = fast && verdict.status === 'reviewed' && verdict.decision === 'block'
            ? { ...verdict, decision: 'ask' }
            : verdict;
        return { ...normalized, rawOutput: text.trim().slice(0, 400), durationMs: Date.now() - started, model, tier };
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
