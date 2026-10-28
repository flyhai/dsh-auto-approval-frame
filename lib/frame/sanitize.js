// Text hygiene for anything that travels into a model prompt.
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/g;

/** Strip control characters, collapse absurd whitespace runs, hard-cap length. */
export function sanitizeText(input, maxChars = 4_000) {
    const text = String(input ?? '').replace(CONTROL, ' ').replace(/\n{3,}/g, '\n\n').trim();
    if (text.length <= maxChars)
        return text;
    return `${text.slice(0, maxChars)}\n…[truncated]`;
}

/** Never let a path or command leak a token-shaped substring into the log. */
export function redactSecrets(input) {
    return String(input ?? '')
        .replace(/(api[_-]?key|token|secret|password|authorization)(["'\s:=]+)([^\s"'&,;]{6,})/gi, '$1$2***')
        .replace(/\bsk-[A-Za-z0-9_-]{12,}\b/g, 'sk-***');
}
