// L0 command facts: tokenize a shell line into segments, words and redirects.
// This plane produces OPERANDS ONLY — it never returns a verdict. Anything it
// cannot resolve to a literal it marks `opaque`, and the grant layer decides.

const SEPARATORS = new Set([';', '&&', '||', '|', '&', '\n']);
const REDIRECT_OPS = /^(\d*)(?:>>|>&|<|>|>)/;

/** Tokenize honoring 'single' / "double" quotes and backslash escapes. */
export function tokenize(command) {
    const tokens = [];
    let current = '';
    let has = false;
    let quote = '';
    for (let i = 0; i < command.length; i += 1) {
        const char = command[i];
        if (quote === "'") {
            if (char === "'")
                quote = '';
            else
                current += char;
            continue;
        }
        if (quote === '"') {
            if (char === '"')
                quote = '';
            else if (char === '\\' && i + 1 < command.length && /["\\$`]/.test(command[i + 1])) {
                i += 1;
                current += command[i];
            }
            else
                current += char;
            continue;
        }
        if (char === "'" || char === '"') {
            quote = char;
            has = true;
            continue;
        }
        if (char === '\\' && i + 1 < command.length) {
            // On Windows a backslash inside a drive path (`C:\Users\…`) or a UNC
            // prefix (`\\server\share`) is a separator, not a POSIX escape. It used
            // to be eaten, which turned `rm -f C:\ws\a.txt` into the literal token
            // `C:Usersa.txt` — then resolved as a bogus path *inside* the workspace,
            // so the wrong root hit and the wrong git state reached the reviewer.
            const windowsPath = /[A-Za-z]:$/.test(current) || current.includes('\\')
                || (current === '' && command[i + 1] === '\\');
            if (windowsPath) {
                current += char;
                has = true;
                continue;
            }
            i += 1;
            current += command[i];
            has = true;
            continue;
        }
        if (char === '\n' || char === '\r' || char === ';') {
            if (has)
                tokens.push(current);
            current = '';
            has = false;
            if (char === '\r')
                continue;
            tokens.push('\n');
            continue;
        }
        if (/\s/.test(char)) {
            if (has)
                tokens.push(current);
            current = '';
            has = false;
            continue;
        }
        if ((char === '>' || char === '<') && /^\d+$/.test(current)) {
            let op = `${current}${char}`;
            current = '';
            has = false;
            if (op.endsWith('>') && command[i + 1] === '&') {
                op += '&';
                i += 1;
            }
            tokens.push(op);
            continue;
        }
        if (char === '&' || char === '|' || char === '<' || char === '>') {
            if (has) {
                tokens.push(current);
                current = '';
                has = false;
            }
            const pair = command[i + 1];
            if ((char === '&' || char === '|') && pair === char) {
                tokens.push(`${char}${char}`);
                i += 1;
                continue;
            }
            if (char === '&' && pair === '>') {
                tokens.push('&>');
                i += 1;
                continue;
            }
            if (char === '>' && pair === '&') {
                tokens.push('>&');
                i += 1;
                continue;
            }
            tokens.push(char);
            continue;
        }
        current += char;
        has = true;
    }
    if (has || quote !== '')
        tokens.push(current);
    return tokens;
}

/** Whether a literal still expands at run time (so its target is unknowable). */
function isDynamic(word) {
    return word.includes('$') || word.includes('`')
        || /[*?[\]]/.test(word) || (word.includes('{') && word.includes('}'));
}

function classifyWord(token) {
    if (token.startsWith('--'))
        return { text: token, kind: 'long-flag' };
    if (token.startsWith('-') && token.length > 1)
        return { text: token, kind: 'short-flag' };
    if (REDIRECT_OPS.test(token))
        return { text: token, kind: 'redirect' };
    return { text: token, kind: 'operand' };
}

/** Split one command line into executable segments with words and redirects. */
export function splitSegments(command) {
    const tokens = tokenize(String(command ?? ''));
    const segments = [];
    let current = null;
    let pendingRedirect = '';
    for (const token of tokens) {
        if (SEPARATORS.has(token)) {
            current = null;
            continue;
        }
        if (pendingRedirect !== '') {
            current.redirects.push({ op: pendingRedirect, text: token, dynamic: isDynamic(token) });
            pendingRedirect = '';
            continue;
        }
        const classified = classifyWord(token);
        if (classified.kind === 'redirect') {
            if (current === null) {
                current = { program: '', words: [], redirects: [], opaque: true };
                segments.push(current);
            }
            pendingRedirect = classified.text;
            continue;
        }
        if (current === null) {
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token))
                continue;
            current = { program: token, words: [], redirects: [], opaque: isDynamic(token) };
            segments.push(current);
            continue;
        }
        current.words.push(classified);
    }
    for (const segment of segments) {
        if (pendingRedirect !== '' && segment.redirects.length === 0)
            continue;
        segment.opaque = segment.opaque || segment.words.some(word => word.kind === 'operand' && isDynamic(word.text))
            || segment.redirects.some(redirect => redirect.dynamic);
    }
    return segments.filter(segment => segment.program !== '' || segment.redirects.length > 0);
}

/** Operands a segment acts on: positional operands plus write-redirect targets. */
export function operandsOf(segment) {
    return segment.words
        .filter(word => word.kind === 'operand')
        .map(word => word.text);
}

export { isDynamic, REDIRECT_OPS };
