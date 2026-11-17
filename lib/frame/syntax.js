// 结构化解析：按工具名选方言，用随包的 tree-sitter 文法取命令边界。
// 词法（引号／转义／Windows 路径／heredoc 正文）仍交给 parse.js——两套解码器才是新裂缝。
// 运行时只读 assets/wasm/ 下随包的 wasm，不 spawn 解析进程、不联网下载。
// 文法加载失败或解析报错 ⇒ 退回手写拆串，并在结果里如实标明（未知只是事实，不是新闸）。
//
// 工作目录沿着**执行结构**传播：`&&` 右侧吃左侧成功态，`||` 右侧吃失败态，
// 管道／子 shell／后台任务各自隔离，条件与循环按分支收束。算不死时留下原因与候选，
// 由事实层决定能不能举出证——这里不猜，也不把「未知」直接写成某个档位。

import { fileURLToPath } from 'node:url';
import { Parser, Language } from '../../assets/wasm/tree-sitter.js';
import { splitSegments, commandSubstitutions, isDynamic, normalizeProgram } from './parse.js';
import { normalizePath, pathApiFor } from './paths.js';

// 只认接口事实：DSH 的 shell 工具就叫 bash／pwsh（persistent 变体同名）。
// 其余带 command 参数的工具（shell／terminal／cmd／run_command…）方言未知——不按 OS 或
// 命令名猜，走原保守路径并在事实里标明。
const DIALECT_BY_TOOL = new Map([
    ['bash', 'bash'],
    ['pwsh', 'powershell'],
]);
const LANGUAGES = [
    ['bash', 'tree-sitter-bash.wasm'],
    ['powershell', 'tree-sitter-powershell.wasm'],
];
const WASM_DIR = new URL('../../assets/wasm/', import.meta.url);
const wasmPath = name => fileURLToPath(new URL(name, WASM_DIR));

let runtimeReady = false;
let runtimeWhy = '';
const parsers = new Map();

// 模块加载时一次：运行库 + 两份文法。约 26 ms 冷启动，之后全部复用；
// 加载失败只降级、不抛——插件照常工作，事实层会带回真实原因。
try {
    await Parser.init({ locateFile: name => wasmPath(name) });
    runtimeReady = true;
}
catch (error) {
    runtimeWhy = `解析运行库加载失败：${String(error?.message ?? error).slice(0, 120)}`;
}
if (runtimeReady) {
    for (const [dialect, file] of LANGUAGES) {
        try {
            const language = await Language.load(wasmPath(file));
            const parser = new Parser();
            parser.setLanguage(language);
            parsers.set(dialect, parser);
        }
        catch (error) {
            runtimeWhy = runtimeWhy || `${dialect} 文法加载失败：${String(error?.message ?? error).slice(0, 120)}`;
        }
    }
}

// 直接执行一条命令的节点（文法里的「简单命令」族）。
const COMMAND_NODES = new Set(['command', 'declaration_command', 'unset_command', 'test_command']);
// 有界解析：超长命令不做结构化（避免为一条命令展开整棵大树），退回手写拆串并标明触顶。
const MAX_STRUCTURED_CHARS = 64 * 1024;
// 工作目录候选的上限：`cd a; cd b` 这类序列的成功／失败组合会翻倍，超过就只报「算不死」。
const MAX_CWD_CANDIDATES = 4;
const NAVIGATE_PROGRAMS = new Set(['cd', 'chdir', 'pushd', 'popd',
    'set-location', 'push-location', 'pop-location']);
const PUSH_PROGRAMS = new Set(['pushd', 'push-location']);
const POP_PROGRAMS = new Set(['popd', 'pop-location']);

function heredocOf(node, text) {
    const start = node.namedChildren.find(child => child.type === 'heredoc_start');
    const body = node.namedChildren.find(child => child.type === 'heredoc_body');
    const raw = start === undefined ? '' : text.slice(start.startIndex, start.endIndex);
    const quoted = raw.startsWith("'") || raw.startsWith('"');
    const value = quoted ? raw.slice(1, -1) : raw.replace(/^-+/, '');
    return {
        quoted,
        value,
        text: body === undefined ? '' : text.slice(body.startIndex, body.endIndex),
    };
}

function redirectsOf(node, text) {
    // 重定向单独成段地词法化：`> out`、`2>&1` 都由 parse.js 的同一把尺判 op／目的。
    const parsed = splitSegments(text.slice(node.startIndex, node.endIndex));
    return {
        redirects: parsed.flatMap(segment => segment.redirects ?? []),
        heredocs: parsed.flatMap(segment => segment.heredocs ?? []),
    };
}

const cloneCwd = state => ({ list: [...state.list], unknown: state.unknown });

function mergeCwd(...states) {
    const list = [];
    let unknown = '';
    for (const state of states) {
        if (state === undefined || state === null)
            continue;
        if (state.unknown !== '' && unknown === '')
            unknown = state.unknown;
        for (const path of state.list)
            if (list.includes(path) === false)
                list.push(path);
    }
    if (list.length > MAX_CWD_CANDIDATES) {
        unknown = unknown || `工作目录候选超过 ${MAX_CWD_CANDIDATES} 种`;
        list.length = MAX_CWD_CANDIDATES;
    }
    return { list, unknown };
}

const unknownCwd = (why, previous) => ({
    list: previous === undefined ? [] : [...previous.list],
    unknown: why,
});

const snapshot = frame => ({
    success: cloneCwd(frame.cwd),
    failure: cloneCwd(frame.cwd),
});

/** 逐段附到段上的 cwd 事实：唯一候选＝`cwd`；多候选＝按可信度排序的 `cwdCandidates`
 * （事实层按序验存不存在）；算不死＝`cwdUnknown` 带来源。三者可以同时出现：
 * 未知时仍留候选，是为了让证据看得见「本来以为是哪儿」。 */
function cwdFields(state) {
    if (state.unknown !== '')
        return {
            cwdUnknown: state.unknown,
            ...(state.list.length > 0 ? { cwdCandidates: [...state.list] } : {}),
        };
    if (state.list.length === 1)
        return { cwd: state.list[0] };
    if (state.list.length > 1)
        return { cwdCandidates: [...state.list] };
    return { cwdUnknown: '工作目录未知' };
}

const cloneFields = fields => ({
    ...(fields.cwd === undefined ? {} : { cwd: fields.cwd }),
    ...(fields.cwdCandidates === undefined ? {} : { cwdCandidates: [...fields.cwdCandidates] }),
    ...(fields.cwdUnknown === undefined ? {} : { cwdUnknown: fields.cwdUnknown }),
});

const nodeText = (node, text) => text.slice(node.startIndex, node.endIndex);

const cloneFrame = frame => ({
    cwd: cloneCwd(frame.cwd),
    vars: new Map([...frame.vars].map(([name, value]) => [name, { ...value }])),
    stack: [...frame.stack],
    functions: new Set(frame.functions),
    relativeNav: frame.relativeNav,
});

/** 字面量取值：只认裸词与无展开的引号串；带 `$`／反引号／拼接就是「算不死」。 */
function literalOfNode(node, text) {
    if (node === undefined || node === null)
        return undefined;
    const raw = nodeText(node, text);
    if (node.type === 'word')
        return raw;
    if (node.type === 'string' || node.type === 'raw_string' || node.type === 'ansi_c_string')
        return /[$`]/.test(raw) ? undefined : raw.slice(1, -1);
    // `${D}/x`、`$D-suffix` 这类拼接不猜：值的边界随变量而变，不是同一个东西。
    return undefined;
}

function assignVariable(node, frame, text) {
    const nameNode = node.namedChildren.find(child => child.type === 'variable_name');
    if (nameNode === undefined)
        return;
    const name = nodeText(nameNode, text);
    const valueNode = node.namedChildren.find(child => child.type !== 'variable_name');
    const value = literalOfNode(valueNode, text);
    if (value === undefined)
        frame.vars.set(name, { dynamic: true });
    else
        frame.vars.set(name, { value });
}

/** 声明族（`export D=sub`／`declare D=sub`／`local D=sub`）：在当前 shell 里持续生效。 */
function applyDeclarations(node, frame, text) {
    for (const assignment of node.namedChildren)
        if (assignment.type === 'variable_assignment')
            assignVariable(assignment, frame, text);
}

/** 循环变量：字面量列表逐项轮换——多个取值时记成 `multi`，cd 用它就算不死。 */
function applyLoopVariables(node, frame, text) {
    const nameNode = node.namedChildren.find(child => child.type === 'variable_name');
    if (nameNode === undefined)
        return;
    const name = nodeText(nameNode, text);
    const values = node.namedChildren.filter(child =>
        child.type === 'word' || child.type === 'string' || child.type === 'raw_string');
    const literals = values.map(value => literalOfNode(value, text));
    if (literals.length === 0 || literals.some(value => value === undefined)) {
        frame.vars.set(name, { dynamic: true });
        return;
    }
    const unique = [...new Set(literals)];
    frame.vars.set(name, unique.length === 1 ? { value: unique[0] } : { multi: unique });
}

/** `cd` 的目标：裸词／字面量／上文定死的变量／`cd`＝回家；其余都算不死并给出来源。 */
function navigationOperand(segment, frame) {
    const operands = (segment.words ?? []).filter(word => word.kind === 'operand').map(word => word.text);
    const text = operands.find(value => String(value) !== '');
    if (text === undefined)
        return { kind: 'home' };
    if (String(text) === '-')
        return { kind: 'unknown', why: 'cd - 读取 OLDPWD，判定这一刻算不出' };
    const simple = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/.exec(String(text));
    if (simple !== null) {
        const entry = frame.vars.get(simple[1]);
        if (entry === undefined)
            return { kind: 'unknown', why: `变量 ${simple[1]} 未在上文确定为字面量` };
        if (entry.multi !== undefined)
            return { kind: 'unknown', why: `变量 ${simple[1]} 可能取 ${entry.multi.join('｜')}` };
        if (entry.dynamic === true)
            return { kind: 'unknown', why: `变量 ${simple[1]} 的值在运行时才确定` };
        return { kind: 'literal', value: entry.value };
    }
    if (isDynamic(String(text)))
        return { kind: 'unknown', why: `目标为运行时展开：${text}` };
    return { kind: 'literal', value: String(text) };
}

const isAnchoredOperand = (raw, home) => String(raw) === home
    || String(raw).startsWith('~')
    || pathApiFor(String(raw)).isAbsolute(String(raw));

/** 应用这一段的换目录效果：成功态＝目标（或多个起点各自的目标），失败态＝原样。
 * 返回两态而不是改一格，是为了让 `&&`／`||` 各吃各的分支；帧上是全部可能态。 */
function applyNavigation(frame, segment, home) {
    const program = normalizeProgram(segment.program ?? '');
    if (NAVIGATE_PROGRAMS.has(program) === false)
        return snapshot(frame);
    const operand = navigationOperand(segment, frame);
    if (operand.kind === 'unknown') {
        frame.cwd = unknownCwd(operand.why, frame.cwd);
        return snapshot(frame);
    }
    if (POP_PROGRAMS.has(program)) {
        if (frame.cwd.list.length !== 1 || frame.cwd.unknown !== '')
            frame.cwd = unknownCwd('popd 在当前工作目录不确定时算不出退回哪一层', frame.cwd);
        else if (frame.stack.length > 0)
            frame.cwd = { list: [frame.stack.pop()], unknown: '' };
        return snapshot(frame);
    }
    if (PUSH_PROGRAMS.has(program) && operand.kind === 'home' && frame.stack.length > 0) {
        // `pushd` 不带参数＝与栈顶交换；栈只记单一目录，多候选时不猜。
        if (frame.cwd.list.length === 1 && frame.cwd.unknown === '') {
            const top = frame.stack.pop();
            frame.stack.push(frame.cwd.list[0]);
            frame.cwd = { list: [top], unknown: '' };
        }
        else
            frame.cwd = unknownCwd('pushd 交换目录时当前工作目录不确定', frame.cwd);
        return snapshot(frame);
    }
    const raw = operand.kind === 'home' ? home : operand.value;
    if (frame.cwd.list.length === 0) {
        frame.cwd = unknownCwd('起始工作目录不可用', frame.cwd);
        return snapshot(frame);
    }
    const targets = frame.cwd.list.map(base => normalizePath(raw, base, home));
    const success = frame.cwd.unknown !== ''
        ? unknownCwd(frame.cwd.unknown, { list: targets })
        : mergeCwd(...targets.map(path => ({ list: [path], unknown: '' })));
    const failure = cloneCwd(frame.cwd);
    if (PUSH_PROGRAMS.has(program)) {
        if (frame.cwd.list.length === 1 && frame.cwd.unknown === '')
            frame.stack.push(frame.cwd.list[0]);
        else
            frame.stack = [];
    }
    if (isAnchoredOperand(raw, home) === false)
        frame.relativeNav = true;
    frame.cwd = mergeCwd(success, failure);
    return { success, failure };
}

function walkStructured(root, text, context = {}) {
    const list = [];
    const home = typeof context.home === 'string' ? context.home : '';
    const annotate = typeof context.cwd === 'string' && context.cwd !== '';
    const startFrame = () => ({
        cwd: annotate ? { list: [context.cwd], unknown: '' } : { list: [], unknown: '未提供起始工作目录' },
        vars: new Map(),
        stack: [],
        functions: new Set(),
        relativeNav: false,
    });
    const emit = (node, frame) => {
        const slice = text.slice(node.startIndex, node.endIndex);
        const parsed = splitSegments(slice);
        const fields = annotate ? cwdFields(frame.cwd) : {};
        for (const segment of parsed) {
            // 原文位置跟着段走：后续按执行结构传播 cwd／变量时不必再回找源串。
            segment.span = { start: node.startIndex, end: node.endIndex };
            Object.assign(segment, cloneFields(fields));
            list.push({ segment, start: node.startIndex, end: node.endIndex });
        }
        return parsed;
    };
    const backgrounded = (node) => {
        let sibling = node.nextSibling;
        while (sibling !== null && sibling.type === 'comment')
            sibling = sibling.nextSibling;
        return sibling !== null && sibling.type === '&';
    };
    const runSequence = (node, frame) => {
        let result = snapshot(frame);
        for (const child of node.namedChildren) {
            if (backgrounded(child)) {
                // `cmd &` 在后台子 shell 里跑：换目录不泄漏，也不改本行后面的判定位置。
                runNode(child, cloneFrame(frame));
                result = snapshot(frame);
                continue;
            }
            const one = runNode(child, frame);
            frame.cwd = mergeCwd(one.success, one.failure);
            result = one;
        }
        return result;
    };
    const runCommand = (node, frame) => {
        const parsed = emit(node, frame);
        let result = snapshot(frame);
        const segment = parsed[0];
        if (segment !== undefined)
            result = applyNavigation(frame, segment, home);
        const program = normalizeProgram(segment?.program ?? '');
        if (node.type === 'declaration_command') {
            if (program === 'unset') {
                for (const word of (segment?.words ?? []))
                    if (word?.kind === 'operand')
                        frame.vars.delete(String(word.text));
            }
            else
                applyDeclarations(node, frame, text);
        }
        if (frame.functions.has(program)) {
            // 本命令内定义的函数：它可能换目录，静态这里算不死——不拿「没换」冒充结论。
            frame.cwd = unknownCwd(`调用了本命令内定义的函数 ${program}，是否换目录未静态确定`, frame.cwd);
            result = snapshot(frame);
        }
        return result;
    };
    const runList = (node, frame) => {
        const children = node.namedChildren;
        if (children.length < 2)
            return runSequence(node, frame);
        const [left, right] = children;
        let operator = '';
        for (let index = 0; index < node.childCount; index += 1) {
            const child = node.child(index);
            if (child.startIndex >= left.endIndex && child.endIndex <= right.startIndex
                && (child.type === '&&' || child.type === '||'))
                operator = child.type;
        }
        const leftResult = runNode(left, frame);
        frame.cwd = mergeCwd(leftResult.success, leftResult.failure);
        if (operator === '||') {
            const rightFrame = cloneFrame(frame);
            rightFrame.cwd = cloneCwd(leftResult.failure);
            const rightResult = runNode(right, rightFrame);
            frame.cwd = mergeCwd(leftResult.success, rightResult.success, rightResult.failure);
            return {
                success: mergeCwd(leftResult.success, rightResult.success),
                failure: rightResult.failure,
            };
        }
        const rightFrame = cloneFrame(frame);
        rightFrame.cwd = cloneCwd(leftResult.success);
        const rightResult = runNode(right, rightFrame);
        // 失败态先排右侧：右侧失败意味着左侧成功过（cd 的目标确实存在），比左侧失败更可信。
        frame.cwd = mergeCwd(leftResult.failure, rightResult.success, rightResult.failure);
        return {
            success: rightResult.success,
            failure: mergeCwd(rightResult.failure, leftResult.failure),
        };
    };
    const runPipeline = (node, frame) => {
        // 管道的每一段都在自己的子 shell 里：换目录互不影响，也不泄漏到管道之后。
        for (const child of node.namedChildren)
            runNode(child, cloneFrame(frame));
        return snapshot(frame);
    };
    const runIsolated = (node, frame) => {
        // 子 shell：里面怎么换都在出口还原。
        runSequence(node, cloneFrame(frame));
        return snapshot(frame);
    };
    const runIf = (node, frame) => {
        const cond = [];
        const then = [];
        let elseNode;
        let mode = 'cond';
        for (let index = 0; index < node.childCount; index += 1) {
            const child = node.child(index);
            if (child.isNamed === false) {
                if (child.type === 'then')
                    mode = 'then';
                continue;
            }
            if (child.type === 'else_clause' || child.type === 'elif_clause') {
                elseNode = child;
                continue;
            }
            (mode === 'cond' ? cond : then).push(child);
        }
        let condResult = snapshot(frame);
        for (const child of cond)
            condResult = runNode(child, frame);
        frame.cwd = mergeCwd(condResult.success, condResult.failure);
        const thenFrame = cloneFrame(frame);
        thenFrame.cwd = cloneCwd(condResult.success);
        let thenResult;
        for (const child of then)
            thenResult = runNode(child, thenFrame);
        let elseResult = { success: cloneCwd(condResult.failure), failure: cloneCwd(condResult.failure) };
        if (elseNode !== undefined) {
            const elseFrame = cloneFrame(frame);
            elseFrame.cwd = cloneCwd(condResult.failure);
            elseResult = runNode(elseNode, elseFrame);
        }
        frame.cwd = mergeCwd(thenResult?.success, thenResult?.failure, elseResult.success, elseResult.failure);
        return {
            success: mergeCwd(thenResult?.success, elseResult.success),
            failure: mergeCwd(thenResult?.failure, elseResult.failure),
        };
    };
    const runLoop = (node, frame, conditional) => {
        const body = node.namedChildren.find(child => child.type === 'do_group');
        let condResult = snapshot(frame);
        if (conditional) {
            for (const child of node.namedChildren) {
                if (child === body)
                    continue;
                condResult = runNode(child, frame);
            }
            frame.cwd = mergeCwd(condResult.success, condResult.failure);
        }
        const bodyFrame = cloneFrame(frame);
        // while／until 的循环体只在条件成立那一支执行；for 的循环体直接继承当前态。
        if (conditional)
            bodyFrame.cwd = cloneCwd(condResult.success);
        else
            applyLoopVariables(node, bodyFrame, text);
        let bodyResult = snapshot(bodyFrame);
        for (const child of body?.namedChildren ?? [])
            bodyResult = runNode(child, bodyFrame);
        const merged = mergeCwd(condResult.success, condResult.failure,
            bodyResult.success, bodyResult.failure);
        // 循环体可能跑多轮：相对换目录会随迭代叠加，静态算不出终点。
        frame.cwd = bodyFrame.relativeNav
            ? unknownCwd('循环体可能多次执行，相对换目录会随迭代叠加', merged)
            : merged;
        return snapshot(frame);
    };
    const runCase = (node, frame) => {
        const entry = cloneCwd(frame.cwd);
        const branches = [entry];
        for (const child of node.namedChildren) {
            if (child.type !== 'case_item')
                continue;
            const branchFrame = cloneFrame(frame);
            const result = runSequence(child, branchFrame);
            branches.push(result.success, result.failure);
        }
        frame.cwd = mergeCwd(...branches);
        return snapshot(frame);
    };
    const runFunction = (node, frame) => {
        const nameNode = node.namedChildren.find(child => child.type === 'word');
        if (nameNode !== undefined)
            frame.functions.add(nodeText(nameNode, text));
        const body = node.namedChildren.find(child => child.type === 'compound_statement');
        if (body !== undefined) {
            // 函数体在**调用时**才执行，那时的工作目录与定义处无关：里面的相对路径一律算不死。
            const bodyFrame = cloneFrame(frame);
            bodyFrame.cwd = unknownCwd('函数体在调用时执行，工作目录未静态确定', frame.cwd);
            runSequence(body, bodyFrame);
        }
        return snapshot(frame);
    };
    const runRedirected = (node, frame) => {
        const before = list.length;
        for (const child of node.namedChildren)
            if (child.type !== 'file_redirect' && child.type !== 'heredoc_redirect')
                runNode(child, frame);
        for (const child of node.namedChildren) {
            if (child.type !== 'file_redirect' && child.type !== 'heredoc_redirect')
                continue;
            const piece = child.type === 'heredoc_redirect'
                ? { redirects: redirectsOf(child, text).redirects, heredocs: [heredocOf(child, text)] }
                : redirectsOf(child, text);
            if (piece.redirects.length === 0 && piece.heredocs.length === 0)
                continue;
            // 重定向归「它前面最近的那一段」：`a > out | b` 归 a，`a | b > out` 归 b。
            let at = -1;
            for (let index = list.length - 1; index >= before; index -= 1) {
                if (list[index].end <= child.startIndex) {
                    at = index;
                    break;
                }
            }
            if (at < 0) {
                list.push({
                    segment: {
                        program: '', words: [], redirects: piece.redirects, heredocs: piece.heredocs,
                        opaque: piece.redirects.some(redirect => redirect.dynamic === true),
                        ...(annotate ? cloneFields(cwdFields(frame.cwd)) : {}),
                    },
                    start: child.startIndex, end: child.endIndex,
                });
                continue;
            }
            const target = list[at].segment;
            target.redirects.push(...piece.redirects);
            target.heredocs = [...(target.heredocs ?? []), ...piece.heredocs];
            target.opaque = target.opaque === true
                || piece.redirects.some(redirect => redirect.dynamic === true);
        }
        return snapshot(frame);
    };
    const runNode = (node, frame) => {
        const type = node.type;
        if (COMMAND_NODES.has(type))
            return runCommand(node, frame);
        if (type === 'variable_assignment') {
            assignVariable(node, frame, text);
            return snapshot(frame);
        }
        if (type === 'list')
            return runList(node, frame);
        if (type === 'pipeline')
            return runPipeline(node, frame);
        if (type === 'subshell')
            return runIsolated(node, frame);
        if (type === 'if_statement')
            return runIf(node, frame);
        if (type === 'while_statement' || type === 'until_statement')
            return runLoop(node, frame, true);
        if (type === 'for_statement' || type === 'c_style_for_statement')
            return runLoop(node, frame, false);
        if (type === 'case_statement')
            return runCase(node, frame);
        if (type === 'function_definition')
            return runFunction(node, frame);
        if (type === 'redirected_statement')
            return runRedirected(node, frame);
        if (type === 'command_substitution' || type === 'process_substitution')
            return snapshot(frame);   // 与旧形一致：命令替换留在词里，另由事实层分析
        return runSequence(node, frame);
    };
    runSequence(root, startFrame());
    return list.map(item => item.segment);
}

/** * 一条 shell 命令 → 段列表。`segments === null` 表示这一条没有用上结构化解析
 * （方言未知／文法报错／运行库不可用），调用方应退回 `splitSegments`。
 * `incomplete` 只说明「结构没被文法证实」，不等于危险、未授权或必须人工。
 * `context.cwd` 给了才附逐段工作目录（`cwd`／`cwdCandidates`／`cwdUnknown`）。
 */
export function splitCommandSegments(command, toolName, context = {}) {
    const text = String(command ?? '');
    const dialect = DIALECT_BY_TOOL.get(String(toolName ?? '').toLowerCase());
    if (dialect === undefined)
        return { segments: null, mode: 'tokenizer', incomplete: false, why: '工具名不声明方言' };
    if (!runtimeReady || !parsers.has(dialect))
        return { segments: null, mode: 'tokenizer', incomplete: false, why: runtimeWhy || `${dialect} 文法不可用` };
    if (text.length > MAX_STRUCTURED_CHARS)
        return { segments: null, mode: 'tokenizer', incomplete: true, why: '命令长度触顶，未做结构化解析' };
    let tree;
    try {
        tree = parsers.get(dialect).parse(text);
    }
    catch (error) {
        return { segments: null, mode: 'tokenizer', incomplete: true, why: `解析异常：${String(error?.message ?? error).slice(0, 120)}` };
    }
    if (tree.rootNode.hasError) {
        tree.delete();
        return { segments: null, mode: 'tokenizer', incomplete: true, why: '文法报错，已退回手写拆串（结构不可证）' };
    }
    let segments;
    try {
        segments = walkStructured(tree.rootNode, text, context);
    }
    catch (error) {
        tree.delete();
        return { segments: null, mode: 'tokenizer', incomplete: true, why: `结构遍历异常：${String(error?.message ?? error).slice(0, 120)}` };
    }
    tree.delete();
    // 未引用定界符的 heredoc 正文里 `$(…)`／反引号会真的执行：与 splitSegments 同一条规则。
    const fromBodies = [];
    for (const segment of segments) {
        const bodies = (segment.heredocs ?? []).filter(heredoc => heredoc.quoted !== true
            && /[$`]/.test(heredoc.text));
        if (bodies.length === 0)
            continue;
        segment.heredocExpanded = true;
        for (const heredoc of bodies)
            for (const inner of commandSubstitutions(heredoc.text))
                for (const sub of splitSegments(inner)) {
                    sub.fromHeredoc = true;
                    // 正文里的替换在父段的同一个 shell 位置执行：工作目录继承父段。
                    Object.assign(sub, cloneFields(segment));
                    fromBodies.push(sub);
                }
    }
    segments.push(...fromBodies);
    return {
        segments: segments.filter(segment => segment.program !== '' || segment.redirects.length > 0),
        mode: dialect,
        incomplete: false,
        why: '',
    };
}
