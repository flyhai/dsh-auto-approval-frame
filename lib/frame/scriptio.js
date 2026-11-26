// 解释器脚本的参数位语义：从脚本正文推断「第几个参数是读、第几个是写」。
//
// 为什么需要：`python x.py A B` 这种形态，命令文本里只有一个路径，脚本行为全在文件里。
// 事实层原来把脚本之后的操作数一律记成 write-destination，于是「读区外文件」被当成
// 「写区外文件」，必问人。这里补一次正文分析，把能判出来的参数位说清楚。
//
// 三条铁律：
// 1. 只认三种解释器（python／node／bash 及其常见别名），其余一律不判。
// 2. 宁写勿读：正文里出现写迹象、但配不上是哪个参数的，不给 read——给 unknown，
//    调用方照旧按写处理。判错方向只能往严的那边错。
// 3. 判不出就说判不出（unknown），不猜。带旗标的段不判（参数位对不齐，容易错位）。
//
// 实现方式（9-19 改）：不再按「哪种赋值写法」逐条枚举正则——那等于每来一个新写法就漏一次
// （`x = sys.argv[1]` 认、`a, b = sys.argv[1], sys.argv[2]` 不认）。改成**按数据流追**：
// 先把正文切成语句与记号，找出所有「第 N 个参数」出现的位置，再沿赋值／解构／for 目标／
// 函数形参一路传播「这个值来自第 N 个参数」，最后看它落到哪个调用里。追不到（传进第三方库、
// 拼进字符串、exec）才是 unknown。
//
// 输出：Map<参数位, 'read'|'write'|'unknown'>，键 1 起（0 是脚本自己）。

const PYTHON = new Set(['python', 'python3', 'py', 'pythonw']);
const NODE = new Set(['node', 'nodejs']);
const SHELL = new Set(['bash', 'sh', 'zsh', 'dash']);

/** 从一段调用的左括号位置抠出第一个实参的文本。 */
function firstArgOf(text, parenIndex) {
    let depth = 0;
    for (let at = parenIndex; at < text.length; at += 1) {
        const ch = text[at];
        if (ch === '(' || ch === '[' || ch === '{') {
            depth += 1;
        }
        else if (ch === ')' || ch === ']' || ch === '}') {
            depth -= 1;
            if (depth === 0)
                return text.slice(parenIndex + 1, at);
        }
        else if (ch === ',' && depth === 1) {
            return text.slice(parenIndex + 1, at);
        }
    }
    return text.slice(parenIndex + 1);
}

/** 把一次调用的顶层实参逐个拆出来（`open(p, 'w', encoding=…)` 要拿到第二参）。 */
function argsOf(text, parenIndex) {
    const parts = [];
    let depth = 0;
    let start = parenIndex + 1;
    for (let at = parenIndex; at < text.length; at += 1) {
        const ch = text[at];
        if (ch === '(' || ch === '[' || ch === '{') {
            depth += 1;
        }
        else if (ch === ')' || ch === ']' || ch === '}') {
            depth -= 1;
            if (depth === 0) {
                parts.push(text.slice(start, at));
                return parts;
            }
        }
        else if (ch === ',' && depth === 1) {
            parts.push(text.slice(start, at));
            start = at + 1;
        }
    }
    parts.push(text.slice(start));
    return parts;
}

/** 收集「某个调用名的第一个实参」——按调用名分读写两组。
 *  允许前面是 `.`（`fs.readFileSync`、`Path(x).read_text` 都不是裸调用）。 */
function callsByName(text, names, sink) {
    for (const name of names) {
        const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp(`(?:^|[^\\w])${escaped}\\s*\\(`, 'g');
        let hit;
        while ((hit = re.exec(text)) !== null)
            sink.push({ name, arg: firstArgOf(text, hit.index + hit[0].length - 1).trim() });
    }
}

// ── 词法：切出标识符／字符串／数字／符号，丢掉空白与注释 ──────────────────
// 只服务「追参数流向」这一件事：不需要表达式树，只要知道名字、字符串字面量、
// 括号深度与逗号层级。字符串整体一个记号，里面的 `open(` 不会被当成调用。
function readString(text, start) {
    const quote = text[start];
    const triple = text.slice(start, start + 3) === quote.repeat(3);
    const open = triple ? 3 : 1;
    let at = start + open;
    let value = '';
    while (at < text.length) {
        if (text[at] === '\\') {
            value += text[at + 1] ?? '';
            at += 2;
            continue;
        }
        if (triple === true && text.slice(at, at + 3) === quote.repeat(3))
            return { value, next: at + 3 };
        if (triple !== true && text[at] === quote)
            return { value, next: at + 1 };
        value += text[at];
        at += 1;
    }
    return { value, next: text.length };
}

const TWO_CHAR = new Set(['==', '!=', '<=', '>=', ':=', '+=', '-=', '*=', '/=', '//', '**', '->', '<<', '>>']);

function tokenize(text) {
    const out = [];
    let at = 0;
    while (at < text.length) {
        const ch = text[at];
        if (ch === '\n') {
            out.push({ t: 'nl' });
            at += 1;
            continue;
        }
        if (ch === ' ' || ch === '\t' || ch === '\r') {
            at += 1;
            continue;
        }
        if (ch === '#') {
            while (at < text.length && text[at] !== '\n')
                at += 1;
            continue;
        }
        if (ch === '\'' || ch === '"') {
            const read = readString(text, at);
            out.push({ t: 'str', v: read.value });
            at = read.next;
            continue;
        }
        if (/[0-9]/.test(ch)) {
            let end = at;
            while (end < text.length && /[0-9a-fA-FxX._]/.test(text[end]))
                end += 1;
            out.push({ t: 'num', v: text.slice(at, end) });
            at = end;
            continue;
        }
        if (/[A-Za-z_]/.test(ch)) {
            let end = at;
            while (end < text.length && /[A-Za-z0-9_]/.test(text[end]))
                end += 1;
            const word = text.slice(at, end);
            // 字符串前缀（r／b／f／u 及组合）：紧跟引号时整段当字符串，前缀不进记号流。
            if (text[end] === '\'' || text[end] === '"') {
                const read = readString(text, end);
                out.push({ t: 'str', v: read.value });
                at = read.next;
                continue;
            }
            out.push({ t: 'id', v: word });
            at = end;
            continue;
        }
        const two = text.slice(at, at + 2);
        if (TWO_CHAR.has(two)) {
            out.push({ t: 'op', v: two });
            at += 2;
            continue;
        }
        out.push({ t: 'op', v: ch });
        at += 1;
    }
    return out;
}

const OPENERS = new Set(['(', '[', '{']);
const CLOSERS = new Set([')', ']', '}']);
const isOp = (tk, v) => tk !== undefined && tk.t === 'op' && tk.v === v;

/** 按「深度 0 的换行／分号」切语句；跨行括号里的换行不算断句。 */
function statements(tokens) {
    const out = [];
    let cur = [];
    let depth = 0;
    for (const tk of tokens) {
        if (tk.t === 'op' && OPENERS.has(tk.v))
            depth += 1;
        else if (tk.t === 'op' && CLOSERS.has(tk.v))
            depth = Math.max(0, depth - 1);
        const cut = depth === 0 && (tk.t === 'nl' || (tk.t === 'op' && tk.v === ';'));
        if (cut === true) {
            if (cur.length > 0)
                out.push(cur);
            cur = [];
            continue;
        }
        cur.push(tk);
    }
    if (cur.length > 0)
        out.push(cur);
    return out;
}

/** 按深度 0 的逗号切段（用于实参表、解构左值、元组右值）。 */
function splitTop(tokens) {
    const parts = [];
    let cur = [];
    let depth = 0;
    for (const tk of tokens) {
        if (tk.t === 'op' && OPENERS.has(tk.v))
            depth += 1;
        else if (tk.t === 'op' && CLOSERS.has(tk.v))
            depth = Math.max(0, depth - 1);
        if (tk.t === 'op' && tk.v === ',' && depth === 0) {
            if (cur.length > 0)
                parts.push(cur);
            cur = [];
            continue;
        }
        cur.push(tk);
    }
    if (cur.length > 0)
        parts.push(cur);
    return parts;
}

/** 深度 0 的赋值等号位置（`==`／`!=`／`:=` 已是独立记号，不会误认；`+=` 同理）。 */
function assignAt(tokens) {
    const hits = [];
    let depth = 0;
    for (let at = 0; at < tokens.length; at += 1) {
        const tk = tokens[at];
        if (tk.t === 'op' && OPENERS.has(tk.v))
            depth += 1;
        else if (tk.t === 'op' && CLOSERS.has(tk.v))
            depth = Math.max(0, depth - 1);
        else if (depth === 0 && isOp(tk, '='))
            hits.push(at);
    }
    return hits;
}

/** 左值段 → 名字列表。只认「单个名字」与「括号／方括号里一串名字」，其余（下标、属性）不绑。 */
function namesOf(segment) {
    let seg = segment;
    if (seg.length >= 2
        && ((isOp(seg[0], '(') && isOp(seg[seg.length - 1], ')'))
            || (isOp(seg[0], '[') && isOp(seg[seg.length - 1], ']'))))
        seg = seg.slice(1, -1);
    return splitTop(seg)
        .map(part => (part.length === 1 && part[0].t === 'id' ? part[0].v : ''))
        .filter(name => name !== '');
}

/** 多值来源的起点：`process.argv.slice(2)`／`sys.argv[1:]` ⇒ 内部参数位起点。
 *  解构 `const [a, b] = …slice(2)` 就按位置依次对位（a 是第 1 个、b 是第 2 个）。
 *  带终止的切片（`[1:3]`）不认：名字数与切片长度对不上时按位硬配会把 c 当成 b。 */
function sliceStartOf(tokens, spec) {
    for (let at = 0; at < tokens.length; at += 1) {
        if (tokens[at]?.t !== 'id' || tokens[at].v !== spec.argvOwner)
            continue;
        if (isOp(tokens[at + 1], '.') === false)
            continue;
        if (tokens[at + 2]?.t !== 'id' || tokens[at + 2].v !== 'argv')
            continue;
        const after = at + 3;
        // `process.argv.slice(2)`：node 的常规写法（不是下标访问，argv 后面不跟 `[`）。
        if (isOp(tokens[after], '.') && tokens[after + 1]?.t === 'id' && tokens[after + 1].v === 'slice'
            && isOp(tokens[after + 2], '(') && tokens[after + 3]?.t === 'num' && isOp(tokens[after + 4], ')'))
            return spec.sliceKey(Number(tokens[after + 3].v));
        // `sys.argv[1:]`：Python 的多值切片（带终止的 `[1:3]` 不认，见上）。
        if (isOp(tokens[after], '[') && tokens[after + 1]?.t === 'num' && isOp(tokens[after + 2], ':'))
            return spec.sliceKey(Number(tokens[after + 1].v));
    }
    return null;
}

/** 深度 0 的第一个 `in`（`for X in EXPR`）——排除 `not in`。 */
function inAt(tokens) {
    let depth = 0;
    for (let at = 0; at < tokens.length; at += 1) {
        const tk = tokens[at];
        if (tk.t === 'op' && OPENERS.has(tk.v))
            depth += 1;
        else if (tk.t === 'op' && CLOSERS.has(tk.v))
            depth = Math.max(0, depth - 1);
        else if (depth === 0 && tk.t === 'id' && tk.v === 'in')
            return tokens[at - 1] !== undefined && tokens[at - 1].t === 'id' && tokens[at - 1].v === 'not' ? -1 : at;
    }
    return -1;
}

/** 参数引用探测器：返回 {key, len} 或 null。key 是内部参数位（1 起）。 */
function pythonArgv(tokens, at) {
    if (tokens[at]?.t === 'id' && tokens[at].v === 'sys'
        && isOp(tokens[at + 1], '.') && tokens[at + 2]?.t === 'id' && tokens[at + 2].v === 'argv'
        && isOp(tokens[at + 3], '[') && tokens[at + 4]?.t === 'num' && isOp(tokens[at + 5], ']')) {
        const raw = Number(tokens[at + 4].v);
        return Number.isInteger(raw) === true ? { key: raw, len: 6 } : null;
    }
    return null;
}

function nodeArgv(tokens, at) {
    if (tokens[at]?.t === 'id' && tokens[at].v === 'process'
        && isOp(tokens[at + 1], '.') && tokens[at + 2]?.t === 'id' && tokens[at + 2].v === 'argv'
        && isOp(tokens[at + 3], '[') && tokens[at + 4]?.t === 'num' && isOp(tokens[at + 5], ']')) {
        const raw = Number(tokens[at + 4].v) - 1;
        return Number.isInteger(raw) === true && raw >= 1 ? { key: raw, len: 6 } : null;
    }
    return null;
}

/** 一段记号里出现了哪些参数位：直接引用＋经变量别名（递归由闭包迭代完成）。
 *  调用点用它（要认出 `open(str(p))` 里的 p）；**传播**用下面的 `pathSources`。 */
function sourcesOf(tokens, argvAt, alias) {
    const out = new Set();
    for (let at = 0; at < tokens.length; at += 1) {
        const direct = argvAt(tokens, at);
        if (direct !== null) {
            out.add(direct.key);
            at += direct.len - 1;
            continue;
        }
        const tk = tokens[at];
        // 属性名不是变量：`os.path.join(...)` 里的 `path` 与用户变量 `path` 同名，
        // 跟着别名走就会把「输出目录的第 2 个参数」错系到「输入的第 1 个参数」上。
        if (tk.t === 'id' && alias.has(tk.v) && isOp(tokens[at - 1], '.') === false)
            for (const key of alias.get(tk.v))
                out.add(key);
    }
    return out;
}

/** 路径包装函数：只经它们派生出来的值仍算「同一个路径」。
 *  不在表里的调用（`split`／`splitext`／`open().read()`／`format`）派生的是**内容或片段**，
 *  不是路径——把它们也算成路径，`fn = join(outdir, 'img_%s' % (n, ext))` 这条路就会把
 *  输入文件的那个参数捎进「写」里（实测：读的 F 盘 mhtml 因此被判 write）。 */
const PATH_WRAP = new Set(['Path', 'PurePath', 'str', 'join', 'abspath', 'normpath', 'realpath',
    'expanduser', 'dirname', 'basename', 'fspath', 'resolve', 'with_suffix', 'with_name', 'relative_to']);

/** 严格版来源：只认「路径表达式」，不认由它派生出来的字符串／内容。 */
function pathSources(tokens, spec, alias) {
    let ts = tokens;
    if (ts.length >= 2 && isOp(ts[0], '(') && isOp(ts[ts.length - 1], ')'))
        ts = ts.slice(1, -1);
    if (ts.length === 0)
        return new Set();
    const direct = spec.argvAt(ts, 0);
    if (direct !== null && direct.len === ts.length)
        return direct.key >= 1 ? new Set([direct.key]) : new Set();
    if (ts.length === 1 && ts[0].t === 'id' && alias.has(ts[0].v))
        return new Set(alias.get(ts[0].v));
    // 属性链（`p.parent`）：取首段变量的来源。
    if (ts[0].t === 'id' && alias.has(ts[0].v)
        && ts.every((tk, at) => tk.t === 'id' || (isOp(tk, '.') && at > 0)))
        return new Set(alias.get(ts[0].v));
    const parenAt = ts.findIndex(tk => isOp(tk, '('));
    if (parenAt > 0) {
        const name = ts[parenAt - 1];
        const headOk = ts.slice(0, parenAt - 1).every(tk => tk.t === 'id' || isOp(tk, '.'));
        let depth = 0;
        let close = -1;
        for (let at = parenAt; at < ts.length; at += 1) {
            if (isOp(ts[at], '('))
                depth += 1;
            else if (isOp(ts[at], ')')) {
                depth -= 1;
                if (depth === 0) {
                    close = at;
                    break;
                }
            }
        }
        if (name.t === 'id' && headOk === true && close === ts.length - 1 && PATH_WRAP.has(name.v)) {
            const out = new Set();
            for (const arg of splitTop(ts.slice(parenAt + 1, close)))
                for (const key of pathSources(arg, spec, alias))
                    out.add(key);
            return out;
        }
    }
    return new Set();
}
/** 调用点：名字、实参段、接收者表达式（`x.y(...)` 里的 x，或 `Path(p).write_text(...)` 的 p）。 */
function callSites(tokens) {
    const sites = [];
    for (let at = 0; at < tokens.length; at += 1) {
        if (tokens[at].t !== 'id' || isOp(tokens[at + 1], '(') === false)
            continue;
        let depth = 0;
        let end = at + 1;
        for (; end < tokens.length; end += 1) {
            const tk = tokens[end];
            if (tk.t === 'op' && OPENERS.has(tk.v))
                depth += 1;
            else if (tk.t === 'op' && CLOSERS.has(tk.v)) {
                depth -= 1;
                if (depth === 0)
                    break;
            }
        }
        const args = splitTop(tokens.slice(at + 2, end));
        let receiver = [];
        if (isOp(tokens[at - 1], '.')) {
            if (isOp(tokens[at - 2], ')')) {
                // `Path(x).write_text()`：接收者是构造调用的实参（`at-2` 是那个右括号）。
                let back = at - 2;
                let inner = 0;
                for (; back >= 0; back -= 1) {
                    const tk = tokens[back];
                    if (tk.t === 'op' && CLOSERS.has(tk.v))
                        inner += 1;
                    else if (tk.t === 'op' && OPENERS.has(tk.v)) {
                        inner -= 1;
                        if (inner === 0)
                            break;
                    }
                }
                const ctorName = tokens[back - 1]?.t === 'id' ? tokens[back - 1].v : '';
                receiver = ctorName === 'Path' || ctorName === 'PurePath' ? splitTop(tokens.slice(back + 1, at - 2)).flat() : [];
            }
            else if (tokens[at - 2]?.t === 'id') {
                receiver = [tokens[at - 2]];
            }
        }
        sites.push({ name: tokens[at].v, args, receiver });
    }
    return sites;
}

// ── 读写族 ────────────────────────────────────────────────────────────────
// 只收「被调用时，实参是路径」的函数；文件对象的方法（`f.write`）不在内——
// 那种路径已经在 `open` 那一步判过了，再加会把 `f.write` 当成路径写。
const PY_READ = new Set(['read_text', 'read_bytes', 'readlines', 'readline', 'read_csv', 'read_table',
    'read_excel', 'read_json', 'loadtxt', 'genfromtxt', 'imread', 'load_workbook', 'load']);
const PY_WRITE = new Set(['write_text', 'write_bytes', 'remove', 'unlink', 'rmdir', 'removedirs', 'rename',
    'renames', 'replace', 'move', 'copy', 'copyfile', 'copy2', 'copytree', 'makedirs', 'mkdir', 'truncate', 'rmtree']);
// `Path(x).write_text(...)`：被写的是构造 Path 的那个表达式，不在实参里。
const PY_RECV_WRITE = new Set(['write_text', 'write_bytes', 'unlink', 'rename', 'replace', 'rmdir', 'mkdir', 'touch']);
const PY_RECV_READ = new Set(['read_text', 'read_bytes', 'readlines', 'readline', 'open', 'stat', 'exists',
    'is_file', 'is_dir', 'iterdir', 'glob', 'rglob']);

const ND_READ = new Set(['readFileSync', 'readFile', 'createReadStream', 'statSync', 'lstatSync', 'existsSync',
    'readdirSync', 'readdir', 'accessSync', 'readlinkSync']);
const ND_WRITE = new Set(['writeFileSync', 'writeFile', 'createWriteStream', 'appendFileSync', 'appendFile',
    'rmSync', 'rm', 'unlinkSync', 'unlink', 'renameSync', 'rename', 'copyFileSync', 'copyFile',
    'mkdirSync', 'mkdir', 'truncateSync', 'truncate', 'chmodSync', 'chmod', 'utimesSync']);

function roleTable() {
    return { write: new Set(), read: new Set(), unknown: new Set(), positions: new Set() };
}

/** 把一次调用落到读写集合里。`open` 的读写由第二实参的字面量决定。 */
function applyCall(site, sources, table, spec) {
    if (sources.size === 0)
        return;
    // 只认**裸 open**：`pdfplumber.open(p)`／`Image.open(p)` 是别人的函数，行为在库里，
    // 按内置 open 的 mode 规则套上去等于替库担保——判不出就 unknown。`Path(p).open()`
    // 由接收者那一支（PY_RECV_READ）管，不走这里。
    if (site.name === 'open' && spec.openMode === true && site.receiver.length === 0) {
        // 第二个实参是 mode：`open(p, 'w')`／`open(p, mode='w')`。不是字面量就判不出——
        // `open(p, m)` 里 m 可能是 'w'，按读处理会把写当读，宁可不判。
        const modeArg = site.args[1];
        if (modeArg === undefined) {
            for (const key of sources) table.read.add(key);
            return;
        }
        const isKeyword = modeArg.length >= 2 && modeArg[0].t === 'id' && modeArg[0].v === 'mode' && isOp(modeArg[1], '=');
        const literal = modeArg.length === 1 && modeArg[0].t === 'str'
            ? modeArg[0].v
            : (isKeyword === true && modeArg.length === 2 && modeArg[1].t === 'str' ? modeArg[1].v : undefined);
        if (literal === undefined) {
            for (const key of sources) table.unknown.add(key);
            return;
        }
        const writeMode = /[wax+]/.test(literal);
        for (const key of sources)
            (writeMode === true ? table.write : table.read).add(key);
        return;
    }
    if (spec.write.has(site.name)) {
        for (const key of sources) table.write.add(key);
        return;
    }
    if (spec.read.has(site.name)) {
        for (const key of sources) table.read.add(key);
        return;
    }
    // 认不出的调用：参数进了别人的函数，看不到它拿去干什么——判不出，但也不否掉
    // 别处已判出的读（`print(path)` 不该把 `open(path)` 的读抹成 unknown）。
    for (const key of sources) table.unknown.add(key);
}

function flowRoles(text, spec) {
    const tokens = tokenize(text);
    const lines = statements(tokens);
    // 绑定对：左名 ← 右表达式（记号段）。解构、for 目标、函数形参都先摊成这种对。
    const pairs = [];
    const defs = new Map();
    const table = roleTable();
    for (const line of lines) {
        if (line[0].t === 'id' && line[0].v === 'def') {
            const nameAt = 1;
            const openAt = line.findIndex((tk, at) => at > nameAt && isOp(tk, '('));
            if (line[nameAt]?.t === 'id' && openAt !== -1) {
                let depth = 0;
                let closeAt = openAt;
                for (; closeAt < line.length; closeAt += 1) {
                    if (isOp(line[closeAt], '(')) depth += 1;
                    else if (isOp(line[closeAt], ')')) {
                        depth -= 1;
                        if (depth === 0) break;
                    }
                }
                const params = splitTop(line.slice(openAt + 1, closeAt))
                    .map(part => part[0]?.t === 'id' ? part[0].v : '')
                    .filter(name => name !== '');
                defs.set(line[nameAt].v, params);
            }
            continue;
        }
        if (line[0].t === 'id' && line[0].v === 'for') {
            const split = inAt(line);
            if (split !== -1) {
                const targets = namesOf(line.slice(1, split));
                const tail = line.slice(split + 1);
                // 只剥句尾那个冒号；切片里的 `[1:]` 若一起剥掉，就成了「第 1 个参数」的直引，
                // 多值被当成单值——方向正好是错的。
                const source = isOp(tail[tail.length - 1], ':') ? tail.slice(0, -1) : tail;
                for (const name of targets) pairs.push({ name, source });
            }
            continue;
        }
        const eqs = assignAt(line);
        if (eqs.length === 0)
            continue;
        // JS 的声明关键字不是名字：`const src = process.argv[2]` 剥掉 const／let／var，
        // 否则左值段变成 `const src` 两个记号，被当成「不像名字」整条丢掉。
        const head = line[0].t === 'id' && (line[0].v === 'const' || line[0].v === 'let' || line[0].v === 'var')
            ? line.slice(1) : line;
        const shift = head === line ? 0 : 1;
        // 链式 `a = b = sys.argv[1]`：最右等号之后是来源，前面每一段都是目标。
        const source = head.slice(eqs[eqs.length - 1] + 1 - shift);
        const segments = [];
        let from = 0;
        for (const eq of eqs) {
            segments.push(head.slice(from, eq - shift));
            from = eq + 1;
        }
        const targetSegs = segments.flatMap(seg => splitTop(seg));
        const names = targetSegs.flatMap(seg => namesOf(seg));
        if (names.length === 0)
            continue;
        const values = splitTop(source);
        // `const [src, out] = process.argv.slice(2)`：多值来源，按位置依次对位。
        const sliceStart = names.length > 1 ? sliceStartOf(source, spec) : null;
        if (sliceStart !== null && sliceStart >= 1) {
            for (let at = 0; at < names.length; at += 1)
                pairs.push({ name: names[at], keys: [sliceStart + at] });
        }
        else if (values.length === names.length && values.length > 1) {
            for (let at = 0; at < names.length; at += 1)
                pairs.push({ name: names[at], source: values[at] });
        }
        else {
            for (const name of names) pairs.push({ name, source });
        }
    }
    // 闭包迭代：先算别名，再拿别名重算后面的对——顺序不影响结果（先用后赋值也追得到）。
    const alias = new Map();
    for (const pair of pairs) {
        if (alias.has(pair.name) === false)
            alias.set(pair.name, new Set());
    }
    // 形参没有赋值语句，但也是「参数流的一个落点」：先给空桶，等调用处往里灌。
    for (const params of defs.values())
        for (const name of params)
            if (alias.has(name) === false)
                alias.set(name, new Set());
    const sites = lines.flatMap(line => callSites(line));
    let changed = true;
    let rounds = 0;
    while (changed === true && rounds < 8) {
        changed = false;
        rounds += 1;
        for (const pair of pairs) {
            const got = pair.keys === undefined
                ? pathSources(pair.source, spec, alias)
                : new Set(pair.keys);
            const bucket = alias.get(pair.name);
            for (const key of got)
                if (bucket.has(key) === false) {
                    bucket.add(key);
                    changed = true;
                }
        }
        // 函数实参 → 形参：`def f(src)` 被 `f(sys.argv[1])` 调用时，src 也来自第 1 个参数。
        for (const site of sites) {
            const params = defs.get(site.name);
            if (params === undefined)
                continue;
            for (let at = 0; at < site.args.length && at < params.length; at += 1) {
                const got = pathSources(site.args[at], spec, alias);
                const bucket = alias.get(params[at]);
                if (bucket === undefined)
                    continue;
                for (const key of got)
                    if (bucket.has(key) === false) {
                        bucket.add(key);
                        changed = true;
                    }
            }
        }
    }
    for (let at = 0; at < tokens.length; at += 1) {
        const direct = spec.argvAt(tokens, at);
        if (direct !== null && direct.key >= 1) {
            table.positions.add(direct.key);
            at += direct.len - 1;
        }
    }
    for (const [name, keys] of alias)
        if (name !== '' && keys.size > 0)
            for (const key of keys)
                if (key >= 1)
                    table.positions.add(key);
    for (const site of sites) {
        const argSources = sourcesOf(site.args.flat(), spec.argvAt, alias);
        applyCall(site, argSources, table, spec);
        if (site.receiver.length > 0) {
            const receiverSources = sourcesOf(site.receiver, spec.argvAt, alias);
            if (spec.recvWrite !== undefined && spec.recvWrite.has(site.name))
                for (const key of receiverSources) table.write.add(key);
            if (spec.recvRead !== undefined && spec.recvRead.has(site.name))
                for (const key of receiverSources) table.read.add(key);
        }
    }
    const roles = new Map();
    for (const at of table.positions) {
        if (at < 1)
            continue;
        if (table.write.has(at))
            roles.set(at, 'write');
        else if (table.read.has(at))
            roles.set(at, 'read');
        else
            roles.set(at, 'unknown');
    }
    return roles;
}

const PY_SPEC = {
    argvAt: pythonArgv, argvOwner: 'sys', openMode: true, sliceKey: n => n,
    read: PY_READ, write: PY_WRITE, recvRead: PY_RECV_READ, recvWrite: PY_RECV_WRITE,
};
const ND_SPEC = {
    argvAt: nodeArgv, argvOwner: 'process', openMode: false, sliceKey: n => n - 1,
    read: ND_READ, write: ND_WRITE,
};

function pythonArgRoles(text) {
    return flowRoles(text, PY_SPEC);
}

function nodeArgRoles(text) {
    return flowRoles(text, ND_SPEC);
}

function shellArgRoles(text) {
    const roles = new Map();
    // `$@`／`$*` 展开成一串，判不出对位——整段不判。
    if (/\$[@*]/.test(text))
        return roles;
    const refs = new Set();
    let hit;
    const refRe = /\$(?:\{)?([1-9])(?:\})?/g;
    while ((hit = refRe.exec(text)) !== null)
        refs.add(Number(hit[1]));
    for (const at of refs) {
        const ref = `\\$(?:\\{)?${at}(?:\\})?(?![0-9])`;
        const write = new RegExp(`(?:>>?\\s*["']?${ref})`
            + `|(?:\\b(?:rm|unlink|mv|cp|tee|truncate|touch|chmod)\\b[^\\n]*${ref})`
            + `|(?:\\bsed\\s+-i[^\\n]*${ref})`);
        const read = new RegExp(`\\b(?:cat|head|tail|wc|grep|rg|awk|sort|uniq|cut|file|stat|md5sum|sha256sum|less|more|sed)\\b[^\\n]*${ref}`);
        if (write.test(text))
            roles.set(at, 'write');
        else if (read.test(text))
            roles.set(at, 'read');
        else
            roles.set(at, 'unknown');
    }
    return roles;
}

/**
 * 分析一个解释器脚本的参数位语义。
 * @param {{ program: string, text: string, hasFlags?: boolean }} input
 * @returns {Map<number, 'read'|'write'|'unknown'>|null} null＝这一种不判（调用方保持原样）
 */
export function analyzeScriptArgs({ program, text, hasFlags = false }) {
    const name = String(program ?? '').toLowerCase();
    const known = PYTHON.has(name) || NODE.has(name) || SHELL.has(name);
    if (known === false)
        return null;
    // 带旗标的段不判：解释器旗标、脚本旗标、旗标取值都混在参数流里，位置对不齐，
    // 判错方向就是把写当读。宁可交回原来的保守处理。
    if (hasFlags === true)
        return null;
    if (String(text ?? '').trim() === '')
        return null;
    if (PYTHON.has(name))
        return pythonArgRoles(String(text));
    if (NODE.has(name))
        return nodeArgRoles(String(text));
    return shellArgRoles(String(text));
}
