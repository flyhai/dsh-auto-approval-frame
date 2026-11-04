// L0 command facts: tokenize a shell line into segments, words and redirects.
// This plane produces OPERANDS ONLY — it never returns a verdict. Anything it
// cannot resolve to a literal it marks `opaque`, and the grant layer decides.

const SEPARATORS = new Set([';', '&&', '||', '|', '&', '\n']);
const REDIRECT_OPS = /^(\d*)(?:>>|>&|<|>|>)/;

/** Skip leading blanks, then one non-blank run. Returns the index after it. */
function skipToken(command, from) {
    let i = from;
    while (i < command.length && /\s/.test(command[i]))
        i += 1;
    while (i < command.length && !/\s/.test(command[i]))
        i += 1;
    return i;
}

/** * Read a heredoc delimiter: quoted (`<<'SEG'`) or bare (`<<SEG`), stopping at shell syntax.
 * `quoted` 是判据的一部分：引号定界符＝正文原样喂给程序；**未引用**定界符的正文仍会做
 * 参数／命令替换（`$(…)`、反引号），不能整体当纯数据（A01）。
 */
function readDelimiter(command, from) {
    let i = from;
    while (i < command.length && /[ \t]/.test(command[i]))
        i += 1;
    const quote = command[i];
    if (quote === "'" || quote === '"') {
        const end = command.indexOf(quote, i + 1);
        if (end === -1)
            return { value: '', next: command.length, quoted: true };
        return { value: command.slice(i + 1, end), next: end + 1, quoted: true };
    }
    const match = /^[^\s;|&)<]+/.exec(command.slice(i));
    if (match === null)
        return { value: '', next: i, quoted: false };
    return { value: match[0], next: i + match[0].length, quoted: false };
}

/** * Consume a here-document body, marker included, and return the index to
 * continue scanning from, plus the body text itself.
 *
 * The body is *data*, not commands: without this every line of
 * `python x <<'SEG' … SEG` arrives as its own segment, so prose words
 * (`HTML token`), table pipes and the delimiter itself get resolved as file
 * paths — and one word named `token` drags the whole call onto the credential
 * floor (真机 seq229：`grant=never`，四条理由里没一条说明危险在哪).
 * An unterminated body runs to end of input: the shape is unknown, but the
 * dropped text still was never executed, so no operands are invented.
 * 正文文本要留出来：未引用定界符时它里面的 `$(…)`／反引号**会执行**（A01）。
 */
function heredocEnd(command, delimiter, afterDelimiter) {
    if (delimiter === '')
        return { end: afterDelimiter, body: '' };
    const lineEnd = command.indexOf('\n', afterDelimiter);
    if (lineEnd === -1)
        return { end: command.length, body: '' };
    let cursor = lineEnd + 1;
    for (const line of command.slice(cursor).split('\n')) {
        // 定界符是**整行相等**，不是前缀：`SEG_MORE` 是正文，认成终止符会把后面几行
        // 放出来当命令扫（凭空造段与操作数）。`<<-` 形式允许前导制表符。
        if (line.replace(/\r$/, '').replace(/^\t+/, '') === delimiter)
            return { end: cursor + line.length + 1, body: command.slice(lineEnd + 1, cursor) };
        cursor += line.length + 1;
    }
    return { end: command.length, body: command.slice(lineEnd + 1) };
}

/** `$(…)`／反引号里的命令文本：未引用定界符的 heredoc 正文里它们会真的被执行。 */
export function commandSubstitutions(text) {
    const out = [];
    let i = 0;
    while (i < text.length) {
        if (text[i] === '$' && text[i + 1] === '(') {
            let depth = 1;
            let j = i + 2;
            while (j < text.length && depth > 0) {
                if (text[j] === '(')
                    depth += 1;
                else if (text[j] === ')')
                    depth -= 1;
                j += 1;
            }
            if (depth === 0)
                out.push(text.slice(i + 2, j - 1));
            i = j;
            continue;
        }
        if (text[i] === '`') {
            const end = text.indexOf('`', i + 1);
            if (end === -1) {
                i += 1;
                continue;
            }
            out.push(text.slice(i + 1, end));
            i = end + 1;
            continue;
        }
        i += 1;
    }
    return out;
}

/** * 内联代码（`python -c`／`node -e`／`perl -e`／`ruby -e`／`powershell -Command`）里的读**与写**动作。
 * 代码本体**不是路径**：旧形把它当一个普通操作数折进目标集，于是凭空造出一条
 * `…\print(open(r'…\.env').read)` 形状的工作区假目标（31 实测），而真正被读的 `.env`
 * 反而不在读面上——同一份凭据，`cat` 落人工、`python -c` 落交模型。
 * 35 补对面那一半：`open(...,'w')`／`writeFileSync`／`Set-Content` 以前**整个看不见**
 * （targets=[] ⇒ 交模型），而同一份区外 `.env` 走 `echo >` 落人工——写比读更该严。
 * 这一层只按语法抠**字面量实参**，不判档、不认变量与模板串；抠不出的那一半由事实层
 * 如实标不透明（「没解析出目标」不等于「没有风险」）。
 */
// 读类调用名（点号末段归一：`io.open`→open／`fs.readFileSync`→readfilesync／`File.read`→read）。
// `Path('x').read_text` 的动作在括号**之后**，所以方法名单与调用名单同一把尺（method 侧也查这张表）。
const CODE_READ_NAMES = new Set([
    'open', 'io_open', 'read', 'readline', 'readlines', 'read_text', 'read_bytes', 'readalltext',
    'readallbytes', 'read_file', 'fileread', 'slurp', 'binread', 'sysread', 'file', 'file_get_contents',
    'fopen', 'io_lines', 'run_path', 'exists', 'existssync', 'is_file', 'is_dir', 'stat', 'lstat',
    'statsync', 'lstatsync', 'getsize', 'readfilesync', 'readfile', 'createreadstream', 'opensync',
    'readdirsync', 'opendirsync',
]);
// 写出类调用名：**第一个**位置实参就是要被写的那个文件（`writeFileSync(p,data)` 的数据在后一个实参位）。
// 光看末段的 `write` 不在这里：`f.write('x')` 的实参是内容不是路径，只有带命名空间的
// `File.write(p,…)`／`IO.write(p,…)` 才把路径放在第一位，所以另按 CODE_WRITE_QUALIFIED_HEADS 认。
const CODE_WRITE_NAMES = new Set([
    'writefilesync', 'writefile', 'appendfilesync', 'appendfile', 'createwritestream',
    'file_put_contents', 'write_text', 'write_bytes',
]);
const CODE_WRITE_QUALIFIED_HEADS = new Set(['file', 'io', 'pathname', 'sys', 'tempfile']);
// 打开类名：这一站是读还是写由**模式／方向实参**决定（`open(p,'w')`／`open($fh,'>',$p)`／`fopen(p,'a')`）。
// `popen`／`subprocess` 不在列：它们的第一个实参是**命令**不是路径，折成目标就是凭空造路径。
const CODE_OPEN_NAMES = new Set(['open', 'fopen', 'io_open', 'file', 'opensync', 'sysopen']);
// 拷贝／移动名：最后一个是**目的**（写），前面的是源（读）——与 `cp src dst` 同一把尺（判据 2c）。
// 只认无歧义的名字：`replace`／`copy`／`move` 光看末段会撞上 `'a'.replace('x','y')` 这种字符串方法，
// 于是凭空造出一条写面，所以带命名空间的写法按**全名**收。
const CODE_COPY_NAMES = new Set(['copyfile']);
const CODE_COPY_FULLNAMES = new Set(['shutil.copy', 'shutil.copy2', 'shutil.copyfile', 'shutil.move',
    'os.rename', 'os.replace', 'fileutils.cp', 'fileutils.mv']);
// 模式／方向实参：`open(p, 'rb')` 的 `'rb'`、perl `open($fh, '<', $p)` 的 `'<'` 都不是路径。
// 带写出位的模式（w／a／x／＋）与 `>`／`>>` 都不算读面——这段代码在写那个文件，事实层不替它冒充「只是读」。
const CODE_MODE_ARG = /^[rwbax+]{1,3}t?$/;
const CODE_DIRECTION_ARG = /^[<>]{1,2}$/;
// 路径构造器：它自己的实参是路径，读动作写在括号**之后**（`Path('x').read_text`）。
// 只有这张表里的名字才允许靠 method 认站——否则 `require('fs').readFileSync(p)` 会把
// 模块名 `'fs'` 也记成一条读面（凭空造目标）。
const CODE_PATH_CONSTRUCTORS = new Set(['path', 'stringio', 'bytesio', 'tempfile', 'nametmpfile']);
// PowerShell 的读侧命令名与「取值是路径」的旗标（`Get-Content 'x'`／`Select-String -Path 'x' -Pattern 'y'`）。
// 别名与 canonical 名都在 PROGRAM_ALIASES 归一过，这里只补代码串内部的写法。
const PS_READ_CMDLETS = new Set(['get-content', 'gc', 'cat', 'type', 'get-item', 'gi', 'select-string',
    'sls', 'stringmatch', 'import-csv', 'import-clixml', 'get-filehash', 'get-childitem', 'gci', 'ls', 'dir']);
// 写侧命令名：`-Path`／`-LiteralPath`／`-FilePath` 的取值与第一个位置实参都是**被写的那个文件**。
const PS_WRITE_CMDLETS = new Set(['set-content', 'sc', 'add-content', 'ac', 'out-file', 'set-item', 'si',
    'new-item', 'ni', 'clear-content', 'clc']);
// 拷贝／移动命令名：`-Path` 是源、`-Destination` 是目的；位置形 `Copy-Item a b` 的最后一个才是目的。
const PS_COPY_CMDLETS = new Set(['move-item', 'mi', 'mv', 'copy-item', 'cpi', 'cp']);
const PS_PATH_FLAGS = new Set(['path', 'literalpath', 'filepath']);
const PS_DEST_FLAGS = new Set(['destination', 'destinationpath']);
// 这些旗标的取值是模式／编码／条数，不是文件——不收进读面，否则 `Select-String -Pattern 'a/b'`
// 会被当成读了一个叫 a/b 的文件（判据 2 的形状：别把非路径的字面量折成路径）。
const PS_VALUE_FLAGS = new Set(['pattern', 'encoding', 'delimiter', 'totalcount', 'tail', 'head',
    'credential', 'erroraction', 'warningaction', 'ea', 'wa', 'filter', 'include', 'exclude', 'depth']);
// `-Value` 的后面整段是**内容**（`Set-Content -Path x -Value 一串`），不是路径：扫到它就收手。
// 开关旗标（`-Force`／`-PassThru`）不在这张表里，也不在这一步收手——它们后面还能跟路径。
const PS_STOP_FLAGS = new Set(['value', 'values', 'property', 'content', 'inputobject']);
// ── 36：删除面 ────────────────────────────────────────────────────────────────
// 删除类调用名：第一个位置实参是**被删掉的那个东西**。
// 裸 `remove`／`delete`／`rm` 不在这一张表里——`s.remove('x')`、`table.remove(t,'x')` 的实参
// 是集合成员不是路径，与 35 不认裸 `write` 同一条理由（别凭空造目标）。
const CODE_DELETE_NAMES = new Set(['unlink', 'unlinksync', 'rmtree', 'rmsync', 'removedirs',
    'rmdir', 'deletefile', 'removefile', 'rm_rf', 'rm_r', 'delete_on_close']);
const CODE_DELETE_AMBIGUOUS = new Set(['remove', 'delete', 'rm']);
// 歧义名只在**限定名**上算，且紧邻的那一段得是文件系统命名空间：
// `os.remove`／`File.delete`／`IO.File::Delete`／`System.IO.Directory.Delete` 成立，`table.remove` 不成立。
const CODE_DELETE_QUALIFIED_HEADS = new Set(['os', 'file', 'io', 'fs', 'filesystem', 'shutil',
    'tempfile', 'dir', 'directory', 'folder', 'pathname', 'path', 'unix', 'boost']);
// 整树删除名：这一站销毁的是**目录里的全部内容**，不是一条条目——形状与 `rm -rf 目录` 对照。
const CODE_TREE_DELETE_NAMES = new Set(['rmtree', 'removedirs', 'rm_rf', 'rm_r']);
// `fs.rmSync(p,{recursive:true})`／`rmSync(p)` 同名不同形：递归要由**选项实参**说，不由名字说。
const RECURSIVE_OPTION = /\brecursive\s*:\s*(?:true|!0)\b/i;
// PowerShell 的删除命令名与别名（`del`／`erd`／`rd` 是 Remove-Item 的既有别名）。
const PS_DELETE_CMDLETS = new Set(['remove-item', 'ri', 'del', 'erase', 'rmdir', 'rd', 'remove-item']);
// `-Recurse`（含 `-r`／`-rec` 简写）把目录删除升级成整树删除。
const PS_RECURSE_FLAG = /^r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$/i;

/** 括号配对（跳过引号里的括号）：`open("(")` 不该把里面那对当成边界。取不到闭合 ⇒ 整段按不透明算。 */
function matchingParen(text, openAt) {
    let depth = 0;
    for (let i = openAt; i < text.length; i += 1) {
        const char = text[i];
        if (char === "'" || char === '"') {
            const end = text.indexOf(char, i + 1);
            i = end === -1 ? text.length : end;
            continue;
        }
        if (char === '\\') { i += 1; continue; }
        if (char === '(') depth += 1;
        else if (char === ')') {
            depth -= 1;
            if (depth === 0) return i;
        }
    }
    return -1;
}

/** * 一段文本里的字符串字面量（带位置）：认 `'…'`／`"…"`。
 * 位置要留着——「这个字面量是第几个实参、前面有没有变量、后面有没有拼接」决定它能不能当读面。
 */
function codeStringLiterals(text) {
    const out = [];
    for (let i = 0; i < text.length; i += 1) {
        const quote = text[i];
        if (quote !== "'" && quote !== '"')
            continue;
        let value = '';
        let j = i + 1;
        for (; j < text.length; j += 1) {
            const char = text[j];
            if (char === '\\' && j + 1 < text.length) {
                const escaped = text[j + 1];
                // 只解「会吃掉反斜杠」的那两种：`\'`／`\"` 与 `\\`。
                // `\t`／`\n` 一律原样留着：Windows 路径写成 `C:\t31\x` 时那是目录名，
                // 当成转义会把真实读面抠成一条带制表符的假路径（31 实测）。
                if (escaped === quote || escaped === '\\') { value += escaped; j += 1; continue; }
                value += char;
                continue;
            }
            if (char === quote)
                break;
            value += char;
        }
        if (j < text.length) {
            out.push({ value, at: i, end: j });
            i = j;
        }
    }
    return out;
}

/** 调用点：`名字(` ＋括号区域＋紧跟的 `.method`。嵌套调用不跳过（内层自己也是一个调用点）。 */
function codeCallSites(text) {
    const sites = [];
    for (let i = 0; i < text.length; i += 1) {
        if (!/[A-Za-z_.]/.test(text[i]))
            continue;
        let end = i;
        while (end < text.length && /[A-Za-z0-9_.:]/.test(text[end]))
            end += 1;
        let open = end;
        while (open < text.length && /[ \t]/.test(text[open]))
            open += 1;
        if (text[open] !== '(') { i = end - 1; continue; }
        const close = matchingParen(text, open);
        if (close === -1) { i = end - 1; continue; }
        let after = close + 1;
        while (after < text.length && /[ \t]/.test(text[after]))
            after += 1;
        let method = '';
        if (text[after] === '.') {
            after += 1;
            let stop = after;
            while (stop < text.length && /[A-Za-z0-9_]/.test(text[stop]))
                stop += 1;
            method = text.slice(after, stop).toLowerCase();
        }
        // `[IO.File]::Delete(p)` 这一形：标识符自己从 `D` 起（`[` 不是标识符字符），
        // 于是限定名被切成两段，`IO.File` 那半丢了。把方括号里的类型名接回名字上，
        // 一个调用点仍只产出**一个** site（不补第二站，否则读面会重复计数）。
        const dotNet = /\]\s*::\s*$/.test(text.slice(0, i))
            ? /\[([\w.]+)\]\s*::\s*$/.exec(text.slice(0, i)) : null;
        const name = (dotNet === null ? '' : `${dotNet[1].toLowerCase()}.`)
            + text.slice(i, end).toLowerCase();
        sites.push({ name, args: text.slice(open + 1, close), method });
        i = end - 1;
    }
    return sites;
}

/** * PowerShell 命令串：命令名后面的位置参数＋`-Path`／`-LiteralPath`／`-FilePath`／`-Destination` 的取值。
 * 读写按命令名分桶：`Get-Content` 的取值是读面，`Set-Content` 同一样子是写面，
 * `Remove-Item` 同一样子是**删除面**（36 判据 1）；
 * `Copy-Item a b`／`Move-Item a b` 的**最后一个**位置实参才是目的（与 `cp` 同一把尺）。
 * 整树与否由 `-Recurse` 说（`Remove-Item -LiteralPath d -Recurse`＝目录整体销毁，与 `rm -rf d` 对照）。
 */
function powerShellEffects(text) {
    const reads = [];
    const writes = [];
    const deletes = [];
    let calls = 0;
    const specs = [
        ...Array.from(PS_READ_CMDLETS, name => ({ name, write: false, copy: false, del: false })),
        ...Array.from(PS_WRITE_CMDLETS, name => ({ name, write: true, copy: false, del: false })),
        ...Array.from(PS_COPY_CMDLETS, name => ({ name, write: true, copy: true, del: false })),
        ...Array.from(PS_DELETE_CMDLETS, name => ({ name, write: false, copy: false, del: true })),
    ];
    for (const spec of specs) {
        const pattern = new RegExp(`(?<![\\w.-])${spec.name.replace(/[-]/g, '\\-')}(?![\\w-])`, 'gi');
        for (const match of text.matchAll(pattern)) {
            // 赋值给一个恰好叫删除别名的变量（`$del = 一个路径`）不是「删那个文件」：
            // 只给删除桶加这条前缀检查——读／写桶是 31／35 已交付的口径，不动。
            if (spec.del === true && match.index > 0 && text[match.index - 1] === '$')
                continue;
            calls += 1;
            const stop = /[;|\n\r}&]/.exec(text.slice(match.index + match[0].length));
            const region = text.slice(match.index + match[0].length,
                stop === null ? text.length : match.index + match[0].length + stop.index);
            const words = regionTokens(region);
            const positional = [];
            const pathFlags = [];
            let destination = '';
            let recurse = false;
            for (let at = 0; at < words.length; at += 1) {
                const token = words[at];
                if (token.startsWith('-')) {
                    const flag = token.slice(1).toLowerCase().split(':')[0];
                    if (PS_STOP_FLAGS.has(flag))
                        break;
                    if (spec.del === true && PS_RECURSE_FLAG.test(flag))
                        recurse = true;
                    if (PS_DEST_FLAGS.has(flag) && words[at + 1] !== undefined) {
                        destination = words[at + 1];
                        at += 1;
                    }
                    else if (PS_PATH_FLAGS.has(flag) && words[at + 1] !== undefined) {
                        pathFlags.push(words[at + 1]);
                        at += 1;
                    }
                    else if (PS_VALUE_FLAGS.has(flag))
                        at += 1;
                    continue;
                }
                positional.push(token);
            }
            for (const value of pathFlags) {
                if (spec.del === true) deletes.push({ path: value, tree: recurse });
                else if (spec.write === true && spec.copy === false) writes.push(value);
                else reads.push(value);
            }
            if (spec.copy === true) {
                for (const item of positional.slice(0, -1))
                    reads.push(item);
                if (positional.length > 1)
                    writes.push(positional[positional.length - 1]);
                if (destination !== '')
                    writes.push(destination);
                continue;
            }
            if (spec.del === true) {
                for (const item of positional)
                    deletes.push({ path: item, tree: recurse });
                continue;
            }
            if (positional.length > 0) {
                if (spec.write === true) writes.push(positional[0]);
                else reads.push(positional[0]);
            }
        }
    }
    return { reads, writes, deletes, calls };
}

/** * 代码串**内部**的重定向（36 判据 2）：`Get-Content x > out.txt` 里那个 out 是被写的东西。
 * 以前整条只看得见读面——同一份区外文件，`powershell -Command "… > f"` 比 `> f` 少一格效果。
 * 只认引号外的 `>`／`>>`／`2>`／`2>>`；`2>&1` 是并流不是写；`1>` 这类带号的先剥掉。
 * 目的取不到字面量（变量／模板／截断）⇒ 交上层按不透明算，不猜。
 */
function powerShellRedirects(text) {
    const writes = [];
    let unresolved = 0;
    for (let i = 0; i < text.length; i += 1) {
        const char = text[i];
        if (char === "'" || char === '"') {
            const end = text.indexOf(char, i + 1);
            i = end === -1 ? text.length : end;
            continue;
        }
        if (char === '\\') { i += 1; continue; }
        if (char !== '>')
            continue;
        // 号在前是**文件描述符**（`2>` 写错误流、`1>>` 追加）不是另一个符号：先剥掉数字再看前一个字符。
        // 前面是 `>`（那是 `>>` 的后半）／`&`（并流 `1>&2`）／`|`／`<` ⇒ 这一处不是写目的。
        let back = i;
        while (back > 0 && /\d/.test(text[back - 1]))
            back -= 1;
        const prev = back > 0 ? text[back - 1] : '';
        if (prev !== '' && /[>&|<]/.test(prev))
            continue;
        const double = text[i + 1] === '>';
        const take = text.slice(double ? i + 2 : i + 1);
        if (/^\s*&/.test(take))
            continue;
        const gap = /^\s*/.exec(take)[0].length;
        const tail = take.slice(gap);
        const quote = tail[0];
        if (quote === "'" || quote === '"') {
            const end = tail.indexOf(quote, 1);
            if (end === -1) { unresolved += 1; continue; }
            const value = tail.slice(1, end);
            if (/[$`{]/.test(value) === false && value.trim() !== '') writes.push(value);
            else unresolved += 1;
            i = i + 1 + (double ? 1 : 0) + gap + end;
            continue;
        }
        const token = /^[^\s;|&)<>]+/.exec(tail);
        if (token === null || token[0] === '') { unresolved += 1; continue; }
        if (/[$`{]/.test(token[0]) === false) writes.push(token[0]);
        else unresolved += 1;
        i = i + 1 + (double ? 1 : 0) + gap + token[0].length - 1;
    }
    return { writes, unresolved };
}

/** PowerShell 区域的词：带引号的取字面量内容，不带的按空白切；变量（`$x`）与模板原样留着，由上层判不成路径。 */
function regionTokens(region) {
    const out = [];
    for (let i = 0; i < region.length; i += 1) {
        const char = region[i];
        if (/\s/.test(char))
            continue;
        if (char === "'" || char === '"') {
            const end = region.indexOf(char, i + 1);
            out.push(end === -1 ? region.slice(i + 1) : region.slice(i + 1, end));
            i = end === -1 ? region.length : end;
            continue;
        }
        let end = i;
        while (end < region.length && !/[\s'"]/.test(region[end]))
            end += 1;
        out.push(region.slice(i, end));
        i = end - 1;
    }
    return out;
}

/** * 调用点方言（python／node／perl／ruby／php／lua）：`名字( 字面量… )` 的位置实参，按读／写分桶。
 * 一个调用点只取**第一个**像路径的实参（`writeFileSync(p,data)` 的 data、`readFileSync(p,'utf8')`
 * 的编码都不算目标）；拷贝／移动取**最后一个**当目的。
 */
function callSiteEffects(text) {
    const sites = codeCallSites(text);
    const reads = [];
    const writes = [];
    const deletes = [];
    let unresolved = 0;
    for (const site of sites) {
        const parts = site.name.split(/[.:]+/).filter(part => part !== '');
        const tail = parts[parts.length - 1];
        const head = parts[0];
        const before = parts[parts.length - 2] ?? '';
        const qualified = site.name.includes('.') || site.name.includes('::');
        const onPathObject = CODE_PATH_CONSTRUCTORS.has(tail);
        const isOpen = CODE_OPEN_NAMES.has(tail) || (onPathObject && CODE_OPEN_NAMES.has(site.method));
        const isRead = CODE_READ_NAMES.has(tail) || (onPathObject && CODE_READ_NAMES.has(site.method));
        // 裸 `write` 的实参是**内容**（`f.write('x')`）：只有带命名空间的 `File.write(p,…)`
        // ／`IO.write(p,…)` 才把路径放在第一位。
        const isWrite = CODE_WRITE_NAMES.has(tail) || (onPathObject && CODE_WRITE_NAMES.has(site.method))
            || (tail === 'write' && qualified === true && CODE_WRITE_QUALIFIED_HEADS.has(head));
        const isCopy = CODE_COPY_NAMES.has(tail) || CODE_COPY_FULLNAMES.has(site.name);
        // 删除站（36 判据 1）：名字自己说（`os.remove`／`File.delete`——歧义名要求紧邻的那一段
        // 是文件系统命名空间），或写在路径对象**之后**（`Path(p).unlink`／`Path(p).rmdir`）。
        const isDelete = CODE_DELETE_NAMES.has(tail)
            || (onPathObject && CODE_DELETE_NAMES.has(site.method))
            || (CODE_DELETE_AMBIGUOUS.has(tail) && qualified === true && CODE_DELETE_QUALIFIED_HEADS.has(before));
        if (isOpen === false && isRead === false && isWrite === false && isCopy === false && isDelete === false)
            continue;
        const args = codeStringLiterals(site.args);
        const mode = args.find(item => CODE_MODE_ARG.test(item.value.trim()));
        const direction = args.find(item => CODE_DIRECTION_ARG.test(item.value.trim()));
        // 写这一站的三种形：拷贝／移动的目的、写出名、打开名＋写出模式（`open(p,'w')`）
        // 或写出方向（perl `open($fh,'>',$p)`）。这一段在动那个文件，不替它冒充「只是读」。
        const writing = isCopy === true || isWrite === true
            || (isOpen === true && ((mode !== undefined && /[wax+]/.test(mode.value.trim()))
                || (direction !== undefined && direction.value.trim().startsWith('>') === true)));
        // 第一个既非模式又非方向的位置实参才是被打开的那个数（`fs.readFileSync(p,'utf8')`
        // 的 `'utf8'` 是编码，收进读面就是一条不存在的路径）。
        const paths = args.filter(item => {
            const value = item.value.trim();
            return value !== '' && CODE_MODE_ARG.test(value) === false && CODE_DIRECTION_ARG.test(value) === false;
        });
        // 路径是运行时拼出来的（f-string／模板串／`+`／`%`）⇒ 半截字符串不是效果：
        // 按「抠不出」交事实层标不透明（判据 2），别拿它凑一个目标数。
        const resolvable = (item) => {
            if (item === undefined)
                return false;
            const pre = site.args.slice(site.args.lastIndexOf(',', item.at - 1) + 1, item.at);
            const post = site.args.slice(item.end + 1).trimStart();
            if (argDepth(site.args, item.at) > 0)
                return false;
            return /[{}]/.test(item.value) === false && /^[+%*]/.test(post) === false
                && /[$`]/.test(pre) === false && site.args.includes('`') === false;
        };
        if (isCopy === true) {
            for (const item of paths.slice(0, -1)) {
                if (resolvable(item) === false) unresolved += 1;
                else reads.push(item.value);
            }
            const destination = paths[paths.length - 1];
            if (resolvable(destination) === false) unresolved += 1;
            else writes.push(destination.value);
            continue;
        }
        const candidate = paths[0];
        if (resolvable(candidate) === false) {
            unresolved += 1;
            continue;
        }
        // 整树（判据 3 的形状）：名字自己说（`rmtree`／`removedirs`／`rm_rf`），
        // 或选项实参说（`rmSync(p,{recursive:true})`）。同名不带递归就不是整树（`rmSync(p)`）。
        const tree = isDelete === true && (CODE_TREE_DELETE_NAMES.has(tail)
            || CODE_TREE_DELETE_NAMES.has(site.method) || RECURSIVE_OPTION.test(site.args));
        if (isDelete === true) deletes.push({ path: candidate.value, tree });
        else if (writing === true) writes.push(candidate.value);
        else reads.push(candidate.value);
    }
    return { reads, writes, deletes, calls: sites.length, unresolved };
}

/** * 字面量在实参区域里的嵌套深度：>0 说明它是**另一个调用的实参**
 * （`writeFileSync(path.join(dir,'.env'),…)` 里的 `'.env'`）。那种路径要运行时才算得出来，
 * 与 `'/x/'+n` 同一类（判据 2 的「运行时拼接」），不许折成一条以 cwd 为基的假目标。
 */
function argDepth(region, at) {
    let depth = 0;
    for (let i = 0; i < at; i += 1) {
        const char = region[i];
        if (char === "'" || char === '"') {
            const end = region.indexOf(char, i + 1);
            i = end === -1 ? region.length : end;
            continue;
        }
        if (char === '\\') { i += 1; continue; }
        if (/[([{]/.test(char)) depth += 1;
        else if (/[)\]}]/.test(char)) depth -= 1;
    }
    return depth;
}

/** * 内联代码的读面、写面与**删除面**。`dialect`＝`'powershell'` 走命令名＋旗标那套（`.NET` 静态调用
 * 与串内重定向同收），其余走调用点那套。返回的 `reads`／`writes`／`deletes[].path` 是**字面量实参原文**
 * ——相对路径按解释器的 cwd 换算，那一步归事实层；`unparsed` 告诉事实层「这份清单可能不全」。
 * 内联代码永远有不透明的一格（代码里的变量与拼接抠不出来），所以抠到了也不免除举证：
 * `unparsed` 只按**读面**算（写面／删除面抠得出来也不把它翻成「清单完整」），保持 31 那一半口径不动。
 * `deletes[].tree` 只说「整树」，不说目标是文件还是目录——目录身份归事实层的 `lstat`。
 */
export function inlineCodeEffects(code, dialect = 'call') {
    const text = String(code ?? '');
    if (text.trim() === '')
        return { reads: [], writes: [], deletes: [], calls: 0, unparsed: true };
    const honest = list => list.filter(item => item.trim() !== '' && item.startsWith('$') === false);
    const honestDel = list => list.filter(item => item.path.trim() !== '' && item.path.startsWith('$') === false);
    if (dialect === 'powershell') {
        const shell = powerShellEffects(text);
        const net = callSiteEffects(text);
        const redir = powerShellRedirects(text);
        const reads = [...honest(shell.reads), ...net.reads];
        const writes = [...honest(shell.writes), ...net.writes, ...honest(redir.writes)];
        const deletes = [...honestDel(shell.deletes), ...net.deletes];
        return { reads, writes, deletes, calls: shell.calls + net.calls,
            unparsed: reads.length === 0 || /[$`]/.test(text) };
    }
    const { reads, writes, deletes, calls, unresolved } = callSiteEffects(text);
    // 一个调用点都没认出／一个读面都没抠出／代码里有运行时才定得下来的展开——
    // 都算「清单不完整」，事实层据此落不透明（判据 1②：不许按「没目标＝没风险」放行）。
    return { reads, writes, deletes, calls, unresolved, unparsed: calls === 0 || reads.length === 0 || /[$`]/.test(text) };
}

// 只有**未加引号**的展开字符才会在运行时变出别的值（B06／判据 5）：`grep '*'` 是
// 找星号这个字面量，`grep *` 才是通配；`echo 'a;b'` 里的分号同理不是段边界。
// 旧词法把引号连同信息一起剥掉，事实层只能看文本 ⇒ 字面量被当成展开、目标集被标 opaque。
const EXPANSION_CHARS = /[$`*?[\]{}]/;

/** Tokenize honoring 'single' / "double" quotes and backslash escapes. */
export function tokenize(command, meta) {
    const tokens = [];
    // 与 tokens 一一对应的「含未引用展开字符」标记；meta 在时随词法一起产出，
    // 供 splitSegments 判断某一段是否 opaque（默认 undefined＝保持旧行为）。
    const bares = [];
    let current = '';
    let has = false;
    let bare = false;
    let quote = '';
    const emit = (token, isBare) => {
        tokens.push(token);
        bares.push(isBare === true);
    };
    const resetWord = () => {
        current = '';
        has = false;
        bare = false;
    };
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
            else {
                // 双引号里 `$`／反引号仍会展开；`*`、`?`、`{}` 在双引号里是字面量。
                if (char === '$' || char === '`')
                    bare = true;
                current += char;
            }
            continue;
        }
        if (char === "'" || char === '"') {
            quote = char;
            has = true;
            continue;
        }
        // `\` ＋换行是**续行**（bash／cmd 的折行），不是转义内容。
        // 旧判据把它当一个普通转义字符吃掉，并把真正的 `\n` 收进词里；而 `\n` 本身就是
        // `SEPARATORS` 成员 ⇒ 这个词随即把命令行切成两段：下一行的 `--file …` 被当成
        // 新的「程序名」、末行的 `2>&1` 变成只有重定向的空段，两段各落一次兜底行
        // 「其他命令」，按最严合成后，用户对 `ds` 写的 release 行被架空。
        // 续行的语义是「这两个字符不存在」：直接跳过，不设 has、不产词。
        if (char === '\\' && (command[i + 1] === '\n' || (command[i + 1] === '\r' && command[i + 2] === '\n'))) {
            i += command[i + 1] === '\r' ? 2 : 1;
            continue;
        }
        if (char === '\\' && i + 1 < command.length) {
            // On Windows a backslash inside a drive path (`C:\Users\…`) or a UNC
            // prefix (`\\server\share`) is a separator, not a POSIX escape. It used
            // to be eaten, which turned `rm -f C:\ws\a.txt` into the literal token
            // `C:Usersa.txt` — then resolved as a bogus path *inside* the workspace,
            // so the wrong root hit and the wrong git state reached the reviewer.
            const windowsPath = /[A-Za-z]:$/.test(current) || current.includes('\\')
                || (current === '' && command[i + 1] === '\\')
                // 位置前缀也是路径，不是转义起点——`~\`（pwsh 的家）、
                // `$env:NAME\`、`%NAME%\` 后面那个反斜杠是分隔符。旧判据只认盘符／
                // 已含反斜杠／UNC 三种，于是 `$env:USERPROFILE\.ssh\config` 塌成
                // `$env:USERPROFILE.sshconfig`，目标整个看不见。
                // 只加这三形，不放开「任何反斜杠＝分隔符」：`$HOME\x` 那种 POSIX
                // 写法与 `\-`／`\ ` 转义一律保持原义，不改判据的另外两面。
                || current === '~'
                || current === '.' || current === '..'
                || /^[$]env:[A-Za-z_][A-Za-z0-9_]*$/.test(current)
                || /%[A-Za-z0-9_]+%$/.test(current);
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
        // A `#` that starts a word is a comment to end of line, and `<<` opens a
        // here-document / here-string. Neither is an operand — see skipHeredoc.
        if (char === '#' && !has) {
            const lineEnd = command.indexOf('\n', i);
            i = lineEnd === -1 ? command.length : lineEnd - 1;
            continue;
        }
        if (char === '<' && command[i + 1] === '<' && !has) {
            let j = i + 2;
            // `<<<word` 是一行内的 here-string：数据词跳过，同一行**后面**的部分回主循环
            // 继续解析，`grep -c x <<<"$in" > /tmp/out` 的写目标才不会被一起吃掉。
            if (command[j] === '<') {
                i = skipToken(command, j + 1) - 1;
                continue;
            }
            if (command[j] === '-')
                j += 1;
            const delimiter = readDelimiter(command, j);
            // 定界符**自己**不是操作数，但它同一行余下的部分是：旧写法整行跳走，
            // `cat <<'SQL' > /tmp/q.sql`、`cat <<'E' >> ~/.bashrc` 里那个写目标就
            // 整个消失了——框架看不见"往这个文件写"（F01 交付项，实测复现）。
            const lineEnd = command.indexOf('\n', i);
            const openerTail = lineEnd === -1
                ? command.slice(delimiter.next)
                : command.slice(delimiter.next, lineEnd);
            const openerMeta = {};
            const openerTokens = tokenize(openerTail, openerMeta);
            for (const [at, token] of openerTokens.entries())
                emit(token, openerMeta.bare?.[at] === true);
            const body = heredocEnd(command, delimiter.value, delimiter.next);
            // 正文留在**这一段**上：段边界与旧形完全一致（正文不成段），但类型
            // （引用／未引用）与正文本身要跟着走，好让事实层判断它是数据还是会执行。
            if (meta !== undefined && meta.heredocs !== undefined)
                meta.heredocs.push({ quoted: delimiter.quoted, value: delimiter.value, text: body.body });
            if (meta !== undefined && meta.marks !== undefined)
                emit({ heredoc: meta.heredocs.length - 1 }, false);
            const next = body.end;
            // 定界符那一行自己的换行被正文一起吃掉了；补回段边界，
            // 下一条命令不许落进这一段里。here-string 不换行，所以不补。
            if (lineEnd !== -1 && lineEnd < next)
                emit('\n', false);
            i = next - 1;
            continue;
        }
        if (char === '\n' || char === '\r' || char === ';') {
            if (has)
                emit(current, bare);
            resetWord();
            if (char === '\r')
                continue;
            emit('\n', false);
            continue;
        }
        if (/\s/.test(char)) {
            if (has)
                emit(current, bare);
            resetWord();
            continue;
        }
        if ((char === '>' || char === '<') && /^\d+$/.test(current)) {
            let op = `${current}${char}`;
            resetWord();
            if (op.endsWith('>') && command[i + 1] === '&') {
                op += '&';
                i += 1;
            }
            emit(op, false);
            continue;
        }
        if (char === '&' || char === '|' || char === '<' || char === '>') {
            if (has) {
                emit(current, bare);
                resetWord();
            }
            const pair = command[i + 1];
            if ((char === '&' || char === '|') && pair === char) {
                emit(`${char}${char}`, false);
                i += 1;
                continue;
            }
            if (char === '&' && pair === '>') {
                emit('&>', false);
                i += 1;
                continue;
            }
            if (char === '>' && pair === '&') {
                emit('>&', false);
                i += 1;
                continue;
            }
            // `>>` 是一个「追加到该文件」的操作符，不是两个重定向：拆开发的话第一个 `>`
            // 吃掉文件名、第二个把**下一条命令**当成重定向目标（F02 交付项）。
            if (char === '>' && pair === '>') {
                emit('>>', false);
                i += 1;
                continue;
            }
            emit(char, false);
            continue;
        }
        if (EXPANSION_CHARS.test(char))
            bare = true;
        current += char;
        has = true;
    }
    if (has || quote !== '')
        emit(current, bare);
    if (meta !== undefined && meta.bare === undefined)
        meta.bare = bares;
    return tokens;
}

/** * Whether a literal still expands at run time (so its target is unknowable).
 * `bare === false` 表示这些特殊字符全在引号／转义里——它们到程序手里就是字面量
 * （`grep '*'`、`echo 'a;b'`），不能按通配／结构算（判据 5）。
 */
function isDynamic(word, bare) {
    const text = String(word ?? '');
    const expands = text.includes('$') || text.includes('`')
        || /[*?[\]]/.test(text) || (text.includes('{') && text.includes('}'));
    if (!expands)
        return false;
    return bare !== false;
}

// Windows 原生命令的斜杠开关（`taskkill /F`、`shutdown /r`、`robocopy /MIR`）
// 此前一律落 operand，事实层再把它读成 POSIX 盘根（`/F`→`F:\`）⇒ 撞 `filesystem-root` 硬闸，
// 一条杀进程的命令被问成人事。只对**这套 Windows 程序**生效：`/tmp`、`/etc` 这类 POSIX
// 绝对路径必须仍是路径；带子命令语义的 `icacls`／`sc`／`reg`（`/save`、`/l` 是子命令）不在此列。
// `//all` 是 Git Bash 给原生命令传 `/all` 的写法（双斜杠防止 MSYS 转成盘符路径）：
// 两种斜杠都按开关认，否则 `ipconfig //all` 会被抽成路径 `\all`，再按 cwd 解析成假目标。
const WIN_SLASH_SWITCH = /^\/{1,2}[A-Za-z][A-Za-z0-9]{0,15}$/;
const WIN_SWITCH_PROGRAMS = new Set(['taskkill', 'shutdown', 'robocopy', 'xcopy', 'attrib',
    'findstr', 'dir', 'tree', 'schtasks', 'where', 'ipconfig', 'route', 'netstat', 'ping',
    'tracert', 'nslookup', 'systeminfo', 'tasklist', 'cmd']);
function winSwitchOf(token, program) {
    return WIN_SLASH_SWITCH.test(token) && WIN_SWITCH_PROGRAMS.has(normalizeProgram(program));
}

/** 给事实层用：解释器的第一个词如果只是原生命令的 `/x`／`//x` 开关，就不是脚本路径。 */
export function isNativeSwitch(token, program) {
    return winSwitchOf(token, program);
}

function classifyWord(token, bare, program = '') {
    if (token.startsWith('--'))
        return { text: token, kind: 'long-flag', bare: bare === true };
    if (token.startsWith('-') && token.length > 1)
        return { text: token, kind: 'short-flag', bare: bare === true };
    if (winSwitchOf(token, program))
        return { text: token, kind: 'short-flag', bare: false };
    if (REDIRECT_OPS.test(token))
        return { text: token, kind: 'redirect', bare: bare === true };
    return { text: token, kind: 'operand', bare: bare === true };
}

// 族分类表（判据 5）：只回答「这个程序属于哪一族动作」，不回答「它是哪条命令」。
// `Get-ChildItem` 与 bash 的 `ls` 是两条命令（按用户要求），各有各的预设行与位表行；
// 这张表只把原生命令归到读／写／删族，供事实层算 opClass，不再作为命令面的匹配权威。
const PROGRAM_ALIASES = new Map([
    // PowerShell 常用命令与别名
    ['get-childitem', 'ls'], ['gci', 'ls'],
    ['get-content', 'cat'], ['gc', 'cat'],
    ['get-item', 'stat'], ['gi', 'stat'],
    ['select-string', 'grep'], ['sls', 'grep'],
    ['measure-object', 'wc'], ['measure', 'wc'],
    ['compare-object', 'diff'], ['compare', 'diff'],
    ['write-output', 'echo'], ['write-host', 'echo'],
    ['get-command', 'which'], ['gcm', 'which'],
    ['test-path', 'test'],
    ['invoke-webrequest', 'curl'], ['iwr', 'curl'],
    ['invoke-expression', 'eval'], ['iex', 'eval'],
    ['set-location', 'cd'], ['sl', 'cd'],
    ['remove-item', 'rm'], ['ri', 'rm'],
    ['copy-item', 'cp'], ['cpi', 'cp'], ['copy', 'cp'],
    ['move-item', 'mv'], ['mi', 'mv'], ['move', 'mv'], ['rename-item', 'mv'], ['ren', 'mv'], ['rename', 'mv'],
    ['new-item', 'mkdir'], ['ni', 'mkdir'],
    ['set-content', 'set-content'], ['add-content', 'set-content'], ['out-file', 'set-content'],
    ['set-item', 'set-content'], ['clear-content', 'rm'],
    ['get-filehash', 'md5sum'], ['import-csv', 'cat'], ['import-clixml', 'cat'],
    ['get-itemproperty', 'stat'], ['get-acl', 'stat'],
    ['start-process', 'start-process'], ['saps', 'start-process'], ['start', 'start-process'],
    ['stop-process', 'kill'],
    ['get-process', 'ps'], ['gps', 'ps'],
    // cmd 内建
    ['type', 'cat'], ['del', 'rm'], ['erase', 'rm'], ['rd', 'rm'], ['rmdir', 'rm'],
    ['md', 'mkdir'], ['findstr', 'grep'],
]);

/** * 同方言别名表：别名与它的本名是**同一条命令**（PowerShell 里 `Get-Alias ls`
 *  就是 Get-ChildItem），所以只在这张表里折。跨方言的同名词（`ls`／`cat`／`rm`…）
 *  是两条命令，各有各的预设行——`Get-ChildItem` 不折成 bash 的 `ls`（按用户要求）。
 *  与 `-` 冲突的几个（`sc`／`type`／`dir`）保留自立门户：`sc.exe` 是服务控制程序，
 *  折给 Set-Content 会把服务操作记到内容写的那一行上。
 */
const NATIVE_ALIASES = new Map([
    ['gci', 'get-childitem'], ['gc', 'get-content'], ['gi', 'get-item'],
    ['sls', 'select-string'], ['stringmatch', 'select-string'],
    ['measure', 'measure-object'], ['compare', 'compare-object'],
    ['gcm', 'get-command'], ['sl', 'set-location'],
    ['ri', 'remove-item'], ['cpi', 'copy-item'], ['mi', 'move-item'],
    ['ni', 'new-item'], ['si', 'set-item'], ['ac', 'add-content'], ['clc', 'clear-content'],
    ['gps', 'get-process'], ['saps', 'start-process'],
    ['iwr', 'invoke-webrequest'], ['iex', 'invoke-expression'], ['write', 'write-output'],
]);

const baseNameOf = raw => String(raw ?? '').split(/[\\/]/).pop().toLowerCase()
    .replace(/\.(?:exe|cmd|bat|com|ps1)$/, '');

/** * 归一 basename：去路径、小写、去可执行后缀，再过方言别名表。
 * `C:\Windows\System32\findstr.EXE` ⇒ `grep`；`.\Remove-Item.ps1` ⇒ `rm`。
 * 只用于**族分类**（读／写／删／执行）；命令身份见 `nativeNameOf`。
 */
export function normalizeProgram(raw) {
    const base = baseNameOf(raw);
    return PROGRAM_ALIASES.get(base) ?? base;
}

/** * 命令本名：去路径、小写、去可执行后缀，只折**同方言别名**。
 * `gci` ⇒ `get-childitem`；`Get-ChildItem` ⇒ `get-childitem`；bash 的 `ls` 仍是 `ls`。
 * 预设表匹配与位表查表都认这个名字——两条命令各有各的行，谁也不替谁说话。
 */
export function nativeNameOf(raw) {
    const base = baseNameOf(raw);
    return NATIVE_ALIASES.get(base) ?? base;
}

/** 重定向方向：带 `<` 的是输入源（stdin），其余是写目的（判据 2）。 */
export function redirectReads(op) {
    return String(op ?? '').includes('<');
}

/** Split one command line into executable segments with words and redirects. */
export function splitSegments(command) {
    const meta = { heredocs: [], marks: [] };
    const tokens = tokenize(String(command ?? ''), meta);
    const segments = [];
    let current = null;
    let pendingRedirect = '';
    for (const [index, token] of tokens.entries()) {
        const bare = meta.bare?.[index] === true;
        // 定界符标记（只有带 meta 的分词才会产出）：记到它所属那一段上，正文照旧不成段。
        if (typeof token !== 'string') {
            if (current !== null)
                current.heredocs.push(meta.heredocs[token.heredoc]);
            continue;
        }
        if (SEPARATORS.has(token)) {
            current = null;
            continue;
        }
        if (pendingRedirect !== '') {
            current.redirects.push({ op: pendingRedirect, text: token, dynamic: isDynamic(token, bare) });
            pendingRedirect = '';
            continue;
        }
        const classified = classifyWord(token, bare, current?.program ?? '');
        if (classified.kind === 'redirect') {
            if (current === null) {
                current = { program: '', words: [], redirects: [], heredocs: [], opaque: true };
                segments.push(current);
            }
            pendingRedirect = classified.text;
            continue;
        }
        // `NAME=$(prog …)`：分词不切 `$(`，赋值前缀会把 prog 一起吞掉——`L=$(grep -n …` 的下一个
        // token 是 `-n`，于是 `-n` 顶成程序名，整段误判执行，段里的 `$F` 落成写目的（曾因此把
        // 一条纯读的排查命令判「目标算不清且会改东西」转人工）。这里把 prog 单独起一段，
        // 赋值前缀照旧丢弃；`$(` 未闭合不影响后续分词（尾 `)` 留在最后一个词上，只影响旗标字面）。
        const substHead = /^[A-Za-z_][A-Za-z0-9_]*=\$\(([A-Za-z0-9_./:\\-]+)$/.exec(token);
        if (substHead !== null) {
            current = {
                program: substHead[1], words: [], redirects: [], heredocs: [],
                opaque: false, fromSubstitution: true,
            };
            segments.push(current);
            continue;
        }
        if (current === null) {
            if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token))
                continue;
            current = { program: token, words: [], redirects: [], heredocs: [], opaque: isDynamic(token, bare) };
            segments.push(current);
            continue;
        }
        current.words.push(classified);
    }
    for (const segment of segments) {
        if (pendingRedirect !== '' && segment.redirects.length === 0)
            continue;
        segment.opaque = segment.opaque
            || segment.words.some(word => word.kind === 'operand' && isDynamic(word.text, word.bare))
            || segment.redirects.some(redirect => redirect.dynamic);
    }
    // 未引用定界符的 heredoc：正文里的 `$(…)`／反引号会真的执行（A01）。
    // 它们**不是数据**——把里面的命令拆成独立段收进作用集合，同时把这一段标成
    // `heredocExpanded`（事实层据此拒绝「已证明只读」）。引用定界符的正文仍是数据。
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
                    fromBodies.push(sub);
                }
    }
    segments.push(...fromBodies);
    return segments.filter(segment => segment.program !== '' || segment.redirects.length > 0);
}

/** * 参数词的四种写法统一成 `(flag, value)`：`--x=y`／`-ovalue`／`--x y`／`-o y`。
 * 只认附值两种时，`sort --output=x`、`grep --file=.env`、`sort -ox` 在判据里根本不存在。
 */
export function splitFlag(word) {
    const text = String(word ?? '');
    const eq = /^(-{1,2}[A-Za-z0-9_-]+)=(.*)$/s.exec(text);
    if (eq !== null)
        return { flag: eq[1], value: eq[2] === '' ? undefined : eq[2], attached: eq[2] !== '' };
    const attached = /^(-[A-Za-z])(.+)$/s.exec(text);
    if (attached !== null)
        return { flag: attached[1], value: attached[2], attached: true };
    return { flag: text, value: undefined, attached: false };
}

/** * 按序取「这些旗标」的取值：只有**登记过的旗标**才拆取值——`--x=y`／`-ovalue`／`-o y`。
 * 不能对所有词套同一条附值规则：`-delete`、`-exec` 这类单横线长选项会被读成
 * 「-d + elete」，`find -delete` 于是不再被认成删除。
 * `foldCase`：PowerShell 参数名大小写不敏感（`-Destination`＝`-destination`），
 * POSIX 旗标不折——只在 cmdlet 那段打开。
 */
export function flagValues(words, flags, foldCase = false) {
    const has = name => flags.has(name) || (foldCase === true && flags.has(String(name).toLowerCase()));
    const out = [];
    for (let index = 0; index < words.length; index += 1) {
        const text = String(words[index]);
        let flag;
        let value;
        if (has(text)) {
            flag = text;
        }
        else {
            const eq = /^(--[A-Za-z0-9_-]+)=(.*)$/s.exec(text);
            const attached = eq === null ? /^(-[A-Za-z])(.+)$/s.exec(text) : null;
            if (eq !== null && has(eq[1])) {
                flag = eq[1];
                value = eq[2];
            }
            else if (attached !== null && has(attached[1])) {
                flag = attached[1];
                value = attached[2];
            }
        }
        if (flag === undefined)
            continue;
        if (value !== undefined) {
            out.push({ flag, value, index });
            continue;
        }
        const next = words[index + 1];
        if (next !== undefined && String(next) !== '') {
            out.push({ flag, value: String(next), index: index + 1 });
            index += 1;
        }
    }
    return out;
}

/** Operands a segment acts on: positional operands plus write-redirect targets. */
export function operandsOf(segment) {
    return segment.words
        .filter(word => word.kind === 'operand')
        .map(word => word.text);
}

/** * ｜闭合展开：只把「能算死」的写法算出来，算不死就整条原样（交 AI）。
 * 支持：字面量 `for v in A B`（词内不许有 $ ` * ? [ ] { }）、`v=<字面量>`、
 * `v=$(basename <字面量或 $v>)`、`$v`／`${v}` 替换。`cd` 不在这里改——事实层逐段 cwd 已在做。
 * 不支持（整条放弃）：glob、$ENV、嵌套 $(…)、反引号、while／until、数组、eval、嵌套 for。
 * 「任何一段展不开 ⇒ 整条保持现状」：任一写法不认识就返回原文，不做部分展开。
 * ｜heredoc 不再整条放弃：**切头不切正文**——只把命令头（含定界符那一行里正文之外的部分）
 * 送进展开，正文按原字节拼回去。正文仍是数据（引用定界符）或仍由 `splitSegments` 按 A01 处理
 * （未引用定界符里的 `$(…)`／反引号），展开这一步碰不到它 ⇒ 正文里的词不会被当成目标。
 */
const SAFE_WORD = /^[^$`*?\[\]{}]+$/;
const LOOP_HEAD = /(^|[;&|\n]\s*)for\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\s+([^;\n]*?)\s*;\s*do\b/g;
const ASSIGN_HEAD = /(^|[;&|\n]\s*)([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|'[^']*'|[^\s;&|]+)/g;
const HAS_ASSIGN = /(?:^|[;&|\n]\s*)[A-Za-z_][A-Za-z0-9_]*=/;
const BASENAME_CALL = /\$\(\s*basename\s+("[^"]*"|'[^']*'|\S+?)\s*\)/g;

const shellBaseName = text => String(text).split(/[\\/]/).filter(Boolean).pop() ?? '';

function replaceVar(text, name, value) {
    const pattern = new RegExp(`\\$\\{${name}\\}|\\$${name}(?![A-Za-z0-9_])`, 'g');
    return text.replace(pattern, value);
}

/** `for` 词表：按空白切，成对引号去掉；引号不闭合＝展不开。 */
function loopWords(list) {
    const words = [];
    let current = '';
    let quote = '';
    for (const char of String(list)) {
        if (quote !== '') {
            if (char === quote)
                quote = '';
            else
                current += char;
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            continue;
        }
        if (/\s/.test(char)) {
            if (current !== '') {
                words.push(current);
                current = '';
            }
            continue;
        }
        current += char;
    }
    if (quote !== '')
        return null;
    if (current !== '')
        words.push(current);
    return words;
}

/** 本命令里所有被赋值的变量名：循环体里引用它们（如 `$d`）是合法的，留给下一格展开。
 *  `X+=…` 同样算赋值——环境变量解析要把这些名字整条排掉（赋值可能来自运行时）。 */
export function assignedNames(text) {
    const names = new Set();
    const re = /(?:^|[^A-Za-z0-9_$])([A-Za-z_][A-Za-z0-9_]*)\+?=/g;
    let match;
    while ((match = re.exec(text)) !== null)
        names.add(match[1]);
    return names;
}

/** 一个循环体按某个取值展开；展不开返回 null（调用方据此整条放弃）。 */
function expandLoopBody(body, name, value, extraNames) {
    // 嵌套循环／while／until 本子集不展开：一个算不死就整条原样。
    if (/\b(?:for|while|until|done)\b/.test(body))
        return null;
    let leftover = replaceVar(body.replace(BASENAME_CALL, ''), name, value);
    for (const other of extraNames) {
        if (other !== name)
            leftover = replaceVar(leftover, other, '');
    }
    if (leftover.includes('$') || leftover.includes('`'))
        return null;
    let out = body;
    let match;
    BASENAME_CALL.lastIndex = 0;
    while ((match = BASENAME_CALL.exec(out)) !== null) {
        const raw = match[1].replace(/^["']|["']$/g, '');
        const arg = replaceVar(raw, name, value);
        if (!SAFE_WORD.test(arg))
            return null;
        out = out.slice(0, match.index) + shellBaseName(arg) + out.slice(match.index + match[0].length);
        BASENAME_CALL.lastIndex = 0;
    }
    return replaceVar(out, name, value);
}

/** 从 bodyStart 起找**同层**的 done；嵌套 for 计入深度。返回 -1＝缺 done／嵌套看不穿。 */
function matchingDone(text, bodyStart) {
    const scan = /\b(for|done)\b/g;
    scan.lastIndex = bodyStart;
    let depth = 0;
    let hit;
    while ((hit = scan.exec(text)) !== null) {
        if (hit[1] === 'for') {
            depth += 1;
            continue;
        }
        if (depth === 0)
            return hit.index;
        depth -= 1;
    }
    return -1;
}

function expandLoops(text) {
    let out = '';
    let index = 0;
    for (;;) {
        LOOP_HEAD.lastIndex = 0; // g 正则会跨调用残留 lastIndex
        const head = LOOP_HEAD.exec(text.slice(index));
        if (head === null) {
            out += text.slice(index);
            return out;
        }
        const name = head[2];
        const words = loopWords(head[3]);
        if (words === null || words.length === 0 || !words.every(word => SAFE_WORD.test(word)))
            return null;
        const bodyStart = index + head.index + head[0].length;
        const doneAt = matchingDone(text, bodyStart);
        if (doneAt === -1)
            return null;
        const body = text.slice(bodyStart, doneAt);
        const pieces = [];
        const extraNames = assignedNames(text);
        for (const word of words) {
            const one = expandLoopBody(body, name, word, extraNames);
            if (one === null)
                return null;
            pieces.push(one.trim());
        }
        out += text.slice(index, index + head.index) + head[1] + pieces.join(' ; ');
        index = doneAt + 4;
    }
}

/** 列表里有没有**引号外**的 `*`／`?`：引号里的星号是字面名，不能当成范围通配。 */
function bareGlobIn(list) {
    let single = false;
    let double = false;
    for (let index = 0; index < list.length; index += 1) {
        const char = list[index];
        if (char === '\\' && single !== true) {
            index += 1;
            continue;
        }
        if (char === "'" && double !== true) {
            single = !single;
            continue;
        }
        if (char === '"' && single !== true) {
            double = !double;
            continue;
        }
        if (single !== true && double !== true && (char === '*' || char === '?'))
            return true;
    }
    return false;
}

/** `for v in <字面通配>` 的列表：恰好一个词，带引号外的通配，能原样落进命令
 *  （不带空白／命令分隔符）。返回 `{ raw, word }`：raw 保留引号（整词替换用），
 *  word 去引号（嵌在字符串里的显示位用）。不是这种列表＝undefined，留给下一刀。 */
function rangeListOf(list) {
    const text = String(list).trim();
    const words = loopWords(text);
    if (words === null || words.length !== 1)
        return undefined;
    const word = words[0];
    if (word === '' || /\s/.test(word) || /[;&|<>()]/.test(word))
        return undefined;
    if (!bareGlobIn(text))
        return undefined;
    return { raw: text, word };
}

/** 把循环体里的 `$v`／`${v}` 换成列表表达式（范围）：整词引用保留列表原来的引号
 *  （通配是引号外还是引号里，语义不能变）；嵌在字符串里的位置只用来显示，用去引号的词。
 *  单引号里的 `$v` 不展开，原样保留。 */
function replaceRangeVar(body, name, range) {
    const pattern = new RegExp(`\\$\\{${name}\\}|\\$${name}(?![A-Za-z0-9_])`);
    const boundary = char => char === undefined || /[\s;&|()<>]/.test(char);
    let out = '';
    let index = 0;
    let single = false;
    while (index < body.length) {
        const char = body[index];
        if (char === '\\' && single !== true) {
            out += body.slice(index, index + 2);
            index += 2;
            continue;
        }
        if (char === "'") {
            single = !single;
            out += char;
            index += 1;
            continue;
        }
        if (single) {
            out += char;
            index += 1;
            continue;
        }
        if (char === '"') {
            const close = body.indexOf('"', index + 1);
            const inner = close === -1 ? '' : body.slice(index + 1, close);
            if (close !== -1 && boundary(body[index - 1]) && boundary(body[close + 1])
                && (inner === `$${name}` || inner === `\${${name}}`)) {
                out += range.raw;
                index = close + 1;
                continue;
            }
        }
        const match = pattern.exec(body.slice(index));
        if (match !== null && match.index === 0) {
            // 整词（裸写）保留列表原文；嵌在别的字符里只放去引号的词。
            const whole = boundary(body[index - 1]) && boundary(body[index + match[0].length]);
            out += whole ? range.raw : range.word;
            index += match[0].length;
            continue;
        }
        out += char;
        index += 1;
    }
    return out;
}

/** * `for v in <字面通配>; do …; done`：把循环体**按列表表达式展开一次**——不枚举文件名，
 * 只是把 `$v` 换成它唯一的取值范围。范围是读、是删、是写，由循环体里用它的程序决定，
 * 这一层不下结论。字面量列表的循环原样留给 `expandLoops`；看不穿（缺 done／变量还有
 * 没换掉的形态）也原样留着，由下一刀或保守路径处理。
 * 返回 null＝循环结构残缺（找不到同层 done），调用方整条保守。
 */
function expandRangeLoops(text) {
    let out = '';
    let index = 0;
    for (;;) {
        LOOP_HEAD.lastIndex = 0;
        const head = LOOP_HEAD.exec(text.slice(index));
        if (head === null) {
            out += text.slice(index);
            return out;
        }
        const bodyStart = index + head.index + head[0].length;
        const doneAt = matchingDone(text, bodyStart);
        if (doneAt === -1)
            return null;
        const name = head[2];
        const range = rangeListOf(head[3]);
        if (range !== undefined) {
            const body = text.slice(bodyStart, doneAt);
            const rewritten = replaceRangeVar(body, name, range);
            const leftover = new RegExp(`\\$\\{${name}\\}|\\$${name}(?![A-Za-z0-9_])`).test(rewritten);
            if (leftover !== true) {
                // 循环体末尾的 `;` 要去掉：`done` 后面可能跟着属于整个循环的重定向／管道
                // （`done 2>&1`），留着这个 `;` 就会凭空造出一个没有程序的空段。
                const piece = rewritten.replace(/[\s;]+$/, '');
                out += text.slice(index, index + head.index) + head[1] + piece;
                index = doneAt + 4;
                continue;
            }
        }
        // 不是这一刀能处理的循环：整段原样留下，交给下一刀。
        out += text.slice(index, doneAt + 4);
        index = doneAt + 4;
    }
}

/** 赋值值里的已知环境变量：`D="$APPDATA/x"` 先按判定时环境展开成真实路径。
 *  只认 `$NAME`／`${NAME}` 两种写法；未知变量、`$(...)`、`${X:-}`、`$1` 等一律返回 null，
 *  整条保守——与其余展开同一把尺，禁部分展开。 */
const ENV_REF = /\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g;
function expandEnvRefs(value, env) {
    let out = String(value ?? '');
    if (out.includes('$') === false)
        return out;
    if (env === undefined || env === null)
        return null;
    for (let depth = 0; depth < 8; depth += 1) {
        let changed = false;
        let missing = false;
        out = out.replace(ENV_REF, (_, braced, bare) => {
            const resolved = env[braced ?? bare];
            if (typeof resolved !== 'string' || resolved === '') {
                missing = true;
                return '';
            }
            changed = true;
            return resolved;
        });
        if (missing === true)
            return null;
        if (changed === false)
            break;
    }
    // 还有 `$` ⇒ 是没认出的写法（`$(...)`／`${X:-}`／`$1`…）或展开循环，整条不展开。
    return out.includes('$') ? null : out;
}

/** 每个位置是否落在引号串内部。赋值扫描靠它跳过内联代码正文里的
 *  `name=value`（`python -c "d=json.load(...)"` 曾被当成一条 shell 赋值 ⇒ 整条命令
 *  展开失败 ⇒ 目标留在 `$B` 上算不清），只认这条 shell 真正会执行的赋值。 */
function quotedMask(text) {
    const mask = new Uint8Array(text.length);
    let quote = '';
    for (let index = 0; index < text.length; index += 1) {
        const char = text[index];
        if (quote !== '') {
            mask[index] = 1;
            if (quote === '"' && char === '\\') {
                if (index + 1 < text.length)
                    mask[index + 1] = 1;
                index += 1;
                continue;
            }
            if (char === quote)
                quote = '';
            continue;
        }
        if (char === '\\') {
            index += 1;
            continue;
        }
        if (char === '"' || char === "'") {
            quote = char;
            mask[index] = 1;
        }
    }
    return mask;
}

/** 字面量赋值：`x=<literal>` 之后同一条链里的 `$x`／`${x}` 按值替换。
 *  值里的已知环境变量先展开（`D="$APPDATA/…"`）；单引号值不展开；任一处算不死就整条放弃。 */
function expandAssignments(text, env) {
    const found = [];
    const mask = quotedMask(text);
    ASSIGN_HEAD.lastIndex = 0;
    let match;
    while ((match = ASSIGN_HEAD.exec(text)) !== null) {
        // 引号里的赋值是内联代码正文，不归这条 shell 管。
        if (mask[match.index + match[1].length] === 1)
            continue;
        const raw = match[3];
        const singleQuoted = raw.length >= 2 && raw.startsWith("'") && raw.endsWith("'");
        const doubleQuoted = raw.length >= 2 && raw.startsWith('"') && raw.endsWith('"');
        let value = raw.replace(/^["']|["']$/g, '');
        // 单引号是字面量：里面的 `$` 不是变量；展开它等于替用户改命令。
        if (singleQuoted === false && value.includes('$'))
            value = expandEnvRefs(value, env);
        // 展不开这一条就跳过它，别废整条：`L=$(grep … | head -1)` 展不开，不代表同一条命令里的
        // `F="字面路径"` 也展不开。跳过的那条原样留在文本里，引用它的地方仍是变量（仍算动态）。
        if (value === null)
            continue;
        // 无引号赋值里出现空格：展开后会被 shell 拆成多个词，宁可这一条不展。
        if (doubleQuoted === false && singleQuoted === false && /\s/.test(value))
            continue;
        if (!SAFE_WORD.test(value))
            continue;
        found.push({ start: match.index + match[1].length, end: match.index + match[0].length, name: match[2], value });
    }
    if (found.length === 0)
        return text;
    let out = text;
    for (const item of found.reverse())
        out = out.slice(0, item.start) + replaceVar(out.slice(item.end), item.name, item.value);
    // 赋值句被吃掉后留下空段：`&& ;`／`;;` 折叠回一个分隔符，展开后的命令仍是合法 shell。
    return out.replace(/&&\s*;+/g, '&&').replace(/;\s*;+/g, ';');
}

/** * ｜把 heredoc 的**正文**从命令文本里拎出来，只留一个占位符，展开之后再原样放回。
 * 为什么要拎：`expandClosedShell` 过去见 `<<` 就整条放弃（展开赋值会把正文里的词当目标），
 * 于是手册 §10 推荐的落档写法（`D=…; python "$D" --add … <<'EOF' 正文 EOF`）里 `$D` 永不还原
 * ⇒ 程序位保持动态 ⇒ 段 opaque ⇒ 评审读不出证据 ⇒ 升人。拎出正文后，赋值还原只作用在命令头上。
 * 返回 null＝这把刀切不开（here-string `<<<`／定界符读不出／占位符在展开里丢了）⇒ 交回调用方整条保守。
 */
const HEREDOC_MARK = '\u0000';
const heredocToken = index => `${HEREDOC_MARK}hd${index}${HEREDOC_MARK}`;

/** 每一条 heredoc 的正文跨度（`[start, end)` 含终止行）；null＝形态不认识。 */
function heredocSpans(text) {
    const spans = [];
    let index = 0;
    let quote = '';
    while (index < text.length) {
        const character = text[index];
        if (quote !== '') {
            if (character === quote)
                quote = '';
            index += 1;
            continue;
        }
        if (character === "'" || character === '"') {
            quote = character;
            index += 1;
            continue;
        }
        if (character === '\\') {
            index += 2;
            continue;
        }
        if (character !== '<' || text[index + 1] !== '<') {
            index += 1;
            continue;
        }
        if (text[index + 2] === '<')
            return null;                    // here-string 的正文在同一行里，切不开
        let from = index + 2;
        if (text[from] === '-')
            from += 1;                      // `<<-` 只改变缩进，不改变跨度算法
        const delimiter = readDelimiter(text, from);
        if (delimiter.value === '')
            return null;                    // 定界符读不出 ⇒ 不知道正文到哪结束
        const gone = heredocEnd(text, delimiter.value, delimiter.next);
        const lineEnd = text.indexOf('\n', delimiter.next);
        if (lineEnd === -1)
            return null;                    // 定界符那行之后没有换行＝正文不存在
        // 终止行**后面那个换行不属于正文**：留着它，占位符前后才是合法的分词边界——
        // 否则 `… <<'EOF' 正文 EOF` 后面的 `exit=$?` 会紧贴占位符，赋值那一条正则看不见它。
        const spanEnd = gone.end > lineEnd + 1 && text[gone.end - 1] === '\n' ? gone.end - 1 : gone.end;
        spans.push({ start: lineEnd + 1, end: spanEnd });
        index = gone.end;
    }
    return spans;
}

/** 拎出正文得到命令头；`restore` 放回正文，`lost` 说占位符有没有被展开过程吃掉。 */
function liftHeredocs(text) {
    const spans = heredocSpans(text);
    if (spans === null)
        return null;
    if (spans.length === 0)
        return { skeleton: text, bodies: [], lost: () => false, restore: value => value };
    const bodies = spans.map(span => text.slice(span.start, span.end));
    let skeleton = '';
    let cursor = 0;
    for (const [index, span] of spans.entries()) {
        skeleton += text.slice(cursor, span.start) + heredocToken(index);
        cursor = span.end;
    }
    skeleton += text.slice(cursor);
    return {
        skeleton,
        bodies,
        lost: value => bodies.some((_, index) => !value.includes(heredocToken(index))),
        restore: value => {
            let out = value;
            // 从后往前放回：正文里若再含占位符形状也不会被二次替换。
            for (let index = bodies.length - 1; index >= 0; index -= 1)
                out = out.split(heredocToken(index)).join(bodies[index]);
            return out;
        },
    };
}

// 位置写法：PowerShell 的 `$env:NAME`、cmd 的 `%NAME%`、以及
// `Join-Path A B` 这个路径拼接函数。它们不是「命令」也不是「旗标」，是**位置**——
// 不认就得把 `$env:USERPROFILE` 当裸词、把 `.ssh)` 拼到工作区根上，
// 造出一条带 `rootHit=workspace` 的假路径送给模型。
const LOCATION_VAR = /[$]env:([A-Za-z_][A-Za-z0-9_]*)|(?<![\w%])%([A-Za-z0-9_]+)%(?![\w%])/g;
const LOCATION_FORM = /[$]env:[A-Za-z_][A-Za-z0-9_]*|(?<![\w%])%[A-Za-z0-9_]+%|Join-Path/i;
// `Join-Path` 的两个实参：带引号或裸词都收，闭合括号一并吃掉（残尾就是那条假路径的尾巴）。
const JOIN_PATH = /(?:\(\s*)?Join-Path\s+(?:"([^"]*)"|'([^']*)'|([^\s"')]+))\s+(?:"([^"]*)"|'([^']*)'|([^\s"')]+))\s*\)?/i;

/** 位置写法求值：变量取环境变量的值，`Join-Path` 拼成一条 Windows 路径。
 *  任一算不死 ⇒ 返回 null（整条不展开）——与 `expandAssignments` 同一把尺，禁部分展开：
 *  半截展开会让「算清了」的旗标骗过证据面。 */
function expandLocations(text, env) {
    let out = String(text ?? '');
    for (const [, pwshName, cmdName] of [...out.matchAll(LOCATION_VAR)]) {
        const name = pwshName ?? cmdName;
        const value = env?.[name];
        if (typeof value !== 'string' || value.length === 0)
            return null;
    }
    out = out.replace(LOCATION_VAR, (_, pwshName, cmdName) => env[pwshName ?? cmdName]);
    for (let guard = 0; guard < 8; guard += 1) {
        const found = JOIN_PATH.exec(out);
        if (found === null)
            break;
        const head = found[1] ?? found[2] ?? found[3] ?? '';
        const tail = found[4] ?? found[5] ?? found[6] ?? '';
        if (head.length === 0 || tail.length === 0)
            return null;
        const joined = `${head.replace(/[\\/]+$/, '')}\\${tail.replace(/^[\\/]+/, '')}`;
        out = out.slice(0, found.index) + joined + out.slice(found.index + found[0].length);
    }
    if (LOCATION_FORM.test(out))
        return null;
    return out === text ? null : out;
}

export function expandClosedShell(command, env = process.env) {
    const raw = String(command ?? '');
    const lifted = liftHeredocs(raw);
    if (lifted === null)
        return { command: raw, expanded: false, why: '含 here-string／heredoc 定界符读不出，整条保守' };
    const text = lifted.skeleton;
    const structural = /\bfor\s+[A-Za-z_]/.test(text) || HAS_ASSIGN.test(text);
    if (structural === false && LOCATION_FORM.test(text) === false)
        return { command: raw, expanded: false, why: '' };
    try {
        let body = text;
        if (structural) {
            // 先按「范围」展开字面通配的循环（不枚举文件名），再把剩下的字面量列表循环按值展开。
            const ranged = expandRangeLoops(text);
            if (ranged === null)
                return { command: raw, expanded: false, why: '循环结构残缺（找不到同层 done）' };
            const loops = expandLoops(ranged);
            if (loops === null)
                return { command: raw, expanded: false, why: '循环写法展不开（glob／嵌套／环境变量等）' };
            const assigned = expandAssignments(loops, env);
            if (assigned === null)
                return { command: raw, expanded: false, why: '赋值写法展不开（值不是字面量）' };
            // 逐条展开后一条都没展成（有别于「没有赋值、只有循环」那支）＝与整条放弃等价：
            // 仍要说清为什么，别让 expanded=false 配一句空原因。
            if (assigned === loops && HAS_ASSIGN.test(loops))
                return { command: raw, expanded: false, why: '赋值写法展不开（值不是字面量）' };
            body = assigned;
        }
        // 位置写法排在结构展开之后：赋值先落地，`$env:`／`Join-Path` 才拿得到完整实参。
        const located = expandLocations(body, env);
        if (located === null && LOCATION_FORM.test(body))
            return { command: raw, expanded: false, why: '位置写法展不开（变量取不到值／Join-Path 实参不是字面量）' };
        const settled = located === null ? body : located;
        if (lifted.lost(settled) === true)
            return { command: raw, expanded: false, why: 'heredoc 正文在展开过程中丢失，整条保守' };
        const restored = lifted.restore(settled);
        return { command: restored, expanded: restored !== raw, why: '' };
    }
    catch {
        return { command: raw, expanded: false, why: '展开过程异常' };
    }
}

export { isDynamic, REDIRECT_OPS };
