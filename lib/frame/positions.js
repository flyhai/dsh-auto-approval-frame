// ｜参数位角色表（POSIX 读族 61 只＋PowerShell 原生 cmdlet 44 条）——读识别只从这张表取位。
import { nativeNameOf } from './parse.js';
//
// 位只有八种：
// read    取值／操作数是读路径
// write   写出口（取值只进写目标，不再重复记读）
// exec    后面跟的是程序名：按同一张表再查（`{}` 之类是占位符，不是路径）
// take    取值不是路径（数／格式／字段清单／键名…）
// key     键名位（`git config <key>`）
// pattern 首个操作数不是路径（模式／脚本）
// nopath  操作数永不是路径（文本／用户名／程序名）
// nav     只改 cwd
//
// 表外程序＝不产读事实（最保守）；表外旗标＝默认 path（最保守）。
// `evidence`：'help'＝本机 `--help` 取证过；'absent'＝本机不在位（按标准用法登记，行为＝默认 read）。
// `face`：'name'＝只回名字／计数／元数据，'body'＝回正文片段；`faceFlags` 登记同程序内切换面的旗标。

const row = (operands, flags = {}, evidence = 'help') => ({ operands, flags, evidence });

const TAKE = (names) => Object.fromEntries(names.map(name => [name, 'take']));
const WRITE = (names) => Object.fromEntries(names.map(name => [name, 'write']));
const READ = (names) => Object.fromEntries(names.map(name => [name, 'read']));

export const POSITIONS = {
    base64: row('read', { ...WRITE(['-o', '--output']), ...TAKE(['-w', '--wrap']) }),
    cat: row('read'),
    chmod: row('pattern', { ...READ(['--reference']) }),
    chown: row('pattern', { ...TAKE(['--from']), ...READ(['--reference']) }),
    cmp: row('read', TAKE(['-i', '-n', '--ignore-initial', '--bytes'])),
    column: row('read', TAKE(['-o', '-s', '-c', '--output-separator', '--separator', '--columns'])),
    comm: row('read'),
    // 容器运行时：操作数是容器／镜像／卷／网络的**名字**，不是文件路径。
    // 名字当路径会凭空造出写目标（`docker volume rm dbdata` ⇒ 写 ./dbdata），档位虽被命令行兜住，
    // 但证据里会这么告诉模型。构建相关的旗标值仍是路径，单独登记成读。
    crictl: row('nopath', READ(['-f', '--file'])),
    cut: row('read', TAKE(['-d', '-f', '-c', '-b', '--delimiter', '--fields', '--characters', '--bytes', '--output-delimiter'])),
    date: row('nopath', { ...TAKE(['-d', '--date', '--rfc-3339', '--format']), ...READ(['-f', '--file', '-r', '--reference']) }),
    // 删用户／删组：操作数是账号名，不是路径。
    delgroup: row('nopath'),
    deluser: row('nopath'),
    df: row('read', TAKE(['-B', '-t', '-x', '--block-size', '--type', '--exclude-type'])),
    diff: row('read', { ...TAKE(['-C', '-U', '--width', '--label', '--tabsize', '--exclude', '--ignore-matching-lines',
        '--ifdef', '--show-function-line', '--horizon-lines', '--palette']), ...READ(['--exclude-from', '--from-file', '--to-file', '--starting-file']) }),
    dir: row('read'),
    // docker：容器族操作数是名字不是路径（同 crictl）。Dockerfile 与构建上下文仍是路径。
    docker: row('nopath', READ(['-f', '--file', '--context'])),
    du: row('read', { ...TAKE(['-B', '-d', '-t', '--block-size', '--max-depth', '--threshold', '--time-style',
        '--exclude']), ...READ(['--files0-from', '--exclude-from']) }),
    echo: row('nopath'),
    egrep: row('pattern', { ...TAKE(['-e', '-m', '-A', '-B', '-C', '--regexp', '--max-count', '--include', '--exclude',
        '--exclude-dir', '--label', '--context', '--before-context', '--after-context', '--binary-files', '--directories',
        '--devices', '--group-separator']), ...READ(['-f', '--file', '--exclude-from', '--patterns-from']) }),
    env: row('nopath', TAKE(['-u', '--unset', '--split-string'])),
    expand: row('read', TAKE(['-t', '--tabs'])),
    false: row('nopath'),
    fd: row('pattern', { ...TAKE(['-e', '-t', '-d', '-M', '--max-depth', '--type', '--extension']),
        ...READ(['--base-directory']) }, 'absent'),
    file: row('read', { ...TAKE(['--exclude', '--exclude-quiet', '--separator', '--mime-type']),
        ...READ(['-m', '--magic-file', '--files-from']) }),
    find: row('read', { ...TAKE(['-name', '-iname', '-lname', '-ilname', '-regex', '-iregex', '-path', '-ipath',
        '-wholename', '-iwholename', '-context', '-maxdepth', '-mindepth', '-size', '-perm', '-links', '-mtime',
        '-atime', '-ctime', '-newermt', '-user', '-group', '-printf']),
        ...Object.fromEntries(['-exec', '-execdir', '-ok', '-okdir'].map(name => [name, 'exec'])),
        ...WRITE(['-fprint', '-fprint0', '-fls', '-fprintf']),
        ...READ(['-newer', '-anewer', '-cnewer']) }),
    fmt: row('read', { ...TAKE(['-w', '-g', '-p', '--width', '--goal', '--prefix']),
        ...WRITE(['-o', '--output']) }),
    fold: row('read', TAKE(['-w', '--width'])),
    free: row('nopath', TAKE(['-s', '-c']), 'absent'),
    // git 的取值旗标：消息正文、配置项、日期／格式串、策略名、分支名、深度——
    // 都是文字或名字，不是路径。旧表漏了 `-m`，提交说明（常带 `memory/` 这类斜杠）
    // 被当成操作数铸成 `<cwd>\<说明原文>` 假目标。
    git: row('pattern', { ...TAKE(['--format', '--grep', '-S', '-O', '--author', '--committer', '--since', '--until',
        '-n', '--max-count', '--abbrev', '--type', '-m', '--message', '-c', '--config', '--date', '--pretty',
        '--sort', '--depth', '--cleanup', '--strategy', '-X', '--strategy-option', '-b', '--set-upstream-to']),
        ...READ(['-C', '--file']),
        ...WRITE(['--output']) }),
    grep: row('pattern', { ...TAKE(['-e', '-m', '-A', '-B', '-C', '--regexp', '--max-count', '--include', '--exclude',
        '--exclude-dir', '--label', '--context', '--before-context', '--after-context', '--binary-files', '--directories',
        '--devices', '--group-separator']),
        ...READ(['-f', '--file', '--exclude-from', '--patterns-from']) }),
    // 删组：操作数是组名，不是路径。
    groupdel: row('nopath'),
    head: row('read', TAKE(['-n', '-c', '--lines', '--bytes'])),
    hostname: row('nopath'),
    id: row('nopath'),
    join: row('read', TAKE(['-1', '-2', '-j', '-o', '-t', '-e', '-a', '-v'])),
    // 进程族：操作数是进程名／PID／信号，不是路径。
    kill: row('nopath', TAKE(['-s', '-n', '--signal'])),
    killall: row('nopath', TAKE(['-s', '-u', '-Z', '--signal', '--user'])),
    less: row('read'),
    ls: row('read', TAKE(['-I', '-w', '-T', '--format', '--time-style', '--sort', '--hide', '--ignore',
        '--width', '--block-size', '--quoting-style', '--indicator-style'])),
    md5sum: row('read', READ(['-c', '--check'])),
    more: row('read', {}, 'absent'),
    nerdctl: row('nopath', READ(['-f', '--file', '--context'])),
    nl: row('read', TAKE(['-b', '-n', '-w', '-s', '-v', '-i', '-l', '--body-numbering', '--number-format',
        '--number-width', '--number-separator', '--starting-line-number', '--line-increment', '--join-blank-lines'])),
    od: row('read', TAKE(['-A', '-j', '-N', '-t', '-S', '--address-radix', '--skip-bytes', '--read-bytes', '--format', '--width'])),
    paste: row('read', TAKE(['-d', '--delimiters'])),
    podman: row('nopath', READ(['-f', '--file', '--context'])),
    pkill: row('nopath', TAKE(['-s', '-P', '-u', '-G', '-F', '--signal', '--parent', '--euid', '--group', '--pidfile'])),
    printenv: row('nopath'),
    printf: row('nopath'),
    ps: row('nopath', TAKE(['-o', '--format', '--sort', '--pid', '--cols', '--rows'])),
    pwd: row('nopath'),
    rg: row('pattern', { ...TAKE(['-e', '-g', '-t', '-T', '-m', '-M', '-E', '--regexp', '--glob', '--iglob', '--type',
        '--type-not', '--max-count', '--max-columns', '--max-depth', '--encoding', '--engine', '--pre-glob', '--dfa-size-limit']),
        ...READ(['-f', '--file']), ...Object.fromEntries([['--pre', 'exec'], ['--sort', 'read']]) }),
    // `-i[SUFFIX]` 是开关（后缀可选），不是写出口：登记成 write 会把 `.bak` 当成写目标、
    // 反而把真正被改的 a.txt 从读面挤掉。原地改写由事实层按 IN_PLACE_EDIT_FLAGS 判成写。
    sed: row('pattern', { ...TAKE(['-e', '-l', '--expression', '--line-length']), ...READ(['-f', '--file']) }),
    // 服务族：单元名／服务名不是路径；`systemctl --root` 的目录才是。
    service: row('nopath'),
    sha1sum: row('read', READ(['-c', '--check'])),
    sha256sum: row('read', READ(['-c', '--check'])),
    shred: row('read', TAKE(['-n', '-s', '-z', '--iterations', '--size', '--random-source'])),
    sort: row('read', { ...WRITE(['-o', '--output']), ...READ(['--files0-from', '--random-source', '-T', '--temporary-directory']),
        ...Object.fromEntries([['--compress-program', 'exec']]),
        ...TAKE(['-k', '-S', '--key', '--buffer-size', '--parallel', '--sort', '--batch-size']) }),
    stat: row('read', TAKE(['-c', '--format', '--printf', '--time-style', '--cached'])),
    strings: row('read', TAKE(['-n', '--bytes']), 'absent'),
    systemctl: row('nopath', { ...TAKE(['-H', '--host', '-M', '--machine', '-t', '--type', '-p', '--property',
        '--state', '-n', '--lines', '-o', '--output', '-s', '--signal']), ...READ(['--root']) }),
    // systemd-run 的操作数是要**执行**的命令，不是要写的文件；执行了什么由段的 execFamily 记，
    // 旧形按「未登记程序」把 `/bin/true` 当写目标，证据里凭空多一条「要写 true」。
    'systemd-run': row('nopath', TAKE(['--unit', '--description', '--on-active', '--on-boot', '--on-startup',
        '--property', '-p', '--working-directory', '-d', '--uid', '--gid', '--slice', '--setenv', '-E',
        '--timer-property', '--path-property', '--service-type'])),
    tac: row('read'),
    tail: row('read', TAKE(['-n', '-c', '--pid', '--sleep-interval', '--max-unchanged-stats', '--lines', '--bytes'])),
    // taskkill：`/IM` 是进程镜像名、`/PID` 是编号、`/FI` 是过滤表达式，都不是路径。
    taskkill: row('nopath', TAKE(['/IM', '/PID', '/FI', '/S', '/U', '/P'])),
    test: row('read'),
    tr: row('nopath'),
    tree: row('read', { ...WRITE(['-o', '--output']),
        ...TAKE(['-L', '-P', '-I', '--level', '--pattern', '--ignore', '--filelimit', '--charset', '--sort', '--timefmt']) }, 'absent'),
    truncate: row('read', { ...TAKE(['-s', '--size']), ...READ(['-r', '--reference']) }),
    true: row('nopath'),
    // `type` 在 cmd／pwsh 里读文件（Get-Content 的别名），不是 bash 的「看名字解析成什么」：
    // 位表按读路径登记（FILE_READ_PROGRAMS 也把 type 当读族，两处同一口径）。
    type: row('read'),
    unexpand: row('read', TAKE(['-t', '--tabs'])),
    uniq: row('read', TAKE(['-f', '-s', '-w', '--skip-fields', '--skip-chars', '--check-chars'])),
    uptime: row('nopath', {}, 'absent'),
    userdel: row('nopath'),
    wc: row('read', READ(['--files0-from'])),
    where: row('nopath'),
    which: row('nopath'),
    whoami: row('nopath'),
    xxd: row('read', TAKE(['-c', '-g', '-l', '-n', '-o', '-s', '-R', '--cols', '--groupsize', '--len', '--name', '--offset', '--seek'])),

    // ── PowerShell 原生 cmdlet ──────────────────────────────────────
    // 每条命令**自己一行**，不向同名 POSIX 程序借位（`Get-ChildItem` ≠ bash 的 `ls`）。
    // 旗标按 cmdlet 自己的参数表登记：取路径的是 path 位，取内容／模式／条数的是 take 位，
    // 写出口（`-Destination` 一族）是 write 位；开关（`-Force`／`-Recurse`／`-Raw`…）
    // 不登记——未登记旗标按「不吞后一个词」走，否则 `-Force x` 会把 x 吃掉。
    // 读数按 cmdlet 文档登记（未逐条跑本机 `--help` 取证）。
    'get-childitem': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-filter', '-include', '-exclude', '-depth', '-attributes', '-stream']) }, 'absent'),
    'get-content': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-totalcount', '-first', '-head', '-tail', '-last', '-delimiter', '-encoding',
            '-readcount', '-stream']) }, 'absent'),
    'get-item': row('read', { ...READ(['-path', '-literalpath']), ...TAKE(['-stream']) }, 'absent'),
    'test-path': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-pathtype', '-filter', '-credential']) }, 'absent'),
    'resolve-path': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-relativebasepath']) }, 'absent'),
    'get-filehash': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-algorithm']) }, 'absent'),
    'select-string': row('pattern', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-pattern', '-patterns', '-encoding', '-context', '-inputobject', '-include', '-exclude']) }, 'absent'),
    'import-csv': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-delimiter', '-header', '-encoding']) }, 'absent'),
    'import-clixml': row('read', { ...READ(['-path', '-literalpath']) }, 'absent'),
    'get-itemproperty': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-name']) }, 'absent'),
    'get-acl': row('read', { ...READ(['-path', '-literalpath']), ...TAKE(['-inputobject']) }, 'absent'),
    'measure-object': row('nopath', TAKE(['-property', '-inputobject', '-culture']), 'absent'),
    'compare-object': row('nopath', { ...READ(['-referenceobject', '-differenceobject']),
        ...TAKE(['-property']) }, 'absent'),
    'get-process': row('nopath', TAKE(['-name', '-id', '-computername', '-module', '-fileversioninfo']), 'absent'),
    'get-command': row('nopath', TAKE(['-name', '-module', '-commandtype', '-noun', '-verb',
        '-argumentlist']), 'absent'),
    'get-location': row('nopath', {}, 'absent'),
    'set-location': row('read', { ...READ(['-path', '-literalpath']) }, 'absent'),
    'push-location': row('read', { ...READ(['-path', '-literalpath']) }, 'absent'),
    'pop-location': row('nopath', {}, 'absent'),
    'write-output': row('nopath', TAKE(['-inputobject', '-object']), 'absent'),
    'write-host': row('nopath', TAKE(['-object', '-foregroundcolor', '-backgroundcolor',
        '-separator']), 'absent'),
    'select-object': row('nopath', TAKE(['-property', '-expandproperty', '-first', '-last', '-skip',
        '-index', '-unique', '-inputobject', '-excludeproperty']), 'absent'),
    'where-object': row('nopath', TAKE(['-filter', '-property', '-value', '-inputobject']), 'absent'),
    'sort-object': row('nopath', TAKE(['-property', '-culture', '-inputobject']), 'absent'),
    'group-object': row('nopath', TAKE(['-property', '-culture', '-inputobject']), 'absent'),
    'format-table': row('nopath', TAKE(['-property', '-groupby', '-view', '-inputobject']), 'absent'),
    'format-list': row('nopath', TAKE(['-property', '-groupby', '-view', '-inputobject']), 'absent'),
    'format-wide': row('nopath', TAKE(['-property', '-groupby', '-view', '-inputobject',
        '-column']), 'absent'),
    'format-custom': row('nopath', TAKE(['-property', '-groupby', '-view', '-inputobject',
        '-depth']), 'absent'),
    'out-string': row('nopath', TAKE(['-width', '-inputobject']), 'absent'),
    'set-content': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-value', '-values', '-encoding', '-delimiter', '-stream', '-filter',
            '-include', '-exclude']) }, 'absent'),
    'add-content': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-value', '-encoding', '-stream', '-filter', '-include', '-exclude']) }, 'absent'),
    'out-file': row('read', { ...READ(['-filepath', '-literalpath', '-path']),
        ...TAKE(['-encoding', '-width', '-inputobject']) }, 'absent'),
    'set-item': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-value', '-credential', '-filter', '-include', '-exclude']) }, 'absent'),
    'new-item': row('read', { ...READ(['-path']),
        ...TAKE(['-name', '-itemtype', '-value', '-target', '-credential']) }, 'absent'),
    'clear-content': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-stream', '-filter', '-include', '-exclude']) }, 'absent'),
    'copy-item': row('read', { ...READ(['-path', '-literalpath']), ...WRITE(['-destination']),
        ...TAKE(['-filter', '-include', '-exclude', '-depth', '-credential']) }, 'absent'),
    'move-item': row('read', { ...READ(['-path', '-literalpath']), ...WRITE(['-destination']),
        ...TAKE(['-filter', '-include', '-exclude', '-credential']) }, 'absent'),
    'rename-item': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-newname', '-credential', '-filter', '-include', '-exclude']) }, 'absent'),
    'remove-item': row('read', { ...READ(['-path', '-literalpath']),
        ...TAKE(['-filter', '-include', '-exclude', '-stream', '-credential']) }, 'absent'),
    'start-process': row('read', { ...READ(['-filepath', '-workingdirectory']),
        ...WRITE(['-redirectstandardoutput', '-redirectstandarderror', '-redirectstandardinput']),
        ...TAKE(['-argumentlist', '-argument', '-verb', '-windowstyle', '-credential']) }, 'absent'),
    'invoke-webrequest': row('read', { ...WRITE(['-outfile']), ...READ(['-infile']),
        ...TAKE(['-method', '-body', '-headers', '-contenttype', '-credential', '-useragent']) }, 'absent'),
    'invoke-expression': row('nopath', TAKE(['-command']), 'absent'),
    'stop-process': row('nopath', TAKE(['-id', '-name', '-inputobject', '-computername']), 'absent'),
};

/** 程序名 → 行；表外返回 undefined（＝不产读事实）。
 *  查表用**命令本名**（同方言别名归到本名）：`gci`／`Get-ChildItem` 都查自己的行，
 *  bash 的 `ls` 查 `ls` 的行——两条命令各说各的。 */
export function positionOf(program) {
    return POSITIONS[nativeNameOf(program)];
}

/** cmdlet 名（`Verb-Noun`）的参数表大小写不敏感；POSIX 程序的旗标是大小写敏感的
 *  （`grep -E` 与 `-e` 不是一回事），所以只对 cmdlet 名开这一层。 */
const CMDLET_NAME = /^[a-z]+-[a-z][a-z0-9]*$/i;
export const isCmdletName = program => CMDLET_NAME.test(nativeNameOf(program));

/** 旗标 → 位。未登记的旗标返回 undefined＝**不假定它会吞后一个词**（§1 补）。
 *  旧形返回 `read`（"取值是读路径"），等于对所有未知开关宣布「后面那个词是文件」：
 *  `git config --global user.email` 里 `user.email` 就是这样被当成路径的。 */
export function flagPositionOf(program, flag) {
    const entry = positionOf(program);
    if (entry === undefined)
        return undefined;
    const text = String(flag);
    const plain = text.split('=')[0];
    const candidates = [text, plain];
    if (isCmdletName(program)) {
        // `-Path`／`-PATH` 是同一个参数；`-Path:C:\x` 的冒号也是取值写法。
        candidates.push(plain.toLowerCase());
        const colon = /^-([A-Za-z][A-Za-z0-9-]*):/.exec(text);
        if (colon !== null)
            candidates.push(`-${colon[1].toLowerCase()}`);
    }
    for (const key of candidates) {
        if (entry.flags[key] !== undefined)
            return entry.flags[key];
    }
    return undefined;
}

/** 写出口旗标集合（`facts.js` 的 WRITE_VALUE_FLAGS 从这里派生）。 */
export function writeFlagsOf(program) {
    const entry = positionOf(program);
    if (entry === undefined)
        return undefined;
    const names = Object.entries(entry.flags).filter(([, position]) => position === 'write').map(([name]) => name);
    return names.length === 0 ? undefined : new Set(names);
}

/** 读位旗标集合（取值或操作数是读路径）：目标集里由这一类旗标带进来的词只记一次。 */
export function readFlagsOf(program) {
    const entry = positionOf(program);
    if (entry === undefined)
        return undefined;
    const names = Object.entries(entry.flags).filter(([, position]) => position === 'read').map(([name]) => name);
    return names.length === 0 ? undefined : new Set(names);
}

/** 执行位旗标集合（`find -exec`／`rg --pre` 一族）。 */
export function execFlagsOf(program) {
    const entry = positionOf(program);
    if (entry === undefined)
        return undefined;
    const names = Object.entries(entry.flags).filter(([, position]) => position === 'exec').map(([name]) => name);
    return names.length === 0 ? undefined : new Set(names);
}

// ──  判据②：每只程序的「返回形态」──────────────────────────────────────
// name＝只回名字／计数／元数据（正文不进会话）；body＝回正文片段（内容面，严审）。
// 元数据族（wc／stat／md5sum／du／df／file／ps／uptime／free／cmp）归 name 档：
// 它们回的是数字与属性，回不出文件正文，依据是各自 `--help` 的「输出」段。
// 无读事实的程序（date／echo／env／printf／test／true／false）也记 name：不产正文。
const FACE = {
    base64: 'body', cat: 'body', column: 'body', comm: 'body', cut: 'body', diff: 'body',
    egrep: 'body', expand: 'body', fold: 'body', fmt: 'body', git: 'body', grep: 'body',
    head: 'body', join: 'body', less: 'body', more: 'body', nl: 'body', od: 'body',
    paste: 'body', printenv: 'body', rg: 'body', sed: 'body', sort: 'body', strings: 'body',
    tac: 'body', tail: 'body', tr: 'body', unexpand: 'body', uniq: 'body', xxd: 'body',
    // name 档：只回名字／路径
    dir: 'name', fd: 'name', find: 'name', hostname: 'name', id: 'name', ls: 'name',
    pwd: 'name', tree: 'name', type: 'name', where: 'name', which: 'name', whoami: 'name',
    // name 档：元数据／计数（回不出正文）
    cmp: 'name', df: 'name', du: 'name', file: 'name', free: 'name', md5sum: 'name',
    ps: 'name', sha1sum: 'name', sha256sum: 'name', stat: 'name', uptime: 'name', wc: 'name',
    // 无读事实
    date: 'name', echo: 'name', env: 'name', false: 'name', printf: 'name', test: 'name', true: 'name',
    // PowerShell 原生 cmdlet：列名字／取属性的只回名字，读正文的才回 body
    'get-childitem': 'name', 'get-item': 'name', 'test-path': 'name', 'resolve-path': 'name',
    'get-filehash': 'name', 'get-itemproperty': 'name', 'get-acl': 'name', 'measure-object': 'name',
    'compare-object': 'name', 'get-process': 'name', 'get-command': 'name', 'get-location': 'name',
    'where-object': 'name', 'sort-object': 'name', 'group-object': 'name', 'out-string': 'name',
    'select-object': 'name', 'format-table': 'name', 'format-list': 'name', 'format-wide': 'name',
    'format-custom': 'name',
    'get-content': 'body', 'select-string': 'body', 'import-csv': 'body', 'import-clixml': 'body',
};

// 同一程序由旗标切换面（判据③）：`grep -l` 只回名字，`grep -n`／`-o` 回正文。
const FACE_FLAGS = {
    grep: Object.fromEntries(['-l', '-L', '-c', '-q', '--files-with-matches', '--files-without-match',
        '--count', '--quiet', '--silent'].map(name => [name, 'name'])),
    egrep: Object.fromEntries(['-l', '-L', '-c', '-q', '--files-with-matches', '--files-without-match',
        '--count', '--quiet', '--silent'].map(name => [name, 'name'])),
    rg: Object.fromEntries(['-l', '-c', '--files', '--files-with-matches', '--count', '--quiet']
        .map(name => [name, 'name'])),
    find: Object.fromEntries(['-print', '-print0', '-printf'].map(name => [name, 'name'])),
};

for (const [name, face] of Object.entries(FACE)) {
    if (POSITIONS[name] !== undefined)
        POSITIONS[name].face = face;
}
for (const [name, table] of Object.entries(FACE_FLAGS)) {
    if (POSITIONS[name] !== undefined)
        POSITIONS[name].faceFlags = table;
}
for (const name of Object.keys(POSITIONS)) {
    if (POSITIONS[name].face === undefined)
        POSITIONS[name].face = 'body';
}

/** 返回形态：旗标覆盖优先，其次行级默认；表外程序 ⇒ undefined（不产事实）。 */
export function faceOf(program, flags = []) {
    const entry = positionOf(program);
    if (entry === undefined)
        return undefined;
    const overrides = entry.faceFlags ?? {};
    for (const flag of flags ?? []) {
        const name = String(flag).split('=')[0];
        if (overrides[name] !== undefined)
            return overrides[name];
    }
    return entry.face ?? 'body';
}

/** 表内程序名（升序）——测试里再写一份字面量，禁止 import 本常量自证。 */
export const POSITION_PROGRAMS = Object.keys(POSITIONS).sort();

// ── 参数写法（唯一语义定义）────────────────────────────────────────────
// 位表回答「这个程序/子命令的这个参数管什么」，下面三条回答「参数写成什么样」。
// 两半都在本模块：事实层只从这一处取语义，不再在词法/判定里各写一套。

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
 * `--` 之后一律不再当旗标：那是「后面全是操作数」的显式声明，值的位语义交给操作数规则。
 */
export function flagValues(words, flags, foldCase = false) {
    const has = name => flags.has(name) || (foldCase === true && flags.has(String(name).toLowerCase()));
    const out = [];
    for (let index = 0; index < words.length; index += 1) {
        const text = String(words[index]);
        if (text === '--')
            break;
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

/** Operands a segment acts on: positional operands (already classified; `--` 后的词也落在这里). */
export function operandsOf(segment) {
    return segment.words
        .filter(word => word.kind === 'operand')
        .map(word => word.text);
}