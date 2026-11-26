// ｜参数位角色表（POSIX 读族＋PowerShell 原生 cmdlet＋解释器）——读识别只从这张表取位。
// 程序行＝这个程序的参数表：操作数位＋选项位＋解释器输入位，普通命令和解释器同一套。
// 行的形状、扩展步骤与验收＝设计档 `审批插件-框架设计.md` §11；这里只存数据，不复述规则。
import { nativeNameOf } from './parse.js';
//
// 位有十二种：
// read    取值／操作数是读路径
// write   写出口（取值只进写目标，不再重复记读）
// exec    后面跟的是程序名：按同一张表再查（`{}` 之类是占位符，不是路径）
// script  后面跟的是被执行的那份脚本（`pwsh -File x.ps1`）
// take    取值不是路径（数／格式／字段清单／键名…）
// key     键名位（`git config <key>`）
// pattern 首个操作数不是路径（模式／脚本）
// nopath  操作数永不是路径（文本／用户名／程序名）
// nav     只改 cwd
// secret  取值是秘密（密码等）：证据／台账遮成占位符，执行仍用真值。选项定义可带
//         `{pos:'secret', attachedOnly:true}`——仅附着取值才算秘密（mysql `-pPass` 是密码，
//         `-p mydb` 分开写时 -p 是开关、mydb 是库名操作数，不遮）。约束通用，非程序特判。
// code    取值是命令正文（`python -c`／`node -e`／`php -r`），正文在命令里
// module  取值是模块名（`python -m`），不是文件、也不是命令正文
//
// 表外程序＝不产读事实（最保守）；表外旗标＝不假定它吞后一个词（也不假定它是开关）＝算不准。
// `evidence`：'help'＝本机 `--help` 取证过；'absent'＝本机不在位（按标准用法登记，行为＝默认 read）。
// `face`：'name'＝只回名字／计数／元数据，'body'＝回正文片段；`faceFlags` 登记同程序内切换面的旗标。
// 解释器行另有 `stdin`（显式读标准输入的写法）、`code`（正文就在命令里的选项）、
// `module`（取值是模块名，不是文件）、`fold`（选项名大小写不敏感，如 pwsh）。

const row = (operands, flags = {}, evidence = 'help', extra = {}) => ({ operands, flags, evidence, ...extra });

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
    // mysql 族：操作数是库／表名（nopath）；`-p` 附着才是密码（分开写是「提示输密码」开关，
    // 后随的库名不遮），`--password` 常规取值。本机不在位，按标准用法登记（absent）。
    mysql: row('nopath', { '-p': { pos: 'secret', attachedOnly: true }, '--password': 'secret',
        ...TAKE(['-u', '--user', '-h', '--host', '-P', '--port', '-e', '--execute', '-D', '--database']) }, 'absent'),
    mysqladmin: row('nopath', { '-p': { pos: 'secret', attachedOnly: true }, '--password': 'secret',
        ...TAKE(['-u', '--user', '-h', '--host', '-P', '--port']) }, 'absent'),
    mysqldump: row('nopath', { '-p': { pos: 'secret', attachedOnly: true }, '--password': 'secret',
        ...TAKE(['-u', '--user', '-h', '--host', '-P', '--port']) }, 'absent'),
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

// ── 解释器行（与普通命令同一张表）────────────────────────────────────
// 每个解释器一条行：操作数＝脚本文件（`wsl`／`cmd` 例外：操作数是远端命令／命令串，不是本地路径）；
// 选项位各自登记。选项取值分四种：code（正文在命令里）、module（模块名）、script（`-File`）、
// take／read（普通取值，不是脚本）。没登记的选项＝**算不准**，不假定它吞后一个词，也不假定它是开关。
// 这些行与普通命令行共用 flagPositionOf／wordRolesOf，目标解析不再另走一条路。
const COMMON_SWITCHES = Object.fromEntries(['-h', '--help', '-V', '--version']
    .map(name => [name, 'nopath']));
const PYTHON_FLAGS = {
    ...COMMON_SWITCHES,
    '-c': 'code', '-m': 'module',
    '-X': 'take', '-W': 'take', '--check-hash-based-pycs': 'take',
    ...Object.fromEntries(['-b', '-B', '-d', '-E', '-i', '-I', '-O', '-OO', '-q', '-R', '-s', '-S',
        '-t', '-tt', '-u', '-v', '-x'].map(name => [name, 'nopath'])),
};
const NODE_FLAGS = {
    ...COMMON_SWITCHES,
    '-e': 'code', '--eval': 'code', '-p': 'code', '--print': 'code',
    // `-r`／`--require` 是预加载模块：后面还可以有主脚本，不能在这里结束扫描。
    '-r': 'take', '--require': 'take',
    '--input-type': 'take', '--conditions': 'take', '-C': 'take',
    '--loader': 'read', '--experimental-loader': 'read', '--env-file': 'read',
    ...Object.fromEntries(['--no-warnings', '--trace-warnings', '--watch', '--no-warnings',
        '--enable-source-maps', '--frozen-intrinsics', '--no-addons', '--disable-warning']
        .map(name => [name, 'nopath'])),
};
const SHELL_FLAGS = {
    ...COMMON_SWITCHES,
    '-c': 'code', '-o': 'take', '+o': 'take',
    ...Object.fromEntries(['-a', '-b', '-e', '-f', '-i', '-l', '-m', '-n', '-p', '-r', '-t', '-u',
        '-v', '-x', '-C', '-D', '-E', '-H', '-P', '-T', '--login', '--norc', '--noprofile',
        '--posix', '--restricted', '--verbose'].map(name => [name, 'nopath'])),
};
const BASH_FLAGS = {
    ...SHELL_FLAGS,
    '-O': 'take', '+O': 'take', '--rcfile': 'read', '--init-file': 'read',
};
const POWERSHELL_FLAGS = {
    ...Object.fromEntries(Object.entries(COMMON_SWITCHES).map(([name, role]) => [name.toLowerCase(), role])),
    '-c': 'code', '-command': 'code', '-encodedcommand': 'code', '-e': 'code',
    '-file': 'script',
    '-executionpolicy': 'take', '-inputformat': 'take', '-outputformat': 'take',
    '-windowstyle': 'take', '-configurationname': 'take', '-custompipename': 'take',
    '-encodedarguments': 'take',
    '-workingdirectory': 'read', '-psconsolefile': 'read',
    ...Object.fromEntries(['-noprofile', '-nologo', '-noninteractive', '-noexit', '-sta', '-mta',
        '-login', '-noprofileloadtime', '-help', '-?', '-version'].map(name => [name, 'nopath'])),
};
const INTERPRETER_ROWS = {
    python: { flags: PYTHON_FLAGS, stdin: ['-'] },
    python2: { flags: PYTHON_FLAGS, stdin: ['-'] },
    python3: { flags: PYTHON_FLAGS, stdin: ['-'] },
    py: { flags: PYTHON_FLAGS, stdin: ['-'] },
    node: { flags: NODE_FLAGS, stdin: ['-'] },
    nodejs: { flags: NODE_FLAGS, stdin: ['-'] },
    deno: {
        flags: { ...COMMON_SWITCHES, eval: 'code', run: 'nopath', test: 'nopath', bench: 'nopath',
            task: 'nopath', cache: 'nopath', info: 'nopath', doc: 'nopath', fmt: 'nopath',
            lint: 'nopath', compile: 'nopath', bundle: 'nopath', coverage: 'nopath',
            '--config': 'read', '--import-map': 'read', '--lock': 'read', '--cert': 'read',
            '--location': 'take', '--reload': 'take', '--allow-read': 'take', '--allow-write': 'take',
            '--allow-net': 'take', '--allow-env': 'take', '--allow-run': 'take' },
        stdin: ['-'],
    },
    bun: {
        flags: { ...COMMON_SWITCHES, '-e': 'code', '--eval': 'code', '-p': 'code', '--print': 'code',
            '-r': 'take', '--require': 'take', '--config': 'read',
            run: 'nopath', test: 'nopath', x: 'nopath', install: 'nopath', add: 'nopath',
            remove: 'nopath', update: 'nopath', pm: 'nopath', create: 'nopath', build: 'nopath',
            '--watch': 'nopath', '--hot': 'nopath', '--smol': 'nopath', '--bun': 'nopath' },
        stdin: ['-'],
    },
    perl: {
        flags: { ...COMMON_SWITCHES, '-e': 'code', '-E': 'code', '-M': 'take', '-m': 'take',
            '-I': 'read', '-x': 'nopath', '-w': 'nopath', '-W': 'nopath', '-T': 'nopath',
            '-t': 'nopath', '-c': 'nopath', '-l': 'nopath', '-0': 'take', '-d': 'take' },
        stdin: ['-'],
    },
    ruby: {
        flags: { ...COMMON_SWITCHES, '-e': 'code', '-r': 'take', '-I': 'read', '-C': 'read',
            '-S': 'take', '-x': 'nopath', '-w': 'nopath', '-W': 'nopath', '-d': 'nopath',
            '-T': 'take', '-E': 'take', '--enable': 'take', '--disable': 'take' },
        stdin: ['-'],
    },
    php: {
        flags: { ...COMMON_SWITCHES, '-r': 'code', '-f': 'script', '-c': 'read', '-z': 'read',
            '-d': 'take', '-B': 'code', '-R': 'code', '-E': 'code',
            '-a': 'nopath', '-i': 'nopath', '-l': 'nopath', '-m': 'nopath', '-v': 'nopath',
            '-n': 'nopath', '-s': 'nopath', '-w': 'nopath', '-H': 'nopath', '-S': 'take', '-t': 'read' },
        stdin: ['-'],
    },
    lua: {
        flags: { ...COMMON_SWITCHES, '-e': 'code', '-l': 'take', '-E': 'nopath', '-i': 'nopath',
            '-v': 'nopath', '-W': 'nopath' },
        stdin: ['-'],
    },
    tclsh: { flags: { ...COMMON_SWITCHES }, stdin: ['-'] },
    expect: { flags: { ...COMMON_SWITCHES, '-c': 'code', '-f': 'script', '-i': 'nopath',
        '-n': 'nopath', '-N': 'nopath', '-d': 'nopath', '-D': 'take' }, stdin: ['-'] },
    pwsh: { flags: POWERSHELL_FLAGS, stdin: ['-'], fold: true },
    powershell: { flags: POWERSHELL_FLAGS, stdin: ['-'], fold: true },
    sh: { flags: SHELL_FLAGS, stdin: ['-s'] },
    bash: { flags: BASH_FLAGS, stdin: ['-s'] },
    zsh: { flags: BASH_FLAGS, stdin: ['-s'] },
    dash: { flags: SHELL_FLAGS, stdin: ['-s'] },
    ksh: { flags: SHELL_FLAGS, stdin: ['-s'] },
    ash: { flags: SHELL_FLAGS, stdin: ['-s'] },
    fish: { flags: { ...SHELL_FLAGS, '-P': 'take' }, stdin: [] },
    cmd: {
        operands: 'nopath', fold: true,
        flags: { '/c': 'code', '/k': 'code', '/s': 'nopath', '/a': 'nopath', '/q': 'nopath',
            '/d': 'nopath', '/v': 'take', '/e': 'take', '/f': 'take', '/t': 'take', '/u': 'nopath' },
        stdin: [],
    },
    wsl: {
        operands: 'nopath',
        flags: { ...COMMON_SWITCHES, '-d': 'take', '--distribution': 'take', '-u': 'take',
            '--user': 'take', '--cd': 'take', '--shell-type': 'take',
            '-e': 'nopath', '--exec': 'nopath', '--list': 'nopath', '-l': 'nopath',
            '--terminate': 'take', '-t': 'take', '--shutdown': 'nopath', '-h': 'nopath' },
        stdin: [],
    },
};
for (const [name, spec] of Object.entries(INTERPRETER_ROWS)) {
    POSITIONS[name] = row(spec.operands ?? 'script', spec.flags ?? {}, 'absent', {
        interpreter: true,
        stdin: spec.stdin ?? [],
        fold: spec.fold === true,
    });
}

/** 解释器名单＝行数据派生的唯一一份；facts.js 不再手写第二份。 */
export const INTERPRETER_KEYS = new Set(Object.keys(INTERPRETER_ROWS));

const OPERAND_ROLES = new Set(['read', 'write', 'pattern', 'nopath', 'script']);
const OPTION_ROLES = new Set(['read', 'write', 'exec', 'script', 'take', 'key', 'pattern', 'nopath',
    'nav', 'secret', 'code', 'module']);

/** 行数据自检：返回错误清单（空＝通过）。测试调用，不在生产路径上抛错。 */
export function validateRows() {
    const errors = [];
    for (const [name, entry] of Object.entries(POSITIONS)) {
        if (entry === null || typeof entry !== 'object') {
            errors.push(`${name}: 行不是对象`);
            continue;
        }
        if (!OPERAND_ROLES.has(entry.operands))
            errors.push(`${name}: 操作数位 ${entry.operands}`);
        for (const [flag, def] of Object.entries(entry.flags ?? {})) {
            const role = typeof def === 'string' ? def : def?.pos;
            if (!OPTION_ROLES.has(role))
                errors.push(`${name} ${flag}: 选项位 ${role}`);
        }
        if (entry.stdin !== undefined
            && (!Array.isArray(entry.stdin) || entry.stdin.some(item => typeof item !== 'string')))
            errors.push(`${name}: stdin 不是字符串数组`);
        if (entry.fold !== undefined && typeof entry.fold !== 'boolean')
            errors.push(`${name}: fold 不是布尔`);
        if (entry.face !== undefined && !['name', 'body'].includes(entry.face))
            errors.push(`${name}: face ${entry.face}`);
        for (const [flag, face] of Object.entries(entry.faceFlags ?? {}))
            if (!['name', 'body'].includes(face))
                errors.push(`${name} ${flag}: faceFlags ${face}`);
        if (entry.interpreter === true && !Array.isArray(entry.stdin))
            errors.push(`${name}: 解释器缺 stdin 数组`);
    }
    return errors;
}

/** 解释器输入位：第一个要执行的东西是什么。
 *  `{kind:'file'}`＝脚本文件（`at` 是 words 下标）；`command`＝正文就在命令里；
 *  `module`＝模块名；`stdin`＝显式读标准输入；`end`＝没有脚本操作数；
 *  `uncertain`＝遇到没登记的选项，算不准它吞不吞下一个词。
 *  裸 `-` 已被词法从 words 里去掉（`python - <<EOF` 的 words 是空），
 *  `end` 由调用方按「有 heredoc ⇒ stdin」处理。 */
export function interpreterInputOf(program, words) {
    const entry = positionOf(program);
    if (entry === undefined)
        return { kind: 'none', at: -1 };
    const list = Array.isArray(words) ? words : [];
    const stdin = new Set(entry.stdin ?? []);
    const fold = entry.fold === true;
    const textOf = item => item !== null && typeof item === 'object' ? String(item.text ?? '') : String(item ?? '');
    const keyOf = text => fold === true ? text.toLowerCase() : text;
    for (let index = 0; index < list.length; index += 1) {
        const text = textOf(list[index]);
        if (text === '')
            continue;
        if (text === '--')
            return index + 1 < list.length ? { kind: 'file', at: index + 1 } : { kind: 'end', at: index + 1 };
        if (stdin.has(text) || text === '-')
            return { kind: 'stdin', at: index };
        const slash = text.startsWith('//') === true ? '/' + text.slice(2) : '';
        const key = slash !== '' && entry.flags[slash] !== undefined ? slash : keyOf(text);
        const def = entry.flags[key];
        if (def === undefined) {
            if (text.startsWith('-') === true)
                return { kind: 'uncertain', at: index, flag: text };
            if (entry.operands === 'nopath')
                return { kind: 'none', at: index };
            return { kind: 'file', at: index };
        }
        const role = typeof def === 'string' ? def : def.pos;
        const { flag, value, attached } = splitFlag(text);
        if (role === 'code')
            return { kind: 'command', at: index, flag, attached: attached === true,
                value: attached === true ? value : (index + 1 < list.length ? textOf(list[index + 1]) : undefined) };
        if (role === 'module') {
            if (attached !== true && index + 1 < list.length)
                index += 1;
            return { kind: 'module', at: index };
        }
        if (role === 'script') {
            if (attached === true && value !== undefined)
                return { kind: 'file', at: index, viaFlag: true, attached: true, value };
            if (index + 1 < list.length)
                return { kind: 'file', at: index + 1, viaFlag: true, attached: false };
            return { kind: 'uncertain', at: index, flag };
        }
        // 取值位：下一个词是它的值，不是脚本；开关位（nopath／nav）不吃下一个词。
        if (['read', 'write', 'take', 'exec', 'key', 'pattern', 'secret'].includes(role)
            && attached !== true && list[index + 1] !== undefined)
            index += 1;
    }
    return { kind: 'end', at: list.length };
}

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
    // cmdlet 与解释器行（`fold:true`，如 pwsh）的参数名大小写不敏感。
    if (isCmdletName(program) || entry.fold === true) {
        // `-Path`／`-PATH` 是同一个参数；`-Path:C:\x` 的冒号也是取值写法。
        candidates.push(plain.toLowerCase());
        const colon = /^-([A-Za-z][A-Za-z0-9-]*):/.exec(text);
        if (colon !== null)
            candidates.push(`-${colon[1].toLowerCase()}`);
    }
    for (const key of candidates) {
        const def = entry.flags[key];
        if (def !== undefined)
            return typeof def === 'string' ? def : def.pos;
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

/** 秘密值位（secret）的取值清单——证据／台账遮罩用，与 readFlagsOf／writeFlagsOf 平行。
 *  attachedOnly 的旗标仅附着取值才算秘密（mysql `-pPass` 遮 Pass；`-p mydb` 分开写时
 *  -p 是开关、mydb 落回操作数不遮）。返回字面值数组；表外程序／无 secret 旗标⇒空。
 *  取值写法（`-pPass`／`--password=Pass`／`--password Pass`）由 splitFlag 通用拆解。 */
export function secretValuesOf(program, words) {
    const entry = positionOf(program);
    if (entry === undefined)
        return [];
    const list = Array.isArray(words) ? words : [];
    const out = [];
    for (let index = 0; index < list.length; index += 1) {
        const text = String(list[index]);
        if (text === '--')
            break;
        const { flag, value, attached } = splitFlag(text);
        const def = entry.flags[flag];
        const isSecret = def !== undefined && (typeof def === 'string' ? def === 'secret' : def.pos === 'secret');
        if (isSecret !== true)
            continue;
        if (attached === true && value !== undefined && value !== '') {
            out.push(value);
            continue;
        }
        if (typeof def === 'object' && def.attachedOnly === true)
            continue;
        const next = list[index + 1];
        if (next !== undefined && String(next) !== '') {
            out.push(String(next));
            index += 1;
        }
    }
    return out;
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