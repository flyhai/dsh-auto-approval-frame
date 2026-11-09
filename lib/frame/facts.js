// AI生成
// L0 facts: read the filesystem and git, describe the action, decide nothing.
// Everything the reviewer cannot see is invisible to it, so this is the only
// module allowed to touch fs/git, and its output is the reviewer's whole world.
import { createHash } from 'node:crypto';
import { lstatSync, realpathSync, readdirSync, readFileSync } from 'node:fs';
import { hostname } from 'node:os';
import { spawnSync } from 'node:child_process';
import { normalizePath, isWithin, pathApiFor, basenameOf, isLocalDeviceNamespace, foldsCase } from './paths.js';
import { splitSegments, assignedNames, isDynamic, normalizeProgram, nativeNameOf, redirectReads, inlineCodeEffects, expandClosedShell, isNativeSwitch } from './parse.js';
import { splitCommandSegments } from './syntax.js';
import { matchPath, parseRules } from './policy.js';
import { execFlagsOf, faceOf, flagPositionOf, flagValues, isCmdletName, operandsOf, positionOf, readFlagsOf, splitFlag, writeFlagsOf } from './positions.js';
import { isSkillDoc } from './scope.js';
import { isSensitiveBasename, neverReasonsFor } from './grant.js';
import { createSourceRootStore } from './source-roots.js';

export const MAX_TARGETS = 20;

// 会话级源根绑定只有这一份进程内状态（注入点＝index 把 sessionId 挂到 authorization 上）。
const sourceRoots = createSourceRootStore();

const SHELL_TOOLS = new Set(['bash', 'shell', 'terminal', 'pwsh', 'powershell', 'cmd', 'run_command', 'execute_command']);
// Session bookkeeping: they edit the conversation (fold / unfold / todo), never
// the disk or the network. Exact names only — a tool that merely contains
// "compress" must stay classified by its own name.
// 这些程序的「操作数」可能落在远端：ssh/scp/rsync/sftp/nc/telnet。
const REMOTE_PROGRAMS = new Set(['ssh', 'scp', 'sftp', 'rsync', 'nc', 'telnet', 'plink', 'pscp', 'psftp']);
const REMOTE_TARGET = /^(?:([\w.-]+)@)?([A-Za-z0-9.-]+):(.+)$/;
const hostOfOperand = text => {
    const value = String(text ?? '');
    const match = /^(?:([\w.-]+)@)?([A-Za-z0-9.-]+)(?::\d+)?$/.exec(value);
    return (match?.[2] ?? value).toLowerCase();
};
const PATH_KEYS = ['path', 'file_path', 'notebook_path', 'target', 'filename', 'abs_path', 'filePath'];

// 外传＝把本机内容送到这台机器外面，而事实层看不见外面发生了什么。族名与命令面上的
// 预设行一一对应（一行一个族，可换档、可停用），这里只报「命中了哪一族」，不报档位。
const CURL_UPLOAD_FLAGS = /^(-T|--upload-file|-F|--form)$/i;
const CURL_BODY_FLAGS = /^(-d|--data(?:-raw|-binary|-urlencode)?)$/i;
// 取值的正文可能来自本地文件：`-d @file`（@ 前缀）与 `-T file`（直接是路径）。
const CURL_FILE_FLAGS = new Set(['-d', '--data', '--data-binary', '--data-raw', '-F', '--form', '-T', '--upload-file']);
// 取值写法（`-Tf`／`--data-binary=@file`）统一由 parse.splitFlag 拆开（A01）。

// 云存储：方向要看位置，不能一看到 `s3 cp` 就报上传——`aws s3 cp s3://b/k ./local` 是往下拉。
const CLOUD_URI = /^(?:s3|gs|azure-blob|https?:\/\/[\w.-]*(?:storage|blob|s3|amazonaws))[+:/]/i;
// 这些旗标带**取值**，取值不是位置参数。旧形把 `--endpoint-url http://127.0.0.1:9000`
// 的取值当成最后一个位置参数 ⇒ `aws s3 cp a.zip s3://b/k --endpoint-url …` 判成下行，
// 上传本机 minio 于是被当「远端下载」放行。只吃登记过的旗标（同 parse.flagValues 的口径：
// 对所有词套附值规则会把 `--region` 之外的单横线长选项读错）。
const VALUE_TAKING_FLAGS = new Set(['--endpoint-url', '--endpoint', '--registry', '--repository-url',
    '--server-url', '--index-url', '--region', '--profile', '--user-agent']);

/** 去掉旗标与旗标取值后的位置参数（方向按这一串算，不按原始词序）。 */
function positionalWords(words) {
    const out = [];
    for (let index = 0; index < words.length; index += 1) {
        const text = String(words[index]);
        if (VALUE_TAKING_FLAGS.has(text)) {
            index += 1;
            continue;
        }
        if (!text.startsWith('-'))
            out.push(text);
    }
    return out;
}

function cloudExfilDirection(words) {
    const last = String(positionalWords(words).at(-1) ?? '');
    return last !== '' && CLOUD_URI.test(last);
}

// 45：`git push` 的目标是不是真远端——pushspec 是本机路径（../x、./x、/x、C:\x）或
// file:/// ⇒ 内容不出本机，不算外传；裸远端名（origin）与带主机的 URL 仍是外传
// （fail-safe：证明不了本机就按远端算； 起「落在谁的机器上」由目的地档位分档）。
function gitPushTargetIsRemote(words) {
    const at = words.indexOf('push');
    const target = String(words[at + 1] ?? '');
    if (target === '')
        return true;                     // 无 pushspec＝用默认远端（通常是 origin）
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target))   // URL 形：只有 file:// 算本机
        return !/^file:\/\//i.test(target);
    if (target.includes('@'))
        return true;                     // scp 形 git@host:path
    return !/^(?:\.{1,2}[\/\\]|[\/\\]|[a-z]:[\/\\])/i.test(target);
}

const EXFIL_MATCHERS = [
    {
        preset: 'exfil:git-push',
        // 45：本地路径/file:///localhost 的 pushspec 不算外传（44 冤弹 1）；远端名/带主机 URL 照旧。
        test: (program, words) => program === 'git' && words.includes('push') && gitPushTargetIsRemote(words),
    },
    {
        preset: 'exfil:curl-upload', test: (program, words) => program === 'curl' && words.some((word, index) => {
            const { flag, value } = splitFlag(word);
            if (CURL_UPLOAD_FLAGS.test(flag))
                return true;
            if (!CURL_BODY_FLAGS.test(flag))
                return false;
            // 正文从文件里取（`@file`）＝把内容送出去，无论值attach在哪一侧。
            return value !== undefined ? value.startsWith('@')
                : String(words[index + 1] ?? '').startsWith('@');
        }),
    },
    {
        preset: 'exfil:cloud-storage', test: (program, words) => (program === 'aws'
            && (words.includes('s3') || words.includes('s3api'))
            && words.some(word => ['cp', 'sync', 'upload', 'upload-file', 'put-object', 'copy'].includes(word))
            && cloudExfilDirection(words))
            || (program === 'gsutil' && words.some(word => ['cp', 'rsync', 'mv'].includes(word))
                && cloudExfilDirection(words))
            || (program === 'az' && words.includes('storage') && words.includes('blob')
                && words.some(word => word.startsWith('upload'))),
    },
    {
        preset: 'exfil:oci-push', test: (program, words) => (['docker', 'podman', 'nerdctl'].includes(program)
            && words.includes('push'))
            // 同一件事的另外三个入口：oras 推制品、skopeo 搬镜像、helm 推 chart。
            // 漏了它们，`oras push reg/x:1` 会落表里那行通用的 ai，比 docker push 松一档。
            || (program === 'oras' && words.includes('push'))
            || (program === 'skopeo' && words.includes('copy'))
            || (program === 'helm' && words.includes('push')),
    },
    {
        preset: 'exfil:package-publish', test: (program, words) => (['npm', 'pnpm', 'yarn', 'bun', 'cargo'].includes(program)
            && words.includes('publish'))
            || (program === 'twine' && words.includes('upload')),
    },
    {
        preset: 'exfil:release', test: (program, words) => program === 'gh' && words.includes('release')
            && words.some(word => ['create', 'upload', 'edit'].includes(word)),
    },
];

function exfilOf(segment) {
    const program = String(segment.program ?? '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
    // 这里读的是 collectFacts 投影后的段：`words` 已经是按序的字面量（含 flag）。
    const words = segment.words ?? [];
    const presets = EXFIL_MATCHERS.filter(matcher => matcher.test(program, words)).map(matcher => matcher.preset);
    // 脚本正文里自己发包：程序名看不出来，但正文里有发送动作和目的主机。
    if (segment.scriptUpload === true)
        presets.push('exfil:script-upload');
    return presets;
}

// ── 脚本正文里的外传（正文可见的那几种：`-c` 内联、heredoc 喂 stdin、脚本文件）──
// 只认「把内容送出去」：POST／PUT／表单／云上传／发信这些。**只连不发**的脚本
// （测延迟、端口探测、TLS 握手）不在此列——它们没有数据显示离开本机。
const SCRIPT_SEND_MARKERS = [
    /\.(?:post|put|patch)\s*\(/i,
    /\.(?:send|sendall|sendto)\s*\(/i,
    /(?:urlopen|urlretrieve|Request)\s*\([^)]*\bdata\s*=/is,
    /\bmethod\s*[:=]\s*['"]?(?:POST|PUT|PATCH)\b/i,
    /-Method\s+['"]?(?:POST|PUT|PATCH)\b/i,
    /['"](?:POST|PUT|PATCH)['"]\s*,/i,
    /\b(?:upload_file|upload_fileobj|put_object|putObject|storbinary|storlines|storeFile|uploadFile)\s*\(/i,
    /\b(?:smtplib|ftplib|paramiko)\b/i,
    /\bcurl\b[^\n]{0,120}(?:\s-T\b|\s-d\b|\s-F\b|--upload-file|--data)/i,
];
const SCRIPT_URL = /\b(?:https?|ftp):\/\/[^\s"'`)]+/gi;
const SCRIPT_IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
// 纯十进制三／四组是时间码（冒号分隔的时分秒），不是 IPv6：带 `::` 的按压缩形收，
// 不带 `::` 的必须是完整八组。
const SCRIPT_IPV6 = /(?<![\w:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])/gi;
// 裸域名只认**整段引号里的字面量**且全小写：`'www.baidu.com'` 是主机，
// `pathlib.Path` 这种属性链不在引号里、也不全小写，不当主机。
const SCRIPT_QUOTED = /'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"/g;
const SCRIPT_HOST_LITERAL = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?$/;
// 引号里的文件名不是主机：`'config.json'`、`'notes.txt'` 这些 TLD 形状的扩展名不进来。
const SCRIPT_FILE_EXT = new Set(['py', 'pyc', 'pyo', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx',
    'json', 'jsonl', 'txt', 'md', 'markdown', 'yml', 'yaml', 'toml', 'ini', 'cfg', 'conf',
    'log', 'csv', 'tsv', 'xml', 'html', 'htm', 'css', 'scss', 'less', 'sh', 'bash', 'zsh',
    'ps1', 'bat', 'cmd', 'exe', 'dll', 'so', 'dylib', 'bin', 'dat', 'db', 'sqlite', 'png',
    'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'webp', 'ico', 'zip', 'tar', 'gz', 'bz2', 'xz',
    '7z', 'rar', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'ipynb', 'lock',
    'tmp', 'bak', 'env', 'pem', 'key', 'crt']);
const SCRIPT_SCAN_MAX = 200_000;

function isIpv4(text) {
    return String(text).split('.').every(part => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function scriptSendsData(text) {
    return SCRIPT_SEND_MARKERS.some(pattern => pattern.test(text));
}

/** 脚本正文里的目的主机：带 scheme 的 URL、IPv4／IPv6、引号里的裸域名字面量。 */
function scriptNetworkTargets(text) {
    const source = String(text ?? '');
    const out = [];
    for (const raw of source.match(SCRIPT_URL) ?? []) {
        try {
            const host = new URL(raw).hostname;
            if (host !== '')
                out.push(host.toLowerCase());
        }
        catch {
            // 形状像 URL 但解析不出来：不收——主机名抽不出就不编一个。
        }
    }
    for (const raw of source.match(SCRIPT_IPV4) ?? [])
        if (isIpv4(raw))
            out.push(raw);
    for (const raw of source.match(SCRIPT_IPV6) ?? []) {
        const valid = raw.includes('::')
            ? raw.split(':').length >= 3
            : raw.split(':').length === 8;
        if (valid)
            out.push(raw.toLowerCase());
    }
    SCRIPT_QUOTED.lastIndex = 0;
    let match;
    while ((match = SCRIPT_QUOTED.exec(source)) !== null) {
        const value = String(match[1] ?? match[2] ?? '').trim();
        if (value === '' || value.length > 253)
            continue;
        if (SCRIPT_HOST_LITERAL.test(value)) {
            const host = value.replace(/:\d{1,5}$/, '');
            const labels = host.split('.');
            if (labels.length >= 2 && !SCRIPT_FILE_EXT.has(labels.at(-1)))
                out.push(host);
            continue;
        }
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) && isIpv4(value))
            out.push(value);
    }
    return [...new Set(out.filter(host => host !== ''))];
}

/** 取这段脚本的正文：内联代码／heredoc 正文／解释器的脚本文件（读不到就当没有）。 */
function scriptTextOf(segment, program, probe, cwd, roots) {
    const parts = [];
    if (segment.execFamily === 'inline') {
        for (const item of inlineCodeArgs(program, segment.words))
            parts.push(String(item.value ?? ''));
    }
    else if (segment.scriptFromStdin === true) {
        parts.push(String(segment.heredocText ?? ''));
    }
    else if (segment.execFamily === 'interpreter') {
        const at = interpreterScript(program, segment.words);
        const raw = at === -1 ? '' : String(segment.words[at] ?? '');
        // 工作目录不确定时读不到脚本文件：不拿 process.cwd() 或 workspace 去替它猜一个。
        if (raw !== '' && isDynamic(raw) !== true && typeof cwd === 'string' && cwd !== '') {
            try {
                const abs = normalizePath(raw, cwd, roots.home);
                const stat = probe.lstat(abs);
                if (stat !== undefined && stat !== null && Number(stat.size ?? 0) <= SCRIPT_SCAN_MAX
                    && typeof probe.read === 'function')
                    parts.push(String(probe.read(abs) ?? ''));
            }
            catch {
                // 读不到脚本（不存在／没权限／是个目录）＝这一步没有正文可判，
                // 解释器自己会报错；不在这里替它编一个。
            }
        }
    }
    const text = parts.join('\n');
    return text.length > SCRIPT_SCAN_MAX ? text.slice(0, SCRIPT_SCAN_MAX) : text;
}

// 读族拆成两列，但**「算不算读类」只由下面的并集 `READ_PROGRAMS` 决定**（两列各自维护过，
// `md5sum`／`strings` 这一族在 `FILE_READ_PROGRAMS` 里、不在读族里 ⇒ 动作落 `exec`，
// 而 `policy.js` 的 `OP_CLASSES` 把 `exec` 记成写 ⇒ 一条纯读命令撞上写档行弹到人）。
// 这一列是「首个操作数是模式／不读具体文件」的读类。
const READ_OTHER_PROGRAMS = new Set(['ls', 'dir', 'grep', 'egrep', 'rg', 'find',
    'fd', 'tree', 'which', 'where',
    'pwd', 'echo', 'printf', 'date', 'hostname', 'whoami', 'id', 'du', 'df', 'free', 'env', 'printenv', 'test',
    'true', 'false', 'git', 'uptime', 'ps', 'stat']);
// Navigation only moves the shell; it never touches the filesystem. It used to
// fall through to `exec`, and since a real command line is usually
// `cd dir && grep ... | head -20`, that one token was enough to send a purely
// read-only action to the reviewer.
const NAVIGATE_PROGRAMS = new Set(['cd', 'pushd', 'popd', 'chdir']);
// 不写路径也读**当前目录**的程序（`git status`／`ls`／`rg TODO`／`find`）：
// 读面就是 cwd 这棵树，事实层要把这一格记成目标，不能留一张空表还说「已证明只读」。
const DEFAULT_CWD_READERS = new Set(['ls', 'du', 'tree', 'git', 'rg', 'find', 'fd']);
// 操作数就是路径、不看扩展名的程序（`ls sub`、`du sub` 里的 `sub`）。
const DIRECTORY_PROGRAMS = new Set(['ls', 'du', 'df', 'tree']);
/** * 只会**带回名字**的程序族——列目录族（shell 的 ls／dir／tree／du／df）与宿主在册的
 * 目录型读工具（read／list_dir／glob 指到目录时返回的是条目清单，不是文件正文）。
 * 这是一把白名单而不是黑名单：`cat`／`head` 打开目录只会报错，`grep`／`rg` 带回的是
 * **命中行的正文**，`git log` 带回的是提交说明——都不在这一族里，宁可少放一格，
 * 也不给区外正文开一条缝。配合 kind==='dir' 一起用（structureOnlyOf）；
 * `find` 的默认输出也是名字，但它带执行／删除参数时不再算列名（见 structureOnlyOf）。
 */
const LISTING_PROGRAMS = new Set(['ls', 'dir', 'du', 'df', 'tree', 'read', 'list_dir', 'glob', 'find']);

/** * 解释器后面的脚本位置（判据 2a）：跳过旗标与它们的内联代码值（`-c`／`-m`／`-e`），
 * 第一个普通词就是被执行的那份脚本。返回它在 words 里的下标，没有则 -1。
 */
function interpreterScript(program, words) {
    const inline = new Set(INLINE_CODE_FLAGS[program] ?? []);
    const codeAt = new Set(inlineCodeArgs(program, words).map(item => item.index));
    for (let at = 0; at < words.length; at += 1) {
        const text = String(words[at]);
        // 内联代码位（含 `-m`／`-r` 的取值）不是「被执行的那份脚本」：
        // 旧形只认小写旗标，`powershell -Command "…"` 于是把代码串当成了脚本路径。
        if (codeAt.has(at))
            continue;
        // `cmd //c "…"`／`cmd /c "…"`：斜杠开关不是脚本路径；`/c`／`/k` 后面那段
        // 是内联命令，不是脚本文件。`//c` 是 Git Bash 写法，按 `/c` 归一。
        if (isNativeSwitch(text, program)) {
            const normalized = text.toLowerCase().replace(/^\/\//, '/');
            const { attached } = splitFlag(text);
            if (inline.has(normalized) && !attached)
                at += 1;
            continue;
        }
        // 裸 `-`＝脚本从 stdin 读（`python - [脚本参数] <<'EOF'`）：后面的词是脚本
        // 自己的 argv，不是脚本文件。漏了这一格，正文明明在命令里，却因为把那个
        // 参数当成脚本文件而报「脚本文本没送评审」。
        if (text === '-')
            return -1;
        if (!text.startsWith('-'))
            return at;
        const { flag, attached } = splitFlag(text);
        const name = flag.toLowerCase();
        if (inline.has(name)) {
            if (!attached)
                at += 1;    // `-c "…"`／`-m pkg`：后面的值是代码或模块名，不是脚本文件
            continue;
        }
        if (name === '-file')
            return at + 1;
    }
    return -1;
}
// 递归读面枚举的三个上限（判据 4）：触顶就必须如实标 truncated，不许当扫干净。
const SCOPE_LIMITS = { depth: 4, visited: 800, files: MAX_TARGETS };
// For these the first non-flag operand is a SEARCH PATTERN, not a path.
// `grep -rn 'file|path|dir' .` used to resolve to two paths, one of them
// `c:\...\file|path|dir` — which then showed up in the ledger and in the
// evidence block the reviewer reads.
const PATTERN_PROGRAMS = new Set(['grep', 'egrep', 'rg']);
// `grep -f PATTERN_FILE x.txt` 的第一个操作数**就是文件**（模式从那儿读），不能再无条件跳过；
// 递归开关（-r／-R）读的是一个子树，事实层没列举过里面的文件，就不许冒充「只读了目录」。
const PATTERN_FILE_FLAGS = new Set(['-f', '--file', '--patterns-from']);
const RECURSIVE_READ_FLAGS = /^(?:-[a-zA-Z]*[rR][a-zA-Z]*|--recursive|--recurse)$/;
// 读族里「操作数就是被读的文件」的程序：无扩展名（README／Makefile／CNAME）也照样是目标。
// 不放进这一族的：grep／rg（首个操作数是模式）、find（表达式里的值不是路径）、git（子命令与分支名）。
const FILE_READ_PROGRAMS = new Set(['cat', 'type', 'head', 'tail', 'less', 'more', 'wc', 'sort', 'uniq', 'sed',
    'cut', 'tr', 'strings', 'xxd', 'od', 'base64', 'md5sum', 'sha1sum', 'sha256sum', 'stat', 'file',
    'diff', 'cmp', 'tac', 'nl', 'column', 'paste', 'join', 'comm', 'expand', 'unexpand', 'fold', 'fmt']);
// 读族的**唯一真相**＝这两列的并集；任何一处再单独维护成员，就会重演那次分裂。
const READ_PROGRAMS = new Set([...READ_OTHER_PROGRAMS, ...FILE_READ_PROGRAMS]);
// PowerShell 原生只读 cmdlet：名字不与 POSIX 同形，但动作用的就是「读」。
// 这里只回答效果面（opClass）；放不放行由命令面各自那一行说话。
// 能跑脚本块的那几个（Select-Object／Where-Object…）也在这里——它们不改文件；
// 命令面按「能执行代码」给 AI 档，效果面与档位是两个轴。
const NATIVE_READ_PROGRAMS = new Set(['get-childitem', 'get-content', 'get-item', 'test-path',
    'resolve-path', 'get-filehash', 'select-string', 'import-csv', 'import-clixml',
    'get-itemproperty', 'get-acl', 'measure-object', 'compare-object', 'get-process', 'get-command',
    'get-location', 'set-location', 'push-location', 'pop-location', 'write-output', 'write-host',
    'select-object', 'where-object', 'sort-object', 'group-object', 'format-table', 'format-list',
    'format-wide', 'format-custom', 'out-string']);
// 这些程序「前几个操作数是源、最后一个是目的」：`cp a b` 的 a 是读、b 才是写。
const COPY_PROGRAMS = new Set(['cp', 'mv', 'install', 'rsync', 'scp', 'sftp',
    'ln', 'link', 'robocopy', 'xcopy']);
// 解释器：第一个非旗标操作数是**被执行脚本**（读），不是写目标（判据 2a）。
// 带内联代码旗标时（`python -c`／`bash -c`／`node -e`）没有脚本文件。
const INTERPRETER_PROGRAMS = new Set(['python', 'python2', 'python3', 'py', 'node', 'nodejs', 'deno', 'bun',
    'perl', 'ruby', 'php', 'lua', 'tclsh', 'expect', 'pwsh', 'powershell', 'sh', 'bash', 'zsh', 'dash',
    'fish', 'cmd', 'wsl']);const INLINE_CODE_FLAGS = {
    python: ['-c', '-m'], python2: ['-c', '-m'], python3: ['-c', '-m'], py: ['-c', '-m'],
    node: ['-e', '--eval', '-p', '--print', '-r', '--require'],
    nodejs: ['-e', '--eval', '-p', '--print', '-r', '--require'],
    deno: ['eval'], bun: ['-e', '--eval'],
    perl: ['-e'], ruby: ['-e'], php: ['-r'], lua: ['-e'],
    sh: ['-c'], bash: ['-c'], zsh: ['-c'], dash: ['-c'], fish: ['-c'], ksh: ['-c'], ash: ['-c'],
    pwsh: ['-c', '-command', '-encodedcommand'], powershell: ['-c', '-command', '-encodedcommand'],
    // cmd.exe 用斜杠形；`/k` 保留窗口，同样是「后面那段是命令」。
    cmd: ['/c', '/k'],
};
// `-m pkg`／`-r module` 的取值是**模块名或模块路径**，不是一段可以抠实参的代码正文：
// 照样不当脚本文件，但不进内联代码解析（否则 `python -m pytest` 白背一条「代码看不懂」）。
// 按方言分：php 的 `-r` 恰恰是代码，全局一刀切会把 `php -r "echo 1;"` 判成来源不可举证。
const INLINE_CODE_NOT_SOURCE = {
    python: ['-m'], python2: ['-m'], python3: ['-m'], py: ['-m'],
    node: ['-r', '--require'], nodejs: ['-r', '--require'],
};
// POSIX shell 的 `-c` 后面是一整条命令行：递归展开成它自己的段，比抠字面量准。
// 只展开一层——内层再套 `bash -c` 由不透明那一格说话，不做递归下降。
const POSIX_SHELL_INLINE = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash']);
// PowerShell 的代码语法与 python／node 不同（命令名＋`-Path` 旗标），按方言分派。
const INLINE_CODE_DIALECT = { pwsh: 'powershell', powershell: 'powershell' };
// `-EncodedCommand` 是 UTF-16LE 的 base64：解出来才看得见它读什么文件。
// 解不动就原样交给不透明那一格——代码串本身照样在证据里，只是抠不出实参。
function decodeEncodedCommand(text) {
    try {
        return Buffer.from(String(text ?? ''), 'base64').toString('utf16le');
    }
    catch {
        return String(text ?? '');
    }
}
/** * 解释器参数里的**内联代码位**（判据 31）：`-c`／`-e`／`-Command` 的取值是代码正文。
 * 整词先认——`powershell -Command "…"` 走 splitFlag 会被拆成「-C ＋ ommand」，
 * 于是那个代码串被当成脚本文件读进来（28 实测的 `script-read` 形状）。
 */
function inlineCodeArgs(program, words) {
    const names = new Set((INLINE_CODE_FLAGS[program] ?? []).map(name => String(name).toLowerCase()));
    const out = [];
    for (let index = 0; index < words.length; index += 1) {
        const text = String(words[index]);
        // 旗标一般是 `-x` 形，但 `deno eval` 是不带横线的子命令：名字登记了就认，
        // 否则代码串取不到，静态可读的一行会被当成「来源不可举证」升人。
        // `cmd //c` 是 Git Bash 的写法：按 `/c` 归一后再查表，否则后面那段命令
        // 会被当成脚本路径铸成假目标。
        const lower = text.toLowerCase();
        const normalized = lower.replace(/^\/\//, '/');
        if (!text.startsWith('-') && names.has(lower) === false && names.has(normalized) === false)
            continue;
        if (names.has(lower) || names.has(normalized)) {
            const flag = names.has(lower) ? lower : normalized;
            const value = words[index + 1];
            if (value !== undefined && String(value) !== '')
                out.push({ flag, value: String(value), index: index + 1, attached: false });
            index += 1;
            continue;
        }
        const eq = /^(--?[A-Za-z0-9_-]+)=(.*)$/s.exec(text);
        if (eq !== null && eq[2] !== '' && names.has(eq[1].toLowerCase())) {
            out.push({ flag: eq[1].toLowerCase(), value: eq[2], index, attached: true });
            continue;
        }
        const attached = /^(-[A-Za-z])(.+)$/s.exec(text);
        if (attached !== null && names.has(attached[1].toLowerCase()))
            out.push({ flag: attached[1].toLowerCase(), value: attached[2], index, attached: true });
    }
    const skip = new Set(INLINE_CODE_NOT_SOURCE[program] ?? []);
    return out.filter(item => skip.has(item.flag) === false);
}
// 「参数取值是一张文件清单」的旗标：`wc --files0-from=list`、`tar -T list`、`xargs -a list`。
// 旧形把前两个当**写目标**（一读一写差一个方向，档位整条错），现在单列 read-manifest
// 并展开清单里列的读面（判据 2d）。
const MANIFEST_FLAGS = {
    wc: new Set(['--files0-from']),
    tar: new Set(['-T', '--files-from']),
    xargs: new Set(['-a', '--arg-file']),
};
// 写出效果写在**参数的取值里**的旗标（A01）：`sort --output=x`／`-ox`／`--output x`
// 与 `sort -o x` 是同一条语义，只看完整词就整条漏判。
// `xxd -r` 按位置参数还原成文件（`xxd -r in.hex out.bin`），旗标藏在动作里而不是取值里。
const RECOVER_FLAGS = new Set(['-r', '--recover']);
const FIND_EXEC_FLAGS = new Set(['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprintf', '-fprint0', '-fls']);
// Stream filters: read stdin, write stdout. They are state-changing only when
// they rewrite their input in place, which is a separate check below.
const FILTER_PROGRAMS = new Set(['awk', 'gawk', 'mawk', 'sed', 'jq', 'yq']);
const IN_PLACE_EDIT_FLAGS = /^(?:-i|--in-place)/;
const DELETE_PROGRAMS = new Set(['rm', 'unlink', 'trash']);

// 一个词只有「长得像路径」才当文件目标看（判据本体在下面，整词判定再收一道）。
const looksLikePath = text => /[\\/]/.test(text) || text.startsWith('.') || text.startsWith('~')
    || /\.[A-Za-z][A-Za-z0-9]{0,7}$/.test(text);
// 单个文件名不可能含的字符（Windows 非法名＋控制符）：整句正文常带 `||`／引号，
// 用它们把「一句话」挡在路径之外——`--set '… ~/.dsh/AGENTS.md …'` 提到路径也不是路径。
const NOT_A_PATH_CHAR = /[|<>"\u0000-\u001F]/;
// 整词是路径才算：长得像路径、且整词不含上述字符。不存在的真路径（`--path ../local-crate`）照旧算。
const wholeWordPath = text => looksLikePath(text) && NOT_A_PATH_CHAR.test(text) === false;
// 不像路径但名字本身就是凭据的（`cat id_rsa`、`head secrets`）必须仍然当目标——
// 漏了它，凭据防线会因为一个没有斜杠的名字而失效。
const sensitiveOperand = text => isSensitiveBasename(String(text).split(/[\\/]/).pop());
// 远端 URI 与镜像引用不是本地路径（历史误折）：`s3://bucket/key`、`https://host/p` 曾被折成
// `…\https:\host\p`，还带着 `rootHit=workspace` 送给模型看，等于把外传伪装成区内文件。
const REMOTE_URI = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]+)/i;
// registry 引用只有「会往机器外送东西」的程序才认——否则工作区里一个名为 `foo.bar/baz`
// 的目录会被误判成远端，丢掉真正的目标。
const OCI_REFERENCE = /^(?:[\w-]+\.)+[a-z]{2,}(?::\d+)?\/[^\s]+$/i;
const PUSH_CAPABLE = new Set(['docker', 'podman', 'nerdctl', 'skopeo', 'oras', 'helm', 'aws', 'gsutil', 'az']);
const DESTROY_PROGRAMS = new Set(['shred', 'dd', 'mkfs', 'fdisk', 'wipefs', 'format', 'cipher']);
const PRIVILEGE_PROGRAMS = new Set(['sudo', 'runas', 'chmod', 'chown', 'cacls', 'icacls', 'reg', 'netsh', 'sc', 'setfacl', 'takeown']);
const VCS_HISTORY_PROGRAMS = new Set(['git', 'hg', 'svn']);
// 会改动东西的程序：操作数即使不像路径也当目标（`rm README`、`mv out dir` 这类无扩展名目标）。
// 读类程序不在这里——它们的 `--line 10`、`--label 决定·面板` 曾被折成 `…\10`、`…\决定·面板`
// 这样的"工作区文件"，一条文档批因此挂着四条理由弹框（历史误折）。
const MUST_TARGET_PROGRAMS = new Set([...DELETE_PROGRAMS, ...DESTROY_PROGRAMS, ...PRIVILEGE_PROGRAMS,
    'mv', 'cp', 'touch', 'mkdir', 'tee', 'sed', 'awk', 'tar', 'zip', 'unzip',
    'install', 'ln', 'link', 'scp', 'rsync', 'sftp', 'notepad', 'set-content']);

// 服务／装包程序的第一词是**子命令**（`systemctl restart`、`pip install`），不是目标。
// 不跳它，台账会把 `restart` 记成「工作区\restart」这种假目标，等于用噪声换掉了空缺。
const SUBCOMMAND_WORDS = {
    systemctl: new Set(['start', 'stop', 'restart', 'reload', 'status', 'enable', 'disable',
        'is-active', 'is-enabled', 'daemon-reload', 'list-units', 'list-unit-files', 'mask', 'unmask']),
    docker: new Set(['start', 'stop', 'restart', 'run', 'rm', 'rmi', 'ps', 'build', 'pull', 'push',
        'exec', 'logs', 'inspect', 'images', 'compose', 'tag', 'commit']),
    'apt-get': new Set(['install', 'remove', 'purge', 'update', 'upgrade', 'dist-upgrade', 'autoremove']),
    apt: new Set(['install', 'remove', 'purge', 'update', 'upgrade', 'autoremove']),
    pip: new Set(['install', 'uninstall', 'download', 'list', 'wheel']),
    pip3: new Set(['install', 'uninstall', 'download', 'list', 'wheel']),
};

// 服务／进程族与装／构建族——它们的作用是**变更**（起停服务、杀进程、装／构建依赖），
// 记 write 让台账直接读得出「这一段在改什么」；目标抽取靠 MUST_TARGET_PROGRAMS 与 SUBCOMMAND_WORDS。
const PROCESS_PROGRAMS = new Set(['systemctl', 'kill', 'pkill', 'docker', 'podman', 'nerdctl', 'crictl',
    'service', 'systemd-run']);
const PACKAGE_PROGRAMS = new Set(['pip', 'pip3', 'apt-get', 'apt', 'npm', 'pnpm', 'yarn', 'cargo', 'make', 'go', 'brew']);
// shell 内建的变量赋值（`export PATH=…`）：操作数是「名字=值」，不是路径。它既不写盘也不执行，
// 铸成目标只会让值里的 `$PATH` 把整条命令记成「动态执行目标」，同一份 allow 因此算不稳、降级转人工。
const ENV_ASSIGNER_PROGRAMS = new Set(['export', 'declare', 'typeset', 'local', 'readonly', 'unset']);
// 装包／构建族里的这几个，操作数是**名字**（crate 名、脚本名、make 目标），不是路径。
// 判据是「看起来像不像路径」——含分隔符、以点／波浪号／盘符开头的一律当路径保留
// （`cargo add --path ../crate`、`go build ./cmd/app`），其余当名字。
// pip／apt／brew 不在其中：它们的取值常是清单文件或本地封包
// （`pip install -r requirements.txt`、`apt install ./pkg.deb`），按名字丢掉会把读源弄没。
// 旧形把名字也铸成文件目标，于是 `cargo add windows-credentials` 记成写
// `src-tauri\windows-credentials`，再被「文件名含凭据字样」拦一道、又被回写支路记成
// 「占位符没回写」——一次装包在审计里留下两条假告警。
const NAME_OPERAND_PROGRAMS = new Set(['cargo', 'npm', 'pnpm', 'yarn', 'bun', 'make', 'go']);
const looksLikePathText = (text) => {
    const value = String(text ?? '').trim();
    if (value === '' || value === '.' || value === '..')
        return true;
    if (value.startsWith('./') || value.startsWith('../') || value.startsWith('~/') || value.startsWith('~\\'))
        return true;
    if (/^[A-Za-z]:[\\/]/.test(value) || value.startsWith('\\\\'))
        return true;
    return /[\\/]/.test(value);
};
// cargo 的这批旗标取值是名字不是路径：`--features Win32_Security_Credentials,Win32_Foundation`、
// `--bin neteco_app`、`--package serde`。feature 名里允许 `/`（`serde/derive`），所以不能
// 交给上面的「像不像路径」判——按旗标位置直接排除。`--target` 不上这张表：pip 的
// `--target <dir>` 是真目录，`-p` 在 `cp -p` 里是无值旗标，通用化会误伤。
const CARGO_NAME_FLAGS = new Set(['--features', '-F', '--bin', '--example', '--package', '--test', '--bench']);

// Discarding stderr is not a write to a path; treating it as one turned every
// `ls x 2>/dev/null` into an out-of-workspace target.
const REDIRECT_SINKS = new Set(['/dev/null', '/dev/stdin', '/dev/stdout', '/dev/stderr', 'nul']);
const isSink = (text) => REDIRECT_SINKS.has(String(text ?? '').toLowerCase());
// 同一族里漏掉的另一半：`2>&1`／`>&2` 的目标是**文件描述符编号**，不是文件名。
// 当成路径解析就会凭空造出一个写目标（真机台账：`cd <区外目录> && … 2>&1`
// ⇒ `…\<目录>` ⇒ 白挂一条"工作区外"，当日多 9 个框）。
const FD_DUP = /^&?\d+$/;
const isFdDup = (text) => FD_DUP.test(String(text ?? '').trim());

// 归一程序名（方言表在 parse.normalizeProgram）：`Get-ChildItem`／`findstr.exe`／
// `C:\Windows\System32\del.exe` 与 bash 的 `ls`／`grep`／`rm` 归到同一套判据上（判据 5）。
const baseProgramOf = text => normalizeProgram(text);

// A10：远端按**方向**拆。旧形只要出现主机名就记一条人工下界，
// 于是 `curl -O`／`git clone`／云盘下行这些「把东西取回来」的调用也一律弹人。
// 再补一刀：方向之外还要看**目的地**——送去自己的机器与送去公网是两件事。
const CURL_DOWNLOAD_FLAGS = new Set(['-O', '--remote-name', '-o', '--output', '-J', '--remote-header-name', '-C', '--continue-at']);
const CLOUD_COPY_WORDS = new Set(['cp', 'sync', 'mv', 'copy', 'upload', 'put-object']);
const REMOTE_WRITE_PROGRAMS = new Set(['ssh', 'nc', 'telnet']);

// 目的地档位。判据①「算法能判的算法判」落在外传这一族上＝先问「这次送出去的东西
// 落在谁的机器上」：本机与内网都是**用户自己的机器**（放自己的机器不需要模型替人答应），
// 公网与「名字猜不出是谁的」才需要人点头。四档里没有「猜成内网」这一档——判不出就是判不出。
const DESTINATION_ENDPOINT_FLAGS = new Set(['--endpoint-url', '--endpoint', '--registry',
    '--repository-url', '--server-url', '--index-url']);
const LOOPBACK_NAME = /^(?:localhost|ip6-localhost|ip6-loopback)$/i;
const PRIVATE_SUFFIX = /\.(?:local|lan|home|internal)$/i;
// 本机主机名（全名与首段）＝这台机器自己。换个用户、换台机器这条照样成立，不是本机特例。
const MACHINE_NAMES = new Set(((name) => [name, name.split('.')[0]])(String(hostname() ?? '').toLowerCase())
    .filter(text => text !== ''));

/** 一个目的地文本落在哪一档：local（本机）／private（内网）／public（公网）／unknown（判不出）。 */
function destinationKindOf(text) {
    const value = String(text ?? '').trim().toLowerCase();
    if (value === '')
        return 'unknown';
    if (/^file:\/\//i.test(value))
        return 'local';
    const authority = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split(/[/?#]/)[0].split('@').pop();
    const bracket = authority.indexOf(']');
    const host = authority.startsWith('[') && bracket !== -1
        ? authority.slice(1, bracket)
        : authority.split(':')[0];
    if (host === '')
        return 'unknown';
    if (LOOPBACK_NAME.test(host) || /\.localhost$/i.test(host) || MACHINE_NAMES.has(host)
        || /^127\./.test(host) || host === '::1' || /^(?:0{1,4}:){7}0{0,3}1$/.test(host))
        return 'local';
    // 链路本地／IPv6 唯一本地／RFC1918，以及内网专用后缀——这些都是「网在内但出不了内网」。
    if (/^169\.254\./.test(host) || /^f[cd][0-9a-f]{2}:/i.test(host) || /^fe80/i.test(host)
        || /^10\./.test(host) || /^192\.168\./.test(host) || /^172\.(?:1[6-9]|2\d|3[01])\./.test(host)
        || PRIVATE_SUFFIX.test(host))
        return 'private';
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.includes('.'))
        return 'public';
    // 单标签名（`bucket`／`host`／`prod`）既可能是内网主机名也可能是对象存储桶名：
    // 名字本身证明不了是谁的机器 ⇒ 判不出，按最严的一档走。
    return 'unknown';
}

/** 旗标点名的端点：有 `--endpoint-url`／`--registry` 时目的地就是它，URI 里的桶名不再算目的地。 */
function endpointTargetsOf(words) {
    const out = [];
    for (let index = 0; index < words.length; index += 1) {
        const { flag, value, attached } = splitFlag(words[index]);
        if (attached === true && DESTINATION_ENDPOINT_FLAGS.has(flag)) {
            out.push(String(value ?? ''));
            continue;
        }
        if (DESTINATION_ENDPOINT_FLAGS.has(flag) && words[index + 1] !== undefined) {
            out.push(String(words[index + 1]));
            index += 1;
        }
    }
    return out.filter(text => text !== '');
}

/** 这一段在往哪些目的地送（新增字段，不参与任何既有字段的语义）。 */
function destinationsOf(segment) {
    const words = (segment.words ?? []).map(String);
    const raw = endpointTargetsOf(words);
    if (raw.length === 0) {
        raw.push(...(segment.hosts ?? []));
        // `docker push localhost:5000/app:1`：没有点的仓库地址进不了 OCI_REFERENCE，
        // 主机清单于是为空 ⇒ 目的地要从 `registry[:port]/path` 自己抠出来。
        if (PUSH_CAPABLE.has(baseProgramOf(segment.program)))
            for (const text of words) {
                const match = /^([\w.-]+)(?::\d+)?\/[^\s]+$/.exec(text);
                if (match !== null)
                    raw.push(match[1]);
            }
        for (const text of words)
            if (/^file:\/\/\S+$/i.test(text))
                raw.push(text);
    }
    const out = [];
    for (const text of [...new Set(raw.map(String))])
        if (text !== '')
            out.push({ text, kind: destinationKindOf(text) });
    return out;
}

/** * 一次远端作用的四个方向（A10）：download（取回本地）／remote-read（无载荷查询）／
 * upload（把本地内容送出去）／remote-exec（在远端执行命令）。
 * 判不出来就返回 'remote'——那是「有主机但方向不明」，照旧走人工。
 */
function remoteDirectionOf(segment) {
    const remoteish = segment.remote === true || (segment.hosts ?? []).length > 0;
    if (!remoteish)
        return '';
    // 非 shell 工具的方向由工具本身定，不看命令名：取页面＝download，只搜不取＝remote-read。
    // 未登记的工具带网址时判不出「往哪去」，记成 `tool-unknown`——目的地的事实照留，
    // 但不许借用「远端执行」或「外发」的名字：那两句说的是方向确知的情形。
    if (segment.isTool === true) {
        const name = String(segment.program ?? '').trim().toLowerCase();
        if (name === 'web_search')
            return 'remote-read';
        if (segment.adapter !== undefined)
            return 'download';
        return 'tool-unknown';
    }
    const program = baseProgramOf(segment.program);
    const words = (segment.words ?? []).map(String);
    const operands = (segment.operands ?? []).map(String);
    if (program === 'git') {
        if (words.includes('clone') || words.includes('fetch') || words.includes('pull'))
            return 'download';
        if (words.includes('push'))
            return 'upload';
        return 'remote-read';
    }
    if (program === 'curl') {
        // `-d`／`-F`／`-T` 都是把载荷送出去；`-d ''` 也算，只是空载荷。
        const sends = words.some((word) => {
            const { flag } = splitFlag(word);
            return CURL_UPLOAD_FLAGS.test(flag) || CURL_BODY_FLAGS.test(flag);
        });
        if (sends)
            return 'upload';
        if (anyFlag(words, CURL_DOWNLOAD_FLAGS))
            return 'download';
        return 'remote-read';
    }
    if (program === 'scp' || program === 'rsync' || program === 'sftp') {
        const remoteOperand = value => REMOTE_TARGET.test(value) || REMOTE_URI.test(value);
        const source = operands[0] ?? '';
        const destination = operands.at(-1) ?? '';
        if (remoteOperand(destination) && !remoteOperand(source))
            return 'upload';
        if (remoteOperand(source) && !remoteOperand(destination))
            return 'download';
        return 'remote';
    }
    if (program === 'aws' || program === 'gsutil' || program === 'az' || program === 'rclone') {
        if (cloudExfilDirection(words))
            return 'upload';
        if ([...CLOUD_COPY_WORDS].some(word => words.includes(word)))
            return 'download';
        return 'remote-read';
    }
    // 镜像推送是把本机内容上行传出去，不是「在远端执行」——旧形没有这一支，
    // `docker push` 落回 'remote'，于是被钉在远端执行那一行的人工下界上。
    if (['docker', 'podman', 'nerdctl'].includes(program) && words.includes('push'))
        return 'upload';
    // ssh 的两半：远端查询（`ssh prod uptime`）与远端执行（`ssh prod "systemctl restart nginx"`）。
    // 只看「看见 ssh 就一律人工」会把只读查询也弹到人（判据 6 的正向臂）；
    // 远端命令串里的删除／写仍按 remote-exec（反向锁：`ssh prod "rm -rf /tmp/x"`）。
    if (program === 'ssh') {
        const hostAt = operands.findIndex(text => String(text).trim() !== '' && !/^\d+$/.test(String(text)));
        const inner = operands.slice(hostAt + 1).map(String).join(' ').trim();
        if (inner === '')
            return 'remote-read';
        const innerSegments = splitSegments(inner);
        if (innerSegments.length === 0)
            return 'remote-read';
        const readable = innerSegments.every(seg => ['read', 'internal'].includes(segmentOpClass(seg)));
        return readable ? 'remote-read' : 'remote-exec';
    }
    if (REMOTE_WRITE_PROGRAMS.has(program))
        return 'remote-exec';
    // 命中外传族＝「把本机内容送出去」这一件事的判别结果，方向只能是上行传内容。
    // 旧形 `npm publish --registry …`／`gh release create` 落回 'remote'，被钉在远端执行那一行，
    // 于是往本机 verdaccio 发包也要弹框。放在全部程序分支之后＝不覆盖下行与只读的判定。
    if ((segment.exfil ?? []).length > 0)
        return 'upload';
    return 'remote';
}

const fsProbe = {
    lstat: (target) => lstatSync(target),
    realpath: (target) => realpathSync(target),
    readdir: (target) => readdirSync(target),
    read: (target) => readFileSync(target, 'utf8'),
    // 第三参数＝这一枚子进程的时间上限（毫秒），由调用方按总预算给；不给就沿用 5s 老默认。
    spawn: (command, args, timeoutMs) => spawnSync(command, args, { encoding: 'utf8', windowsHide: true, timeout: timeoutMs ?? 5_000 }),
};

/** * 递归读一个子树时，子树里**凭据形状**的文件也要进目标集（A03）：
 * `grep -rn TODO .` 放行的是「检索代码」，不是「把 .env／id_rsa 先读一遍」。
 * 只收有名字特征的、最多 20 个——全量列举会把目标数撑爆，反而不是这条判据要的东西。
 */
function enumerateSensitive(dir, probe) {
    return walkScope(dir, probe).sensitive;
}

/** * 递归读面的枚举（判据 3／4）：既收整棵树的文件清单，也单列凭据形状的那些。
 * `completeness`：'ok'｜'truncated'（深度／访问数／条数触顶）｜'error'（读目录或 stat 失败）。
 * **报错不等于「没发现」**：权限失败／坏链接都要如实写 error，不许当扫干净。
 */
function walkScope(dir, probe) {
    const files = [];
    const sensitive = [];
    let completeness = 'ok';
    let visited = 0;
    // 量具不带 readdir（离线桩／无 FS 环境）：枚举不可用不等于扫描出错，
    // 保持旧形「没有发现」，由别的举证项说话。
    if (typeof probe.readdir !== 'function')
        return { files, sensitive, completeness };
    const trip = () => {
        if (completeness === 'ok')
            completeness = 'truncated';
    };
    const walk = (current, depth) => {
        if (depth > SCOPE_LIMITS.depth) {
            trip();
            return;
        }
        if (files.length >= SCOPE_LIMITS.files) {
            trip();
            return;
        }
        let entries;
        try {
            entries = probe.readdir(current);
        }
        catch (error) {
            // 目录**不存在**＝那里本来就没有读面；读不了（权限／IO）才是「不知道」。
            if (String(error?.code ?? '') === 'ENOENT')
                return;
            completeness = 'error';
            return;
        }
        for (const item of entries) {
            visited += 1;
            if (visited > SCOPE_LIMITS.visited) {
                trip();
                return;
            }
            if (files.length >= SCOPE_LIMITS.files) {
                trip();
                return;
            }
            if (item === 'node_modules' || item === '.git')
                continue;
            const full = pathApiFor(current).join(current, item);
            let info;
            try {
                info = probe.lstat(full);
            }
            catch {
                completeness = 'error';
                continue;
            }
            if (info.isDirectory()) {
                walk(full, depth + 1);
                continue;
            }
            if (isSensitiveBasename(item))
                sensitive.push(full);
            files.push(full);
        }
    };
    walk(dir, 0);
    return { files, sensitive, completeness };
}

/** 参数取值是一张文件清单（`--files0-from`／`-T`／`-a`）：读出里面的条目。 */
function readManifest(path, nul, probe) {
    if (typeof probe.read !== 'function')
        return { entries: [], error: true };
    try {
        const raw = String(probe.read(path));
        const parts = nul ? raw.split('\0') : raw.split(/\r?\n/);
        return { entries: parts.map(entry => entry.trim()).filter(entry => entry !== ''), error: false };
    }
    catch {
        return { entries: [], error: true };
    }
}

/** * 文件身份三态（F02 判据 3）：路径字符串写得像在区里，**真身**未必在区里——
 * 父目录是 symlink／junction 时，`workspace\x\y` 实际落在外面。所以按真实路径说结论：
 * `proven-inside`＝解析后仍在信任区内；`proven-outside`＝字符串在里、真身在外；
 * `unknown`＝解析不出来（没权限／链接环／没实现）。
 * 目标还没落地时沿父链往上找最近存在的 ancestor 再解析，并把缺的那几段接回去。
 * **只有 ENOENT 才允许往上走**：权限失败／链接环是「不知道」，沿父目录往上拿高层
 * 证明子文件安全，等于把看不见的东西说成安全（A02）。
 */
function identityOf(path, roots, probe) {
    if (typeof probe.realpath !== 'function')
        return { verdict: 'unknown', real: undefined };
    let cursor = path;
    const tail = [];
    for (let depth = 0; depth < 8; depth += 1) {
        let real;
        try {
            real = probe.realpath(cursor);
        }
        catch (error) {
            if (String(error?.code ?? '') !== 'ENOENT')
                return { verdict: 'unknown', real: undefined };
            const parent = pathApiFor(cursor).dirname(cursor);
            if (parent === cursor)
                return { verdict: 'unknown', real: undefined };
            tail.unshift(basenameOf(cursor));
            cursor = parent;
            continue;
        }
        const resolved = tail.length === 0 ? real : pathApiFor(real).join(real, ...tail);
        const inside = isWithin(roots.workspace, resolved, roots.home)
            || roots.trusted.some(rule => matchPath(rule, resolved, 'read'))
            || roots.dshOpen.some(rule => matchPath(rule, resolved, 'read'));
        return { verdict: inside ? 'proven-inside' : 'proven-outside', real: normalizePath(resolved, resolved, roots.home) };
    }
    return { verdict: 'unknown', real: undefined };
}

/** * 「只读」不是程序名在表里就算，而是要能举证。举不出证的读照样要审——
 * 只读快路是**免检特权**，特权必须拿证据换，不能拿名字换（0.6.2 审查报告 F01）。
 * 三条都要过：① 程序属于读族且不在解释器/执行器名单里；② 参数里没有写出·删除·执行语义；
 * ③ 段内没有运行时展开（`$`、反引号、`$VAR`、glob）——展开后落到哪些文件，事实层不知道。
 * `git` 额外要子命令在白名单里：`git status` 是读，`git branch -D x` 不是。
 */
const GIT_READ_SUBCOMMANDS = new Set(['status', 'diff', 'log', 'show', 'blame', 'describe', 'ls-files',
    'ls-tree', 'cat-file', 'rev-parse', 'shortlog', 'grep', 'show-ref', 'mergetool--list', 'config']);
// 判据④：本地建仓／暂存／提交三条此前落进读族，再由 readProof 说「举不出证」，
// 台账把写动作标成「读类但举不出证」。这三条按写面判（不动任何档位，也不新增预设行）；
// 其余 git 子命令的既有归类（push／clean／reset／restore／apply…）一格不动。
const GIT_WRITE_SUBCOMMANDS = new Set(['init', 'add', 'commit']);
// `sed` 不在这张表里：`sed -n 1p file` 是纯读，`sed -i`／`-e`／`-f` 才可能写出或执行。
// 安全形态由下面 readProofFor 里那条保守的白名单判（只认行号＋p／d／n 的脚本）。
const NEVER_PROVEN_READ = new Set(['env', 'xargs', 'awk', 'perl', 'python', 'python3', 'node', 'nodejs',
    'ruby', 'php', 'deno', 'bun', 'tclsh', 'expect', 'make', 'cmake', 'npm', 'npx', 'pnpm', 'yarn', 'bun',
    'pip', 'pip3', 'cargo', 'docker', 'podman', 'kubectl', 'helm', 'eval', 'source', '.', 'sh', 'bash', 'zsh',
    'dash', 'fish', 'powershell', 'pwsh', 'cmd', 'wsl', 'ssh', 'scp', 'sftp', 'rsync', 'nc', 'telnet']);
/** 段内有没有这几个旗标：附值（`--output=x`／`-ox`）与分离（`-o x`）两种写法都算（A01）。
 *  只对登记过的旗标拆附值——`-delete` 不是「-d + elete」。
 *  `foldCase`：cmdlet 参数名大小写不敏感，POSIX 旗标不折。 */
function anyFlag(words, flags, foldCase = false) {
    const has = name => flags.has(name) || (foldCase === true && flags.has(String(name).toLowerCase()));
    for (const word of words) {
        const text = String(word);
        if (has(text))
            return true;
        const eq = /^(--[A-Za-z0-9_-]+)=/.exec(text);
        if (eq !== null && has(eq[1]))
            return true;
        const attached = /^(-[A-Za-z])(.+)$/s.exec(text);
        if (attached !== null && has(attached[1]))
            return true;
    }
    return false;
}
// 命令替换与变量展开会让参数在运行时变成任意内容——照旧否掉只读证；
// 通配只影响「列出哪些名字」，不影响「会不会改东西」，对只枚举目录项的程序单判。
const EXPANSION = /\$\(|\$\{|`|\$\w|\$\[/;
const GLOB_CHARS = /[*?[\]]/;
const ENUMERATE_PROGRAMS = new Set(['ls', 'dir', 'vdir', 'find', 'tree']);
// 未引用通配展开成真实名字（`globExpanded`）⇒ 目标集确定，任何读程序同判；
// 引号里的（不展开）与展不出的仍按「参数含通配」否证——判读不看程序名。

// 位语义只有一张表（`positions.js`）。这里只负责「把词映射成位」，不再自带枚举。
function wordRolesOf(program, words, kinds) {
    // 先按**命令本名**查表：`Get-ChildItem` 用自己的行，不借 bash 的 `ls`；
    // 本名没有行时才退回族名（`findstr` 借 grep 的位语义）。
    const native = nativeNameOf(program);
    const name = positionOf(native) !== undefined ? native : baseProgramOf(program);
    // 表外程序按最保守的「操作数＝路径」走（不产读事实），但**仍要过旗标位这一层**：
    // cmdlet（`Set-Content`／`Out-File`…）大多不在 POSIX 表里，一律当 path 会把
    // `-Value 一串` 那种内容折成第二个目标。
    const entry = positionOf(name) ?? { operands: 'read', flags: {}, evidence: 'absent' };
    const execFlags = execFlagsOf(name);
    // `git config <key>` 的键名位：config 子命令之后、第一个「没有位语义的普通操作数」。
    const configAt = name === 'git' ? words.indexOf('config') : -1;
    const configIsSubcommand = configAt >= 0
        && !(configAt > 0 && String(words[configAt - 1]).startsWith('-')
            && flagPositionOf(name, String(words[configAt - 1])) === 'read');
    const roles = [];
    let afterDashDash = false;
    let operands = 0;
    let plainOperands = 0;
    for (let index = 0; index < words.length; index += 1) {
        const word = String(words[index]);
        if (word === '--') {
            roles.push('flag');
            afterDashDash = true;
            continue;
        }
        if (afterDashDash) {
            roles.push('path');
            continue;
        }
        if (kinds[index] !== 'operand') {
            roles.push('flag');
            continue;
        }
        // `-exec rm {} \;` 的占位符与结尾分号：不是路径。
        if (/^[{};]+$/.test(word)) {
            roles.push('nopath');
            operands += 1;
            continue;
        }
        const prev = index > 0 ? String(words[index - 1]) : '';
        const prevPosition = prev.startsWith('-') ? flagPositionOf(name, prev) : undefined;
        if (prevPosition === 'write' || prevPosition === 'read') {
            roles.push('path');
            operands += 1;
            continue;
        }
        if (prevPosition === 'exec') {
            // 执行位的取值是**程序名**：它不占操作数位，`rg --pre sh TODO x` 的 TODO 仍是模式位。
            roles.push('nopath');
            plainOperands += 1;
            continue;
        }
        if (prevPosition === 'take' || prevPosition === 'key' || (execFlags !== undefined && execFlags.has(prev))) {
            roles.push('nopath');
            operands += 1;
            continue;
        }
        if (entry.operands === 'nopath') {
            roles.push('nopath');
            operands += 1;
            continue;
        }
        // `git config --global user.name`：键名位（子命令 config 后的含点首操作数）。
        if (configIsSubcommand && index > configAt && plainOperands === 0
            && /^[\w-]+(\.[\w-]+)+$/.test(word)) {
            roles.push('nopath');
            operands += 1;
            plainOperands += 1;
            continue;
        }
        // 键名位之后的那个词是**设置的值**（`git config user.email a@b.c`）：不是路径。
        if (configIsSubcommand && index > configAt && plainOperands >= 1) {
            roles.push('nopath');
            operands += 1;
            plainOperands += 1;
            continue;
        }
        if (entry.operands === 'pattern' && operands === 0) {
            roles.push('nopath');
            operands += 1;
            continue;
        }
        roles.push('path');
        operands += 1;
        plainOperands += 1;
    }
    return roles;
}

/** 判据⑥②：把命令替换里的「段首程序」（管道每段第一个词）抠出来。
 *  只认 `$(…)` 与反引号；`$VAR`／`${…}`／`$[…]` 记成裸变量（仍是运行时展开）。
 *  返回 { programs, commandSub, bareVar }：commandSub＝确实有命令替换。 */
function commandSubParts(words) {
    const programs = [];
    let bareVar = false;
    let commandSub = false;
    for (const word of words ?? []) {
        const text = String(word);
        const subs = text.match(/\$\(([^()]*)\)|`([^`]*)`/g);
        if (subs === null) {
            if (/\$\{|\$\w|\$\[/.test(text))
                bareVar = true;
            continue;
        }
        commandSub = true;
        for (const sub of subs) {
            const body = sub.replace(/^\$\(|^`|\)$|`$/g, '');
            for (const part of body.split('|')) {
                const name = part.trim().split(/\s+/)[0];
                if (name !== '')
                    programs.push(name);
            }
        }
    }
    return { programs, commandSub, bareVar };
}

/** 命令替换里每一段的程序位都在读族／导航族、且没有裸变量 ⇒ 展开不改变「不改任何东西」。 */
function commandSubReadOnly(words) {
    const { programs, commandSub, bareVar } = commandSubParts(words);
    return commandSub === true && bareVar === false && programs.length > 0
        && programs.every(name => (READ_PROGRAMS.has(name) || NAVIGATE_PROGRAMS.has(name))
            && NEVER_PROVEN_READ.has(name) === false);
}

/** 这一段是不是「递归读一个子树」：读族程序 ＋ 递归开关（`-r`／`-R`／`--recursive`）。 */
function recursiveScopeOf(segment) {
    const program = baseProgramOf(segment.program);
    if (!READ_PROGRAMS.has(program) || NAVIGATE_PROGRAMS.has(program))
        return false;
    // rg 默认就是递归的：没有 -r 也读整棵 cwd（判据 3 的 `rg TODO`）。
    if (program === 'rg')
        return true;
    return (segment.words ?? []).some(word => RECURSIVE_READ_FLAGS.test(String(word)));
}

/** * 递归读的**范围**落在哪：最后一个操作数（没有操作数就是这一段当前的工作目录）。
 * 在信任区内 ⇒ 仍然是免检的读（用户已经把这块地给了会话，里面真有 `.env`  also 由结果侧脱敏兜着）；
 * 在信任区外 ⇒ 事实层没列举过里面有什么，不能算「只读了目录」（判据 6 要的就是这一格）。
 */
/** 这个路径是不是**单个文件**（读不到＝不是，交下游按缺失处理）。 */
function isFileAt(target, probe) {
    if (typeof probe.lstat !== 'function')
        return false;
    try {
        return probe.lstat(target).isFile() === true;
    }
    catch {
        return false;
    }
}

function scopeInsideRoots(segment, cwd, roots) {
    const operand = [...segment.operands ?? []].reverse().find(text => String(text).trim() !== '' && !isDynamic(text));
    const base = normalizePath(operand ?? cwd, cwd, roots.home);
    // 技能说明子树本身就是任务资源——`scope.js` 的 isSkillDoc 说的是同一件事。
    // 不在这里认它，同一份 SKILL.md 会出现 `cat` 举得出证、`grep -rn` 举不出证的分裂
    // （报告 §1.1／ 判据 P4：换入口不得换出不同授权结论）。
    if (isSkillDoc(base, roots.home))
        return true;
    // 本会话绑定的源根（用户点过名的那个目录）其内的读＝任务资源，
    // 递归读不再落「区外子树没列举过」那一格。
    const sourceRoot = sourceRootOf(roots);
    if (sourceRoot !== '' && isWithin(sourceRoot, base, roots.home))
        return true;
    return isWithin(roots.workspace, base, roots.home)
        || roots.trusted.some(rule => matchPath(rule, base, 'read'))
        || roots.dshOpen.some(rule => matchPath(rule, base, 'read'));
}

/** 这一段有没有「相对于工作目录」的路径词：工作目录算不死时，只有这类段才真的失去锚点。
 * 绝对路径与 `~` 自成锚点，不受 cd 未知影响。 */
function hasRelativePathWord(segment) {
    const words = segment.words ?? [];
    for (let at = 0; at < words.length; at += 1) {
        const text = String(words[at] ?? '');
        if (text === '' || text.startsWith('-'))
            continue;
        if ((segment.wordRoles?.[at] ?? 'path') !== 'path')
            continue;
        if (text.startsWith('~') || pathApiFor(text).isAbsolute(text))
            continue;
        return true;
    }
    return false;
}

/** `opaque` 的成因。只有未引用的通配算「通配」；命令替换／变量／大括号展开、
 *  动态重定向一律按展开算——它们在运行时可以变成任意内容，仍要走原来那条否证。 */
function opaqueWhyOf(segment) {
    if (typeof segment.opaqueWhy === 'string' && segment.opaqueWhy !== '')
        return segment.opaqueWhy;
    if (segment.cwdUnproven === true)
        return `工作目录不确定：${segment.cwdUnknown ?? '来源未说明'}`;
    const words = segment.words ?? [];
    const bares = segment.wordsBare ?? [];
    let glob = false;
    let placeholder = false;
    let unresolved = false;
    for (let index = 0; index < words.length; index += 1) {
        // `$X` 已按判定这一刻的环境值算死（见 envGuardFor）⇒ 不再是运行时展开。
        if (bares[index] !== true || segment.wordsEnvResolved?.has(index) === true)
            continue;
        unresolved = true;
        const text = String(words[index]);
        // `find … -exec … {} \;` 的占位符：不是大括号展开，也不是路径。
        if (/^[{};\\]+$/.test(text)) {
            placeholder = true;
            continue;
        }
        if (text.includes('$') || text.includes('`') || (text.includes('{') && text.includes('}')))
            return '参数含命令替换／变量展开';
        if (GLOB_CHARS.test(text))
            glob = true;
    }
    if ((segment.redirectDynamic ?? []).some(dynamic => dynamic === true))
        return '段内含运行时展开或通配，目标集不确定';
    // 只有 `-exec` 的占位符（`{}`／`\;`）不算展开——它既不变名字也不变范围。
    if (unresolved === false || (placeholder === true && glob === false))
        return '';
    return glob ? '参数含通配' : '段内含运行时展开或通配，目标集不确定';
}

function readProofFor(segment) {
    const program = baseProgramOf(segment.program);
    if (segment.opaque === true) {
        const why = opaqueWhyOf(segment);
        // 判据⑥②：纯只读计数（`echo "$(git remote | wc -l)"`）——只对**只输出文案**的
        // echo／printf 且替换里全是读族时放宽；`find -name "$(whoami)*"` 这类把展开当模式用的照旧拒。
        const readOnlyExpansion = why === '参数含命令替换／变量展开'
            && (program === 'echo' || program === 'printf') && commandSubReadOnly(segment.words);
        const plainGlob = why === '参数含通配' && segment.globExpanded === true;
        if (why !== '' && (why !== '参数含通配' || ENUMERATE_PROGRAMS.has(program) === false) && plainGlob !== true && readOnlyExpansion !== true)
            return { proven: false, why };
    }
    // 未引用定界符的 heredoc 正文会做命令替换：它不是数据，已经在正文里执行过命令。
    if (segment.heredocExpanded === true)
        return { proven: false, why: '未引用定界符的 heredoc 会展开并执行正文里的命令' };
    // 目标真身跑到区外（父目录是链接）：字符串在区里，读的却是别处——
    // 「只读了工作区里那个文件」这句话不再成立（A02）。
    if (segment.linkEscapes === true)
        return { proven: false, why: '目标真身落在工作区外（父目录是链接），读的不是路径上写的那个文件' };
    // 递归读的子树里有凭据形状的文件：允许读代码不等于允许把这些秘密先读出来（A03）。
    if (segment.secretScopeHit === true)
        return { proven: false, why: '递归读的子树里有凭据形状的文件，读面比「目录」宽' };
    // 非 shell 的举证看**适配器**：在册且声明为读类才算——名字里恰好有 read 不算。
    if (segment.adapter !== undefined)
        return segment.adapter.op === 'read'
            ? { proven: true, why: '' }
            : { proven: false, why: `${segment.program} 是 ${segment.adapter.op} 类工具，不是读` };
    // sed 的纯读证（§7.2：native／sed／grep 读同一份说明要同结论）：脚本只认行号＋p／d／n，
    // 且不带 -i／-e／-f；任何别的脚本都有写出（w／W）或执行（e）的可能，照旧交模型。
    if (program === 'sed') {
        const words = (segment.words ?? []).map(String);
        const unsafe = words.filter(word => String(word).startsWith('-')).some(word =>
            IN_PLACE_EDIT_FLAGS.test(word) || /^--(?:expression|file)\b/.test(word)
            || /^-[ef]/.test(word) || /^-[a-z]*[ef]/.test(word));
        const script = words.find(word => !String(word).startsWith('-'));
        if (unsafe || script === undefined || !/^(?:[\s\d,$;]|[pdnP])+$/.test(script))
            return { proven: false, why: 'sed 的脚本或旗标可能写出／执行，不是纯读' };
    }
    else if (NEVER_PROVEN_READ.has(program))
        return { proven: false, why: `${program} 会执行参数里的东西，不是读` };
    // 换目录只动 shell，不碰文件系统——它必须算已证明，否则整条纯读管道被拖去付费。
    if (NAVIGATE_PROGRAMS.has(program))
        return { proven: true, why: '' };
    if (!READ_PROGRAMS.has(program))
        return { proven: false, why: `${program} 不在读族里` };
    // 递归读的枚举触顶或报错：清单不完整（判据 4），不许拿它换免检。
    if (segment.readCompleteness !== undefined && segment.readCompleteness !== 'ok')
        return { proven: false, why: `读面枚举${segment.readCompleteness === 'error' ? '出错' : '触顶被截断'}，清单不完整` };
    // 递归读信任区**外**的一个子树：事实层只看见那个目录名，里面有什么它没列举过，
    // 就不能拿「只读了目录」换免检（判据 6）。区内的递归照旧免检（对照臂锁着这件事）。
    if (segment.scopeOutside === true)
        return { proven: false, why: '递归读的是信任区外的一个子树，里面有哪些文件事实层没有列举' };
    // 通配目标的有界结构探测已经证明「匹配到的都是目录名」——不再按
    // 「参数含通配 ⇒ 目标集不确定」把这一段的读证明整个否掉（未探测成功的不受影响）。
    if (segment.structureProven === true)
        return { proven: true, why: '' };
    const words = (segment.words ?? []).map(word => String(word));
    // 写出口检查提到通配之前——判 false 时理由写真实原因，不再一律写「通配」。
    // `-exec` 一族交给下面的执行位分支按内层程序再判（内层是读族⇒本段仍算读）；
    // 这里只管 `-delete` 这类**本段自己就会动手**的旗标。
    if (program === 'find' && anyFlag(words, new Set([...FIND_EXEC_FLAGS].filter(flag => execFlagsOf('find')?.has(flag) !== true))))
        return { proven: false, why: 'find 带执行／删除参数' };
    // 判据③④：执行位（`-exec`／`--pre`／`-H`／`-i`…）。内层程序按同一张表再判：
    // 内层是删除／非读族 ⇒ 这一段不是读；内层是读族（`find -exec grep -n X {}`）⇒ 照旧往下走。
    const execFlags = execFlagsOf(program);
    if (execFlags !== undefined && anyFlag(words, execFlags)) {
        const at = words.findIndex(word => execFlags.has(word));
        const inner = words.slice(at + 1).find(word => !word.startsWith('-') && !/^[{};\\]+$/.test(word)) ?? '';
        const innerName = baseProgramOf(inner);
        if (DELETE_PROGRAMS.has(innerName) || DESTROY_PROGRAMS.has(innerName) || NEVER_PROVEN_READ.has(innerName))
            return { proven: false, why: `执行位：内层是 ${innerName}（${DELETE_PROGRAMS.has(innerName) || DESTROY_PROGRAMS.has(innerName) ? '会删／毁东西' : '会执行参数'}），不是读` };
        if (positionOf(innerName) === undefined)
            return { proven: false, why: `执行位：内层 ${innerName || '（缺程序）'} 不在读族位表上` };
    }
    // 写出效果藏在取值里的旗标：`sort --output=x`、`wc --files0-from=x`、`git diff --output=x`。
    const writeFlags = writeFlagsOf(segment.program);
    if (writeFlags !== undefined && anyFlag(words, writeFlags, isCmdletName(segment.program)))
        return { proven: false, why: `${program} 带写出参数（--output／-o 一类），不是读` };
    // 丢掉 stderr（`2>/dev/null`、`>nul`）不写出任何东西：它不该打断举证。
    // 输入重定向（`cat < in.txt`）同样不写：只有**输出**重定向才打断举证（判据 2b）。
    const writeRedirect = (segment.redirects ?? []).some((text, at) => !isSink(String(text))
        && !isFdDup(String(text)) && redirectReads(segment.redirectOps?.[at] ?? '>') === false);
    if (writeRedirect)
        return { proven: false, why: '带输出重定向，写了东西' };
    // 判据⑥②：只对 echo／printf 的纯只读计数放宽（展开里全是读族）；其余照旧拒。
    // 已按环境变量算死的词（`cat "$X"`）不再按运行时展开否证——见 envGuardFor。
    if (words.some((word, index) => EXPANSION.test(word)
        && segment.wordsEnvResolved?.has(index) !== true)
        && !((program === 'echo' || program === 'printf') && commandSubReadOnly(words)))
        return { proven: false, why: '参数含命令替换／变量展开' };
    // 通配只影响「列出哪些名字」，不影响「会不会改东西」——只枚举目录项的程序不因此否证。
    // 通配只对**路径位**的词否证——`grep -e "^\[ok\]"` 的模式位含 `[` 不再冒充「范围数不清」。
    // 只有**未引用**的通配才算「目标集数不清」——引号里的 `*` 是普通字符（`cat "*微软*"`
    // 读的是名字叫 `*微软*` 的文件，仍是读）；未引用通配已展开过（含 0 命中、目标为空）也是确定结论。
    const unquotedGlob = words.some((word, index) => (segment.wordRoles?.[index] ?? 'path') === 'path'
        && segment.wordsBare?.[index] === true && GLOB_CHARS.test(word));
    if (unquotedGlob && ENUMERATE_PROGRAMS.has(program) === false && segment.globExpanded !== true)
        return { proven: false, why: '参数含通配' };
    if (program === 'git') {
        const sub = words.find(word => !word.startsWith('-') && word !== 'git');
        if (sub === undefined || !GIT_READ_SUBCOMMANDS.has(sub)) {
            // `git tag --list` 列标签是读（F12）；`git tag v1` 建标签不是。
            if (sub === 'tag' && words.some(word => word === '--list' || word === '-l'))
                return { proven: true, why: '' };
            return { proven: false, why: `git ${sub ?? ''} 的子命令未证明只读` };
        }
        if (sub === 'config') {
            // 判据④：`git config <key>` 是读（键名位），`git config <key> <value>` 是写。
            const after = words.slice(words.indexOf('config') + 1).filter(word => !word.startsWith('-'));
            const asks = words.some(word => ['--get', '--get-all', '--get-regexp', '--list', '-l'].includes(word));
            if (after.length >= 2 && asks === false)
                return { proven: false, why: 'git config 只在 --get／--list 时算读' };
            if (after.length === 0 && asks === false)
                return { proven: false, why: 'git config 只在 --get／--list 时算读' };
        }
    }
    // `xxd -r` 把十六进制还原成文件（并表后它落在读族里，这一条要显式挡回）。
    if (program === 'xxd' && anyFlag(words, RECOVER_FLAGS))
        return { proven: false, why: 'xxd -r 还原成文件，不是读' };
    return { proven: true, why: '' };
}

function shellTargets(args) {
    return String(args?.command ?? args?.cmd ?? '');
}

/** * 非 shell 工具的效果**只按在册的精确名字**分类（F04）。过去靠名字子串
 * （`read|^ls$|glob|grep|search|view|list|fetch…`），于是 `create_thread`（含 read）、
 * `search_and_replace`（含 search）、`web_fetch`（含 fetch）都领到了「只读」资格，
 * 而它们里有的正在写文件、正在往外发东西。不在册的一律 `other`＋`opaque`，
 * 由表里 `unclassified-tool`／`mcp-tool` 那两行说话（默认交模型判）——
 * 名字里恰好有 read 不再等于免检，也不给 MCP 的自述开后门。
 * paths＝作用在哪些文件上；urls＝往哪些主机去（进网络平面）；body＝要送出去的内容（进敏感面）。
 */
const TOOL_ADAPTERS = {
    read: { op: 'read', paths: ['file_path', 'path', 'notebook_path'] },
    'notebook.read': { op: 'read', paths: ['notebook_path'] },
    ls: { op: 'read', paths: ['path', 'dir_path', 'target'] },
    'list_dir': { op: 'read', paths: ['path', 'dir_path', 'target'] },
    glob: { op: 'read', paths: ['path', 'cwd'] },
    grep: { op: 'read', paths: ['path'] },
    // 技能调用只把本机技能文档装进上下文：读文档本身已由 docs-subtree-read 放行，
    // 调用不写文件、不出网；登记成 read 会因「无路径可举证」落 unproven-read 白白过 AI。
    skill: { op: 'internal', body: ['args'] },
    write: { op: 'write', paths: ['file_path', 'path'], body: ['content'] },
    edit: { op: 'write', paths: ['file_path', 'path'], body: ['new_string', 'replacement'] },
    'notebook.edit': { op: 'write', paths: ['notebook_path'], body: ['new_source'] },
    delete: { op: 'delete', paths: ['file_path', 'path', 'target'] },
    remove_file: { op: 'delete', paths: ['file_path', 'path', 'target'] },
    'ask_user_question': { op: 'internal', body: ['questions'] },
    compress: { op: 'internal' },
    decompress: { op: 'internal' },
    acp_status: { op: 'internal' },
    acp_cache: { op: 'internal' },
    todo_write: { op: 'internal' },
    // `job_output` 只读后台任务输出（`jobs.read` ＋可选 `jobs.wait`），
    // 不碰文件系统、不出网；杀进程是另一个工具 `job_kill`，与它无关。归 `internal` ⇒
    // 落「会话内部工具」那行 release，不再每次叫模型、也就不会再撞依据引文那道门。
    // 边界如实记：它读出的内容直接进上下文（结果侧敏感扫描仍在，>32KB 的段不扫）。
    job_output: { op: 'internal' },
    // 取网页／搜网页：都是**取回本地**，没有载荷离开本机。旧形没给它们登记，落 `other`
    // ＋参数里的网址被当成目的地 ⇒ 方向缺省按 `remote` 算，被「远端执行」和网络面兜底
    // 「未知外发」两行接住，一次公开页面的 GET 被读成「往外发东西」。
    web_fetch: { op: 'read', urls: ['url'] },
    web_search: { op: 'read', urls: ['query'] },
};

const toolAdapterFor = candidate => {
    const name = String(candidate ?? '').trim().toLowerCase();
    // MCP 的名字带前缀（`mcp:server/tool`、`mcp_server_tool`）——一律不认：
    // 服务自述「我只读」不是证据（F04），表里 `mcp-tool` 那行才说话。
    if (name === '' || /^mcp[:_.-]/.test(name))
        return undefined;
    return TOOL_ADAPTERS[name];
};

/** 一条文本里出现的所有 URL／主机（shell 与工具参数同一把尺）。 */
const URL_IN_TEXT = /\bhttps?:\/\/[^\s"'`)]+|\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?(?:\/\S*)?/gi;
function networkUrlTargets(text) {
    const out = [];
    for (const raw of String(text ?? '').match(URL_IN_TEXT) ?? []) {
        out.push(raw);
        try {
            const url = new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
            if (url.hostname)
                out.push(url.hostname.toLowerCase());
        }
        catch {
            // 形状像主机但解析不出来：原文仍交给网络平面按文本匹配。
        }
    }
    return [...new Set(out)];
}

/** 把主机记到产生它的那一段上（F03 逐作用项）并进全调用清单。 */
function pushSegmentHost(segment, remoteHosts, value) {
    segment.remote = true;
    if (!segment.hosts)
        segment.hosts = [];
    // 原文一律留着：`bucket`・`localhost`・`10.9.9.9` 这类没有点的目的名，正则认不出但确实要拦。
    const targets = [String(value), ...networkUrlTargets(value)];
    for (const target of [...new Set(targets.filter(text => text !== ''))]) {
        segment.hosts.push(target);
        remoteHosts.push(target);
    }
}

// 正文上限只防病态内存，不再是「先砍再遮」：脱敏必须排在裁剪之前（A06），
// 所以这里尽量原样带出去，由证据层先投影再按预算裁。200 KB 之外的尾巴才丢。
const MAX_PAYLOAD = 200_000;

/** * 非 shell 参数里「送出去的内容」（写文件的正文、新串、技能参数…）：敏感面要看得见它。
 * 不在册的工具（含 MCP）**全部参数**都要带上——过去只捞少数路径键，数据库语句、
 * API body、对象 ID 全被藏起来，等于让 AI「看不见也要判」（A05）。
 */
function nonShellPayloads(args, adapter) {
    const out = [];
    const keys = adapter !== undefined ? (adapter.body ?? []) : Object.keys(args ?? {});
    for (const key of keys) {
        const value = args?.[key];
        const text = typeof value === 'string' ? value
            : value !== undefined && typeof value === 'object' ? JSON.stringify(value) : '';
        if (text.trim() !== '')
            out.push(text.slice(0, MAX_PAYLOAD));
    }
    return out;
}

/** 非 shell 参数里的 URL：主机进网络平面，别再只靠 shell 命令串（F04 的第二半）。 */
function nonShellUrls(args, adapter) {
    const found = [];
    const keys = adapter !== undefined ? (adapter.urls ?? []) : Object.keys(args ?? {});
    for (const key of keys) {
        const value = args?.[key];
        for (const item of Array.isArray(value) ? value : [value]) {
            if (typeof item !== 'string')
                continue;
            // 未知工具的参数里混着文件名（`content.txt` 会被 URL 正则当主机）：
            // 只收带 scheme 或 www 开头的串，别把一个本地文件名判成远端。
            if (adapter === undefined && !/:\/\//.test(item) && !/^www\./i.test(item))
                continue;
            found.push(...networkUrlTargets(item));
        }
    }
    return [...new Set(found)];
}

/** * 调用自带的工作目录（F02 的第二个来源）：客户端把「在哪个目录里跑」放进参数时，
 * 相对路径必须以它为准，否则审的是 session 目录、动的是别处。
 * 键名取台账里出现过的形状；一个都对不上就当没有，不猜。
 */
function workingDirOf(args) {
    for (const key of ['cwd', 'dir_path', 'workdir', 'working_directory', 'directory', 'dir']) {
        const value = args?.[key];
        if (typeof value === 'string' && value.trim() !== '')
            return value.trim();
    }
    return undefined;
}

function nonShellPaths(args, adapter) {
    const found = [];
    // 在册的按适配器取（它声明了哪些字段是路径），不在册的照旧扫路径键——
    // 认不出工具不该连带把它指的文件也看不见。
    for (const key of adapter ? adapter.paths ?? [] : PATH_KEYS) {
        const value = args?.[key];
        if (typeof value === 'string' && value.trim() !== '')
            found.push(value);
    }
    for (const key of ['paths', 'files', 'targets']) {
        const value = args?.[key];
        if (Array.isArray(value))
            found.push(...value.filter(item => typeof item === 'string' && item.trim() !== ''));
    }
    return found;
}

// 提权族里"只看不动"的子命令（F12：`reg query` 与 `reg delete` 不该同档，
// `sc query` 与 `sc stop` 也不该同档）。它们仍是读，落读类判定；改动型子命令照旧走提权行。
const READ_ONLY_SUBCOMMANDS = {
    reg: new Set(['query', 'qw', 'compare']),
    sc: new Set(['query', 'qcconfig', 'qdescription', 'qsid', 'qtriggerinfo', 'qtriggerdata', 'enumdepend', 'status']),
    netsh: new Set(['show']),
    icacls: new Set(['/save', '/l']),
};

// `segmentOpClass` 拿的是解析层的原始段（那时 `operands` 还没算出来），所以子命令要从 words 里取
// 第一个非 flag 的词——写成 `segment.operands[0]` 会永远是空串，判据静默失效。
const privilegeSubCommand = segment => String((segment.words ?? [])
    .find(word => word.kind === 'operand')?.text ?? '').toLowerCase();

function segmentOpClass(segment) {
    // 一律按归一 basename 分档（判据 5）：同名程序的 PowerShell／cmd 别名不再各认一半。
    const program = baseProgramOf(segment.program);
    // 原生命令先按**自己的名字**认读族（`Get-ChildItem` 与 `ls` 是两条命令，
    // 别名表只负责把它们归到同一族）：这一格不靠 POSIX 同名词兜底。
    if (NATIVE_READ_PROGRAMS.has(nativeNameOf(segment.program)))
        return 'read';
    // §4.5：只问版本／帮助的调用不动任何东西——`dd --version`、`mkfs --help`
    // 此前按程序名整族落提权行，问人问得没有信息量。
    const words = (segment.words ?? []).map(word => String(word.text ?? word));
    if (words.length > 0 && words.every(word => /^(?:--version|--help|-h|-V|-\?)$/i.test(word)))
        return 'read';
    if (DESTROY_PROGRAMS.has(program))
        return 'destroy';
    if (PRIVILEGE_PROGRAMS.has(program)) {
        const readSet = READ_ONLY_SUBCOMMANDS[program];
        // 子命令＝程序名后面的第一个操作数（`reg query HKU\…`／`sc query svc`）。
        if (readSet?.has(privilegeSubCommand(segment)) === true)
            return 'read';
        // §4.5：`chmod +x build.sh` 只是把一个文件打开执行位，不是提权改系统；
        // 数字模式（`chmod 600`）与递归（`-R`）仍算提权——它们能悄悄扩大／收窄敏感文件权限。
        // 45：数字模式再拆——三位或以 0 开头的四位、无 setuid/setgid/sticky 且 group/other
        // 无写位（44 冤弹 2：`chmod 644` 是降权）算普通写；`4755`／`2755`／`777`／`664`／
        // 带 s/t 的符号模式与递归仍算提权（fail-safe：证明不了不放大就按提权算）。
        if (program === 'chmod') {
            const mode = (segment.words ?? []).find(word => word.kind === 'operand')?.text ?? '';
            const symbolic = /^[ugoa]*[-+=][rwxXst]+$/i.test(mode);
            const recursive = (segment.words ?? []).some(word => /^-[a-z]*R[a-z]*$/.test(word.text));
            // group/other 写位＝数字 2/3/6/7（含 w 的都算）；owner 位（首位）不限制。
            const numericPlain = (/^\d{3}$/.test(mode) || /^0\d{3}$/.test(mode))
                && !/[2367]/.test(mode.slice(-2));
            if (!recursive && (numericPlain
                || (symbolic && !/[st]/i.test(mode.replace(/^[ugoa]*[-+=]/i, '')))))
                return 'write';
        }
        return 'privilege';
    }
    if (DELETE_PROGRAMS.has(program))
        return 'delete';
    if (program === 'mv')
        return 'rename';
    // 服务／进程／装包族是变更动作。此前它们一路落到 `exec`——`OP_CLASSES` 虽把 exec 折进
    // write，但段落那一格读不出「在改什么」；记 write 之后，具名行与目标抽取才落在同一轴上。
    if (PROCESS_PROGRAMS.has(program) || PACKAGE_PROGRAMS.has(program))
        return 'write';
    // 只有**输出**重定向才是写：`cat < in.txt` 的 `<` 是输入源（判据 2b），
    // 旧形把它也算成写，一条纯读命令因为这个符号落进写档。
    if (segment.redirects.some((redirect) => {
        const text = typeof redirect === 'string' ? redirect : redirect.text;
        const op = typeof redirect === 'string' ? '>' : redirect.op;
        return !isSink(text) && !isFdDup(text) && redirectReads(op) === false;
    }))
        return 'write';
    // `sed -i` rewrites the file in place, so it is a write however the flag
    // is spelled — and it must be decided before the filter whitelist below.
    if (FILTER_PROGRAMS.has(program) && segment.words.some(word => word.kind !== 'operand'
        && IN_PLACE_EDIT_FLAGS.test(word.text)))
        return 'write';
    if (READ_PROGRAMS.has(program)) {
        if (VCS_HISTORY_PROGRAMS.has(program)) {
            const words = segment.words.map(word => word.text);
            // 判据④：本地建仓／暂存／提交按写面判——此前落进读族，再由 readProof
            // 说「举不出证」，台账把写动作标成「读类但举不出证」。
            if (program === 'git') {
                const sub = words.find(word => !word.startsWith('-') && word !== 'git');
                if (GIT_WRITE_SUBCOMMANDS.has(sub))
                    return 'write';
            }
            if (program === 'git' && words.includes('push') && words.some(word => word === '--force' || word === '-f' || word === '--force-with-lease'))
                return 'history-rewrite';
            if (program === 'git' && (words.includes('clean') || (words.includes('reset') && words.includes('--hard'))
                || (words.includes('checkout', ) && words.includes('--')) || words.includes('restore')))
                return 'delete';
            // `git branch -d/-D` 删的是引用，`-m/-M/-c/-C/-f` 改的是引用：都不是列分支。
            // 表里那一行是「列分支」的允许行，不带这条，删除分支会被直接放行。
            if (program === 'git' && words.includes('branch'))
            {
                if (words.some(word => /^-[dD]$/.test(word)))
                    return 'delete';
                if (words.some(word => /^-[mMcCf]$/.test(word)))
                    return 'write';
            }
            // 数据外传不是读：push／tag（含 --tags，随 push 一起发）／apply（改工作区）都进判定链。
            // `git tag --list` 例外——列标签是读（F12：同名程序要按动作分档，不能一律当写）。
            if (program === 'git' && words.includes('tag') && !(words.includes('--list') || words.includes('-l')))
                return 'write';
            if (program === 'git' && (words.includes('push') || words.includes('apply')
                || words.includes('am') || words.includes('cherry-pick')))
                return 'write';
        }
        // `xxd -r in.hex out.bin`＝按位置参数落盘，并表后它虽在读族里，这一条仍是写。
        if (program === 'xxd' && anyFlag(segment.words.map(word => String(word.text)), RECOVER_FLAGS))
            return 'write';
        return 'read';
    }
    if (['touch', 'mkdir', 'cp', 'tee', 'set-content'].includes(program))
        return 'write';
    if (NAVIGATE_PROGRAMS.has(program) || FILTER_PROGRAMS.has(program))
        return 'read';
    return 'exec';
}

function fileFacts(target, probe) {
    try {
        const stat = probe.lstat(target);
        return {
            exists: true,
            kind: stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'dir' : stat.isFile() ? 'file' : 'other',
            bytes: stat.size,
        };
    }
    catch (error) {
        // F09：只有「确认不存在」才叫 absent。权限被拒／IO 错／路径过深都是**不知道**——
        // 把看不见写成「没有」会让删除看起来无害（`delete-of-non-file` 与可恢复性都跟着错）。
        const code = String(error?.code ?? '');
        if (code === 'ENOENT')
            return { exists: false, kind: 'absent', bytes: undefined };
        return { exists: 'unknown', kind: 'unknown', bytes: undefined, why: code === '' ? String(error) : code };
    }
}

/** 只判「这里是不是一个目录」：给 cd 的成功／失败候选挑锚点用。
 * 符号链接按真身算（cd 会跟过去）；读不到一律 false——不拿猜的当真。 */
function isDirectoryAt(path, probe) {
    if (typeof path !== 'string' || path === '')
        return false;
    const meta = fileFacts(path, probe);
    if (meta.exists !== true)
        return false;
    if (meta.kind === 'dir')
        return true;
    if (meta.kind !== 'symlink' || typeof probe.realpath !== 'function')
        return false;
    try {
        return fileFacts(probe.realpath(path), probe).kind === 'dir';
    }
    catch {
        return false;
    }
}

/** * 命中 `never` 凭据族的**读**不取元数据。`lstat` 不打开文件，但「存在＋多大」对
 * 密钥类文件本身就是信息（有几把密钥、各多大），而这一档的判定并不需要它。
 * 写／删照旧取——`delete-of-non-file` 与 `unrecoverable-content` 靠 kind/bytes 说话。
 * 不核实就照实在证据里写 `unchecked`，不假装看见，也不拿旧值猜。
 */
function metaOf(path, opClass, roots, probe) {
    if (opClass === 'read'
        && neverReasonsFor({ path, opClass }, roots).some(reason => String(reason).startsWith('credential-')))
        return { exists: 'unchecked', kind: 'unchecked', bytes: undefined };
    return fileFacts(path, probe);
}

/** * 这一次动作带回来的是**目录结构**还是**文件正文**。事实层只报这一格，
 * 升不升人仍由 policy 那条闸拍板——这里不产 decision，也不改 role／opClass 的既有形状。
 * 四件事缺一即不算「只带回结构」：① 是读族；② 真身是目录（凭据族刻意不 stat ⇒
 * `unchecked` 一律不算看见）；③ 程序只会列名字（LISTING_PROGRAMS 白名单，`git log`／`cat` 不在册）；
 * ④ find 没带执行／删除参数（`-exec rm`／`-delete` 列的是要动的东西，不是结构）。
 * 递归这一维不再否掉列名族——`ls -R`／`tree` 递归的仍然是**名字**（读面变宽，带回的
 * 仍是结构）；正文递归（`grep -r`／`rg`）根本进不了白名单，照旧不算结构。
 */
function structureOnlyOf(opClass, meta, segment) {
    // 补：`ls *.txt` 命中的是**文件**，回给模型的仍只是文件名——「只列结构」判的是
    // 「有没有读正文」，不是「目标是不是目录」。旧形要求 kind==='dir'，于是列文件一律不算结构。
    // 宿主 `read` 工具指到**文件**时回的是正文，不是名字——只有指到目录才是条目清单。
    // 这一格若误报，外项目闸会把它当成「只带回结构」放过去（别的项目的文件被自动放行）。
    if (opClass !== 'read' || meta.exists !== true || nameOnlySegment(segment) !== true)
        return false;
    return baseProgramOf(String(segment?.program ?? '')) !== 'read' || meta.kind === 'dir';
}

/** 这一段是不是「只列名字」的调用（find 带执行／删除参数时不算）。 */
function nameOnlySegment(segment) {
    const program = baseProgramOf(String(segment?.program ?? ''));
    if (!LISTING_PROGRAMS.has(program))
        return false;
    return program !== 'find' || !anyFlag((segment?.words ?? []).map(String), FIND_EXEC_FLAGS);
}

/** * 通配目标的**有界结构探测**——`ls <区外根>/*` 这种「列目录程序＋通配」此前只有一句
 * 「参数含通配」的 unproven，用户实见弹框。这里只做一件事：把通配在**父目录**里展开
 * （只读一层目录名，不递归、不读任何文件内容），确认每一项都是目录、名字里没有凭据形状、
 * 且没触顶／出错。全过 ⇒ 这次调用带回来的确实只是结构；任一不过或判不了 ⇒ 维持原证据等级。
 * 上限复用 SCOPE_LIMITS.files（＝MAX_TARGETS＝20）。默认只回一格标量读数（matches）；
 * 起调用方也可取 `names` 把子项按真实路径铸成目标——铸不铸由调用方按段判，
 * 本函数只保证「这些名字是这一次真读到的目录项」。
 */
function probeGlobStructure(text, probe, options = {}) {
    if (typeof probe.readdir !== 'function' || typeof probe.lstat !== 'function')
        return { known: false };
    const dirsOnly = options.dirsOnly === true;
    const admitSensitive = options.admitSensitive === true;
    // 只列名字的段：目标是**父目录**，子项是文件还是目录不影响「读的是这一层名字」。
    // 仍保留 dirsOnly（尾 `/` 只收目录）与敏感名检查；只免掉「全是目录」这条结构证明。
    const namesOnly = options.namesOnly === true;
    const limit = Number.isFinite(options.limit) ? options.limit : SCOPE_LIMITS.files;
    const api = pathApiFor(text);
    const parent = api.dirname(text);
    const pattern = api.basename(text);
    // 只认纯通配（*／?）：`$(…)`／变量／字符类这些仍是「目标集不确定」，不探。
    if (parent === text || !/[*?]/.test(pattern) || /[$`[]/.test(pattern))
        return { known: false };
    const regex = new RegExp(`^${pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
    let entries;
    try {
        entries = probe.readdir(parent);
    }
    catch {
        return { known: false };
    }
    const matches = [];
    let sensitiveName = false;
    for (const name of entries ?? []) {
        const entry = String(name);
        if (!regex.test(entry))
            continue;
        if (dirsOnly) {
            // `*/` 在 shell 里只展开目录：文件既不进目标，也不算「混进文件」。
            let stat;
            try {
                stat = probe.lstat(api.join(parent, entry));
            }
            catch {
                return { known: false };
            }
            if (stat?.isDirectory?.() !== true)
                continue;
        }
        if (isSensitiveBasename(entry)) {
            // 展开目标集时不拦名字：文件面还要按真实路径判。structureOnly 由调用方据 sensitive 置假。
            if (admitSensitive !== true)
                return { known: false };
            sensitiveName = true;
        }
        matches.push(entry);
        if (matches.length > limit)
            return { known: false };     // 触顶：清单不完整，不许说「看见的就是全部」
    }
    if (matches.length === 0)
        return { known: false };
    if (!dirsOnly && namesOnly !== true)
        for (const name of matches) {
            let stat;
            try {
                stat = probe.lstat(api.join(parent, name));
            }
            catch {
                return { known: false };
            }
            if (stat?.isDirectory?.() !== true)
                return { known: false };     // 混进文件＝带回的不是纯结构
        }
    return { known: true, matches: matches.length, names: matches, sensitive: sensitiveName };
}

/** * 判据⑥：未引用的纯通配（只认 `*`／`?`）在**段的当前目录**里有界展开：
 * 最多 `SCOPE_LIMITS.files`（＝20）个名字，触顶不算「看见的就是全部」，返回空并标截断。
 * 带目录前缀的通配不在这里展开（仍按「参数含通配」的老口径）；引号里的通配走不到这里
 * （`bare` 为假）。
 */
function expandGlobNames(text, cwd, probe, state) {
    if (typeof probe.readdir !== 'function' || typeof cwd !== 'string' || cwd === '')
        return { names: [], known: false };
    const pattern = String(text);
    if (/[\\/]/.test(pattern) || !/[*?]/.test(pattern) || /[`$[\]{}]/.test(pattern))
        return { names: [], known: false };
    const regex = new RegExp(`^${pattern.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
    let entries;
    try {
        entries = probe.readdir(cwd);
    }
    catch {
        return { names: [], known: false };
    }
    const hits = [];
    for (const name of entries ?? []) {
        if (!regex.test(String(name)))
            continue;
        hits.push(String(name));
        if (hits.length > SCOPE_LIMITS.files) {
            if (state !== undefined)
                state.truncated = true;
            return { names: [], known: false };
        }
    }
    return { names: hits.sort(), known: true };
}

/** * 量具读数（Phase 6·①）：Git spawn 占判定耗时 90%（44 条实测 1432ms／1591ms，p95 206ms）。
 * 四处收口都不动四态语义：
 * ① 可恢复性判据只被**写／删**消费（tracked clean 才有资格免 unrecoverable-content）；
 *    调用里没有任何非读目标时，status／ls-files 两次 spawn 整个省掉，读目标如实标
 *    `unchecked`（＝没查，不是「没事」）。
 * ② `rev-parse`（仓库发现）按 workspace 缓存 30s：仓库的存在性不随一次判定翻转；
 *    误判方向也保守——缓存说没仓库 ⇒ gitState 走 not-a-repo/unknown ⇒ 不继承放行资格。
 * ③ `ls-files` 只补 `status` **没吭声**的那批路径（判据本来就是 `if (!states.has(path))`
 *    才补 tracked）⇒ status 已逐条报过档位的场景一枚都不多问，pathspec 也只带静默子集。
 * ④ 这一格的总预算 `GIT_PROBE_BUDGET_MS`：旧写法三枚各拿 5s ⇒ 最坏 15s 把判定钉死。
 *    额度用尽就收尾，留下的状态是 `unknown`＝更严的一侧，不是更松。
 * ⑤ pathspec 用盘上真名（`trueCasePathspecs`）：git 的 pathspec 分大小写，而事实层的
 *    路径在 Windows 上折过小写 ⇒ 旧写法让所有带大写的文件名（`AGENTS.md`／`CHANGELOG.md`／
 *    `DSH-*.md`…）在 git 那里全程查无此档，状态永远 `unknown`，且每轮白起一枚 `ls-files`。
 *    这条**会变判定结果**：这类文件从此拿得到真状态，可恢复性判据第一次说得上话。
 */
const repoDiscovery = new Map();
const REPO_TTL_MS = 30_000;
const GIT_PROBE_BUDGET_MS = 4_000;
const GIT_SPAWN_MAX_MS = 5_000;
// 预算剩这么点就别再起进程了：一枚 git 的启动本身就要几十毫秒，硬起只会超时后白拿 unknown。
const GIT_SPAWN_MIN_MS = 150;

// 状态表的键与 git 回的路径用同一把尺折（Windows 不分大小写、POSIX 分）；判据住在 `paths.js`，
// 与 `normalizePath` 末尾那步折叠同源——一处折一处不折就会永远对不上。
const foldStateKey = (workspace, value) => {
    const text = String(value ?? '').replaceAll('\\', '/').replace(/\/+$/, '');
    return foldsCase(workspace) ? text.toLowerCase() : text;
};

/** * 发给 git 的 pathspec 要**盘上真名**：git 的 pathspec 分大小写（本机现读＝
 * `git ls-files -- AGENTS.md` 命中、`agents.md` 命中 0，`core.ignorecase=true` 也不改这一点），
 * 而事实层的路径在 Windows 上被 `normalizePath` 折成小写 ⇒ 拿折过的串当 pathspec，
 * 凡名字带大写的目标 git 全程答「不认识」：状态只能落 unknown，还每轮白起一枚 `ls-files`。
 * 这只换**发给 git 的那一份**，状态表的键照旧折叠（两侧同一把尺，判据不变）。
 * 逐段列目录取真名——`fs.realpath` 在这台机器上不会把末段大小写纠回来（现读试过），
 * 而列目录是文件系统按不敏感匹配回给的真名。取不到就照旧发折过的写法：
 * ① 目标还没落盘（新建文件，git 本来也答不出它）；② 目录列不出来（权限／IO 失败）。
 * 同一次判定里同一目录只列一枚，段数受 `MAX_TARGETS` 上限约束。
 */
function trueCasePathspecs(workspace, relatives, probe) {
    if (foldsCase(workspace) === false)
        return relatives.slice();
    const api = pathApiFor(workspace);
    const listings = new Map();
    const namesOf = dir => {
        if (listings.has(dir) === false) {
            try {
                listings.set(dir, probe.readdir(dir).map(String));
            }
            catch {
                listings.set(dir, undefined);
            }
        }
        return listings.get(dir);
    };
    return relatives.map(rel => {
        const fixed = [];
        let dir = workspace;
        for (const part of String(rel).split('/')) {
            const entries = namesOf(dir);
            const hit = entries === undefined ? undefined
                : entries.find(name => name.toLowerCase() === part.toLowerCase());
            fixed.push(hit ?? part);
            dir = api.join(dir, hit ?? part);
        }
        return fixed.join('/');
    });
}

function gitStates(workspace, relatives, probe, needStates = true) {
    const states = new Map();
    if (relatives.length === 0)
        return { states, repo: false };
    const deadline = Date.now() + GIT_PROBE_BUDGET_MS;
    const spawned = (command, args) => {
        const left = deadline - Date.now();
        if (left < GIT_SPAWN_MIN_MS)
            return { status: null, stdout: '', stderr: '', error: new Error('git-probe-budget') };
        return probe.spawn(command, args, Math.min(left, GIT_SPAWN_MAX_MS));
    };
    let discovery = repoDiscovery.get(workspace);
    if (discovery === undefined || Date.now() - discovery.at > REPO_TTL_MS) {
        const probeRepo = spawned('git', ['-C', workspace, 'rev-parse', '--is-inside-work-tree']);
        discovery = { repo: probeRepo.error === undefined && probeRepo.status === 0, at: Date.now() };
        repoDiscovery.set(workspace, discovery);
    }
    if (!discovery.repo)
        return { states, repo: false };
    if (!needStates)
        return { states, repo: true };
    const pathspecs = trueCasePathspecs(workspace, relatives, probe);
    // 先读 `status` 再补 `ls-files`：反过来的话，脏文件会先被 ls-files 标成干净的 tracked，
    // 而 status 那一轮又「见到就跳过」，四态永远分不出来（判据 4 的真脏样本就是为了咬住这一点）。
    const status = spawned('git', ['-C', workspace, 'status', '--porcelain=v1', '-z',
        '--untracked-files=all', '--ignored', '--', ...pathspecs]);
    const statusOk = status.error === undefined && status.status === 0;
    if (statusOk) {
        const entries = String(status.stdout ?? '').split('\0');
        for (let at = 0; at < entries.length; at += 1) {
            const entry = entries[at];
            if (entry === '')
                continue;
            const mark = entry.slice(0, 2);
            // `-z` 里目录会带尾斜杠（`!! dist/`），目标名不带——不剥掉就永远对不上状态表。
            const path = foldStateKey(workspace, entry.slice(3));
            // rename／copy 在 -z 形态里是**两条记录**（新名一条，原名紧随其后）：
            // 当成独立条目解析会把原名当垃圾键（mark `ol`）再丢掉。
            const pair = (mark[0] === 'R' || mark[0] === 'C') && entries[at + 1] !== undefined;
            if (mark === '??')
                states.set(path, 'untracked');
            else if (mark === '!!')
                states.set(path, 'ignored');
            // F09／判据 4：「已跟踪」不等于「当前内容有副本」。只有干净跟踪（索引与工作区
            // 都和最后一次提交一致）才算有第二份；改动过／只进了索引的内容，盘上这一份就是唯一一份。
            // staged（索引变过）与 dirty（工作区变过）是两件事，别合并成一档。
            else if (mark[0] !== ' ' && mark[0] !== '?')
                states.set(path, 'staged');
            else if (mark[1] !== ' ')
                states.set(path, 'dirty');
            else
                states.set(path, 'tracked');
            if (pair) {
                const original = foldStateKey(workspace, entries[at + 1]);
                if (original !== '' && !states.has(original))
                    states.set(original, 'staged');
                at += 1;
            }
        }
    }
    // status 失败／超时 ⇒ 状态保持 unknown：**不许**用 ls-files 把文件补成 tracked
    // 再拿「已跟踪」去换删除豁免（A11 判据 8）。
    if (!statusOk)
        return { states, repo: true, statusFailed: true };
    // 判据＝只给 status **没吭声**的那批路径补索引成员资格（下面也只在 `!states.has(path)` 时落 tracked），
    // 所以逐条报过档位的（??／!!／staged／dirty）一条都不必再问；全报完就连一枚都不起。
    // `relatives` 与 `pathspecs` 同序同号：静默判定按折叠键比，发出去的那枚 pathspec 取真名那份。
    const quiet = relatives.map((rel, index) => states.has(foldStateKey(workspace, rel)) ? -1 : index)
        .filter(index => index >= 0);
    if (quiet.length === 0)
        return { states, repo: true };
    const listed = spawned('git', ['-C', workspace, 'ls-files', '-z', '--', ...quiet.map(index => pathspecs[index])]);
    if (listed.error === undefined && listed.status === 0) {
        for (const entry of String(listed.stdout ?? '').split('\0').filter(Boolean)) {
            const path = foldStateKey(workspace, entry);
            if (!states.has(path))
                states.set(path, 'tracked');   // 在索引里且 status 没报任何改动＝有可验证的副本
        }
    }
    return { states, repo: true };
}

function rootHitFor(normalized, roots, opClass) {
    if (isWithin(roots.workspace, normalized, roots.home))
        return { hit: 'workspace', root: roots.workspace };
    // A trust root is an `allow` row from the rule table, so it can be scoped to
    // the operations the operator actually allowed (read / write / delete).
    // 命中哪一条要把它的模式带回去：删「根目录本身」与删它里面的东西是两件事，
    // 判据需要知道这个根在哪（`rootMatch`），不能只凭「目标是个目录」一刀切。
    const trusted = roots.trusted.find(rule => matchPath(rule, normalized, opClass));
    if (trusted !== undefined)
        return { hit: 'trusted', root: String(trusted.matchResolved ?? trusted.match ?? '') };
    const opened = roots.dshOpen.find(rule => matchPath(rule, normalized, opClass));
    if (opened !== undefined)
        return { hit: 'dsh-open', root: String(opened.matchResolved ?? opened.match ?? '') };
    return { hit: 'outside', root: '' };
}

// ── 外项目根（读面硬闸的事实来源）──────────────────────────────────────
// 「别的项目」只认确定特征：同层或向上有 `AGENTS.md`／`.git`。向上最多 8 层，
// 按调用内缓存（同一目录链只 stat 一次）；找不到就不猜（`foreignProject:false`）。
// 家目录与宿主状态树（`~/.dsh`）不是「别的项目」：它们的 AGENTS.md 是用户级说明，
// 技能说明子树本来就是任务资源（与 scope.js 同口径）。
const FOREIGN_ROOT_DEPTH = 8;

function hasProjectMarker(dir, probe) {
    if (typeof probe.lstat !== 'function')
        return false;
    const api = pathApiFor(dir);
    for (const name of ['AGENTS.md', '.git']) {
        try {
            probe.lstat(api.join(dir, name));
            return true;
        }
        catch {
            // 查不到（不存在／读不了）就是没有这个标记
        }
    }
    return false;
}

function foreignRootOf(startDir, probe, cache) {
    if (startDir === '')
        return '';
    const api = pathApiFor(startDir);
    const chain = [];
    let dir = startDir;
    let found = '';
    for (let depth = 0; depth < FOREIGN_ROOT_DEPTH; depth += 1) {
        const cached = cache.get(dir);
        if (cached !== undefined) {
            found = cached;
            break;
        }
        chain.push(dir);
        if (hasProjectMarker(dir, probe)) {
            found = dir;
            break;
        }
        const parent = api.dirname(dir);
        if (parent === dir)
            break;
        dir = parent;
    }
    for (const item of chain)
        cache.set(item, found);
    return found;
}

/** 家目录／宿主状态树不是「别的项目」；命中的根不合格就当没找到。 */
function qualifyForeignRoot(root, roots) {
    if (root === '')
        return '';
    if (root === roots.home)
        return '';
    if (typeof roots.dshHome === 'string' && roots.dshHome !== '' && isWithin(roots.dshHome, root, roots.home))
        return '';
    return root;
}

// ── 源根（唯一裸名 ⇒ 本会话 sourceRoot）────────────────────────────────
// 消息里只提了一个项目名时，把「点名」扩成可核的事实：
// 在**两处父目录**的直接子项里找大小写不敏感全等的目录名，唯一命中⇒绑根。
// 扫描有界：每处一次 readdir、按名字排序后取前 200 条、不递归；命中 ≥2 ⇒ 不绑（不猜）。
const SOURCE_SCAN_LIMIT = 200;

function sourceRootOf(roots) {
    const bound = sourceRoots.get(sessionIdOf(roots));
    if (bound !== '')
        return bound;
    return typeof roots?.authorization?.sourceRoot === 'string' ? roots.authorization.sourceRoot : '';
}

function sessionIdOf(roots) {
    return typeof roots?.authorization?.sessionId === 'string' ? roots.authorization.sessionId : '';
}

/** * 绑定点。一次**纯读**的目标落在用户消息里以绝对路径给出、经 lstat 确认是目录的
 * resource 之下，且本会话当前没有任何绑定、62 也没解析出唯一命中时，记一条会话级绑定。
 * 不猜、不近似、不新增扫描：resource 与目标都来自既有 PATHISH／namedByUser 结果。
 */
function bindSourceRoot(roots, targets, probe) {
    const sessionId = sessionIdOf(roots);
    if (sessionId === '' || sourceRoots.get(sessionId) !== '')
        return '';
    if (typeof probe?.lstat !== 'function')
        return '';
    if (targets.length === 0
        || targets.some(target => target?.dynamic !== true && String(target?.opClass) !== 'read'))
        return '';
    const reads = targets.filter(target => target?.dynamic !== true
        && String(target?.opClass) === 'read' && target?.namedByUser === true
        && typeof target?.path === 'string' && target.path !== '');
    if (reads.length === 0)
        return '';
    const resources = Array.isArray(roots?.authorization?.resources) ? roots.authorization.resources : [];
    for (const raw of resources) {
        const text = String(raw ?? '');
        if (text === '' || isDynamic(text))
            continue;
        if (!pathApiFor(text, roots.workspace).isAbsolute(text))
            continue;
        const dir = normalizePath(text, roots.workspace, roots.home);
        let info;
        try {
            info = probe.lstat(dir);
        }
        catch {
            continue;
        }
        if (info?.isDirectory?.() !== true)
            continue;
        if (reads.some(target => isWithin(dir, target.path, roots.home)))
            return sourceRoots.put(sessionId, dir);
    }
    return '';
}

function withinSourceRoot(targetPath, roots) {
    const root = sourceRootOf(roots);
    return root !== '' && isWithin(root, targetPath, roots.home);
}

const USER_SCAN_LIMIT = 20;

/** 配置里的补充目录。只收绝对路径（`~` 展开成家目录），归一后去重；按配置顺序取前 20 条。 */
function userScanDirs(roots) {
    const configured = Array.isArray(roots?.sourceRootDirs) ? roots.sourceRootDirs : [];
    const valid = [];
    for (const raw of configured) {
        if (typeof raw !== 'string')
            continue;
        const text = raw.trim();
        if (text === '')
            continue;
        const tilde = text === '~' || text.startsWith('~/') || text.startsWith('~\\');
        if (tilde !== true && pathApiFor(text, roots.workspace).isAbsolute(text) !== true)
            continue;
        valid.push({ raw, dir: normalizePath(text, roots.workspace, roots.home) });
    }
    const kept = [];
    for (const item of valid.slice(0, USER_SCAN_LIMIT)) {
        if (!kept.includes(item.dir))
            kept.push(item.dir);
    }
    return { dirs: kept, trimmed: valid.slice(USER_SCAN_LIMIT).map(item => item.raw) };
}

/** 扫描父目录：家目录本身 ＋ 会话工作区的父目录 ＋ 配置的补充目录（去重、保序、同一把归一）。 */
function sourceScanDirs(roots) {
    const out = [];
    if (typeof roots.home === 'string' && roots.home !== '')
        out.push(normalizePath(roots.home, roots.home, roots.home));
    const api = pathApiFor(roots.workspace);
    const parent = api.dirname(roots.workspace);
    if (parent !== roots.workspace) {
        const normalizedParent = normalizePath(parent, parent, roots.home);
        if (!out.includes(normalizedParent))
            out.push(normalizedParent);
    }
    const extra = userScanDirs(roots);
    for (const dir of extra.dirs) {
        if (!out.includes(dir))
            out.push(dir);
    }
    return { dirs: out, trimmed: extra.trimmed };
}

/** * 裸名 ⇒ sourceRoot。解析不出唯一目录就不绑：不做模糊匹配、不做编辑距离，
 * 归一只有「大小写不敏感全等」这一条。家目录本身、`~/.dsh`、点开头目录、
 * `skills` 子树一律不当源根（它们是用户级说明或宿主状态，不是任务资源）。
 */
function resolveSourceRoot(roots, probe) {
    const names = Array.isArray(roots.authorization?.bareNames) ? roots.authorization.bareNames.map(String) : [];
    const result = { root: '', candidates: 0, names, scanned: [], limited: [] };
    if (names.length === 0 || typeof probe.readdir !== 'function')
        return result;
    const wanted = new Set(names.map(name => name.toLowerCase()));
    const scanned = sourceScanDirs(roots);
    const dirs = scanned.dirs;
    result.scanned = dirs;
    // 超出 20 条的补充目录原值（不参与扫描，但要让结果里看得见）。
    result.trimmedDirs = scanned.trimmed;
    const matches = new Set();
    const homeNorm = normalizePath(roots.home, roots.home, roots.home);
    for (const dir of dirs) {
        let entries;
        try {
            entries = probe.readdir(dir);
        }
        catch {
            continue;
        }
        const all = [...(entries ?? [])].map(String).sort((left, right) => left.localeCompare(right));
        if (all.length > SOURCE_SCAN_LIMIT)
            result.limited.push(dir);
        for (const entry of all.slice(0, SOURCE_SCAN_LIMIT)) {
            if (entry.startsWith('.') || entry.toLowerCase() === 'skills' || !wanted.has(entry.toLowerCase()))
                continue;
            const full = pathApiFor(dir).join(dir, entry);
            const normalized = normalizePath(full, dir, roots.home);
            if (normalized === homeNorm)
                continue;
            if (typeof roots.dshHome === 'string' && roots.dshHome !== ''
                && isWithin(roots.dshHome, normalized, roots.home))
                continue;
            let info;
            try {
                info = probe.lstat(full);
            }
            catch {
                continue;
            }
            if (info?.isDirectory?.() === true)
                matches.add(normalized);
        }
    }
    result.candidates = matches.size;
    // 多义时 ask 文案要列出候选目录——集合就取这里实际 lstat 命中的目录，
    // 由 index.js 的 askText 消费；不另做扫描、不把扫描根或未命中项算进候选。
    result.matches = [...matches].sort();
    if (matches.size === 1)
        result.root = [...matches][0];
    return result;
}

/** * 用户在消息里点过名没有，三条路：源根内／`authorization.resources`
 * （PATHISH 抽出来的路径形状）／用户显式文件行覆盖到这条路径（该行对 read 表了态）。
 */
function namedByUserOf(targetPath, roots, cache, ruleRowsOf) {
    const cached = cache.get(targetPath);
    if (cached !== undefined)
        return cached;
    let named = withinSourceRoot(targetPath, roots);
    if (named === false) {
        const resources = Array.isArray(roots.authorization?.resources) ? roots.authorization.resources : [];
        named = resources.some((raw) => {
            const resource = normalizePath(String(raw ?? ''), roots.workspace, roots.home);
            return resource === targetPath || isWithin(resource, targetPath, roots.home);
        });
    }
    if (named === false)
        named = ruleRowsOf().some(row => row.enabled !== false && row.removed !== true
            && matchPath(row, targetPath, 'read'));
    cache.set(targetPath, named);
    return named;
}

/** * Build the action record for one tool call.
 *
 * `targets` are literals only; a dynamic operand (`$(...)`, glob, brace
 * expansion) is kept as `dynamic: true` with no filesystem read, because its
 * real target is unknowable here and must not be presented as a proven fact.
 */
/** * POSIX shell 的内联命令行展开（判据 31）：`bash -c "cat …/.env"` 里被读的就是 `.env`，
 * 但按字面量抠代码抠不出来（shell 的路径是裸词）。旧形既不展开、又把整段代码折成
 * 一条工作区内的假路径 ⇒ 同一份凭据 `cat` 落人工、包一层 `bash -c` 落交模型（更松的一档）。
 * 展开成它自己的段，父段仍然留着（命令面匹配与 argv 口径不变），只把代码位从路径里剔掉。
 * 只展开一层：内层再套 `bash -c` 由不透明那一格说话。
 */
function expandInlineShell(segment, home) {
    const program = baseProgramOf(segment.program);
    if (POSIX_SHELL_INLINE.has(program) === false)
        return [segment];
    const codes = inlineCodeArgs(program, segment.words.map(word => word.text)).filter(item => item.flag === '-c');
    if (codes.length === 0)
        return [segment];
    // 内联代码仍是 bash：交给同一套结构化解析（能算死就带上父段的 cwd，算不死退回手写拆串）。
    // 内层段只做证据，换目录的效果不外泄——后面的外层段各自带着自己的注解。
    const context = typeof segment.cwd === 'string' && segment.cwd !== ''
        ? { cwd: segment.cwd, home }
        : {};
    const inner = codes.flatMap((item) => {
        const parsed = splitCommandSegments(item.value, 'bash', context);
        return (parsed.segments ?? splitSegments(item.value))
            .map(nested => ({ ...nested, fromInline: true }));
    });
    return inner.length === 0 ? [segment] : [segment, ...inner];
}

/** * `cat "$X"`——X 是环境变量时，算法在判定这一刻就能把它算死：
 * 取当前环境里的值（空值／未设＝空串），只对**读族 + 路径位 + 整词 `$NAME`／`${NAME}`** 展开。
 * 三条收窄，缺一不展开：
 *   ① 命令里出现能在运行时改名的写法（`read X`／`eval`／`source`／`X=…`／`for X in …`）
 *      ⇒ 整条不按环境变量算（运行时的 X 与判定这一刻不是同一个值）；
 *   ② 未引用的值里有空白／通配（shell 会分词、通配）⇒ 目标集算不死，保持运行时展开；
 *   ③ 非空值必须是**真实存在的路径**（只 lstat，不读正文）⇒ 不把令牌这类非路径值带进目标证据。
 * 只替换目标解析用的操作数文本；`segment.words`／argv 仍是原文，环境变量的值不进证据。
 */
const ENV_OPERAND_WORD = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?$/;
const ENV_VALUE_PATH_SAFE = /^[^\s$`*?[\]{}'"();|&<>]+$/;
const ENV_ASSIGNER_WORDS = /(?:^|[\s;&|(){}])(?:read|readarray|mapfile|getopts|eval|source|declare|typeset|local|export|unset)(?=[\s;&|(){}]|$)|(?:^|[\s;&|(){}])printf(?=[\s;&|(){}]|$)[^;&|\n]*\s-v(?:\s|$)|(?:^|[;&|(){}])\s*\.\s+\S|\(\(/;
const FOR_ASSIGN = /\b(?:for|select)\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b/g;
// `${X:=…}`／`${X=…}` 会在运行时给 X 赋值（`:=` 是「空则赋」），与 `X=…` 同等对待。
const PARAM_ASSIGN = /\$\{([A-Za-z_][A-Za-z0-9_]*)[:]?=/g;

function envGuardFor(command, env) {
    if (env === undefined || env === null)
        return undefined;
    const text = String(command ?? '');
    if (ENV_ASSIGNER_WORDS.test(text))
        return undefined;
    const names = assignedNames(text);
    for (const match of text.matchAll(FOR_ASSIGN))
        names.add(match[1]);
    for (const match of text.matchAll(PARAM_ASSIGN))
        names.add(match[1]);
    return { env, names };
}

/** undefined＝不展开；''＝展开成空串；其余＝展开出的路径。 */
function resolveEnvOperand(text, guard, cwd, probe, roots) {
    if (guard === undefined || typeof cwd !== 'string' || cwd === '')
        return undefined;
    const match = ENV_OPERAND_WORD.exec(String(text));
    if (match === null || guard.names.has(match[1]))
        return undefined;
    const value = guard.env[match[1]];
    // 变量**没设**（或设成空串）时不拿空值当"算死了"：`cat $NOPE` 实际是运行时才展开，
    // 折成空串等于把「读了什么不知道」写成「什么也没读」，还顺手给了只读证明。
    if (value === undefined || String(value) === '')
        return undefined;
    const resolved = String(value);
    if (ENV_VALUE_PATH_SAFE.test(resolved) === false || typeof probe.lstat !== 'function')
        return undefined;
    try {
        probe.lstat(normalizePath(resolved, cwd, roots.home));
    }
    catch {
        return undefined;
    }
    return resolved;
}

export function collectFacts({ toolName, args, roots, probe = fsProbe, env = process.env }) {
    const shellCommand = shellTargets(args);
    const isShell = SHELL_TOOLS.has(String(toolName ?? '').toLowerCase())
        || typeof shellCommand === 'string' && typeof args?.command === 'string';
    // 闭合展开（字面量 for／字面量赋值／basename 派生）——展不开就原样返回，
    // 后面仍按 opaque 走；**不部分展开**（任一段算不死 ⇒ 整条保持现状）。
    const closed = isShell
        ? expandClosedShell(shellCommand, env)
        : { command: shellCommand, expanded: false, why: '' };
    // 环境变量只在**整条命令**没有运行时改名写法时才拿来算（见 envGuardFor）。
    const envGuard = isShell ? envGuardFor(String(args?.command ?? args?.cmd ?? ''), env) : undefined;
    // MCP tool names use the `mcp:<server>` convention (some hosts spell it
    // `mcp_<server>` / `mcp.<server>`). They get their own default below.
    const isMcp = /^mcp[:_.-]/i.test(String(toolName ?? '').trim());
    // 起始工作目录要在解析之前定：结构化解析要沿执行结构把它传播下去。
    const baseCwd = workingDirOf(args) ?? roots.workspace;
    // 结构由文法给出（bash／pwsh），词法仍用 parse.js 的同一把尺；方言未知或文法报错
    // 退回手写拆串，并由 parseMode 如实带回原因——不完整只说明结构没被证实，不是新闸。
    const parsed = isShell
        ? splitCommandSegments(closed.command, toolName, { cwd: baseCwd, home: roots.home })
        : { segments: null, mode: 'none', incomplete: false, why: '' };
    const segments = isShell
        ? (parsed.segments ?? splitSegments(closed.command))
            .flatMap(segment => expandInlineShell(segment, roots.home)).map((segment) => {
            // 段的动作类要看**程序本身**，不能被重定向连累：`cat .env > out.txt` 这一段
            // 在命令面是写（有重定向），但 .env 是读源、out.txt 才是写目的（A03）。
            const baseOpClass = segmentOpClass({ ...segment, redirects: [] });
            // 段内每个词的位语义（flag／path／nopath）——目标解析与通配否证共用这一列。
            const wordRoles = wordRolesOf(segment.program,
                segment.words.map(word => word.text), segment.words.map(word => word.kind));
            const operandRoles = segment.words
                .map((word, index) => ({ word, index }))
                .filter(item => item.word.kind === 'operand')
                .map(item => wordRoles[item.index]);
            return {
                program: segment.program,
                programName: baseProgramOf(segment.program),
                opClass: segmentOpClass(segment),
                baseOpClass,
                // Ordered argument words (flags included): the command plane matches
                // "program + argument prefix", which needs the sequence, not a set.
                words: segment.words.map(word => word.text),
                kinds: segment.words.map(word => word.kind),
                // 引号里的特殊字符是字面量（判据 5）：这一列跟 words 一一对应，
                // 事实层判「会不会展开」时只认 bare＝true 的那些词。
                wordsBare: segment.words.map(word => word.bare === true),
                argv: [String(segment.program ?? ''), ...segment.words.map(word => word.text)],
                flags: segment.words.filter(word => word.kind !== 'operand').map(word => word.text),
                operands: operandsOf(segment),
                // 与 `operands` 一一下标的位语义（`nopath` 的词不进目标集）。
                operandRoles,
                wordRoles,
                operandBare: segment.words.filter(word => word.kind === 'operand').map(word => word.bare === true),
                redirects: segment.redirects.map(redirect => redirect.text),
                redirectOps: segment.redirects.map(redirect => redirect.op),
                redirectDynamic: segment.redirects.map(redirect => redirect.dynamic === true),
                heredocExpanded: segment.heredocExpanded === true,
                // 这段自带 heredoc（正文就在命令里）：解释器从 stdin 读脚本时，
                // 正文对评审可见，不再按“外部脚本文件”一刀切。
                heredoc: Array.isArray(segment.heredocs) && segment.heredocs.length > 0,
                heredocText: Array.isArray(segment.heredocs)
                    ? segment.heredocs.map(heredoc => String(heredoc.text ?? '')).join('\n') : '',
                fromHeredoc: segment.fromHeredoc === true,
                fromInline: segment.fromInline === true,
                opaque: segment.opaque === true,
                // 结构化解析给出的逐段工作目录：唯一值＝cwd；多候选按可信度排序；
                // 算不死时 cwdUnknown 带来源。退回手写拆串时这三格都不存在，走原线性扫描。
                cwd: segment.cwd,
                cwdCandidates: Array.isArray(segment.cwdCandidates) ? [...segment.cwdCandidates] : undefined,
                cwdUnknown: typeof segment.cwdUnknown === 'string' ? segment.cwdUnknown : undefined,
            };
        })
        : [];
    // 整条调用的读面（name／body；非读调用为 undefined）。
    let callReadFace;
    const literalInputs = [];
    const remoteHosts = [];
    // 非 shell 参数里要送出去的内容（写入正文／新串／技能参数）：敏感面与深评都要看得见。
    const payloads = [];
    // 网络面的作用项（源／目的）与被执行体：它们不是本地路径，不进 targets，
    // 但要在 effects 里按角色分开（判据 1／6）。
    const networkEffects = [];
    const executableEffects = [];
    // 读面枚举的完备性：任何一段触顶／读盘报错都要带出去（判据 4）。
    const scanState = { truncated: false, error: false };
    const bumpScan = (segment, state) => {
        const rank = { ok: 0, truncated: 1, error: 2 };
        if (rank[state] > rank[segment.readCompleteness ?? 'ok'])
            segment.readCompleteness = state;
        if (state === 'error')
            scanState.error = true;
        if (state === 'truncated')
            scanState.truncated = true;
    };

    // 源根解析要在逐段举证**之前**算出来——`scopeInsideRoots`（递归读的范围）
    // 与逐目标的 namedByUser 都吃这一格。解析结果回写到本次调用的 authorization 上，
    // 证据块与台账因此看到同一份事实。
    // 撤销句当场清空本会话的全部绑定；随后按「store ＞ 62 的唯一命中 ＞ 空」取源根。
    // 撤销后本会话不再自动绑定（授权里没有「撤销位置」可对齐资源先后 ⇒ 宁可不绑，也不拿旧点名复活）。
    const sessionId = sessionIdOf(roots);
    const revoked = sessionId !== '' && typeof roots?.authorization?.latestRevoke === 'string'
        && roots.authorization.latestRevoke !== '';
    if (revoked)
        sourceRoots.clear(sessionId);
    const resolved = resolveSourceRoot(roots, probe);
    const boundRoot = sourceRoots.get(sessionId);
    const sourceRoot = boundRoot === '' ? resolved : { ...resolved, root: boundRoot };
    if (roots.authorization !== undefined && roots.authorization !== null
        && typeof roots.authorization === 'object') {
        roots.authorization.sourceRoot = sourceRoot.root;
        roots.authorization.sourceRootCandidates = sourceRoot.candidates;
    }

    // 逐段 cwd（F02 的第一刀）：`cd sub && cat config.txt` 里 cat 动的是 `sub/config.txt`，
    // 不是 workspace 下那个同名文件——审错位置比不审更糟，因为它会给出一个「已审过」的假象。
    // 有工作目录参数时以它为准（台账里出现过的形状都收进来，认不出就当没有）。
    // 它必须先算出来：cp 的目的是不是目录、递归读在哪一棵子树，都吃它。
    // 结构化解析已沿执行结构算好（&&／|| 各吃各的分支、子 shell／管道隔离）时直接采用；
    // 只有退回手写拆串（方言未知／文法报错）才走线性扫描——那正是语法不可证的边界。
    const cwdOf = new Map();
    const cwdUnknownOf = new Map();
    if (parsed.segments !== null) {
        // `bash -c "…"` 内联展开与 heredoc 正文里的替换：在父段的同一位置执行，继承父段 cwd。
        let inherited;
        for (const [index, segment] of segments.entries()) {
            let own = segment.cwd !== undefined || segment.cwdCandidates !== undefined
                || segment.cwdUnknown !== undefined;
            if (own === false && inherited !== undefined
                && (segment.fromInline === true || segment.fromHeredoc === true)) {
                segment.cwd = inherited.cwd;
                segment.cwdCandidates = inherited.cwdCandidates === undefined
                    ? undefined : [...inherited.cwdCandidates];
                segment.cwdUnknown = inherited.cwdUnknown;
                own = true;
            }
            if (own === false) {
                cwdUnknownOf.set(index, '结构解析未给出这一段的工作目录');
                continue;
            }
            inherited = segment;
            if (segment.cwd !== undefined) {
                cwdOf.set(index, segment.cwd);
                continue;
            }
            // 「算不死」优先于候选：cwdUnknown 在时，候选只是证据里「本来以为是哪儿」，
            // 不能拿来当锚点——那会把未知重新折成一个具体目录。
            if (typeof segment.cwdUnknown === 'string' && segment.cwdUnknown !== '') {
                cwdUnknownOf.set(index, segment.cwdUnknown);
                continue;
            }
            if (Array.isArray(segment.cwdCandidates) && segment.cwdCandidates.length > 0) {
                // 候选按可信度排序（cd 成功态在前）：取第一个真实存在的目录；
                // 都不存在时这一段的相对路径就没有可信锚点，按「工作目录不确定」处理。
                const picked = segment.cwdCandidates.find(path => isDirectoryAt(path, probe));
                if (picked !== undefined) {
                    cwdOf.set(index, picked);
                    continue;
                }
                cwdUnknownOf.set(index, `候选工作目录都不存在：${segment.cwdCandidates.join('｜')}`);
                continue;
            }
            cwdUnknownOf.set(index, '工作目录未知');
        }
    }
    else {
        // 手写拆串：原线性规则（`cd` 后跟不出字面量就保持当前段的位置）。
        let cursor = baseCwd;
        const stack = [];
        for (const [index, segment] of segments.entries()) {
            cwdOf.set(index, cursor);
            const program = segment.programName ?? baseProgramOf(segment.program);
            const operand = (segment.operands ?? []).find(text => text !== '' && text !== '-' && !isDynamic(text));
            if (program === 'cd' || program === 'chdir') {
                if (operand !== undefined)
                    cursor = normalizePath(operand, cursor, roots.home);
                continue;
            }
            // pushd／popd 是「换目录并记账」：账本要跟着走，否则 `popd && cat x` 审的还是旧位置。
            if (program === 'pushd') {
                stack.push(cursor);
                if (operand !== undefined)
                    cursor = normalizePath(operand, cursor, roots.home);
                continue;
            }
            if (program === 'popd')
                cursor = stack.pop() ?? cursor;
        }
    }

    if (isShell) {
        for (const [index, segment] of segments.entries()) {
            const program = segment.programName;
            // 命令面执行族标签——文件面只按路径说话，执行／进程／装包归命令面具名行判。
            // 五种：interpreter／inline／piped／process／package；`execDynamic`＝「来源不可举证」。
            {
                const flagTexts = (segment.words ?? []).map(word => String(word.text ?? word).toLowerCase());
                // 内联代码旗标以 INLINE_CODE_FLAGS 为准（`deno eval` 这种不带横线的写法也算），
                // 再兜住通用短旗标；`cmd /c` 用的是斜杠，单独认。
                const declaredInline = (INLINE_CODE_FLAGS[program] ?? []).map(name => String(name).toLowerCase());
                const inlineFlag = flagTexts.some(flag => declaredInline.includes(flag)
                    || /^-(?:c|e|p|command|encodedcommand)$/.test(flag) || flag === '--eval'
                    // Git Bash 把 `/c` 写成 `//c`（`cmd //c "dir …"`）：归一后再判，
                    // 否则 cmd 被当成「执行外部脚本」，正文明明在命令里却说没送来。
                    || (program === 'cmd' && /^\/+[ck]$/i.test(flag)));
                const programText = String(segment.program ?? '');
                const scriptLike = /\.(?:sh|bash|zsh|ksh|py|js|mjs|cjs|rb|pl|php|ps1)$/i.test(programText)
                    || /[\\/]/.test(programText);
                const rawCommand = String(args?.command ?? '');
                const escapeRe = text => String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const pipedIn = new RegExp(`\\|\\s*(?:sudo\\s+)?[\\w./\\\\-]*${escapeRe(program)}\\b`).test(rawCommand);
                const shellOrInterp = POSIX_SHELL_INLINE.has(program) || INTERPRETER_PROGRAMS.has(program);
                segment.execFamily = '';
                segment.execDynamic = false;
                if (inlineFlag && shellOrInterp) {
                    segment.execFamily = 'inline';
                    const items = inlineCodeArgs(program, segment.words);
                    const code = items.length > 0 ? String(items[0].value ?? '') : '';
                    // 正文为空、带 `$`／反引号、或压根抠不出＝来源不可读，交人工。
                    segment.execDynamic = code.trim() === '' || /[$`]/.test(code);
                }
                else if (shellOrInterp || scriptLike || program === 'source' || program === '.') {
                    segment.execFamily = pipedIn ? 'piped' : 'interpreter';
                    if (pipedIn) {
                        const statics = /(?:cat|head|tail|type)\s+["']?([^\s|"']+)["']?\s*\|\s*(?:bash|sh)\b/.exec(rawCommand);
                        let known = false;
                        // 工作目录不确定时不去猜脚本文件在哪：不读比读错强。
                        if (statics !== null && typeof probe.lstat === 'function'
                            && cwdOf.get(index) !== undefined) {
                            try {
                                probe.lstat(normalizePath(statics[1], cwdOf.get(index) ?? roots.workspace, roots.home));
                                known = true;
                            }
                            catch {
                                known = false;
                            }
                        }
                        // 左侧是已举证的静态脚本文件＝ai；其余（curl | bash、变量喂进去）＝ask。
                        segment.execDynamic = !known;
                    }
                    // 解释器没有脚本文件参数、正文由 heredoc 从 stdin 喂进来 ⇒
                    // 正文就在命令里（`python - <<'EOF' … EOF`），与 `-c` 内联同档。
                    else if (segment.heredoc === true
                        && interpreterScript(program, segment.words) === -1) {
                        segment.scriptFromStdin = true;
                    }
                }
                else if (program === 'xargs' || PROCESS_PROGRAMS.has(program))
                    segment.execFamily = 'process';
                else if (PACKAGE_PROGRAMS.has(program))
                    segment.execFamily = 'package';
            }
            // 脚本正文里的外传：正文里既有发送动作、又点得出目的主机 ⇒ 记成外传事实。
            // 目的主机同时进这一段与全调用清单，网络表的行（含兜底行）才看得见它们。
            const scriptText = scriptTextOf(segment, program, probe, cwdOf.get(index), roots);
            if (scriptText !== '' && scriptSendsData(scriptText)) {
                const scriptHosts = scriptNetworkTargets(scriptText);
                if (scriptHosts.length > 0) {
                    segment.scriptUpload = true;
                    for (const host of scriptHosts)
                        pushSegmentHost(segment, remoteHosts, host);
                }
            }
            // 工作目录不确定时这里保持 undefined：所有「把相对路径折成绝对路径」的地方
            // 都要先看得到它，不能借 workspace 兜底——那会把区外目标折成区内的假目标。
            const cwd = cwdOf.get(index);
            const cwdCertain = cwd !== undefined;
            const remote = REMOTE_PROGRAMS.has(program);
            // 这一段自己在跟哪些远端打交道：F03 要按作用项定局，主机清单不能只留全调用的并集。
            const pushRemote = host => pushSegmentHost(segment, remoteHosts, host);
            let remoteHost = false;
            // 模式文件三种写法同一条语义（A01/A03）：`-f FILE`／`--file=FILE`／`-fFILE`。
            // 旧写法只认完整词，`--file=.env` 的文件藏在旗标里，`.env` 规则根本没机会参与。
            // 只在检索程序上成立：`rm -f x` 的 `-f` 是 force，不是模式文件。
            const patternFiles = PATTERN_PROGRAMS.has(program)
                ? flagValues(segment.words, PATTERN_FILE_FLAGS) : [];
            const patternTexts = new Set(patternFiles.map(item => item.value));
            for (const item of patternFiles)
                literalInputs.push({
                    text: item.value, segment, dynamic: isDynamic(item.value),
                    role: 'pattern-file', opClass: 'read',
                });
            // 「第一个操作数是模式」只在没有 `-f` 时成立：给了 `-f FILE`，模式从文件里读。
            // 服务／装包族的第一词是子命令（`systemctl restart`／`pip install`），同样不是目标。
            const subCommandSkip = SUBCOMMAND_WORDS[program] !== undefined
                && segment.operands.length > 0
                && SUBCOMMAND_WORDS[program].has(String(segment.operands[0]).toLowerCase());
            // 模式位已由位语义排除时（`grep -e PATTERN`），首操作数不再是模式——不再跳过它。
            const skipFirst = ((PATTERN_PROGRAMS.has(program) && patternFiles.length === 0
                && (segment.operandRoles?.[0] ?? 'path') !== 'nopath') || subCommandSkip);
            // 解释器的内联代码位（判据 31）：`-c`／`-e`／`-Command` 的取值是**代码**——
            // 既不是脚本文件，也不是一条路径。旧形把它当普通操作数折进目标集，于是
            // `python -c "print(open(r'…\.env').read)"` 的读面上留下一条工作区内的假路径，
            // 真正被读的 `.env` 反而不在表里：同一份凭据，`cat` 落人工、`python -c` 落交模型。
            // POSIX shell 不在这儿抠字面量（上面已展开成它自己的段），但代码位照样剔掉。
            const inlineArgs = INTERPRETER_PROGRAMS.has(program) ? inlineCodeArgs(program, segment.words) : [];
            const inlineTexts = new Set(inlineArgs.map(item => item.value));
            for (const item of inlineArgs) {
                const code = item.flag === '-encodedcommand' ? decodeEncodedCommand(item.value) : item.value;
                const extracted = POSIX_SHELL_INLINE.has(program)
                    ? { reads: [], writes: [], deletes: [], unparsed: false }
                    : inlineCodeEffects(code, INLINE_CODE_DIALECT[program] ?? 'call');
                for (const literal of extracted.reads) {
                    if (isDynamic(literal) === true)
                        continue;
                    if (looksLikePath(literal) === false && sensitiveOperand(literal) === false)
                        continue;
                    literalInputs.push({
                        text: literal, segment, dynamic: false,
                        role: 'read-auto', opClass: 'read', fromInlineCode: true,
                    });
                }
                // 写面同一把尺（35）：`open(p,'w')`／`writeFileSync(p,…)`／`Set-Content -Path p`
                // 里那个 p 是**写目的**，与 `echo > p` 记同一种效果。以前四形一律抠不出 ⇒
                // targets=[] ⇒ 命中不了写域那几行，同一份区外 `.env` 走 `echo >` 落人工、
                // 走 `python -c` 落交模型——换入口换出更松的结论，而且发生在更该严的写轴。
                for (const literal of extracted.writes) {
                    if (isDynamic(literal) === true)
                        continue;
                    if (looksLikePath(literal) === false && sensitiveOperand(literal) === false)
                        continue;
                    literalInputs.push({
                        text: literal, segment, dynamic: false,
                        role: 'write-destination', opClass: 'write', fromInlineCode: true,
                    });
                }
                // 删除面同一把尺（36）：`os.remove(p)`／`Path(p).unlink`／`Remove-Item -Path p`
                // 里那个 p 是**被删掉的东西**，与 `rm p` 记同一种效果。以前这些形一律抠不出 ⇒
                // targets=[] ⇒ 命中不了删除那几行，同一份区外 `.env` 走 `rm` 落人工、走 `python -c`
                // 落交模型——比写面更该严的一轴上「换入口换出更松的结论」还开着。
                for (const item of extracted.deletes) {
                    if (isDynamic(item.path) === true)
                        continue;
                    // 删除面不套「像不像路径」：`shutil.rmtree('build')` 的参数就是被删的目录，
                    // 没有斜杠也不带扩展名。这一族（MUST_TARGET_PROGRAMS）本来就按操作数全收。
                    literalInputs.push({
                        text: item.path, segment, dynamic: false,
                        role: 'delete', opClass: 'delete', tree: item.tree === true, fromInlineCode: true,
                    });
                }
                // 代码里剩下的那一半（变量、拼接、没认出的调用）不猜：整段标不透明，
                // 由表里 `opaque-command` 那一行交模型——抠到读面或写面也不免除举证（判据 2）。
                segment.opaque = true;
                segment.inlineCode = {
                    flag: item.flag,
                    chars: String(code ?? '').length,
                    reads: extracted.reads.length,
                    writes: extracted.writes.length,
                    deletes: extracted.deletes.length,
                    unparsed: extracted.unparsed === true,
                };
            }
            // 清单旗标（判据 2d）：取值是一张**清单文件**，读它并展开列出的读面。
            const manifestFlags = MANIFEST_FLAGS[program];
            const manifestTexts = new Set();
            const manifestEntries = [];
            let innerProgram = '';
            let innerIndex = -1;
            if (manifestFlags !== undefined) {
                for (const item of flagValues(segment.words, manifestFlags)) {
                    manifestTexts.add(item.value);
                    literalInputs.push({
                        text: item.value, segment, dynamic: isDynamic(item.value),
                        role: 'read-manifest', opClass: 'read',
                    });
                    if (isDynamic(item.value) || cwdCertain === false) {
                        bumpScan(segment, 'error');
                        continue;
                    }
                    const nul = item.flag.toLowerCase().includes('files0');
                    const manifest = readManifest(normalizePath(item.value, cwd, roots.home), nul, probe);
                    if (manifest.error) {
                        bumpScan(segment, 'error');
                        continue;
                    }
                    if (manifest.entries.length > SCOPE_LIMITS.files)
                        bumpScan(segment, 'truncated');
                    manifestEntries.push(...manifest.entries.slice(0, SCOPE_LIMITS.files));
                }
                if (program === 'xargs') {
                    // `xargs -a list.txt rm`：清单里的名字交给**内层程序**去动。
                    // 内层是删除程序时整段仍按删除判（判据 2d 反向锁），不许因为
                    // 「只是读清单」就把一批删除放过去。
                    innerIndex = segment.operands.findIndex(text => !manifestTexts.has(text) && !String(text).startsWith('-'));
                    innerProgram = innerIndex === -1 ? '' : baseProgramOf(segment.operands[innerIndex]);
                }
                // 清单里的名字按**内层动作**记账：xargs rm 的条目是删除目标，wc／tar 的是读面。
                const innerClass = DELETE_PROGRAMS.has(innerProgram) || DESTROY_PROGRAMS.has(innerProgram)
                    ? (innerProgram === 'rm' ? 'delete' : 'destroy') : 'read';
                for (const entry of manifestEntries)
                    literalInputs.push({
                        text: entry, segment, dynamic: false,
                        role: innerClass === 'read' ? 'read-source' : 'delete', opClass: innerClass, fromManifest: true,
                    });
            }
            // 写出效果藏在取值里的旗标（`sort --output=x`、`git diff --output=x`）：那个文件是写目的。
            // 判据⑧：读位旗标带进来的词只记一次——它们已在 literalInputs 里，
            // 不再由操作数循环折第二份（`find -newer docs.md` 的 docs.md 只出现一次）。
            const readValues = readFlagsOf(segment.program);
            const readValueTexts = new Set();
            // 路径旗标的取值按**这一段的动作**记账：`Remove-Item -LiteralPath x` 的 x 是被删的，
            // `Set-Content -Path x` 的 x 是被写的——只记成读会让删除／写面那几行根本没机会说话。
            // 复制／移动族的 `-Path` 是**源**（目的由 `-Destination` 走写出口），照旧记读。
            const flagAction = COPY_PROGRAMS.has(program)
                || segment.baseOpClass === 'read' || segment.baseOpClass === 'privilege'
                || segment.baseOpClass === 'exec'
                ? 'read' : segment.baseOpClass;
            const flagRole = flagAction === 'read' ? 'read-auto'
                : flagAction === 'delete' || flagAction === 'destroy' ? 'delete' : 'write-destination';
            if (readValues !== undefined)
                for (const item of flagValues(segment.words, readValues, isCmdletName(segment.program))) {
                    readValueTexts.add(String(item.value));
                    // 读位的取值本身就是读源（`git -C <dir>`／`git config --file <cfg>`／`grep -f <清单>`）：
                    // 去重的前提是这里照样记一份，否则目标会掉。已经由别的分支记过的不再记第二份。
                    if (!literalInputs.some(entry => entry.segment === segment && String(entry.text) === String(item.value)))
                        literalInputs.push({
                            text: item.value, segment, dynamic: isDynamic(item.value),
                            role: flagRole, opClass: flagAction,
                        });
                }
            // curl 的正文可能从本地文件取：`-d @file`／`-F k=@file`／`-T file`。那个文件是读源；
            // `-d hello` 是数据不是路径，所以只认 `@` 前缀与 `-T`，不把整类取值都当路径。
            if (program === 'curl')
                for (const item of flagValues(segment.words, CURL_FILE_FLAGS)) {
                    const raw = String(item.value ?? '');
                    const file = raw.startsWith('@') ? raw.slice(1)
                        : /^(-T|--upload-file)$/i.test(item.flag) ? raw : '';
                    if (file === '')
                        continue;
                    if (!literalInputs.some(entry => entry.segment === segment && String(entry.text) === file))
                        literalInputs.push({
                            text: file, segment, dynamic: isDynamic(file),
                            role: 'read-source', opClass: 'read',
                        });
                }
            const writeValues = writeFlagsOf(segment.program);
            // 判据④：写出口的取值**只**进写目标，目标集里不再记一份读（双面清零）。
            const writeValueTexts = new Set();
            if (writeValues !== undefined)
                for (const item of flagValues(segment.words, writeValues, isCmdletName(segment.program))) {
                    writeValueTexts.add(String(item.value));
                    literalInputs.push({
                        text: item.value, segment, dynamic: isDynamic(item.value),
                        role: 'write-destination', opClass: 'write',
                    });
                }
            if (innerProgram !== '') {
                if (DELETE_PROGRAMS.has(innerProgram) || DESTROY_PROGRAMS.has(innerProgram))
                    segment.opClass = innerProgram === 'rm' ? 'delete' : 'destroy';
                else if (COPY_PROGRAMS.has(innerProgram))
                    segment.opClass = 'write';
            }
            // `sed` 的第一个操作数是**脚本**（`1p`），不是文件；带 `-e`／`-f` 时没有这个位置。
            // 脚本位已由位语义排除时（`sed -e SCRIPT`），operands 的下标 0 已是文件——不再跳过。
            const sedScriptIndex = program === 'sed'
                && (segment.flags ?? []).some(flag => /^--(?:expression|file)\b/.test(flag) || /^-[a-z]*[ef]/.test(flag)) === false
                && (segment.operandRoles?.[0] ?? 'path') !== 'nopath'
                ? 0 : -1;
            const operands = segment.operands
                .map((text, at) => ({ text, bare: segment.operandBare?.[at] === true, at }))
                .filter(item => segment.operandRoles?.[item.at] !== 'nopath'
                    && !writeValueTexts.has(String(item.text))
                    && !readValueTexts.has(String(item.text))
                    && !patternTexts.has(item.text) && !manifestTexts.has(item.text)
                    && !inlineTexts.has(item.text)
                    && item.at !== innerIndex && item.at !== sedScriptIndex);
            const copy = COPY_PROGRAMS.has(program);
            const interpreter = INTERPRETER_PROGRAMS.has(program);
            const pathExists = (text) => {
                if (typeof probe.lstat !== 'function' || cwdCertain === false)
                    return false;
                try {
                    probe.lstat(normalizePath(text, cwd, roots.home));
                    return true;
                }
                catch {
                    return false;
                }
            };
            const scriptAt = interpreter ? interpreterScript(program, segment.words) : -1;
            // 操作数下标 → 词下标（wordsEnvResolved 按词记，readProof 那两处要按词跳）。
            const operandWordAt = [];
            for (let wordIndex = 0; wordIndex < (segment.words ?? []).length; wordIndex += 1)
                if (segment.kinds?.[wordIndex] === 'operand')
                    operandWordAt.push(wordIndex);
            let scriptTaken = false;
            let seen = 0;
            // `sed -i` 原地改：被改的那个文件**同时是读源**——改之前要先读原文。
            // 只记写会让「读面」空着，档位也跟着落到放行（清单里 sed -i.bak 那格）。
            const inPlace = program === 'sed'
                && (segment.flags ?? []).some(flag => IN_PLACE_EDIT_FLAGS.test(String(flag)));
            if (inPlace === true)
                for (const operand of operands)
                    literalInputs.push({
                        text: operand.text, segment, dynamic: isDynamic(operand.text),
                        role: 'read-source', opClass: 'read',
                    });
            const pathOperands = [];
            // cargo 名字旗标的取值（feature 列表允许 `serde/derive` 这种带斜杠的写法）：
            // 不能交给「像不像路径」判，按旗标位置直接排除。
            const cargoNameValues = program === 'cargo'
                ? new Set(flagValues(segment.words ?? [], CARGO_NAME_FLAGS).map(item => String(item.value)))
                : undefined;
            for (const [position, operand] of operands.entries()) {
                const rawText = operand.text;
                // 读族 + 路径位 + 整词 `$X` ⇒ 用判定这一刻的环境值算死；其余一律保留原文。
                const resolvedText = READ_PROGRAMS.has(program)
                    ? resolveEnvOperand(rawText, envGuard, cwd, probe, roots) : undefined;
                const text = resolvedText === undefined ? rawText : resolvedText;
                const bare = resolvedText === undefined ? operand.bare : false;
                if (resolvedText !== undefined && operandWordAt[operand.at] !== undefined) {
                    segment.wordsEnvResolved ??= new Set();
                    segment.wordsEnvResolved.add(operandWordAt[operand.at]);
                }
                seen += 1;
                // 远端操作数不是本地路径：把 host 收进 remoteHosts，别再折成工作区假路径。
                if (remote) {
                    if (program === 'scp' || program === 'rsync') {
                        const match = REMOTE_TARGET.exec(text);
                        if (match !== null) {
                            pushRemote(match[2].toLowerCase());
                            continue;
                        }
                    }
                    else if (!remoteHost && !String(text).startsWith('-')) {
                        remoteHost = true;
                        pushRemote(hostOfOperand(text));
                        continue;
                    }
                    else if (remoteHost) {
                        continue; // ssh 后面的远端命令及其参数
                    }
                }
                if (skipFirst === true && seen === 1)
                    continue;
                // 远端 URI：`s3://bucket/key`、`https://host/p` 的 host 进网络平面，
                // 不再折成 `…\https:\host\p` 这种带 rootHit=workspace 的本地假目标（历史误折）。
                // 本机文件 URI（`file:///C:/x/bare.git`）不是工作区里的路径，也不出本机：
                // 折成 `<ws>/file://c:/x/…` 这种假目标会让「工作区」那条行替它放行/抬高。
                // 它既不当本地路径目标，也不进远端主机表（本机就是本机）。
                if (/^file:\/\//i.test(text))
                    continue;
                const uri = REMOTE_URI.exec(text);
                if (uri !== null) {
                    pushRemote(hostOfOperand(uri[1].split(':')[0]));
                    continue;
                }
                // UNC（`\\fileserver\share\x`）是**跨机**操作数：写出去＝外传，读进来＝远端读。
                // 旧形把它当本地路径 ⇒ 只剩一条 `rootHit=outside` 的普通文件目标，
                // 网络面整个失明（`remoteHosts=[]`），外传下界没人管。
                // 但 `\\.\pipe\…`／`\\?\C:\…` 是 Windows 设备／长路径命名空间：本机对象，
                // 不是 UNC 主机。旧形把 `\\.\pipe\` 抽成 host `.` ⇒ `remote-execute`，
                // 一条本地命名管道列表被问成远程执行。先判本地命名空间，再判 UNC。
                if (isLocalDeviceNamespace(text) !== true) {
                    const unc = /^\\\\([^\\/]+)\\/.exec(text);
                    if (unc !== null) {
                        pushRemote(unc[1].toLowerCase());
                        continue;
                    }
                }
                if (PUSH_CAPABLE.has(program) && OCI_REFERENCE.test(text)) {
                    pushRemote(text.split('/')[0].toLowerCase());
                    continue;
                }
                // 解释器的第一个普通词是**脚本**（判据 2a）：它会被读进解释器执行。
                // 旧形按「脚本路径像路径」把它归到段动作（exec）⇒ 整段按写算。
                if (interpreter && !scriptTaken && scriptAt !== -1 && rawText === segment.words[scriptAt]) {
                    scriptTaken = true;
                    pathOperands.push(text);
                    literalInputs.push({
                        text, segment, dynamic: isDynamic(text, bare),
                        role: 'script-read', opClass: 'read',
                    });
                    continue;
                }
                // 取值参数的值、标签、纯符号：不是路径就别给它编一个（历史误折）；
                // 例外——会改动东西的程序、读文件的程序（`cat NOTES` 的 NOTES）、
                // 检索程序剩下的路径（`grep TOKEN CNAME`）、列目录的程序（`ls sub`）、
                // 名字本身像凭据的操作数（`cat id_rsa`）。
                // 列目录类（`ls`／`du`）的操作数是路径，但**得真的存在**才算：
                // `ls -la . --line 10 --label 决定·面板` 里那两个取值不该被折成工作区文件。
                const directoryish = DIRECTORY_PROGRAMS.has(program) && (looksLikePath(text)
                    || sensitiveOperand(text) || pathExists(text));
                if (!isDynamic(text, bare) && !wholeWordPath(text)
                    && !sensitiveOperand(text) && !MUST_TARGET_PROGRAMS.has(program)
                    && !FILE_READ_PROGRAMS.has(program) && !PATTERN_PROGRAMS.has(program)
                    && !directoryish)
                    continue;
                // 判据⑧：引号里的通配是字面量，不是路径——一个字目标也不铸。
                if (bare === false && GLOB_CHARS.test(text) && positionOf(baseProgramOf(program)) !== undefined
                    && ENUMERATE_PROGRAMS.has(program) === false)
                    continue;
                // 判据⑥：未引用的通配在段的当前目录里展开出真实名字 ⇒ 名字进目标；
                // 展不出（0 命中／不可列／触顶）⇒ 一个字目标也不铸（旧形会在目标集里留假路径）。
                if (bare && cwdCertain && segment.baseOpClass === 'read'
                    && /[*?]/.test(text) && !/[\\/]/.test(text)) {
                    const expanded = expandGlobNames(text, cwd, probe, scanState);
                    if (expanded.known !== true)
                        continue;
                    // 展开成功（0 命中也算）：目标集确定——0 个就是空集，不是「数不清」。
                    segment.globExpanded = true;
                    for (const name of expanded.names) {
                        pathOperands.push(name);
                        literalInputs.push({
                            text: name, segment, dynamic: false, role: 'read-auto', opClass: 'read',
                        });
                    }
                    continue;
                }
                // 带路径的通配（`ls ~/.workbuddy/*/`）此前直接标动态，送 AI 前目标集是残的。
                // 只列名字的读段读的是**父目录这一层名字**，不是每个子项的内容 ⇒ 只铸父目录一个目标；
                // 名字里有凭据形状的，再把那几个名字单独铸成目标（文件面那条 ask 仍要能命中）。
                // 全过 ⇒ 集合确定；任一不过 ⇒ 维持动态（今天的口径）。
                // 写／删／外传不展开：执行那一刻的通配可能变，不能拿决定时数到的名字替它背书。
                if (bare && cwdCertain && segment.baseOpClass === 'read'
                    && /[*?]/.test(text) && /[\\/]/.test(text)
                    && nameOnlySegment(segment)
                    && (segment.scope ?? '') !== 'recursive'
                    && !/[$`[\]{}]/.test(text)
                    && !(segment.words ?? []).some(word => /[$`{}]/.test(String(word)))) {
                    const probePath = normalizePath(text, cwd, roots.home);
                    const expanded = probeGlobStructure(probePath, probe, {
                        dirsOnly: /[/\\]$/.test(text), admitSensitive: true, limit: 100, namesOnly: true,
                    });
                    if (expanded.known === true) {
                        segment.globExpanded = true;
                        const api = pathApiFor(probePath);
                        const parent = api.dirname(probePath);
                        pathOperands.push(parent);
                        literalInputs.push({
                            text: parent, segment, dynamic: false, role: 'read-auto', opClass: 'read',
                        });
                        for (const name of expanded.names ?? []) {
                            if (!isSensitiveBasename(name))
                                continue;
                            const child = api.join(parent, name);
                            pathOperands.push(child);
                            literalInputs.push({
                                text: child, segment, dynamic: false, role: 'read-auto', opClass: 'read',
                                globSensitive: true,
                            });
                        }
                        continue;
                    }
                }
                // 读类字面通配：范围＝「这个基底下的匹配项」，不逐项展开；一个模式目标就够 AI 判。
                // `wc`／`md5sum`／`cat` 这类读正文的程序，通配在决定时和执行时是同一个范围；
                // 不送每个文件名，省证据与模型时间。运行时展开（$／反引号／字符类）仍按动态。
                // 写／删／改名不走这一支：那几个动作要知道具体目标，不能拿模式替执行背书。
                if (bare && cwdCertain && segment.baseOpClass === 'read'
                    && /[*?]/.test(text) && /[\\/]/.test(text)
                    && !/[$`[\]{}]/.test(text)
                    && !(segment.words ?? []).some(word => /[$`{}]/.test(String(word)))) {
                    const probePath = normalizePath(text, cwd, roots.home);
                    const api = pathApiFor(probePath);
                    const parent = api.dirname(probePath);
                    let parentIsDir = false;
                    if (typeof probe.lstat === 'function' && parent !== probePath && !/[*?]/.test(parent)) {
                        try {
                            parentIsDir = probe.lstat(parent)?.isDirectory?.() === true;
                        }
                        catch {
                            parentIsDir = false;
                        }
                    }
                    if (parentIsDir === true) {
                        // 范围是模式本身（基底已知、模式字面），不是逐项展开；读证明按「已知范围」算。
                        segment.globExpanded = true;
                        pathOperands.push(text);
                        literalInputs.push({
                            text, segment, dynamic: false, role: 'read-auto', opClass: 'read',
                        });
                        continue;
                    }
                }
                // 变量赋值的操作数是「名字=值」，不是路径：跳过，不铸成目标（赋值本身仍在命令原文里）。
                if (ENV_ASSIGNER_PROGRAMS.has(program) && /^[A-Za-z_][A-Za-z0-9_]*=/.test(String(text)))
                    continue;
                // 装包／构建族的名字（crate 名、脚本名、make 目标、feature 列表）不是路径：
                // 铸成目标会凭空造出一个文件，判定与回写都跟着记账。
                if (cargoNameValues !== undefined && cargoNameValues.has(String(text)))
                    continue;
                if (NAME_OPERAND_PROGRAMS.has(program) && looksLikePathText(text) === false)
                    continue;
                pathOperands.push(text);
                // 逐作用项的操作类型（A03）：cp／mv 前面的操作数是源（读），最后一个是目的；
                // 其余按程序本身分（重定向不再把整段的读源折成写）。
                const last = position === operands.length - 1;
                let opClass = segment.baseOpClass === 'read' ? 'read' : segment.baseOpClass;
                if (copy)
                    opClass = last ? (segment.baseOpClass === 'rename' ? 'rename' : 'write') : 'read';
                let role;
                if (opClass === 'read')
                    role = 'read-auto';
                else if (opClass === 'delete' || opClass === 'destroy')
                    role = 'delete';
                else if (copy && last && segment.baseOpClass !== 'rename')
                    role = 'write-auto';   // 目的是不是目录要到读盘那一步才知道（判据 2c）
                else
                    role = 'write-destination';
                // 进程／装包族的操作数是**名字**
                // （服务名、PID、包名），不是路径——不铸成文件目标，也不许被「工作区里的写」顺带放行。
                // 它们由命令面执行族那几行判（`segment.execFamily`）。
                literalInputs.push({
                    text, segment, dynamic: isDynamic(text, bare), opClass, role,
                    sourceText: copy && last ? (operands[position - 1]?.text ?? '') : undefined,
                });
            }
            for (const [at, redirect] of segment.redirects.entries()) {
                if (isSink(redirect) || isFdDup(redirect))
                    continue;
                const reads = redirectReads(segment.redirectOps?.[at] ?? '>');
                literalInputs.push({
                    text: redirect, segment, dynamic: segment.redirectDynamic?.[at] === true,
                    role: reads ? 'stdin' : 'write-destination', opClass: reads ? 'read' : 'write',
                });
            }
            // 省略路径的读（`git status`／`rg TODO`／`grep -rn TOKEN`）：读面是宿主默认 cwd。
            const recursiveRead = PATTERN_PROGRAMS.has(program)
                && (program === 'rg' || (segment.flags ?? []).some(flag => RECURSIVE_READ_FLAGS.test(String(flag))));
            if (pathOperands.length === 0 && segment.opClass === 'read'
                && (DEFAULT_CWD_READERS.has(program) || recursiveRead))
                literalInputs.push({
                    text: cwd, segment, dynamic: false, role: 'directory-container', opClass: 'read',
                });
            // 装／构建的落点（`npm install` 写 node_modules、`cargo build` 写 target）**不再铸成
            // 文件目标**——那会让「工作区里的写」这条路径行替一次装包背书（装包会跑包自带的脚本）。
            // 这些动作归命令面执行族判；文件的写面仍由重定向／cp 这类真路径目标说话。
            // 被执行体本身（带路径的程序，如 `C:\Python\python.exe`）：效果是「执行这个文件」。
            if (/[\\/]/.test(String(segment.program ?? '')))
                executableEffects.push({
                    role: 'executable', text: segment.program, opClass: 'read', segmentIndex: index,
                });
        }
    }
    else {
        const adapter = toolAdapterFor(toolName);
        const synthetic = {
            program: String(toolName ?? ''),
            opClass: adapter?.op ?? 'other',
            adapter,
            // 非 shell 调用的段标记：方向判定要知道「这是工具，不是命令」，否则未登记工具
            // 带网址时会按命令那条默认值算成 `remote`（＝远端执行）。
            isTool: true,
            words: [], flags: [], operands: [], redirects: [],
            // 不在册的工具不标 opaque——它不是「命令看不懂」，是「认不出这是什么工具」，
            // 该由表里 `unclassified-tool`／`mcp-tool` 那两行说话（台账要指名对的行）。
            opaque: false,
        };
        segments.push(synthetic);
        // 在册的按适配器取路径；不在册的照旧扫一遍路径键，
        // 免得「认不出工具」连带把它的文件目标也看不见。
        const shellPaths = nonShellPaths(args, adapter);
        for (const value of shellPaths)
            literalInputs.push({
                text: value, segment: synthetic, dynamic: isDynamic(value),
                role: 'path', opClass: synthetic.opClass,
            });
        // 判据 3：宿主原生读工具省略 path 时，读面是**宿主默认 cwd**（grep 默认递归、
        // glob 默认在 cwd 展开、read 缺路径）。旧形不补这一格 ⇒ targets=[] 却照样走
        // 「已证明只读」（派单端实测 `grep {pattern:"TODO"}` ⇒ release）。
        if (shellPaths.length === 0 && adapter?.op === 'read'
            && ['read', 'grep', 'glob', 'ls', 'list_dir'].includes(String(toolName ?? '').toLowerCase())) {
            literalInputs.push({
                text: roots.workspace, segment: synthetic, dynamic: false,
                role: 'directory-container', opClass: 'read',
            });
        }
        for (const host of nonShellUrls(args, adapter))
            pushSegmentHost(synthetic, remoteHosts, host);
        for (const text of nonShellPayloads(args, adapter))
            payloads.push(text);
    }

    // 每个段各自举证（shell 与非 shell 同一把尺）；非读段拿不到免检。
    // 外传族也逐段记（F03）：判定要按作用项定局，「这一段在往外送东西」不能只留全调用的并集。
    // 递归读要把整棵读面展开进目标集（判据 3）：完整的清单才配说「只读了这些」，
    // 凭据形状的那些也照样在列（A03）。
    for (const [index, segment] of segments.entries()) {
        const cwd = cwdOf.get(index);
        const cwdCertain = cwd !== undefined;
        // 工作目录算不死时，带相对路径词的段失去锚点：如实标来源，读面不能再算「已证明只读」。
        // 只用绝对路径／`~` 的段不受影响——cd 未知不改变它们的位置。
        if (cwdCertain === false && cwdUnknownOf.has(index)) {
            segment.cwdUnknown = cwdUnknownOf.get(index);
            const relative = hasRelativePathWord(segment);
            if (relative)
                segment.cwdPathWords = true;
            // 读段的读面本身就是 cwd（`grep -rn`）或含相对路径词时，位置算不死就不算已举证；
            // 只用绝对路径的写/删不受影响。
            if (relative || segment.opClass === 'read') {
                segment.cwdUnproven = true;
                segment.opaque = true;
            }
        }
        segment.scope = recursiveScopeOf(segment) ? 'recursive' : '';
        segment.scopeOutside = cwdCertain && segment.scope === 'recursive'
            && scopeInsideRoots(segment, cwd, roots) === false;
        if (segment.scope === 'recursive' && cwdCertain === false) {
            // 递归读的读面就是这一段的工作目录；目录算不死时不去猜一棵子树来扫，
            // 如实标成「相对目标不可定位」，由证据与判定按未举证处理。
            segment.cwdBlocked = cwdUnknownOf.get(index) ?? '工作目录不确定';
        }
        if (segment.scope === 'recursive' && cwdCertain) {
            // 检索程序的第一个操作数是**模式**，不是路径：`grep -rn TODO` 的读面是 cwd，
            // 不是工作区里一个叫 TODO 的文件（判据 3）。
            const patternFile = PATTERN_PROGRAMS.has(baseProgramOf(segment.program))
                ? flagValues(segment.words ?? [], PATTERN_FILE_FLAGS).length : 0;
            const scopeTexts = patternFile === 0 && PATTERN_PROGRAMS.has(baseProgramOf(segment.program))
                ? (segment.operands ?? []).slice(1) : (segment.operands ?? []);
            const operand = [...scopeTexts].reverse()
                .find(text => String(text).trim() !== '' && !isDynamic(text));
            const base = normalizePath(operand ?? cwd, cwd, roots.home);
            // `-r` 后面跟的是**单个文件**时，读面就是这一个文件——别拿 readdir 去开它，
            // 否则同一份技能说明 `cat` 举得出证、`grep -rn` 因「读目录出错」举不出（判据 P4）。
            const baseIsFile = isFileAt(base, probe);
            if (baseIsFile === true) {
                literalInputs.push({
                    text: base, segment, dynamic: false, role: 'read-source', opClass: 'read', fromScope: true,
                });
                segment.secretScopeHit = isSensitiveBasename(basenameOf(base));
            }
            else if (segment.scopeOutside === true) {
                // 区外子树不做整树列举（区外有什么不该由本插件代猜），**但凭据形状的名字要列**：
                // 否则同一份 `.env`，`cat` 落人工、递归 `grep` 落交模型——换入口换出更松的结论
                // （报告 §1.1／ 判据 P4）。只按名字收，上限 20 个，不读内容。
                const outside = walkScope(base, probe);
                for (const file of outside.sensitive)
                    literalInputs.push({
                        text: file, segment, dynamic: false, role: 'read-source', opClass: 'read', fromScope: true,
                    });
                segment.secretScopeHit = outside.sensitive.length > 0;
            }
            else {
                const scanned = walkScope(base, probe);
                bumpScan(segment, scanned.completeness);
                for (const file of scanned.files)
                    literalInputs.push({
                        text: file, segment, dynamic: false, role: 'read-source', opClass: 'read', fromScope: true,
                    });
                segment.secretScopeHit = scanned.sensitive.length > 0;
            }
        }
        segment.exfil = exfilOf(segment);
        // 远端方向要在主机清单都收齐之后算：`curl -O` 与 `curl -T` 是两件事（A10）。
        segment.remoteDirection = remoteDirectionOf(segment);
        // 目的地档位同样要在主机清单收齐之后算：`--endpoint-url` 的取值、
        // `s3://bucket/key` 的桶名、`localhost:5000/app` 的仓库地址都在这时才看得见。
        segment.destinations = destinationsOf(segment);
        // 网络作用项按方向记角色（判据 6）：取回来的进 network-source，
        // 送出去／远端执行的进 network-destination。
        if (segment.remote === true || (segment.hosts ?? []).length > 0) {
            const sourceish = ['download', 'remote-read'].includes(segment.remoteDirection);
            networkEffects.push({
                role: sourceish ? 'network-source' : 'network-destination',
                text: (segment.hosts ?? [])[0] ?? String(segment.program ?? ''),
                opClass: 'read',
                segmentIndex: index,
            });
        }
    }

    // 一份调用内的缓存——同一条目录链不给每个目标各 stat 一遍。
    const foreignRootCache = new Map();
    const namedByUserCache = new Map();
    // 规则行只在第一次真用到时解析一次（同一份表、同一把 parseRules）。
    let namedRuleRows;
    const ruleRowsOf = () => {
        if (namedRuleRows === undefined)
            namedRuleRows = Array.isArray(roots.fileRules) ? parseRules(roots.fileRules, 'file', roots) : [];
        return namedRuleRows;
    };
    const globProbeFlags = [];
    // `cat "$X"` 里 X 为空（未设环境变量）时，词是空串——程序拿到的是空文件名，
    // 读不到任何东西。不许把它折成 cwd 的假目标（normalizePath('') 会落回 cwd）。
    const usableInputs = literalInputs.filter(input => String(input.text ?? '') !== '');
    const preparedRaw = usableInputs.map((input) => {
        // 目标属于哪一段，判定就要在哪一段里定局（F03）：并集会让一段的允许替另一段作主。
        const segmentIndex = segments.indexOf(input.segment);
        const opClass = input.opClass ?? input.segment.opClass;
        if (input.dynamic)
            return {
                input: input.text, dynamic: true, dynamicWhy: input.dynamicWhy ?? '',
                opClass, role: input.role ?? 'operand', segmentIndex,
            };
        // 非 shell 工具没有 cwd 概念：宿主给相对路径就是相对工作区（与原行为一致）。
        const cwd = isShell ? cwdOf.get(segmentIndex) : roots.workspace;
        // 工作目录算不死、操作数又是相对路径 ⇒ 不拿 workspace 兜底（那会把区外折成区内的
        // 假目标）；这一条算不出绝对位置，同时给段盖一格来源，证据里看得见为什么。
        const rawText = String(input.text ?? '');
        const anchored = rawText.startsWith('~') || pathApiFor(rawText).isAbsolute(rawText);
        if (cwd === undefined && anchored === false) {
            const why = cwdUnknownOf.get(segmentIndex) ?? '工作目录不确定';
            if (input.segment !== undefined)
                input.segment.cwdBlocked = why;
            return {
                input: input.text, dynamic: true, dynamicWhy: `工作目录不确定：${why}`,
                opClass, role: input.role ?? 'operand', segmentIndex,
            };
        }
        let normalized = normalizePath(input.text, cwd ?? roots.workspace, roots.home);
        let role = input.role ?? 'operand';
        let meta = metaOf(normalized, opClass, roots, probe);
        // 列目录程序＋通配目标 ⇒ 有界结构探测（只展开父目录一层；递归段不探——单内口径「非递归」）。
        // 段里还有别的展开词（$／反引号）时也不探：那种段的目标集本来就不确定。
        const globProbe = opClass === 'read' && input.dynamic !== true
            && (input.segment?.scope ?? '') !== 'recursive'
            && nameOnlySegment(input.segment)
            && /[*?]/.test(String(input.text)) && !/[$`[]/.test(String(input.text))
            && !(input.segment?.words ?? []).some(word => /[$`]/.test(String(word)))
            ? probeGlobStructure(normalized, probe)
            : { known: false };
        globProbeFlags.push(globProbe.known === true);
        // cp／mv 的**目的**是一个已存在的目录时，真正被写的是「目录 + 源文件名」
        // （判据 2c）：`cp src/a.md <ws>/.` 写的是 `<ws>/a.md`，不是工作区根本体——
        // 旧形把 `.` 本身记成写目标，于是命中 workspace-root，白弹一个人工框。
        let container;
        if (role === 'write-auto') {
            if (meta.exists === true && meta.kind === 'dir') {
                container = normalized;
                normalized = pathApiFor(normalized).join(normalized, basenameOf(String(input.sourceText ?? '')));
                meta = metaOf(normalized, opClass, roots, probe);
            }
            role = 'write-destination';
        }
        else if (role === 'read-auto')
            role = meta.exists === true && meta.kind === 'dir' ? 'directory-container' : 'read-source';
        // 文件身份按**真实路径**说：字符串在区里不算，父目录是链接时真身在区外（判据 3）。
        // 凭据族的读连 realpath 都不做（同一条口径：存在性本身也是信息）。
        const identity = meta.exists === 'unchecked'
            ? { verdict: 'unchecked', real: undefined }
            : identityOf(normalized, roots, probe);
        const lexical = rootHitFor(normalized, roots, opClass);
        // 只给「区外、非凭据读、非技能说明」的目标找项目根——凭据读连 stat 都不做，
        // 技能说明子树本来就是任务资源（scope.js 同一条口径）。
        const foreignRoot = lexical.hit !== 'outside' || meta.exists === 'unchecked'
            || isSkillDoc(normalized, roots.home)
            ? ''
            : qualifyForeignRoot(foreignRootOf(
                meta.kind === 'dir' ? normalized : pathApiFor(normalized).dirname(normalized),
                probe, foreignRootCache,
            ), roots);
        // 字符串在区里、真身在区外：读到／改到的是别处的文件（A02）。
        // 写类按区外算；读类由 readProofFor 拒绝「已证明只读」（见 linkEscapes）。
        const escapes = identity.verdict === 'proven-outside' && lexical.hit === 'workspace';
        return {
            input: input.text,
            path: normalized,
            container,
            // 整树删除的形状只由**语法**说（`rmtree`／`rmSync(…,{recursive:true})`／`-Recurse`）：
            // 它表示「这一站销毁目录里的全部内容」，不是一条条目。目录身份本身另由 lstat 带（kind）。
            ...(input.tree === true ? { tree: true } : {}),
            realPath: identity.real,
            dynamic: false,
            opClass,
            role,
            segmentIndex,
            cwd,
            identity: identity.verdict,
            linkEscapes: escapes,
            program: input.segment.program,
            rootHit: escapes ? 'outside' : lexical.hit,
            // 命中的那条信任规则的根路径（没命中＝空串）：区外删除只保护「根目录本身」，
            // 根里面的东西——包括子目录——都算区内。
            rootMatch: escapes ? '' : lexical.root,
            // 外项目根（未命中＝空串）与「用户消息点没点名这条路径」。
            // 源根内的读也算点过名（绑定只买范围证明，不买内容放行——敏感面另判）。
            // 点名与否只看用户说过没有，与有没有外项目根／源根无关——先算，算不出才 false。
            foreignProject: foreignRoot !== '',
            foreignRoot,
            // 只带回目录结构，还是带回了文件正文——判定不在这里（policy 那条闸读这一格）。
            // 通配目标经有界结构探测证明「匹配到的都是目录名」时，也按「只带回结构」报，
            // 并附一格标量读数（探测到的条目数）；展开出来的子项不进目标集。
            structureOnly: input.globSensitive !== true
                && (structureOnlyOf(opClass, meta, input.segment) || globProbe.known === true),
            ...(globProbe.known === true ? { structureEntries: globProbe.matches } : {}),
            namedByUser: namedByUserOf(normalized, roots, namedByUserCache, ruleRowsOf),
            ...meta,
        };
    });
    // 判据⑧：同段、同字符串、同动作只留一份——重复目标清零。
    const prepared = preparedRaw.filter((target, index, list) => list.findIndex(other =>
        String(other.path ?? other.input ?? '') === String(target.path ?? target.input ?? '')
        && other.opClass === target.opClass && other.segmentIndex === target.segmentIndex) === index);
    // 绑定只对**后续**调用生效——本次调用仍按绑定前的源根判，不借自己刚记下的绑定放宽。
    if (resolved.root === '' && boundRoot === '' && revoked === false)
        bindSourceRoot(roots, prepared, probe);
    // 授权对象上补一格「这次外项目读有没有被用户点名」——证据块整块带走
    // authorization（evidence.js 的既有形状），评审因此看得见，不用回猜用户说过什么。
    // 只有真的碰到外项目根才写：区内读不产生这一格（避免把「没问过」误读成「未授权」）。
    const foreignReads = prepared.filter(target =>
        target.dynamic !== true && target.opClass === 'read' && target.foreignProject === true);
    if (foreignReads.length > 0 && roots.authorization !== undefined && roots.authorization !== null
        && typeof roots.authorization === 'object')
        roots.authorization.namedByUser = foreignReads.every(target => target.namedByUser === true);
    // 通配探测只证明「这一段里**每一个**读目标都是结构」时才回填读证明——
    // 一段里还有别的目标（普通文件／未探成的通配）就不许拿一格探测代表整段。
    const readTargetCount = new Map();
    for (const target of prepared) {
        if (target.dynamic === true || target.opClass !== 'read')
            continue;
        const segment = segments[target.segmentIndex];
        if (segment !== undefined)
            readTargetCount.set(segment, (readTargetCount.get(segment) ?? 0) + 1);
    }
    const probedCount = new Map();
    prepared.forEach((target, index) => {
        if (globProbeFlags[index] !== true || target.dynamic === true || target.opClass !== 'read')
            return;
        const segment = segments[target.segmentIndex];
        if (segment !== undefined)
            probedCount.set(segment, (probedCount.get(segment) ?? 0) + 1);
    });
    for (const [segment, probed] of probedCount)
        if (readTargetCount.get(segment) === probed)
            segment.structureProven = true;
    // 身份／读面是**段级**举证输入：换算完目标才回填到段上，再算段的读证明。
    // 「这一段列过任何目标」也是判据：一张空表不配换免检（判据 3）。
    // ── 读的两面（name／body）与三类组合（-exec／管道／xargs）。整条取最严 ──
    {
        // 管道下游：原文里这个程序紧跟着一个 `|`（与命令面 `piped` 同一口径）。
        const rawCommand = isShell ? String(args?.command ?? args?.cmd ?? '') : '';
        const escapeRe = text => String(text).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const innerFlagsOf = (segment, innerProgram) => {
            const words = (segment.words ?? []).map(word => String(word.text ?? word));
            const at = words.findIndex(word => word.endsWith(innerProgram));
            return at === -1 ? [] : words.slice(at + 1).filter(word => word.startsWith('-'));
        };
        const innerProgramOf = (segment) => {
            const name = baseProgramOf(segment.program);
            const words = (segment.words ?? []).map(word => String(word.text ?? word));
            // `-exec` 族：旗标后面第一个不是 `{}`／`\;` 的词就是内层程序。
            const execFlags = execFlagsOf(name);
            if (execFlags !== undefined) {
                const at = words.findIndex(word => execFlags.has(word));
                if (at !== -1) {
                    const inner = words.slice(at + 1).find(word => !word.startsWith('-') && !/^[{};\\]+$/.test(word));
                    return inner === undefined ? '' : baseProgramOf(inner);
                }
            }
            // `xargs`：流里的名字变成参数，内层程序是它后面的第一个非旗标词。
            if (name === 'xargs') {
                const inner = words.find(word => !word.startsWith('-'));
                return inner === undefined ? '' : baseProgramOf(inner);
            }
            return '';
        };
        let streamFace;
        for (const segment of segments) {
            const name = baseProgramOf(segment.program);
            const flags = (segment.words ?? []).map(word => String(word.text ?? word)).filter(word => word.startsWith('-'));
            let own = faceOf(name, flags);
            const inner = innerProgramOf(segment);
            if (inner !== '') {
                const innerFace = faceOf(inner, innerFlagsOf(segment, inner));
                if (innerFace !== undefined)
                    own = innerFace;
            }
            segment.readFaceOwn = own;
            // 从流里读正文（下游没有自己的路径操作数）⇒ 继承上游流的面：不升也不降。
            const pipedIn = rawCommand !== '' && new RegExp(`\\|\\s*(?:sudo\\s+)?[\\w./\\\\-]*${escapeRe(name)}\\b`).test(rawCommand);
            const pathOperands = (segment.operandRoles ?? []).filter(role => role === 'path').length;
            let face = own;
            if (pipedIn === true && pathOperands === 0 && streamFace !== undefined && own !== undefined)
                face = streamFace;
            segment.readFace = face;
            // 换目录不动流；其余段把面交给下一段。
            if (segment.opClass === 'read' && own !== undefined) {
                if (face === 'body')
                    streamFace = 'body';
                else if (streamFace === undefined)
                    streamFace = face;
            }
        }
        // 整条取最严：任一段回正文 ⇒ body；全是名字／元数据 ⇒ name。
        const faces = segments
            .filter(segment => segment.readFace !== undefined)
            .map(segment => segment.readFace);
        if (faces.length > 0)
            callReadFace = faces.includes('body') ? 'body' : 'name';
    }
        const segmentsWithTargets = new Set(usableInputs.map(input => input.segment));
    for (const segment of segments) {
        // 把 `$X` 全算死的读段不再标「命令看不懂」——目标集已确定，
        // 留着 opaque 只会让证据与台账自相矛盾（`cat "$X"` 已举出只读证却报不透明）。
        if (segment.opClass === 'read' && segment.wordsEnvResolved?.size > 0 && opaqueWhyOf(segment) === '')
            segment.opaque = false;
        segment.linkEscapes = prepared.some(target => target.dynamic !== true
            && segments[target.segmentIndex] === segment && target.linkEscapes === true);
        segment.readFaceEmpty = segmentsWithTargets.has(segment) === false;
        // 读段但一个**可解析**目标都没算出来、而且原因是运行时展开 ⇒ 读了什么其实不知道
        // （`cat $(ls)`／`cat $NOPE`）。只算"有没有记目标"不够：动态操作数会留下 path=undefined 的空壳。
        const ownTargets = prepared.filter(target => segments[target.segmentIndex] === segment);
        segment.readTargetless = segment.opClass === 'read' && opaqueWhyOf(segment) !== ''
            && ownTargets.every(target => typeof target.path !== 'string' || target.path === '');
        // 段级同样标不透明：整次调用的「看不全」要靠这一格逐段发到每个作用项上（grant 里按段取）。
        if (segment.readTargetless === true)
            segment.opaque = true;
        segment.readProof = segment.opClass === 'read'
            ? readProofFor(segment)
            : { proven: false, why: '不是读段' };
    }
    const relatives = prepared
        .filter(target => target.dynamic === false && target.rootHit === 'workspace')
        .map(target => pathApiFor(target.path).relative(roots.workspace, target.path).replaceAll('\\', '/'));
    // 有非读目标才付 status／ls-files；纯读调用连仓库发现都走缓存。
    const needStates = prepared.some(target =>
        target.dynamic === false && target.rootHit === 'workspace' && target.opClass !== 'read');
    const { states, repo } = gitStates(roots.workspace, relatives, probe, needStates);
    for (const target of prepared) {
        if (target.dynamic === true || target.rootHit !== 'workspace')
            continue;
        // 取状态用的相对路径必须与状态表的键**同一把尺**折（判据住在 `paths.js`）：
        // 无条件 `toLowerCase()` 在 POSIX 上会把两个不同文件当一个（#8）。
        const rel = foldStateKey(roots.workspace,
            pathApiFor(target.path).relative(roots.workspace, target.path));
        let state = states.get(rel);
        // 目录目标：git 只列**叶子**（`!! dist/bundle.js`），目录名本身不在状态表里。
        // 全部子项都被忽略＝可重建（build／dist）；混着别的就按第一条非 ignored 的算。
        if (state === undefined && needStates) {
            const children = [...states.entries()]
                .filter(([key]) => key.startsWith(`${rel}/`))
                .map(([, value]) => value);
            if (children.length > 0)
                state = children.every(value => value === 'ignored') ? 'ignored' : children[0];
        }
        target.gitState = needStates
            ? (state ?? (repo ? 'unknown' : 'not-a-repo'))
            : 'unchecked';
    }
    // Only an unparseable segment that CHANGES STATE makes the action
    // unverifiable; a `$(...)` inside a read-only segment stays evidence.
    // 补：读段自己也有界限——目标**一个都没算出来**时，它就等于"读了什么不知道"，
    // 不能再带着「已证明只读」放行（`cat $(ls)`、`cat $NOPE`）。
    const opaque = segments.some(segment => (segment.opClass !== 'read'
            ? segment.opaque === true
            : segment.readTargetless === true))
        || (isShell === true && segments.length === 0 && String(args?.command ?? '').trim() !== '');
    const actionHash = createHash('sha256')
        .update(`${toolName}|${JSON.stringify(isShell ? String(args?.command ?? args?.cmd ?? '') : args ?? {})}`)
        .digest('hex')
        .slice(0, 16);
    const completeness = scanState.error ? 'error'
        : (scanState.truncated || prepared.length > MAX_TARGETS) ? 'truncated' : 'ok';
    // 判据 3／4：读面枚举**不完整**（出错／触顶）时，段级的「已证明只读」也不许留着——
    // 判定链读的是逐段的 readProof，只压调用级的 provenRead 挡不住 proven-read 那一行。
    // 换目录（cd／pushd／popd）不碰文件系统，不在这一条里。
    // 目标为空是**确定结论**（`cat *.nomatch` 0 命中、`cat "*微软*"` 读一个字面名），
    // 不再因为它把读压回未证——空集不是「不确定」，只有枚举失败／截断才是。
    if (completeness !== 'ok') {
        for (const segment of segments) {
            if (segment.opClass !== 'read' || NAVIGATE_PROGRAMS.has(baseProgramOf(segment.program)))
                continue;
            segment.readProof = {
                proven: false,
                why: `读面枚举${completeness === 'error' ? '出错' : '触顶被截断'}，清单不完整`,
            };
        }
    }
    // 目标为空但**有路径参数**（`cat *.nomatch` 0 命中、`cat "*微软*"` 读一个字面名）
    // 是确定结论，保留该段的举证；没有路径参数的读（`grep TODO` 读 stdin）仍算「读面为空」，
    // 不换已证明只读。两类不再共用同一个 false。
    else if (prepared.length === 0) {
        for (const segment of segments) {
            if (segment.opClass !== 'read' || NAVIGATE_PROGRAMS.has(baseProgramOf(segment.program)))
                continue;
            const hasPathWord = (segment.words ?? []).some((word, index) =>
                (segment.wordRoles?.[index] ?? 'path') === 'path');
            if (!(hasPathWord && segment.readProof?.proven === true))
                segment.readProof = { proven: false, why: '读面为空：没有路径参数可举证' };
        }
    }
    return {
        remoteHosts: [...new Set(remoteHosts)],
        exfil: [...new Set(segments.flatMap(segment => segment.exfil ?? []))],
        toolName: String(toolName ?? ''),
        // 原文（shell 的命令串）：证据层要能带它走，脱敏前不留第二份猜测（F05）。
        command: isShell ? String(args?.command ?? args?.cmd ?? '') : '',
        // 这一条命令有没有被闭合展开、为什么没展开（测试与台账都读这一格）。
        closedExpansion: { expanded: closed.expanded === true, why: closed.why ?? '' },
        // 这一条用的是哪套结构（'bash'／'powershell'）还是退回手写拆串（'tokenizer'）；
        // incomplete 只说「结构没被文法证实」，不携带任何档位含义。
        parseMode: {
            mode: parsed.mode,
            incomplete: parsed.incomplete === true,
            why: parsed.why ?? '',
        },
        isShell,
        isMcp,
        actionHash,
        workspace: roots.workspace,
        // 源根绑定与解析过程（台账、证据与测试都读这一格；没绑时为 ''）。
        sourceRoot,
        segments,
        // 整条调用的读面——'name'（只回名字／计数／元数据）或 'body'（回正文片段）。
        readFace: callReadFace,
        targets: prepared,
        // 非 shell 的正文／参数原文（已按 8K 截断）：敏感面扫它、深评也要读它（F04/F05）。
        payloads,
        opaque,
        // 免检特权要拿证据换：全部段都是「举得出证的读」、这次读面枚举没有触顶／报错。
        // 不再要求「至少列出一个目标」——目标为空是确定结论（读不到东西也是读）。
        provenRead: segments.length > 0 && completeness === 'ok'
            && segments.every(segment => segment.readProof.proven === true),
        readProofWhy: (segments.find(segment => segment.readProof.proven !== true)?.readProof ?? {}).why ?? '',
        // 只改本会话状态、不碰文件系统也不出网的一族（compress／todo_write…）。
        // 与「已证明只读」同性质：它是**举证结果**，放不放由表里那一行拍板（A2）。
        internalOnly: segments.length > 0 && segments.every(segment => segment.opClass === 'internal'),
        hasReadSegment: segments.some(segment => segment.opClass === 'read'),
        // 效果清单（判据 1）：文件目标按 role 分（脚本／输入源／清单／写目的／目录容器／删除），
        // 再加网络源／目的与被执行体。targets 仍是「能落到盘上的路径」那份台账。
        effects: [
            ...prepared.map(target => ({
                role: target.role,
                text: target.path ?? target.input,
                input: target.input,
                opClass: target.opClass,
                segmentIndex: target.segmentIndex,
                dynamic: target.dynamic === true,
                ...(target.tree === true ? { tree: true } : {}),
            })),
            ...networkEffects,
            ...executableEffects,
        ],
        // 读面枚举的完备性（判据 4）：'truncated'／'error' 的调用不许走 proven-read 直放。
        completeness,
        truncated: prepared.length > MAX_TARGETS,
        counts: {
            total: prepared.length,
            dynamic: prepared.filter(target => target.dynamic === true).length,
            deletes: prepared.filter(target => target.opClass === 'delete').length,
        },
    };
}

export { fsProbe, READ_PROGRAMS, DELETE_PROGRAMS, DESTROY_PROGRAMS, PRIVILEGE_PROGRAMS, segmentOpClass };
