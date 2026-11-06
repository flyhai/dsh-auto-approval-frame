// L1 grant：把事实命中整理成「哪一行、哪一格是什么档」，喂给有序表；表决定之后，
// 这里不再拿同一路径上的其它命中行二次改判（那一步已删）。
// state 只如实记「这次 AI 能不能放行」：AI 档＝auto；问人＝never；拒绝＝deny。
// 行说人工就不叫模型；行说 AI 就是模型真裁决（`mode=auto` 时 allow 才放行）。
import { normalizePath, segmentsOf, basenameOf, isWithin } from './paths.js';
import { CREDENTIAL_DIR_ROWS, CREDENTIAL_FILE_ROWS, DESTROY_ROWS, ELEVATED_ROWS, OS_CRITICAL_ROWS, isNeverReason, matchPath, opOf } from './policy.js';

const SENSITIVE_SEGMENTS = ['.ssh', '.gnupg', '.aws', '.azure', '.kube', '.git', '.copilot', '.docker', '.dsh', '.workbuddy', '.qoder'];
const PLAIN_SENSITIVE = new Set(['.gitconfig', '.gitmodules', '.netrc', '.npmrc', '.pypirc', '.mcp.json']);
const CREDENTIAL_BASENAME = /(credential|secret|token|password|apikey|api_key|passwd)/i;
const KEY_BASENAME = /\.(pem|key|p12|pfx|kdbx|jks|keystore)$/i;
// 行层面把「密钥容器」与「PEM」分开：.pem 内容可能是证书链，不默认当私钥。
const KEY_MATERIAL_BASENAME = /\.(key|p12|pfx|kdbx|jks|keystore)$/i;
const PEM_BASENAME = /\.pem$/i;
const SSH_KEY_BASENAME = /^id_(rsa|dsa|ecdsa|ed25519)$/i;
const SSH_PUBKEY_BASENAME = /^id_(rsa|dsa|ecdsa|ed25519)\.pub$/i;
const DOTENV_BASENAME = /^\.env(\..+)?$/i;
const DOTENV_EXEMPT = /^\.env\.(example|sample|template)$/i;
// 启动脚本＝开壳／开终端就会自动执行的文件。两类同构，防的是同一件事：
// 改一次、以后每次会话都生效（持久化点），而不是这一次命令干了什么。
// POSIX 侧：.bashrc .zshrc .profile .bash_profile .zlogin 等；
// Windows 侧：PowerShell 的 $PROFILE 家族（profile.ps1、Microsoft.PowerShell_profile.ps1、
// Microsoft.VSCode_profile.ps1……），形状统一是「*profile.ps1」。
// 文件名大小写不敏感：Windows 上 .BASHRC 和 Microsoft.PowerShell_Profile.PS1 同样会被读。
const STARTUP_SCRIPT_BASENAME = /^\.(?:ba|z|k|c|tc)sh(?:rc|_profile|_login|_logout)$|^\.(?:bash|zsh)?profile$|^\.(?:profile|zlogin|zlogout|bash_login|bash_logout)$|^(?:.*_)?profile\.ps1$/i;

// A delete flag the frame cannot interpret is a delete whose real operand set
// is unknown (`--files0-from list` reads paths from a file, `-i` waits on a
// terminal), so it may be reviewed but never auto-released.
// 只认短选项簇（-rf／-R）：不锚定时 --files0-from 里的 "-from" 也会被当成递归标志。
const RECURSIVE_FLAG = /^-[a-zA-Z]*[rR][a-zA-Z]*$/;
const KNOWN_DELETE_FLAGS = new Set(['-', '--', '-f', '-v', '--force', '--verbose']);

// 这些理由一出现，本次授权最多到「确认」级（AI 可判但不得自放）。
// 文件面尾部 8 行条目已撤出：其中五族（动态操作数／一次删太多／目标是符号链接／
// 删的不是普通文件／内容没有第二份副本）不再由代码造理由，也就不在这份名单里。
const CONFIRM_REASONS = new Set(['opaque-command', 'path-outside-trusted-roots',
    'unclassified-tool', 'mcp-tool', 'unrecognized-delete-flag',
    // 原「remote-operand」一行按方向拆两行（远端执行仍人工／上行传内容按目的地分档）。
    'remote-execute', 'remote-upload']);

/** * 客户端状态目录（装工具自己的产物，不是密钥目录）里「读的是文件而不是密钥」的子树白名单。
 * 两道条件缺一不可：① 目录本身在这族里（`~/.gnupg/skills` 不算——目录名是凭据目录就不放）；
 * ② 紧挨着目录的那一段在白名单里（`~/.dsh/profiles/**` 不算——宿主配置本体必须问人）。
 * `skills`／`docs`＝说明书，默认直接放行；其余四段＝工具自己的产物，默认交模型判。
 */
const TOOL_STATE_DIRS = new Set(['.dsh', '.workbuddy', '.qoder', '.copilot']);
const DOCS_SUBTREES = new Set(['skills', 'docs']);
// 这两族下读的是宿主自己的配置与可执行体，不是产物：必须问人（审核方 H 段的底线）。
const TOOL_BLOCK_SUBTREES = new Set(['profiles', 'bin']);
// 用户数据：会话记录／存储／审批台账。它们不是「工具产物」——读它们等于读用户在机器上做过什么，
// 起不再走 tool-state 豁免（此前 `~/.dsh/sessions/**` 的读是直接放行的）。
const USER_DATA_SUBTREES = new Set(['sessions', 'storages', 'auto-approval-frame', 'memory', 'rewind-snapshots']);
/** 路径里出现凭据形状的段（目录名也算）就不豁免——豁免只看首层子树太粗。 */
const credentialishSegment = segments => segments.some(segment => segment !== undefined
    && (CREDENTIAL_BASENAME.test(segment) || KEY_BASENAME.test(segment) || SSH_KEY_BASENAME.test(segment)
        || /^(?:tokens?|credentials?|auth(?:entication)?|secrets)$/.test(segment)));

/** * 客户端状态目录（装工具自己的产物，不是密钥目录）的读类豁免。
 * ① 目录必须在这族里（`~/.gnupg/skills` 不算——那是凭据目录）；
 * ② 豁免只给**子树里的文件**，目录本体下直接摆的文件算宿主配置（`settings.yaml.imported`）→ 不豁免；
 * ③ `skills`／`docs`＝说明书，默认直接放行；其余子树（plugins／hooks／workspace／projects／memory…）
 *    ＝工具自己的产物，默认交模型判；`profiles`／`bin` 与任何凭据形状的路径一律不豁免。
 */
function toolReadExemption(segments) {
    const at = segments.findIndex(segment => TOOL_STATE_DIRS.has(segment));
    if (at === -1)
        return undefined;
    // 目标就是目录本身（`ls ~/.dsh`）：列一层名字，不是读内容 ⇒ 交模型判，不静默放行。
    if (segments.length === at + 1)
        return 'tool-state-read';
    const subtree = segments[at + 1];
    // 目录本体下面**直接摆的文件**（`~/.dsh/settings.yaml.imported`）＝宿主配置，不豁免；
    // 而 `ls ~/.dsh/plugins/` 是列一个子树目录，属于产物。两者的差别只看有没有扩展名。
    const directlyUnder = segments.length === at + 2;
    if (directlyUnder && /\.[a-z0-9]{1,8}$/.test(subtree))
        return undefined;
    if (TOOL_BLOCK_SUBTREES.has(subtree) || USER_DATA_SUBTREES.has(subtree) || credentialishSegment(segments))
        return undefined;
    return DOCS_SUBTREES.has(subtree) ? 'docs-subtree-read' : 'tool-state-read';
}

// 源码文件不因名字里含 token／secret 就当凭据（F12）：`tokenizer.py`、敏感检测器自己的
// `secrets-scan.ts` 都被旧判据打成人工。真含秘密时结果侧的形状检测照样遮。
// 形状型判据（.env／密钥库后缀／shell rc）不受这条豁免影响。
const CODE_SOURCE_EXT = /\.(js|mjs|cjs|ts|tsx|jsx|py|go|rs|java|kt|rb|php|c|h|cpp|hpp|cs|swift|sh|bash|ps1|lua|pl|vim|el)$/i;

export function isSensitiveBasename(name) {
    if (name === '' || DOTENV_EXEMPT.test(name))
        return false;
    if (CODE_SOURCE_EXT.test(name))
        return PLAIN_SENSITIVE.has(name) || DOTENV_BASENAME.test(name) || KEY_BASENAME.test(name)
            || SSH_KEY_BASENAME.test(name) || STARTUP_SCRIPT_BASENAME.test(name);
    return PLAIN_SENSITIVE.has(name) || DOTENV_BASENAME.test(name) || CREDENTIAL_BASENAME.test(name)
        || KEY_BASENAME.test(name) || SSH_KEY_BASENAME.test(name) || STARTUP_SCRIPT_BASENAME.test(name);
}

/** * 一个路径上的全部理由（A04：理由先收齐，再由表排序——不能由一个分类函数提前裁掉）。
 * 返回空数组＝这个路径上没有一条下界理由。
 */
function reasonsForPath(path, target, roots) {
    // 「路径解析不出来」随表行一起撤了：抠不出路径就是没有路径可判，
    // 不替"看不见"这一事实自己造一档；没人接的调用由默认档交模型。
    if (typeof path !== 'string' || path === '')
        return [];
    const out = [];
    const segments = segmentsOf(path).map(segment => segment.toLowerCase());
    const base = basenameOf(path).toLowerCase();
    const lower = path.replaceAll('\\', '/').toLowerCase();
    // An operator-opened DSH_HOME subtree stops being "harness state", but only
    // the `.dsh` row itself is excused; other credential dirs still count.
    const opened = roots.dshOpen.some(rule => matchPath(rule, path, target.opClass));
    // `homeOnly` 的目录行要按家目录锚定；家目录自己的段序列在这里算一次，逐行复用。
    const homeSegments = segmentsOf(normalizePath(roots.home, roots.home, roots.home))
        .map(segment => segment.toLowerCase());
    const fileReason = credentialFileReason(base);
    const dirReasons = credentialDirReasons(segments, lower, opened, homeSegments);
    // 读类先看「这是不是工具自己的文档／产物」，再看目录本体——文件名自己像凭据的不豁免，
    // 顺序反了就等于用目录名当免死金牌（审核方 H 段的 `~/.gnupg/skills` 就是这个洞）。
    // 豁免只压**目录那一行**：私钥／密码这类文件形状的理由照旧进候选（A04）。
    const exempt = target.opClass === 'read' && fileReason === undefined
        ? toolReadExemption(segments) : undefined;
    if (exempt !== undefined)
        out.push(exempt);
    else
        out.push(...dirReasons);
    if (fileReason !== undefined)
        out.push(fileReason);
    // 目标是否落在本次会话已声明的工作区／信任根里（F12：家目录族据此豁免）。
    const insideManaged = isWithin(roots.workspace, path, roots.home)
        || roots.trusted.some(rule => matchPath(rule, path, target.opClass));
    const osReason = osCriticalReason(lower, insideManaged);
    if (osReason !== undefined)
        out.push(osReason);
    // 工作区根本体的删／搬／销毁：与 policy.evaluatePolicies 的 rootGate 是同一条事实。
    // 这里记一条 never 理由，台账才不会把「问人」写成 auto；`git add .` 这类以 `.`
    // 为操作数的写／执行不在此列（旧写法把 `target.opClass !== 'read'` 全算进来，白弹人工框）。
    if (['delete', 'rename', 'destroy'].includes(String(target.opClass))
        && path === roots.workspace)
        out.push('workspace-root');
    if (target.opClass === 'delete' && !opened && roots.dshHome !== undefined
        && isWithin(roots.dshHome, path, roots.home))
        out.push('harness-state-tree');
    return out;
}

/** * Why a resolved path can never be auto-released; 全部理由（去重后按「路径上的顺序」）。
 * **词法路径与解析后的真实路径都要过一遍**：父目录是 junction 时，
 * `workspace\creds\id_rsa` 的字面路径什么都不像，真身却在 `~/.ssh` 里（A02）。
 */
export function neverReasonsFor(target, roots) {
    const paths = [target.path, target.realPath]
        .filter(path => typeof path === 'string' && path !== '');
    if (paths.length === 0)
        return [];
    const out = [];
    const seen = new Set();
    for (const path of paths) {
        for (const reason of reasonsForPath(path, target, roots)) {
            if (seen.has(reason))
                continue;
            seen.add(reason);
            out.push(reason);
        }
    }
    return out;
}

/** 第一个理由（老调用方／单理由场景）：语义与旧版一致。 */
export function neverReasonFor(target, roots) {
    return neverReasonsFor(target, roots)[0];
}

/** 子树行按**段边界**匹配：`/.git/index` 只管 `index` 本身与它下面的东西，
 * 不再把 `index.lock`／`index.tmp` 这种「前缀相同、不是同一个文件」的路径算进来——
 * 行名与它管到的东西必须对得上，否则人会以为识别错了。
 */
function underSubtree(lower, token) {
    const needle = `/${token}`;
    for (let at = lower.indexOf(needle); at !== -1; at = lower.indexOf(needle, at + 1)) {
        const after = lower.slice(at + needle.length);
        if (after === '' || after.startsWith('/'))
            return true;
    }
    return false;
}

/** 凭据目录：一行一个目录（gcloud／azure 子树也各占一行）。返回**全部**命中的行。 */
function credentialDirReasons(segments, lower, opened, homeSegments) {
    const out = [];
    for (const row of CREDENTIAL_DIR_ROWS) {
        if (row.kind === 'segment') {
            if (row.token === '.dsh' && opened)
                continue;
            // 客户端的家目录（`.workbuddy`／`.qoder`／`.copilot`）在每个会话工作区里还会被
            // 注入一份**同名**目录。按「任意段名相等」匹配会把 `<会话>/.workbuddy/**` 也说成
            // `~/.workbuddy`——理由文案指向用户没碰的目录，还把区内读写拉成人工。
            // `homeOnly` 的行只认「家目录的直接子段」；`.ssh`／`.aws` 这类真凭据目录照旧按段名抓（别处也拦）。
            if (row.homeOnly === true) {
                const underHome = segments.length >= homeSegments.length
                    && segments.slice(0, homeSegments.length).join('/') === homeSegments.join('/');
                if (underHome && segments[homeSegments.length] === row.token)
                    out.push(row.preset);
                continue;
            }
            if (segments.includes(row.token))
                out.push(row.preset);
            continue;
        }
        const tokens = row.tokens ?? [row.token];
        if (tokens.some(token => underSubtree(lower, token)))
            out.push(row.preset);
    }
    return out;
}

const FILE_RULE_TESTS = {
    'dotenv': name => !DOTENV_EXEMPT.test(name) && DOTENV_BASENAME.test(name),
    'ssh-private-key': name => SSH_KEY_BASENAME.test(name),
    'ssh-public-key': name => !SSH_KEY_BASENAME.test(name) && SSH_PUBKEY_BASENAME.test(name),
    'key-material': name => !PEM_BASENAME.test(name) && KEY_MATERIAL_BASENAME.test(name),
    'pem': name => PEM_BASENAME.test(name),
    'token-name': name => /token/i.test(name),
    'password-name': name => /password/i.test(name),
    'secret-name': name => /secret/i.test(name),
    'credential-name': name => CREDENTIAL_BASENAME.test(name),
    'netrc': name => ['.netrc', '.pypirc'].includes(name),
    'gcloud-adc': name => name === 'application_default_credentials.json',
    'msal-cache': name => /^msal_token_cache/i.test(name),
    'npmrc': name => name === '.npmrc',
    'git-config': name => name === '.gitconfig',
    'git-modules': name => name === '.gitmodules',
    'mcp': name => name === '.mcp.json',
    'shell-rc': name => STARTUP_SCRIPT_BASENAME.test(name),
};

/** 凭据文件名：一类一行（.env／SSH 私钥／证书密钥库／含 token…）。 */
function credentialFileReason(base) {
    for (const row of CREDENTIAL_FILE_ROWS) {
        const test = FILE_RULE_TESTS[row.test];
        if (test === undefined)
            continue;
        // 名字型判据（token-name／secret-name…）对源码文件不生效——`tokenizer.py`、
        // 敏感检测器自己的 `secrets-scan.ts` 都不该当凭据（F12）；形状型判据照旧。
        if (CODE_SOURCE_EXT.test(base) && NAME_ONLY_TESTS.has(row.test))
            continue;
        if (test(base))
            return row.preset;
    }
    return undefined;
}

const NAME_ONLY_TESTS = new Set(['token-name', 'password-name', 'secret-name', 'credential-name']);

/** * 系统关键目录：Windows／POSIX 各一行一目标。
 * `insideManaged`＝这个目标落在本次会话**已声明的工作区／信任根**里。POSIX 下 `/home`
 * 覆盖所有人的家目录，而 Linux 的开发工作区本来就在 `/home/<user>/…` 下面——
 * 照整棵树问人等于"每次写自己的项目都要点框"（F12）。所有权／角色才是区分依据，
 * 不是目录名：凭据目录、shell rc、宿主状态树各自另有判据，不受这条豁免影响。
 */
function osCriticalReason(lower, insideManaged) {
    for (const row of OS_CRITICAL_ROWS) {
        const token = row.token.replaceAll('\\', '/').toLowerCase();
        // 家目录这一族只在"不在受管工作区内"时才算系统关键树；/opt 里的项目也一样。
        if (insideManaged && (row.preset === 'os:home' || row.preset === 'os:root' || row.preset === 'os:opt'))
            continue;
        const family = row.kind === 'windows'
            ? (token === 'c:/program files' ? ['c:/program files', 'c:/program files (x86)'] : [token])
            : (token === '/bin' ? ['/bin', '/sbin']
                : token === '/lib' ? ['/lib', '/lib64']
                    : token === '/private' ? ['/private', '/system', '/library'] : [token]);
        if (family.some(one => lower === one || lower.startsWith(`${one}/`)))
            return row.preset;
    }
    return undefined;
}

const ELEVATED_BY_PROGRAM = new Map(ELEVATED_ROWS
    .filter(row => row.program !== undefined)
    .map(row => [row.program.toLowerCase(), row.preset]));

/** 提权／销毁类命令：一行一个程序；历史改写按 git push --force 一行。 */
function elevatedReasonOf(segment) {
    // 按**动作**而不是按程序名拉高：`reg query` 在事实层已经是读（F12），
    // 这里再按程序名命中就把只读的子命令也拖进提权族。
    if (!['privilege', 'destroy', 'exec'].includes(segment.opClass))
        return segment.opClass === 'history-rewrite' ? 'elevated:git-push-force' : undefined;
    const program = String(segment.program ?? '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
    const byProgram = ELEVATED_BY_PROGRAM.get(program);
    if (byProgram !== undefined)
        return byProgram;
    if (segment.opClass === 'history-rewrite')
        return 'elevated:git-push-force';
    return undefined;
}

const DESTROY_BY_PROGRAM = new Map(DESTROY_ROWS
    .flatMap(row => (row.programs ?? []).map(program => [program.toLowerCase(), row.preset])));

/** 这一段如果是在销毁**本机以外**的东西（云／IaC／集群／库表／容器产物／账号），返回它的硬闸行名。 */
function destroyReasonOf(segment) {
    const program = String(segment.program ?? '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
    const preset = DESTROY_BY_PROGRAM.get(program);
    if (preset === undefined)
        return undefined;
    const row = DESTROY_ROWS.find(item => item.preset === preset);
    const words = (segment.words ?? []).map(word => String(word).toLowerCase());
    const flags = (segment.flags ?? []).map(flag => String(flag).toLowerCase());
    const text = (segment.words ?? []).map(word => String(word)).join(' ');
    // 命中形状四选一；只有程序名的行（`userdel`）＝程序本身就是删除动作，不看参数。
    if (row.verbs === undefined && row.flags === undefined && row.statements === undefined
        && row.pairs === undefined)
        return preset;
    if (row.verbs !== undefined && words.some(word => row.verbs.includes(word)))
        return preset;
    if (row.flags !== undefined && flags.some(flag => row.flags.includes(flag)))
        return preset;
    if (row.pairs !== undefined && row.pairs.some(pair => pair.every(word => words.includes(word))))
        return preset;
    if (row.statements !== undefined && row.statements.test(text))
        return preset;
    return undefined;
}

function disposabilityFacts(facts) {
    const deletes = facts.targets.filter(target => target.opClass === 'delete' || target.opClass === 'destroy');
    if (deletes.length === 0)
        return undefined;
    return deletes.map((target) => {
        if (target.dynamic === true)
            return `${target.input} (unresolvable operand)`;
        const git = target.gitState === undefined ? '' : `, ${target.gitState}`;
        return `${target.path} (${target.kind}, ${target.bytes ?? '?'} B, ${target.rootHit}${git})`;
    }).join('; ');
}

const PUBLISH_PROGRAMS = new Set(['docker', 'podman', 'nerdctl', 'npm', 'pnpm', 'yarn', 'bun', 'cargo', 'twine', 'gh']);

/** 这一段如果是在发布／推送，返回它的目标（远端＋分支）；不是就返回 undefined。 */
function publishTargetOf(segment) {
    const program = String(segment.program ?? '').split(/[\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
    const words = (segment.words ?? []).map(word => String(word));
    // `operands` 里带着子命令本身（`push`／`publish`），先剥掉再谈远端与分支。
    const operands = (segment.operands ?? []).map(word => String(word))
        .filter(word => !word.startsWith('-') && !['push', 'publish', 'upload'].includes(word.toLowerCase()));
    if (program === 'git') {
        if (!words.includes('push'))
            return undefined;
        return { remote: (operands[0] ?? '').toLowerCase(), branch: (operands[1] ?? '').toLowerCase() };
    }
    if (PUBLISH_PROGRAMS.has(program) && (words.includes('push') || words.includes('publish') || words.includes('upload')))
        return { remote: (operands[0] ?? '').toLowerCase(), branch: '' };
    return undefined;
}

/** * 授权面覆盖不覆盖这次发布：目标要对得上，且没有任何一条排除句点到它。
 * 覆盖 ⇒ 外传行从「人工」降成「交模型」——**不是直接放行**：模型仍可因别的理由拒绝。
 */
function publishAuthorized(segment, authorization) {
    const target = publishTargetOf(segment);
    if (target === undefined)
        return false;
    // 判据 2：**撤销当场作废**。`revokeSeq` 是最后一条撤销句在意图序列里的位置
    // （-1＝没撤销），只有它之后签的发布授权才算数；不带 `seq` 的条目按「撤销前」处理，fail-closed。
    const revokeSeq = Number(authorization?.revokeSeq ?? -1);
    const signedAfterRevoke = entry => Number(entry?.seq ?? -1) > revokeSeq;
    // 判据 3：**一次性**。同一个远端＋分支成功用过一次就不再授权（记账在调用方，这里只读）。
    const consumed = Array.isArray(authorization?.consumed) ? authorization.consumed : [];
    const alreadyUsed = entry => consumed.some(row => (typeof row === 'string'
        ? row === `${entry.remote}|${entry.branch}`
        : row?.remote === entry.remote && row?.branch === entry.branch));
    const excluded = (authorization?.excludes ?? []).some((text) => {
        const value = String(text ?? '').toLowerCase();
        if (!/(推|推送|发布|publish|deploy)/i.test(value))
            return false;
        if (target.remote !== '' && !value.includes(target.remote))
            return false;
        if (target.branch !== '' && !value.includes(target.branch))
            return false;
        return true;
    });
    if (excluded)
        return false;
    return (authorization?.publish ?? []).some(entry =>
        signedAfterRevoke(entry)
        && alreadyUsed(entry) === false
        && (entry.remote === '' || entry.remote === target.remote)
        // B09 的「空 branch 匹配多分支」：空只配空（docker／npm 这类本来没有分支），
        // 想要覆盖全部得显式写 `remote/*`（publishTargetsOf 把 `*` 当通配）。
        && (entry.branch === target.branch || entry.branch === '*'));
}

/** * 目的地闸——这一次要把内容送到**本机之外**吗。
 * 本机（回环／本机主机名／`file://`）与内网（RFC1918／链路本地／唯一本地／`.local|lan|home|internal`）
 * ＝用户自己的机器，不算「出去」；公网算；**判不出也算**（空清单、`bucket`／`host`／`prod` 这类
 * 单标签名既可能是内网主机名也可能是桶名）——宁可多问一句，不许猜成内网。
 */
function offMachine(segment) {
    // 空清单与单标签名同走「判不出」这一档（目标①）：判不出的写法只有一处，变异才红得全。
    const list = (segment?.destinations ?? []).length === 0
        ? [{ text: '', kind: 'unknown' }]
        : segment.destinations;
    return list.some(row => row.kind === 'public' || row.kind === 'unknown');
}

/** * Facts → 命中表＋授权档位。所有命中行都进表；每条理由也都按该行**当前的档位**
 * 记账（台账要能复盘「哪一行在场、它是什么档」）。
 * 判定只走表：表内按行序先命中即停，表间取最严；表把这一档交给 AI 之后，
 * `walkLadder` 把 state 落成 auto，不再让同路径的其它命中行事后否决。
 * `floor` 是预设行的当前档位（`policy.floorActions`）：行被改成 `ai`／`release`／停用，
 * 这一格就照实记；`state` 只回答 AI 能不能放行，不再替表改判。
 */
export function grantFor(facts, roots, floor = new Map(), authorization = null) {
    // 文件面的预设行按操作给档位（{read,write,delete}）；其余平面是一个字符串。
    const actionOf = (reason, op = 'write') => {
        const entry = floor.get(reason) ?? 'ask';
        return typeof entry === 'string' ? entry : (entry[op] ?? 'ask');
    };
    const opOfTarget = target => opOf(target.opClass) ?? 'write';
    const denied = new Set();
    // 事实命中表：preset → { op: 档位 }。有序判定按它决定预设行算不算「命中」。
    const hits = new Map();
    // F03：同一份命中还要落到**产生它的那个作用项**上。只留全调用的并集，会让
    // `release echo` 替同一条命令里的 `node 脚本` 作主、让 `.ssh` 的豁免替 `.aws` 说话。
    const segmentScopes = facts.segments.map(() => new Map());
    const targetScopes = facts.targets.map(() => new Map());
    const rank = { release: 1, ai: 2, ask: 3, deny: 4 };
    const put = (map, reason, op, action) => {
        const entry = map.get(reason) ?? {};
        if (entry[op] === undefined || rank[action] > rank[entry[op]])
            entry[op] = action;
        map.set(reason, entry);
    };
    const record = (reason, op, action, scopes) => {
        put(hits, reason, op, action);
        for (const scope of scopes ?? [])
            put(scope, reason, op, action);
    };
    const keep = (reason, op = 'write', scopes) => {
        const action = actionOf(reason, op);
        // `off`＝这一行被停用；`''`＝这一行对该操作不表态（读类就靠它不再拉高）。
        // 两种都不算命中：命中了就等于在有序表里占一格，不表态的行不该占。
        if (action === 'off' || action === '')
            return false;
        record(reason, op, action, scopes);
        if (action === 'deny') {
            denied.add(reason);
            return false;
        }
        // ai／release 也是命中（有序判定要用），但不进 reasons（它们不拉高 grant 状态）。
        return action === 'ask';
    };
    const reasons = new Set();
    // 一个文件目标既算在自己头上，也算给它所属那一段的补充意见。
    const scopesOfTarget = index => {
        const scopes = [targetScopes[index]];
        const at = facts.targets[index].segmentIndex;
        if (typeof at === 'number' && segmentScopes[at] !== undefined)
            scopes.push(segmentScopes[at]);
        return scopes;
    };
    /** * 一行外传／上行预设的落点：表档位是人工 ⇒ 照表（人工）。表档位被改成交模型／放行
     * ⇒ **目的地闸仍兜得住**：这一段送去公网或判不出落在谁的机器上，命中照样硬上升成人工，
     * 模型无权翻案（判据③「授权必须绑目的地：只放自己的机器」）。
     */
    const riseByDestination = (preset, indexes) => {
        const scopes = indexes.map(index => segmentScopes[index]);
        if (keep(preset, 'write', scopes)) {
            reasons.add(preset);
            return;
        }
        if (indexes.some(index => offMachine(facts.segments[index])) === false)
            return;
        put(hits, preset, 'write', 'ask');
        for (const scope of scopes)
            put(scope, preset, 'write', 'ask');
        reasons.add(preset);
    };
    for (const [index, target] of facts.targets.entries()) {
        const scopes = scopesOfTarget(index);
        // 动态目标（`$X`／`$(…)`）没有路径可匹配，跳过；「操作数是动态的」
        // 那行条目之后，这里不再替它造理由——它落哪一档由表里的行说，没人接就默认交模型。
        if (target.dynamic === true)
            continue;
        // 一条目标上的**全部**理由都要进表（A04）：目录理由先返回就吃掉同一路径的
        // 私钥／密码理由，只把 `.ssh` 目录行调成允许时，私钥那条就再没机会说话。
        // 以前这里还叠了两层"具体压泛化"——具体文件行或子树行一表态就把泛化目录行整个
        // 剔出理由集（deny 还特例永不被剔）。那是在替一张没排好的表打补丁：出厂表已按
        // 「范围从小到大」重排，窄行天然排在宽行之前，谁说话由行序定，这里不再挑掉任何理由。
        const neverList = neverReasonsFor(target, roots);
        const op = opOfTarget(target);
        for (const never of neverList) {
            if (keep(never, op, scopes))
                reasons.add(never);
        }
    }
    // 「看不全」不再当一条理由：看不见就是看不见，交给证据面如实标
    // `unknowns`，由"没有行接住 ⇒ 默认交模型"兜，不在这里替自己加一档。
    if (facts.opaque && keep('opaque-command', 'write',
        facts.segments.map((segment, index) => segment.opaque === true ? segmentScopes[index] : undefined)
            .filter(Boolean)))
        reasons.add('opaque-command');
    // A2：「已证明只读」「会话内部工具」连同它们的反面都是表里的行——事实层只举证，
    // 档位、顺序、停用归这张表（此前它们是判定链末尾写死的免检分支，页面上改不动）。
    // 举证也按段记：`cat 说明书 && node 脚本` 只有前一段举得出证，后一段没有行替它说话。
    const remoteUploadIndexes = [];
    const remoteExecuteIndexes = [];
    const downloadScopes = [];
    const remoteReadScopes = [];
    const exfilHits = [];
    for (const [index, segment] of facts.segments.entries()) {
        const scopes = [segmentScopes[index]];
        if (segment.opClass === 'read')
            keep(segment.readProof?.proven === true ? 'proven-read' : 'unproven-read', 'write', scopes);
        else if (segment.opClass === 'internal')
            keep('internal-only', 'write', scopes);
        // A10：方向决定这一段的远端作用落在哪一行——下载／无载荷查询交模型，
        // 上行传内容与远端执行各有各的行（拆开后由目的地闸分档，不再一刀切人工）。
        if (segment.remote === true || (segment.hosts ?? []).length > 0) {
            const direction = segment.remoteDirection || 'remote';
            if (direction === 'download')
                downloadScopes.push(segmentScopes[index]);
            else if (direction === 'remote-read')
                remoteReadScopes.push(segmentScopes[index]);
            else if (direction === 'upload')
                remoteUploadIndexes.push(index);
            // 未登记的工具带着网址：方向判不出，既不记「远端执行」也不记「外发」——
            // 那两条都声称方向确知。档位交给工具面「认不出操作类型的工具」那一行说。
            else if (direction !== 'tool-unknown')
                remoteExecuteIndexes.push(index);
        }
        for (const preset of segment.exfil ?? [])
            exfilHits.push({ preset, index });
        const elevated = elevatedReasonOf(segment);
        if (elevated !== undefined && keep(elevated, 'write', scopes))
            reasons.add(elevated);
        // 补充：本机以外的破坏族也进同一份命中表；命令行由事实层的 factActionOf 加严成 ask。
        const destroyed = destroyReasonOf(segment);
        if (destroyed !== undefined && keep(destroyed, 'write', scopes))
            reasons.add(destroyed);
        if (segment.opClass === 'other' && !facts.isShell) {
            const reason = facts.isMcp === true ? 'mcp-tool' : 'unclassified-tool';
            if (keep(reason, 'write', scopes))
                reasons.add(reason);
        }
        // `find -delete`／`-exec rm` 是删除，但段本身算"读族程序"⇒ 只看 opClass 会整个漏掉
        //（22:2x 按机制造的跨平台语料抓出来的，单机会话台账里没有这一形）。
        const findDestroys = String(segment.program ?? '').split(/[\/]/).pop().toLowerCase() === 'find'
            && (segment.flags ?? []).some(flag => /^-(?:delete|exec|execdir|ok|okdir)$/.test(flag));
        if (segment.opClass === 'delete' || segment.opClass === 'destroy' || findDestroys) {
            if (segment.flags.some(flag => RECURSIVE_FLAG.test(flag) || flag === '--recursive')
                && keep('recursive-delete', 'write', scopes))
                reasons.add('recursive-delete');
            if (segment.flags.some(flag => !KNOWN_DELETE_FLAGS.has(flag) && !/^-[fv]+$/i.test(flag)
                && !RECURSIVE_FLAG.test(flag) && flag !== '--recursive')
                && keep('unrecognized-delete-flag', 'write', scopes))
                reasons.add('unrecognized-delete-flag');
        }
    }
    // 远端按方向分档（A10 拆方向／ 拆目的地）：下载与无载荷查询交模型判（不弹人）；
    // 上行传内容出厂交模型，但目的地在公网／判不出时由目的地闸升人工；远端执行默认仍人工。
    if (downloadScopes.length > 0)
        keep('remote-download', 'write', downloadScopes);
    if (remoteReadScopes.length > 0)
        keep('remote-read', 'write', remoteReadScopes);
    if (remoteUploadIndexes.length > 0)
        riseByDestination('remote-upload', remoteUploadIndexes);
    if (remoteExecuteIndexes.length > 0)
        riseByDestination('remote-execute', remoteExecuteIndexes);
    // 授权面覆盖这次发布时，外传行降成交模型（仍不直接放行）；排除句优先。
    // 判据④：用户点名目的地＝用户自己答应，公网也照这一条降——目的地闸不推翻点名授权。
    for (const { preset, index } of exfilHits) {
        const scopes = [segmentScopes[index]];
        if (publishAuthorized(facts.segments[index], authorization)) {
            put(hits, preset, 'write', 'ai');
            for (const scope of scopes)
                put(scope, preset, 'write', 'ai');
            continue;
        }
        riseByDestination(preset, [index]);
    }
    // 「一次删得太多」这条理由随表行一起撤了：删得多不多由目标自己算，
    // 要拦就在表里写行，不在这里给自己加一档。
    for (const [index, target] of facts.targets.entries()) {
        const scopes = scopesOfTarget(index);
        if (target.dynamic === false && target.rootHit === 'outside'
            && keep('path-outside-trusted-roots', opOfTarget(target), scopes))
            reasons.add('path-outside-trusted-roots');
    }
    // 删的是目录／符号链接／设备、内容没有第二份副本——这两档不再由代码
    // 自己造理由。删的是什么、内容有没有第二份，仍是事实层给的事实，只是不再自动等于
    // 一条人工下界；要这条下界，就在表里写一行。

    const list = [...reasons];
    const disposability = disposabilityFacts(facts);
    const scoped = { hits, segmentScopes, targetScopes };
    if (denied.size > 0)
        return { state: 'deny', reasons: [...new Set([...denied, ...list])], disposability, ...scoped };
    if (list.some(reason => isNeverReason(reason)))
        return { state: 'never', reasons: list, disposability, ...scoped };
    // 提权与外传两族按前缀算：它们的理由是逐程序拆行的，写进名单跟不上拆行速度。
    const confirmLike = list.some(reason => CONFIRM_REASONS.has(reason)
        || reason.startsWith('elevated:') || reason.startsWith('exfil:'));
    if (confirmLike)
        return { state: 'confirm', reasons: list, disposability, ...scoped };
    return { state: 'auto', reasons: list, disposability, ...scoped };
}

// 把「这一段是不是发布」「授权面覆不覆盖它」两问暴露给调用方——
// index.js 要在执行成功后按目标记账（一次性消费），不能自己复制一份匹配逻辑。
export { SENSITIVE_SEGMENTS, CONFIRM_REASONS, publishAuthorized, publishTargetOf };
