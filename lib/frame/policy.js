// AI生成
// L1: the ordered rule tables. One list per plane; inside a list the first
// matching row wins, across lists the strictest row wins (deny > ask > ai > release).
//
// Four tiers on every plane, no fifth: `release` is a real release (the operator
// said so), `ai` routes this action to the model (terminal for this table — later
// rows do not get a second say), `ask` goes to the human, `deny` stops it.
// Masking is not a tier — the sensitive plane masks every hit it reports,
// whatever tier the row carries.
//
// 四个平面共用同一套档位，敏感面**不多出一档**：命中就遮是这一层自己在做的事，
// 不是给人挑的选项。档位只决定遮完之后还要不要再问／再判／整段拦掉。
import { createHash } from 'node:crypto';
import { DETECTOR_SHAPES } from './sensitive.js';
import { ENTROPY_LABEL, ENTROPY_PRESET, highEntropyRanges } from './entropy.js';
import { normalizePath } from './paths.js';
import { nativeNameOf } from './parse.js';
import { configVersionOf } from './record.js';
import { CURRENT_KEY_ID, isSealed, openSealed, openText, sealText } from './secretbox.js';

export const RULE_ACTIONS = ['release', 'ai', 'ask', 'deny'];
export const RULE_OPS = ['read', 'write', 'delete', 'all'];
/** * 没有任何一行表态时的**行名**（条1：allow 要能点出依据行）。
 * 证据块里必须把这句话摆出来，模型才有一个真东西可抄——它不是谁的允许行，
 * 点它就等于说「这次是默认档交我判」，机器照样验得出它读的是哪一份证据。
 */
export const NO_RULE_ROW = '无行表态：默认交模型判（这不是任何人的允许行）';
/** * 文件面的预设行按「会独立触发的一条理由」拆开：一个目录／一类文件名一行。
 * 只有拆到这个粒度，才能只放行 `.ssh` 的读、而 `.aws` 仍必人工。
 * 匹配逻辑（哪个路径落到哪一行）住在 `grant.js`；这里只给 id／label／说明。
 */
export const CREDENTIAL_DIR_ROWS = [
    // 审批器自身的存储件——这三行把「用来管你的那套」单独点名必问人
    //（`kind:'subtree'`＝这一行按目录及其全部内容算）。
    { preset: 'approver-tier-carrier', label: '审批器档位载体', note: '插件自己的档位载体：改这些＝改「用来管你的那套」', kind: 'subtree', tokens: ['.dsh/auto-approval-frame/config.json', '.dsh/auto-approval-frame/settings.json', '.dsh/settings.json', '.dsh/rules.json', '.dsh/policy.json'], ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'approver-audit-store', label: '审批器审计台账', note: 'audit 段（*.jsonl／manifest／state）：改台账＝改证据本身', kind: 'subtree', tokens: ['.dsh/auto-approval-frame/audit'], ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'approver-grant-record', label: '审批记录与秘密账', note: 'secrets.json 与授权／待批记账件：写它＝改审批账本', kind: 'subtree', tokens: ['.dsh/auto-approval-frame/secrets.json', '.dsh/auto-approval-frame/grants.json', '.dsh/auto-approval-frame/pending.json'], ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:gcloud-config', label: 'gcloud（.config）', note: '~/.config/gcloud', kind: 'subtree', token: '.config/gcloud', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:gcloud-roaming', label: 'gcloud（Roaming）', note: 'AppData/Roaming/gcloud', kind: 'subtree', token: 'appdata/roaming/gcloud', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:gcloud-local', label: 'gcloud（Local）', note: 'AppData/Local/gcloud', kind: 'subtree', token: 'appdata/local/gcloud', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:gcloud-sdk', label: 'google-cloud-sdk', note: 'Library/Application Support/google-cloud-sdk', kind: 'subtree', token: 'library/application support/google-cloud-sdk', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:azure-roaming', label: 'Azure（Roaming）', note: 'AppData/Roaming/azure', kind: 'subtree', token: 'appdata/roaming/azure', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:azure-cloudsdk', label: 'CloudSDK', note: 'AppData/Roaming/CloudSDK', kind: 'subtree', token: 'appdata/roaming/cloudsdk', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:windows-credentials', label: 'Windows 凭据', note: 'AppData/Roaming/Microsoft/Credentials', kind: 'subtree', token: 'appdata/roaming/microsoft/credentials', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    // §4.1 拆行：目录层再往下按「资源类型」分——一行一个具体地方，表内按行序，
    // 谁先命中谁说话；别的命中行不再事后改判（那是第四步，已删）。
    { preset: 'credential-dir:ssh-known-hosts', label: '~/.ssh/known_hosts／known_hosts2', note: '主机指纹与 known_hosts2：出厂读问人；要放宽就读这一格，写删仍人工', kind: 'subtree', tokens: ['.ssh/known_hosts', '.ssh/known_hosts2'], ops: { read: 'ask', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:git-metadata', label: '~/.git 的 objects／refs／HEAD／packed-refs／index／logs', note: '仓库对象、引用、HEAD、packed-refs、index、logs：出厂读问人；要放宽就读这一格，写删仍人工', kind: 'subtree', tokens: ['.git/objects', '.git/refs', '.git/head', '.git/packed-refs', '.git/index', '.git/logs'], ops: { read: 'ask', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:git-config-read', label: '~/.git/config', note: '仓库配置可能带 remote URL／token：出厂读问人；要放宽就读这一格，写删仍人工', kind: 'subtree', tokens: ['.git/config'], ops: { read: 'ask', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:git-hooks', label: '~/.git/hooks', note: '放钩子＝放可执行入口：任何操作都问人', kind: 'subtree', tokens: ['.git/hooks'], ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:ssh', label: '~/.ssh', note: '~/.ssh/**（含全部内容）', kind: 'segment', token: '.ssh', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:gnupg', label: '~/.gnupg', note: '~/.gnupg/**（含全部内容）', kind: 'segment', token: '.gnupg', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:aws', label: '~/.aws', note: '~/.aws/**（含全部内容）', kind: 'segment', token: '.aws', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:azure', label: '~/.azure', note: '~/.azure/**（含全部内容）', kind: 'segment', token: '.azure', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:kube', label: '~/.kube', note: '~/.kube/**（含全部内容）', kind: 'segment', token: '.kube', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:git', label: '~/.git', note: '~/.git/**（含全部内容）', kind: 'segment', token: '.git', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:docker', label: '~/.docker', note: '~/.docker/**（含全部内容）', kind: 'segment', token: '.docker', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-dir:copilot', label: '~/.copilot', note: '~/.copilot/**（含全部内容）', kind: 'segment', token: '.copilot', homeOnly: true, ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:dsh', label: '~/.dsh', note: '~/.dsh/**（含全部内容）', kind: 'segment', token: '.dsh', ops: { read: 'ask', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:workbuddy', label: '~/.workbuddy', note: '~/.workbuddy/**（含全部内容）', kind: 'segment', token: '.workbuddy', homeOnly: true, ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-dir:qoder', label: '~/.qoder', note: '~/.qoder/**（含全部内容）', kind: 'segment', token: '.qoder', homeOnly: true, ops: { read: 'ai', write: 'ask', delete: 'ask' } },
];

export const CREDENTIAL_FILE_ROWS = [
    { preset: 'credential-file:dotenv', label: '.env', note: '.env（.example／.sample／.template 除外）', test: 'dotenv', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    // §4.2 拆行：私钥与公钥分开、.pem 不默认私钥、.npmrc 走字段投影、
    // .gitmodules 与 .gitconfig 分开、.mcp.json 的读视图与可执行入口分开。
    { preset: 'credential-file:ssh-private-key', label: 'SSH 私钥', note: 'id_rsa／id_dsa／id_ecdsa／id_ed25519（**不含 .pub**）', test: 'ssh-private-key', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:ssh-public-key', label: 'SSH 公钥', note: 'id_*.pub：公钥本身不是秘密，读交模型（不再按私钥问人）', test: 'ssh-public-key', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-file:key-material', label: '密钥库与容器', note: '*.key *.p12 *.pfx *.kdbx *.jks *.keystore', test: 'key-material', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:pem', label: 'PEM 文件', note: '*.pem 不再默认当私钥：读交模型，写／删仍人工', test: 'pem', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-file:token-name', label: '文件名含 token', note: '*token*', test: 'token-name', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:password-name', label: '文件名含 password', note: '*password*', test: 'password-name', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:secret-name', label: '文件名含 secret', note: '*secret*', test: 'secret-name', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:credential-name', label: '文件名含凭据字样', note: '*credential*／*apikey*／*api_key*／*passwd*', test: 'credential-name', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:netrc', label: '.netrc / .pypirc', note: '.netrc .pypirc', test: 'netrc', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:gcloud-adc', label: 'gcloud 应用默认凭据', note: 'application_default_credentials.json：真正的认证材料', test: 'gcloud-adc', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:msal-cache', label: 'Azure 令牌缓存', note: 'msal_token_cache*：真正的认证材料', test: 'msal-cache', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:npmrc', label: '.npmrc', note: '读走字段投影（令牌字段由脱敏出口遮），不是整读直放', test: 'npmrc', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-file:git-config', label: '.gitconfig', note: '.gitconfig', test: 'git-config', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'credential-file:git-modules', label: '.gitmodules', note: '.gitmodules 只列子模块，不含凭据；读交模型', test: 'git-modules', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-file:mcp', label: '.mcp.json', note: '读＝看视图（交模型）；写／删＝加可执行入口（人工）', test: 'mcp', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'credential-file:shell-rc', label: '启动脚本', note: '开壳／开终端就自动执行的文件：POSIX 的 .bashrc .zshrc .profile 等，Windows 的 PowerShell $PROFILE 家族（*profile.ps1）', test: 'shell-rc', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
];

export const OS_CRITICAL_ROWS = [
    // §4.3 拆行：具体文件／子树排在整棵树之前，先命中先说话。
    { preset: 'os:etc-shadow', label: '/etc/shadow', note: '口令散列：读也问人', kind: 'posix', token: '/etc/shadow', ops: { read: 'ask', write: 'ask', delete: 'ask' } },
    { preset: 'os:var-log', label: '/var/log', note: '日志：读交模型，写删人工', kind: 'posix', token: '/var/log', ops: { read: 'ai', write: 'ask', delete: 'ask' } },
    { preset: 'os:etc-release', label: '/etc/os-release', note: '系统标识文件，不是秘密：读直接放行', kind: 'posix', token: '/etc/os-release', ops: { read: 'release', write: '', delete: '' } },
    { preset: 'os:windows', label: 'C:\\Windows', note: 'C:\\Windows 及其全部内容', kind: 'windows', token: 'c:\\windows' },
    { preset: 'os:program-files', label: 'Program Files', note: 'C:\\Program Files（含 x86）', kind: 'windows', token: 'c:\\program files' },
    { preset: 'os:programdata', label: 'C:\\ProgramData', note: 'C:\\ProgramData 及其全部内容', kind: 'windows', token: 'c:\\programdata' },
    { preset: 'os:boot', label: 'C:\\Boot', note: 'C:\\Boot 及其全部内容', kind: 'windows', token: 'c:\\boot' },
    { preset: 'os:etc', label: '/etc', note: '/etc 及其全部内容', kind: 'posix', token: '/etc' },
    { preset: 'os:bin', label: '/bin /sbin', note: '/bin /sbin 及其全部内容', kind: 'posix', token: '/bin' },
    { preset: 'os:usr', label: '/usr', note: '/usr 及其全部内容', kind: 'posix', token: '/usr' },
    { preset: 'os:lib', label: '/lib /lib64', note: '/lib /lib64 及其全部内容', kind: 'posix', token: '/lib' },
    { preset: 'os:var', label: '/var', note: '/var 及其全部内容', kind: 'posix', token: '/var' },
    { preset: 'os:opt', label: '/opt', note: '/opt 及其全部内容', kind: 'posix', token: '/opt' },
    { preset: 'os:home', label: '/home', note: '/home 及其全部内容', kind: 'posix', token: '/home' },
    { preset: 'os:root', label: '/root', note: '/root 及其全部内容', kind: 'posix', token: '/root' },
    { preset: 'os:macos', label: 'macOS 系统目录', note: '/private /system /library', kind: 'posix', token: '/private' },
];

/** 旧的大包 id：读配置时把它的档位折给拆出来的每一行（下次保存时自然写散）。 */
export const LEGACY_FLOOR_SPLIT = {
    'credential-or-client-tree': CREDENTIAL_DIR_ROWS.map(row => row.preset),
    'credential-material': CREDENTIAL_FILE_ROWS.map(row => row.preset),
    'os-critical-tree': OS_CRITICAL_ROWS.map(row => row.preset),
};
const LEGACY_PARENT = new Map(Object.entries(LEGACY_FLOOR_SPLIT)
    .flatMap(([parent, children]) => children.map(child => [child, parent])));
export const FLOOR_LABEL = new Map([...CREDENTIAL_DIR_ROWS, ...CREDENTIAL_FILE_ROWS, ...OS_CRITICAL_ROWS]
    .map(row => [row.preset, row.label])
    // 脚本正文里发包：卡片与台账要说人话，不把内部 id 甩给人。
    .concat([['exfil:script-upload', '脚本把内容发到外部']]));

/** * 预设行清单：判定链里每一条「代码自己会拉高」的理由，在这里就是一行，默认档位是它
 * 今天实际的行为。它们与用户行同表同形制，**全部可改**：改档位、停用都可以。
 *
 * `match` 是给人看的说明，不是匹配式——这些行的命中由 `grant.js` 的事实判断给出，
 * 所以页面上编辑的是档位与开关，不是那串描述（这一点在页面上也要写清，不让人误以为
 * 改了字就能改命中范围）。
 */
/** 提权／销毁类命令也按程序拆开：一行一个程序，单独换档或停用。 */
export const ELEVATED_ROWS = [
    { preset: 'elevated:shred', label: 'shred', note: '覆写文件内容（不可逆）', program: 'shred' },
    { preset: 'elevated:dd', label: 'dd', note: '直接写块设备／文件', program: 'dd' },
    { preset: 'elevated:mkfs', label: 'mkfs', note: '格式化文件系统', program: 'mkfs' },
    { preset: 'elevated:fdisk', label: 'fdisk', note: '改分区表', program: 'fdisk' },
    { preset: 'elevated:wipefs', label: 'wipefs', note: '擦除文件系统签名', program: 'wipefs' },
    { preset: 'elevated:format', label: 'format', note: '格式化卷', program: 'format' },
    { preset: 'elevated:cipher', label: 'cipher', note: '擦除卷空闲空间', program: 'cipher' },
    { preset: 'elevated:sudo', label: 'sudo', note: '以其他用户身份执行', program: 'sudo' },
    { preset: 'elevated:runas', label: 'runas', note: '以其他用户身份执行（Windows）', program: 'runas' },
    { preset: 'elevated:chmod', label: 'chmod', note: '改文件权限（45：数字模式无 setuid/setgid/sticky 且 group/other 无写位、符号模式不带 s/t、不递归 ⇒ 只是普通写，不进本行）', program: 'chmod' },
    { preset: 'elevated:chown', label: 'chown', note: '改文件属主', program: 'chown' },
    { preset: 'elevated:cacls', label: 'cacls', note: '改 ACL（Windows）', program: 'cacls' },
    { preset: 'elevated:icacls', label: 'icacls', note: '改 ACL（Windows）', program: 'icacls' },
    { preset: 'elevated:reg', label: 'reg', note: '改注册表', program: 'reg' },
    { preset: 'elevated:netsh', label: 'netsh', note: '改网络／防火墙配置', program: 'netsh' },
    { preset: 'elevated:sc', label: 'sc', note: '改 Windows 服务', program: 'sc' },
    { preset: 'elevated:setfacl', label: 'setfacl', note: '改 ACL', program: 'setfacl' },
    { preset: 'elevated:takeown', label: 'takeown', note: '夺取文件所有权', program: 'takeown' },
    { preset: 'elevated:set-acl', label: 'Set-Acl', note: '改 ACL（PowerShell）', program: 'Set-Acl' },
    { preset: 'elevated:git-push-force', label: 'git push --force', note: '改写远端历史', history: 'push-force' },
];

/** * 补充（对照物＝外部公开的危险命令正则规则集）：
 * **本机以外**的破坏动作——云控制面／IaC／集群／库表／容器产物／账号与调度——进硬闸行（`ask`）。
 * 判据按「程序名＋子命令词／语句形状／旗标」认，不按 `opClass` 认：`aws s3 rm`／`terraform destroy`
 * 在事实层归不进本机文件面（没有可 lstat 的目标），只看 opClass 会整族漏掉。
 * 硬闸只做加严：这一族由事实层把命中段的档位升成 ask（命令表里那行写 ai 也一样）。
 */
export const DESTROY_ROWS = [
    {
        preset: 'destroy:cloud',
        label: '云资源删除／销毁',
        programs: ['aws', 'az', 'gcloud', 'oci', 'ibmcloud', 'hcloud', 'gcutil', 'ovh'],
        verbs: ['delete', 'destroy', 'terminate', 'deregister', 'purge', 'remove', 'rm'],
        note: '云控制面上的删除／销毁子命令：动的是共享资源，本机没有回收站可退',
    },
    {
        preset: 'destroy:iac',
        label: '基础设施拆毁（terraform／opentofu）',
        programs: ['terraform', 'tofu'],
        verbs: ['destroy'],
        flags: ['-destroy'],
        note: '`terraform destroy` 与 `apply -destroy`：整份基础设施被拆掉',
    },
    {
        preset: 'destroy:k8s',
        label: '集群资源删除／驱逐',
        programs: ['kubectl', 'kubeadm', 'oc', 'kustomize'],
        verbs: ['delete', 'drain'],
        note: '集群里的对象被删／节点被驱逐：多人在用的东西，不是本会话造的',
    },
    {
        preset: 'destroy:helm',
        label: 'helm 卸载／回滚',
        programs: ['helm'],
        verbs: ['uninstall', 'delete', 'rollback'],
        note: '共享集群上的发布状态被撤或被换回旧版',
    },
    {
        preset: 'destroy:db-statement',
        label: '库表破坏语句',
        programs: ['mysql', 'mariadb', 'psql', 'postgresql', 'sqlcmd', 'isql', 'mongo', 'mongosh',
            'influx', 'clickhouse-client', 'redis-cli', 'supabase'],
        statements: /(^|[^A-Za-z0-9_])(DROP\s+(DATABASE|TABLE|SCHEMA|USER)|TRUNCATE\s+TABLE|DELETE\s+FROM[\s\S]*?WHERE\s*(1\s*=\s*1|TRUE)|FLUSHALL|FLUSHDB|DROP\s+KEY)/i,
        note: '随命令带过去的 SQL／Redis 语句：删库、删表、清表、无条件 DELETE、FLUSHALL／FLUSHDB、删键',
    },
    {
        preset: 'destroy:container-store',
        label: '容器与镜像批量销毁',
        programs: ['docker', 'podman', 'nerdctl', 'crictl'],
        pairs: [['system', 'prune'], ['system', 'rm'], ['volume', 'rm'], ['volume', 'prune'],
            ['image', 'rm'], ['image', 'prune'], ['builder', 'prune']],
        note: '`docker system prune`／`volume rm` 这类清空本机镜像与数据卷的动作：卷里的东西别处没有第二份',
    },
    {
        preset: 'destroy:account',
        label: '系统账号删除',
        programs: ['userdel', 'groupdel', 'deluser', 'delgroup'],
        note: '账号与用户组被删：程序名本身就是删除动作，不需要看参数',
    },
    {
        preset: 'destroy:crontab',
        label: '清空计划任务',
        programs: ['crontab'],
        flags: ['-r'],
        note: '`crontab -r` 一把抹掉该用户全部定时任务，抹掉的清单别处没有',
    },
];

export const EXFIL_ROWS = [
    { preset: 'exfil:git-push', label: 'git push', note: '把本地提交推到远端仓库（45：pushspec 是本机路径／file://／localhost ⇒ 内容不出本机，不进本行）' },
    { preset: 'exfil:curl-upload', label: 'curl 上传', note: '-T／--upload-file／-F／--form／--data @文件' },
    { preset: 'exfil:cloud-storage', label: '云存储上传', note: 'aws s3 cp／sync、gsutil cp、az storage blob upload' },
    { preset: 'exfil:oci-push', label: '镜像推送', note: 'docker／podman／nerdctl push' },
    { preset: 'exfil:package-publish', label: '包发布', note: 'npm／pnpm／yarn／cargo publish、twine upload' },
    { preset: 'exfil:release', label: '发布产物', note: 'gh release create／upload／edit' },
];

/** * ｜命令面＝一张**命令清单**：一条命令一行。
 *
 * 行上只有四件：`command`（命令名：程序名，或程序名＋子命令词）／`action`（四档）／
 * `enabled`（开关）／`note`（说明）。行内**不写条件与范围**——`verbs`／`flags`／
 * `statements`／`pairs`／`history`／`ops`／`execFamily`／`execDynamic`／`scope` 都是
 * 算法按**这次调用**算出来的结果（事实层给），只喂判定与内部下界，不进表、不可配。
 *
 * 顺序即语义：具体（子命令）行排在泛化（程序名）行前面；同一个段命中多行时取最长命令名
 * （具体压泛化）。末行固定是兜底「其他命令」（可改档、不可删、不可上移）——前面所有行
 * 都没命中时，这次调用交 AI 判，绝不空放。表间取最严：这一面写「允许」也抹不掉别的
 * 面要问人／要拒的那一格。
 *
 * 行档位是**基线**：算法算出的结果只许把它加严（事实层那几族理由——远端四方向／提权／
 * 破坏／外传——按这次调用算出的档位并回命令行的档位上）。所以今天的触发格一格
 * 不动：`aws s3 rm` 仍人工、`aws s3 ls` 仍交 AI、`docker system prune` 仍人工、
 * `ssh prod "systemctl restart …"` 仍人工。
 */
export const COMMAND_FALLBACK = '其他命令';

/** * 出厂读族行是 `release`——这是既有设定，不是新增放行：111 之前走结果行
 * `{ preset: 'proven-read', plane: 'command', action: 'release' }`（`16cda5c:policy.js:310`），
 * 111 把结果行整类拿掉、改成「一条命令一行」后才落成本表的 `release` 行；
 * `bbb068b:389` 里那对 `['proven-read','ai']` 是 111 改形的中间态，不是要长期交模型的裁决。
 * 覆盖面＝`facts.js` 的读族 61 只里的 60 只（`git` 按子命令拆行，本体不单列）。
 * 本行按程序名命中，不给它另开例外：段里真是写（`sort -o out.txt a.txt`）仍由本行放行，
 * 严不严看落点——文件面按路径取最严；真是删（`find src -delete`）由事实层的删除下界问人。
 */
export const COMMAND_ROWS = [
    // ── PowerShell 原生 cmdlet：每条命令一行，与同名 POSIX 程序地位相等 ──
    // `Get-ChildItem` 不是 `ls`、`Remove-Item` 不是 `rm`：各有各的档位与说明，
    // 设置页按原生命令名能搜到。跨方言只共用事实层的族分类，不共用这一行。
    // 档位按动作本身定（列／读→放行，改→AI，杀进程→人工），不按它像哪个 POSIX 命令定。
    { command: 'Get-ChildItem', action: 'release', enabled: true, note: '只列目录条目：读什么由文件面按实际路径判，区外或碰凭据照样问人' },
    { command: 'Get-Content', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Get-Item', action: 'release', enabled: true, note: '只读条目元数据：目标由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Test-Path', action: 'release', enabled: true, note: '只问存在与否：目标由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Resolve-Path', action: 'release', enabled: true, note: '只把路径解析成绝对路径：不读正文、不改东西' },
    { command: 'Get-FileHash', action: 'release', enabled: true, note: '只算摘要：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Select-String', action: 'release', enabled: true, note: '只在文件里找匹配：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Import-Csv', action: 'release', enabled: true, note: '只读取表格：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Import-Clixml', action: 'release', enabled: true, note: '只读取序列化对象：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Get-ItemProperty', action: 'release', enabled: true, note: '只读条目属性：目标由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Get-Acl', action: 'release', enabled: true, note: '只读权限表：目标由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'Measure-Object', action: 'release', enabled: true, note: '只做计数／求和：不碰文件，也不执行脚本块' },
    { command: 'Compare-Object', action: 'release', enabled: true, note: '只比较两组对象：不碰文件' },
    { command: 'Get-Process', action: 'release', enabled: true, note: '只列进程：不碰文件' },
    { command: 'Get-Command', action: 'release', enabled: true, note: '只查命令在哪：不碰文件' },
    { command: 'Get-Location', action: 'release', enabled: true, note: '只回当前目录：不改任何东西' },
    { command: 'Set-Location', action: 'release', enabled: true, note: '只切当前目录：不改任何东西' },
    { command: 'Push-Location', action: 'release', enabled: true, note: '只切当前目录：不改任何东西' },
    { command: 'Pop-Location', action: 'release', enabled: true, note: '只切当前目录：不改任何东西' },
    { command: 'Write-Output', action: 'release', enabled: true, note: '只往管道写值：不碰文件' },
    { command: 'Write-Host', action: 'release', enabled: true, note: '只往屏幕写文字：不碰文件' },
    { command: 'Format-Table', action: 'release', enabled: true, note: '只排版显示：不碰文件' },
    { command: 'Format-List', action: 'release', enabled: true, note: '只排版显示：不碰文件' },
    { command: 'Format-Wide', action: 'release', enabled: true, note: '只排版显示：不碰文件' },
    { command: 'Format-Custom', action: 'release', enabled: true, note: '只排版显示：不碰文件' },
    { command: 'Out-String', action: 'release', enabled: true, note: '只把对象转成文字：不碰文件' },
    { command: 'Select-Object', action: 'ai', enabled: true, note: '算属性时能跑脚本块：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'Where-Object', action: 'ai', enabled: true, note: '过滤条件能跑脚本块：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'Sort-Object', action: 'ai', enabled: true, note: '排序键能跑脚本块：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'Group-Object', action: 'ai', enabled: true, note: '分组键能跑脚本块：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'ForEach-Object', action: 'ai', enabled: true, note: '每项都跑脚本块：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'Add-Content', action: 'ai', enabled: true, note: 'PS 追加写文件：目的由文件面按实际路径判，区内放行、跨区或碰凭据升人工' },
    { command: 'Out-File', action: 'ai', enabled: true, note: 'PS 写文件：目的由文件面按实际路径判，区内放行、跨区或碰凭据升人工' },
    { command: 'Set-Item', action: 'ai', enabled: true, note: 'PS 改条目：目的由文件面按实际路径判，区内放行、跨区或碰凭据升人工' },
    { command: 'New-Item', action: 'ai', enabled: true, note: 'PS 新建文件／目录：目的由文件面按实际路径判' },
    { command: 'Clear-Content', action: 'ai', enabled: true, note: 'PS 清空文件内容：删的是内容不是文件，仍交 AI 判' },
    { command: 'Copy-Item', action: 'ai', enabled: true, note: 'PS 复制：源与目的由文件面按实际路径判，跨区或碰凭据升人工' },
    { command: 'Move-Item', action: 'ai', enabled: true, note: 'PS 移动／改名：源与目的由文件面按实际路径判，跨区或碰凭据升人工' },
    { command: 'Rename-Item', action: 'ai', enabled: true, note: 'PS 改名：改的是哪一条由文件面按实际路径判' },
    { command: 'Remove-Item', action: 'ai', enabled: true, note: 'PS 删除：删的是谁、在不在区内，由文件面按实际目标升人工' },
    { command: 'Start-Process', action: 'ai', enabled: true, note: 'PS 起进程：跑的是什么命令名看不出来，交 AI 判' },
    { command: 'Invoke-WebRequest', action: 'ai', enabled: true, note: 'PS 取网页／下文件：目的地与写出由事实层判，公网上行升人工' },
    { command: 'Invoke-Expression', action: 'ai', enabled: true, note: 'PS eval：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'Stop-Process', action: 'ask', enabled: true, note: 'PS 杀进程：动了就不是本会话能兜的' },
    // ── cmd 内建与 pwsh 同名词（与 POSIX 同名词各自一行，档位按动作定）──
    { command: 'findstr', action: 'release', enabled: true, note: '只找匹配：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'del', action: 'ai', enabled: true, note: 'cmd 删除：删的是谁、在不在区内，由文件面按实际目标升人工' },
    { command: 'erase', action: 'ai', enabled: true, note: 'cmd 删除：删的是谁、在不在区内，由文件面按实际目标升人工' },
    { command: 'rd', action: 'ai', enabled: true, note: 'cmd 删除目录：删的是谁、在不在区内，由文件面按实际目标升人工' },
    { command: 'md', action: 'ai', enabled: true, note: 'cmd 新建目录：目的由文件面按实际路径判' },
    { command: 'copy', action: 'ai', enabled: true, note: 'cmd 复制：源与目的由文件面按实际路径判，跨区或碰凭据升人工' },
    { command: 'move', action: 'ai', enabled: true, note: 'cmd 移动／改名：源与目的由文件面按实际路径判，跨区或碰凭据升人工' },
    { command: 'ren', action: 'ai', enabled: true, note: 'cmd 改名：改的是哪一条由文件面按实际路径判' },
    { command: 'rename', action: 'ai', enabled: true, note: 'cmd／pwsh 改名：改的是哪一条由文件面按实际路径判' },
    // ── 读族：常用查看与定位（出厂默认放行；区外路径与凭据由文件面取最严，不靠本行兜底）──
    // ── 读族：取文件内容（同上；sed／find 的改写与删除形由事实层算出来再取最严）──
    // ── 解释器：命令只是壳，代码里干什么看不出来（交 AI；读面写面仍进事实层）──
    // ── 写与改：目的路径由文件面按实际判，区内放行、跨区或碰凭据升人工 ──
    // ── 删与改名：命令面交 AI；删的是谁、在不在区内，由文件面按实际目标升人工 ──
    // ── 进程与系统：动了就不是本会话能兜的 ──
    // ── 复制与改名（写目的由文件面判；跨区、碰凭据照样升人工）──
    // ── 远端文件传输（原远端四行之一，方向由事实层判）──
    // ── 容器与镜像批量销毁（原 destroy:container-store 的条件行拆成子命令行；触发格档位取原行 ask）──
    // ── 外传：镜像推送／包发布／发布产物（原 exfil 六行按程序名折开；目的地闸仍由事实层加严）──
    // ── 远端（原远端四行按程序名折开；方向仍由事实层判，这里只放下界）──
    // ── 本机以外的破坏族（原 destroy 八行的条件拆掉，程序名一行；破坏形由事实层升人工）──
    // ── 提权／销毁类（原 elevated 二十行按程序名折开；触发格档位取原行 ask）──
    // ── 版本库／包管理（原 remote-download＋exfil 两族的程序名；档位＝交 AI，公网上行升人工）──
    // ── 导航与列目录别名（只切目录、只列，不改任何东西）──
    // ── 版本库只读子命令（比整行 git 更具体，只吃这一格）──
    // ── 版本库写入（add／commit／init 会改库；git config 故意不给只读格，它会改写配置）──
    // ── 别的版本库 ──
    // ── 过滤器（jq／yq 有原地写，awk 有重定向与 system）──
    // ── 归档与压缩（会覆盖同名文件）──
    // ── 构建与包管理（装东西、改环境）──
    // ── 执行别的东西：命令行上给的名字就是一段程序或一行命令 ──
    // ── 系统服务与进程管理（一动手就不是本会话能兜的）──
    // ── 远端（ssh 族补齐）──
    // ── 镜像搬运工具 ──
    // ── 文本编辑（会把内容写回去）──
    // ── 删到回收站（可恢复，仍是删除）──
    // ── 末行兜底：前面一行都没命中 ⇒ 这次调用交 AI 判（固定最后、可改档、不可删、不可上移）──
    { command: 'docker system prune', action: 'ask', enabled: true, note: '清空本机镜像／构建缓存／网络（卷里的东西别处没有第二份）' },
    { command: 'docker system rm', action: 'ask', enabled: true, note: '清掉 docker 的系统级对象' },
    { command: 'docker volume rm', action: 'ask', enabled: true, note: '删数据卷：卷里的东西别处没有第二份' },
    { command: 'docker volume prune', action: 'ask', enabled: true, note: '清掉未使用的数据卷' },
    { command: 'docker image rm', action: 'ask', enabled: true, note: '删镜像' },
    { command: 'docker image prune', action: 'ask', enabled: true, note: '清掉悬空镜像' },
    { command: 'docker builder prune', action: 'ask', enabled: true, note: '清掉构建缓存' },
    { command: 'podman system prune', action: 'ask', enabled: true, note: '清空本机镜像／构建缓存／网络' },
    { command: 'podman system rm', action: 'ask', enabled: true, note: '清掉 podman 的系统级对象' },
    { command: 'podman volume rm', action: 'ask', enabled: true, note: '删数据卷' },
    { command: 'podman volume prune', action: 'ask', enabled: true, note: '清掉未使用的数据卷' },
    { command: 'podman image rm', action: 'ask', enabled: true, note: '删镜像' },
    { command: 'podman image prune', action: 'ask', enabled: true, note: '清掉悬空镜像' },
    { command: 'podman builder prune', action: 'ask', enabled: true, note: '清掉构建缓存' },
    { command: 'nerdctl system prune', action: 'ask', enabled: true, note: '清空本机镜像／构建缓存／网络' },
    { command: 'nerdctl system rm', action: 'ask', enabled: true, note: '清掉 nerdctl 的系统级对象' },
    { command: 'nerdctl volume rm', action: 'ask', enabled: true, note: '删数据卷' },
    { command: 'nerdctl volume prune', action: 'ask', enabled: true, note: '清掉未使用的数据卷' },
    { command: 'nerdctl image rm', action: 'ask', enabled: true, note: '删镜像' },
    { command: 'nerdctl image prune', action: 'ask', enabled: true, note: '清掉悬空镜像' },
    { command: 'nerdctl builder prune', action: 'ask', enabled: true, note: '清掉构建缓存' },
    { command: 'crictl rm', action: 'ask', enabled: true, note: '删容器（集群侧，不是本会话造的）' },
    { command: 'crictl rmi', action: 'ask', enabled: true, note: '删镜像（集群侧）' },
    { command: 'sed -i*', action: 'ai', enabled: true, note: '原地改写：文件被就地覆盖，改了什么只有模型能看；区外或凭据另由文件面说话' },
    { command: 'docker push', action: 'ai', enabled: true, note: '把镜像推到仓库：交模型判，目的地是公网或判不出＝升人工' },
    { command: 'podman push', action: 'ai', enabled: true, note: '把镜像推到仓库：交模型判，公网或判不出＝升人工' },
    { command: 'nerdctl push', action: 'ai', enabled: true, note: '把镜像推到仓库：交模型判，公网或判不出＝升人工' },
    { command: 'npm publish', action: 'ai', enabled: true, note: '发布 npm 包：交模型判，公网或判不出＝升人工' },
    { command: 'pnpm publish', action: 'ai', enabled: true, note: '发布 pnpm 包：交模型判，公网或判不出＝升人工' },
    { command: 'yarn publish', action: 'ai', enabled: true, note: '发布 yarn 包：交模型判，公网或判不出＝升人工' },
    { command: 'bun publish', action: 'ai', enabled: true, note: '发布 bun 包：交模型判，公网或判不出＝升人工' },
    { command: 'cargo publish', action: 'ai', enabled: true, note: '发布 crate：交模型判，公网或判不出＝升人工' },
    { command: 'twine upload', action: 'ai', enabled: true, note: '上传 Python 包：交模型判，公网或判不出＝升人工' },
    { command: 'gh release', action: 'ai', enabled: true, note: '在 GitHub 上建／改／传发布产物：交模型判，公网或判不出＝升人工' },
    { command: 'git push', action: 'ai', enabled: true, note: '把本地提交推到远端：交模型判；公网／判不出＝升人工，--force＝升人工' },
    { command: 'git init', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'git add', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'git commit', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'git status', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git log', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git show', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git diff', action: 'release', enabled: true, note: '只读：只比对不落盘；--output 落文件那一形由事实层算写面后取最严' },
    { command: 'git blame', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git branch', action: 'release', enabled: true, note: '只读：列分支不改任何东西；带 -d／-D／-m／-M 的新建／移动／删除由事实层判成写后取最严，不再由这一行放行' },
    { command: 'git remote', action: 'release', enabled: true, note: '只读：不带子命令／-v 只列远端；add／remove／set-url 改 .git/config 由事实层判成写后取最严' },
    { command: 'git describe', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git ls-files', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git ls-tree', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git cat-file', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git rev-parse', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git shortlog', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'git show-ref', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'kill', action: 'ask', enabled: true, note: '给进程发信号：问人' },
    { command: 'killall', action: 'ask', enabled: true, note: '按名字杀一批进程：问人' },
    { command: 'pkill', action: 'ask', enabled: true, note: '按模式杀进程：问人' },
    { command: 'taskkill', action: 'ask', enabled: true, note: '按 PID／映像名结束进程：问人' },
    { command: 'userdel', action: 'ask', enabled: true, note: '删账号：程序名本身就是删除动作，不看参数' },
    { command: 'groupdel', action: 'ask', enabled: true, note: '删用户组：程序名本身就是删除动作' },
    { command: 'deluser', action: 'ask', enabled: true, note: '删账号：程序名本身就是删除动作' },
    { command: 'delgroup', action: 'ask', enabled: true, note: '删用户组：程序名本身就是删除动作' },
    { command: 'mkfs', action: 'ask', enabled: true, note: '格式化文件系统（`mkfs.ext4`／`mkfs.xfs` 同族）：目标上原有内容不可恢复，问人' },
    { command: 'systemctl', action: 'ask', enabled: true, note: '问人：动的是本会话之外的东西' },
    { command: 'service', action: 'ask', enabled: true, note: '问人：动的是本会话之外的东西' },
    { command: 'systemd-run', action: 'ask', enabled: true, note: '问人：动的是本会话之外的东西' },
    { command: 'trash', action: 'ask', enabled: true, note: '问人：把文件移进回收站' },
    { command: 'python', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'python2', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'python3', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'py', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'node', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'nodejs', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'deno', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'perl', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'ruby', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'php', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'lua', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'tclsh', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'expect', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'pwsh', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'powershell', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'sh', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'bash', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'zsh', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'dash', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'fish', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'cmd', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'wsl', action: 'ai', enabled: true, note: '命令里跑代码：代码里干什么命令名看不出来，交 AI 判' },
    { command: 'mkdir', action: 'ai', enabled: true, note: '建目录：目标由文件面判，跨区或碰凭据升人工' },
    { command: 'touch', action: 'ai', enabled: true, note: '建空文件／改时间戳：同上' },
    { command: 'tee', action: 'ai', enabled: true, note: '写文件：目标由文件面判' },
    { command: 'truncate', action: 'ai', enabled: true, note: '截断文件（清空内容，不可逆）：交 AI 判' },
    { command: 'rm', action: 'ai', enabled: true, note: '删文件／目录：目标由文件面判，区外或整树升人工' },
    { command: 'rmdir', action: 'ai', enabled: true, note: '删空目录：同上' },
    { command: 'unlink', action: 'ai', enabled: true, note: '删单个文件：同上' },
    { command: 'cp', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'mv', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'install', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'ln', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'link', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'robocopy', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'xcopy', action: 'ai', enabled: true, note: '写与改名：目的路径由文件面按实际判，跨区或碰凭据问人' },
    { command: 'sftp', action: 'ai', enabled: true, note: '远端文件传输：交 AI 判；公网上行升人工' },
    { command: 'ssh', action: 'ai', enabled: true, note: '在远端执行：交模型判；远端变更（重起服务等）由事实层升人工' },
    { command: 'nc', action: 'ai', enabled: true, note: '开网络连接／远端交互：交模型判，远端变更升人工' },
    { command: 'telnet', action: 'ai', enabled: true, note: '远端交互：交模型判，远端变更升人工' },
    { command: 'rsync', action: 'ai', enabled: true, note: '增量同步：交模型判；远端执行／公网上行升人工' },
    { command: 'scp', action: 'ai', enabled: true, note: '拷贝到远端或从远端取回：交模型判，公网上行升人工' },
    { command: 'curl', action: 'ai', enabled: true, note: '取回内容／无载荷查询交模型判；上传到公网或判不出＝升人工' },
    { command: 'wget', action: 'ai', enabled: true, note: '取回内容／镜像下载交模型判；上传或判不出＝升人工' },
    { command: 'gsutil', action: 'ai', enabled: true, note: '云存储操作：交模型判，上行到公网或判不出＝升人工' },
    { command: 'aws', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'az', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'gcloud', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'oci', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'ibmcloud', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'hcloud', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'gcutil', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'ovh', action: 'ai', enabled: true, note: '云控制面：交模型判；删除／销毁类子命令升人工' },
    { command: 'terraform', action: 'ai', enabled: true, note: '基础设施：交模型判；destroy／apply -destroy 升人工' },
    { command: 'tofu', action: 'ai', enabled: true, note: '基础设施（OpenTofu）：交模型判；destroy 升人工' },
    { command: 'kubectl', action: 'ai', enabled: true, note: '集群：交模型判；delete／drain 升人工' },
    { command: 'kubeadm', action: 'ai', enabled: true, note: '集群：交模型判；删除／驱逐升人工' },
    { command: 'oc', action: 'ai', enabled: true, note: '集群（OpenShift）：交模型判；删除／驱逐升人工' },
    { command: 'kustomize', action: 'ai', enabled: true, note: '集群清单：交模型判；删除／驱逐升人工' },
    { command: 'helm', action: 'ai', enabled: true, note: '集群发布：交模型判；uninstall／delete／rollback 升人工' },
    { command: 'mysql', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'mariadb', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'psql', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'postgresql', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'sqlcmd', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'isql', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'mongo', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'mongosh', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'influx', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'clickhouse-client', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'redis-cli', action: 'ai', enabled: true, note: '库表：交模型判；FLUSHALL／FLUSHDB／DROP KEY 升人工' },
    { command: 'supabase', action: 'ai', enabled: true, note: '库表：交模型判；DROP／TRUNCATE／无条件 DELETE 升人工' },
    { command: 'crontab', action: 'ai', enabled: true, note: '计划任务：交模型判；-r 一把抹掉全部定时任务＝升人工' },
    { command: 'shred', action: 'ai', enabled: true, note: '覆写文件内容（不可逆）' },
    { command: 'dd', action: 'ai', enabled: true, note: '直接写块设备／文件' },
    { command: 'fdisk', action: 'ai', enabled: true, note: '改分区表' },
    { command: 'wipefs', action: 'ai', enabled: true, note: '擦除文件系统签名' },
    { command: 'format', action: 'ai', enabled: true, note: '格式化卷' },
    { command: 'cipher', action: 'ai', enabled: true, note: '擦除卷空闲空间' },
    { command: 'sudo', action: 'ai', enabled: true, note: '以其他用户身份执行' },
    { command: 'runas', action: 'ai', enabled: true, note: '以其他用户身份执行（Windows）' },
    { command: 'chmod', action: 'ai', enabled: true, note: '改文件权限：普通写交模型判；setuid／setgid／sticky／递归由事实层升人工' },
    { command: 'chown', action: 'ai', enabled: true, note: '改文件属主' },
    { command: 'cacls', action: 'ai', enabled: true, note: '改 ACL（Windows）' },
    { command: 'icacls', action: 'ai', enabled: true, note: '改 ACL（Windows）' },
    { command: 'setfacl', action: 'ai', enabled: true, note: '改 ACL' },
    { command: 'takeown', action: 'ai', enabled: true, note: '夺取文件所有权' },
    { command: 'Set-Acl', action: 'ai', enabled: true, note: '改 ACL（PowerShell）' },
    { command: 'reg', action: 'ai', enabled: true, note: '注册表：查询交模型判；改写由事实层升人工' },
    { command: 'netsh', action: 'ai', enabled: true, note: '网络／防火墙配置：查询交模型判；改写由事实层升人工' },
    { command: 'sc', action: 'ai', enabled: true, note: 'Windows 服务：查询交模型判；起停由事实层升人工' },
    { command: 'git', action: 'ai', enabled: true, note: '版本库操作：交模型判；push 到公网或判不出＝升人工，改写远端历史＝升人工' },
    { command: 'npm', action: 'ai', enabled: true, note: '包管理：装包／构建交模型判；publish 到公网或判不出＝升人工' },
    { command: 'pnpm', action: 'ai', enabled: true, note: '包管理：装包／构建交模型判；publish 到公网或判不出＝升人工' },
    { command: 'yarn', action: 'ai', enabled: true, note: '包管理：装包／构建交模型判；publish 到公网或判不出＝升人工' },
    { command: 'bun', action: 'ai', enabled: true, note: '包管理／运行时：交模型判；publish 到公网或判不出＝升人工' },
    { command: 'cargo', action: 'ai', enabled: true, note: '包管理：构建交模型判；publish 到公网或判不出＝升人工' },
    { command: 'twine', action: 'ai', enabled: true, note: 'Python 包上传：交模型判，公网或判不出＝升人工' },
    { command: 'gh', action: 'ai', enabled: true, note: 'GitHub CLI：交模型判；release create／upload／edit 升人工' },
    { command: 'docker', action: 'ai', enabled: true, note: '容器：交模型判；system prune／volume rm／image rm 等升人工，push 到公网升人工' },
    { command: 'podman', action: 'ai', enabled: true, note: '容器：交模型判；system prune／volume rm／image rm 等升人工，push 到公网升人工' },
    { command: 'nerdctl', action: 'ai', enabled: true, note: '容器：交模型判；system prune／volume rm／image rm 等升人工，push 到公网升人工' },
    { command: 'crictl', action: 'ai', enabled: true, note: '容器（集群侧）：交模型判；rm／rmi 等删除升人工' },
    { command: 'hg', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'svn', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'awk', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'gawk', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'mawk', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'jq', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'yq', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'tar', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'zip', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'unzip', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'make', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'cmake', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'go', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'brew', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'pip', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'pip3', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'apt', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'apt-get', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'npx', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'xargs', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'eval', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'source', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'ksh', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'ash', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'plink', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'pscp', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'psftp', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'skopeo', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'oras', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'notepad', action: 'ai', enabled: true, note: '交 AI 判：能写能改或代码里干什么看不出来，实际动作仍由事实层与文件面核' },
    { command: 'set-content', action: 'ai', enabled: true, note: '交 AI 判：PS 写文件，目的由文件面按实际路径判' },
    { command: 'ls', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'dir', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'grep', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'egrep', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'rg', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'find', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'fd', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'tree', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'which', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'where', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'pwd', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'echo', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'printf', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'date', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'hostname', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'whoami', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'id', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'du', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'df', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'free', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'env', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'printenv', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'test', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'true', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'false', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'uptime', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'ps', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'stat', action: 'release', enabled: true, note: '只读查看：碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'cat', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'type', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'head', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'tail', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'less', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'more', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'wc', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'sort', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'uniq', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'sed', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人；带 -i 的原地改写走下面更具体的那一行' },
    { command: 'cut', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'tr', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'strings', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'xxd', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'od', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'base64', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'md5sum', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'sha1sum', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'sha256sum', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'file', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'diff', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'cmp', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'tac', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'nl', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'column', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'paste', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'join', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'comm', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'expand', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'unexpand', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'fold', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'fmt', action: 'release', enabled: true, note: '只读取内容：读的文件由事实层按参数取，跨区或碰凭据照样问人' },
    { command: 'cd', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'pushd', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'popd', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'chdir', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: 'vdir', action: 'release', enabled: true, note: '只读：不改任何东西；碰什么由文件面按实际路径判，区外或凭据照样问人' },
    { command: COMMAND_FALLBACK, action: 'ai', enabled: true, note: '表外命令一律交 AI 判，绝不空放；这一行固定最后，可改档、可停用，删不掉也挪不走' },
];

const COMMAND_PRESET_PREFIX = 'command:';
export const commandPresetOf = command => `${COMMAND_PRESET_PREFIX}${command}`;
// 兜底行的键单独钉死：`COMMAND_FALLBACK` 是**显示名**，文案会改；键存在用户配置里，
// 一旦跟着显示名走，改一个字就把用户改过的档位全断掉。两个字符串从此各管一头。
export const COMMAND_FALLBACK_PRESET = 'command:fallback';
export const isCommandFallbackPreset = preset => String(preset ?? '') === COMMAND_FALLBACK_PRESET;

/** 命令面在生效表里的行：预设行与用户行同表同权（改档／停用／调序都写在 `commandRules` 里）。 */
const COMMAND_FLOOR_ROWS = COMMAND_ROWS.map(row => ({
    // 兜底行用钉死的键，其余行仍按命令名派生：中文只当 label，不进 preset。
    preset: row.command === COMMAND_FALLBACK ? COMMAND_FALLBACK_PRESET : commandPresetOf(row.command),
    plane: 'command',
    label: row.command,
    action: row.action,
    enabled: row.enabled !== false,
    note: row.note,
    // 兜底行用 `*` 参与匹配，但只对 shell 段生效（见 evaluatePolicies 的 `fallback` 分支）：
    // 非 shell 工具（write／read／mcp…）不是「命令」，不能因为兜底行一律交 AI。
    match: row.command === COMMAND_FALLBACK ? '*' : row.command,
    // `fallback` 是身份：命中范围、排在末位、不可删／不可上移都按它认。
    fallback: row.command === COMMAND_FALLBACK,
}));



/** * 11 条结果行整类拿掉后，事实层的结论仍在、还按原来的档位参与判定：
 * 纯读／读类举不出证／命令看不懂＝交 AI（与今天相同），解释不了的删除参数＝人工。
 * 它们不是表行、不可配；`floorActions` 把它们当内部下界发给事实层（只影响判定）。
 *
 * 文件面尾部那 8 行撤出表之后，
 * 档位**不搬进这里**。搬进来就是"表里没这行、判读还在表外"，比留着条目更坏——你的两条规矩是
 * 「表内按行序命中即停、表间取最严」，判读只许从表里读。这 8 条理由的发射已从 `grant.js` 一并撤掉，
 * 所以它们不再拉高任何东西；要那条下界，就在表里写一行看得见的行。
 */
const INTERNAL_RESULT_ACTIONS = new Map([
    ['proven-read', 'ai'],
    ['unproven-read', 'ai'],
    ['opaque-command', 'ai'],
    ['unrecognized-delete-flag', 'ask'],
]);

export const FLOOR_ROWS = [
    ...CREDENTIAL_FILE_ROWS.map(row => ({
        preset: row.preset, plane: 'file', label: row.label, action: 'ask', note: row.note,
        // 拆出来的行自己带作用面（.pub 读交模型、.pem 读不默认私钥…）。
        ops: row.ops,
    })),
    ...CREDENTIAL_DIR_ROWS.map(row => ({
        preset: row.preset, plane: 'file', label: row.label, action: 'ask', note: row.note,
        // 起目录行也可以自带作用面（known_hosts／git 元数据出厂读问人，要放宽就改那一格）。
        ops: row.ops,
    })),
    ...OS_CRITICAL_ROWS.map(row => ({
        preset: row.preset, plane: 'file', label: row.label, action: 'ask', note: row.note,
        // 系统目录的**读**交模型判（列个目录名不是危险动作），写／删仍必问人。
        // 起行可以自带作用面（`/etc/os-release` 读直接放行、`/etc/shadow` 读也问人）。
        ops: row.ops ?? { read: 'ai', write: 'ask', delete: 'ask' },
    })),
    // 盘根／家目录
    // 不再单列两条下界行——它们就是普通目录，删／改／读一律按「工作区外」与
    // 各删除族的通用下界同判；要更严就写一条普通路径行（deny／ask 都行）。
    // ／99：工作区只有**一条**行的时代——读、写都直接放行（AI 自己的作业面），
    // 删留空（删除族各行有自己的下界）。原来是「工作区根（等值）＋工作区内的写（前缀）」两条，
    // 同样是路径却两套判法，用户看不出哪条管到哪；99 把根那条并进来，只留这一条。
    // 范围＝`workspace` 展开成工作区绝对路径，按路径段前缀匹配，写一个目录就管整片。
    { preset: 'harness-state-tree', plane: 'file', label: '宿主状态树', action: 'ask', note: '~/.dsh/**（允许行按子目录开过口的除外）', ops: { read: 'ask', write: 'ask', delete: 'ask' }},
    { preset: 'docs-subtree-read', plane: 'file', label: '技能／文档子树（只读）', action: 'ask', ops: { read: 'release', write: '', delete: '' }, note: '~/.dsh・~/.workbuddy・~/.qoder・~/.copilot 下紧邻 skills／docs 的读＝看说明书，不是看密钥；写／删仍由目录本体那行管' },
    { preset: 'tool-state-read', plane: 'file', label: '客户端状态的产物（只读）', action: 'ai', ops: { read: 'ai', write: '', delete: '' }, note: '~/.dsh・~/.workbuddy・~/.qoder・~/.copilot 子树里的读＝工具自己的产物（插件、hooks、会话工作区…）：不改任何东西、路径里也没有凭据形状的名字，交模型按任务判是否必要；profiles／bin、目录本体下的文件、任何凭据形状的路径不豁免（纯列目录不该弹框）' },
    // 工作区＝一条普通路径行（目录含子树并含自身）。它排在**凭据族之后、兜底行之前**：
    // 工作区里的普通读／写／删（含删目录、删自己产的文件）由它放行；凭据目标排在
    // 它前面先说话——它是「作业面」，不是「免死金牌」。
    { preset: 'workspace', plane: 'file', label: '当前工作区', action: 'release', match: 'workspace', deleteSelf: false, ops: { read: 'release', write: 'release', delete: 'release' }, note: '工作区这一格路径变量：目录含子树并含自身，普通读／写／删出厂放行（AI 自己的作业面）；凭据族在前，先说话' },
    // 兜底行：
    // 工作区 与 工作区外 合起来就是全部路径，两行互斥、谁也不盖谁——所以它挪到末位不改任何判读
    // （实测对照 347 条逐字相同）。工作区外的路径若没有更前面的具名行接住，就落这一行。
    { preset: 'path-outside-trusted-roots', plane: 'file', label: '工作区外', action: 'ask', ops: { read: 'ai', write: 'ai', delete: 'ask' }, note: '不在工作区里的一切路径：读与写交模型判（正文读不经你手），删除必问人；凭据族、系统目录那些具名行排在它前面，先命中先说话' },
    // 命令面＝一张命令清单（一条命令一行＋末行兜底）；行定义见 COMMAND_ROWS。
    ...COMMAND_FLOOR_ROWS,
    // 网络面兜底：只对**往外送**的方向说话——上行／远端执行的目的地，前面没有一行点名，
    // 就落这一行（出厂人工）。下载与只读查询不在此列：它们不把本机内容送出去。
    { preset: 'network:unlisted-egress', plane: 'network', label: '未知外发', action: 'ask', match: '*', fallback: true, note: '往机器外送内容时，没被你前面的行点名的目的地默认问人；只对上行方向生效，下载与查询不受影响。这一行固定最后，可改档、可停用，删不掉也挪不走' },
    { preset: 'internal-only', plane: 'tool', label: '会话内部工具', action: 'release', note: '只改本会话状态、不碰文件系统也不出网的工具（compress／todo_write…）＝直接放行；停用这一行＝每个内部工具都过模型' },
    { preset: 'unclassified-tool', plane: 'tool', label: '认不出操作类型的工具', action: 'ai', note: '非 shell 且框架无法归类（MCP 工具见下一行）' },
    { preset: 'mcp-tool', plane: 'tool', label: 'MCP 工具', action: 'ai', note: 'mcp:* 工具默认交 AI 审查；可在表里改档或停用' },
];

export const FLOOR_BY_PRESET = new Map(FLOOR_ROWS.map(row => [row.preset, row]));

/** ／98：工作区内普通写／改名的具名结论——台账 rule 那一格的名字。 */
export const PLAIN_CHANGE_LABEL = '当前工作区';

// 静态的 never 理由（其余由拆出来的三族前缀认定）。
// `workspace-root` 与 policy.evaluatePolicies 的 rootGate 同一事实（删／搬工作区根本体）；
// `harness-state-tree` 仍按行判。
const NEVER_IDS = new Set(['workspace-root', 'harness-state-tree']);
const NEVER_FAMILIES = ['credential-dir:', 'credential-file:', 'os:'];
export function isNeverReason(reason) {
    return NEVER_IDS.has(reason) || NEVER_FAMILIES.some(prefix => reason.startsWith(prefix));
}
/** 台账与提示里给人看的理由名：拆出来的行有自己的 label。 */
export function reasonText(reason) {
    return FLOOR_LABEL.get(reason) ?? FLOOR_BY_PRESET.get(reason)?.label ?? reason;
}

export const RULE_PLANES = ['command', 'file', 'network', 'tool', 'sensitive'];

// A10：规则按 `configVersion` 编译**一次**。旧形 `floorActions` 为每个预设重建整张表，
// `walkOne` 又为每个段／目标再解析一遍——规则越多，重复工作按 段×目标×行数 放大。
const ROWS_CACHE = new Map();
const ROWS_CACHE_MAX = 64;

export function effectiveRows(config, plane, roots) {
    const version = configVersionOf(config);
    // 键要带 workspace：文件行的 matchResolved 是按它展开的；敏感面还要看总闸。
    const key = `${plane}|${version}|${roots?.workspace ?? ''}|${config?.sensitiveDetect === false ? '0' : '1'}`;
    const cached = ROWS_CACHE.get(key);
    if (cached !== undefined)
        return cached;
    const rows = buildEffectiveRows(config, plane, roots);
    if (ROWS_CACHE.size >= ROWS_CACHE_MAX)
        ROWS_CACHE.delete(ROWS_CACHE.keys().next().value);
    ROWS_CACHE.set(key, rows);
    return rows;
}

function buildEffectiveRows(config, plane, roots) {
    if (plane === 'sensitive')
        return sensitiveRows(config);
    const stored = parseRules(config?.[`${plane}Rules`], plane, roots);
    const overrides = new Map(stored.filter(row => row.preset !== '').map(row => [row.preset, row]));
    // 用户调过档的预设行仍然带着它自己的中文名：台账与模拟审批要说「已证明只读」，
    // 不能因为改过一次档就把人话换成机器 id（改档＝换了力度，不是换了条目）。
    const named = row => row.preset !== '' && !row.label
        ? { ...row, label: FLOOR_BY_PRESET.get(row.preset)?.label ?? row.label } : row;
    // 已删掉的预设行留在配置里（removed:true），但不进生效表——floorActions 见不到它＝这一条不再拉高。
    // origin 只用来区分「这一行是人写进配置的」还是「出厂预设」——判据 2 的范围降级
    // 只能接管纯预设放行；人显式写的行，覆盖要发生在看得见的规则里，不能被后台改档。
    const visible = stored.filter(row => !(row.preset !== '' && row.removed === true))
        .map((row) => {
            // 带范围词的出厂行（`workspace-plain-write`）被用户改过档之后，配置里只存档位、
            // 没有匹配式（预设覆盖本来就该这样）。这里把出厂行的范围补回这一行，否则「点成允许」
            // 之后它连目标都命不中——可调就成了摆设。
            const floor = row.preset !== '' ? FLOOR_BY_PRESET.get(row.preset) : undefined;
            const bare = String(row.match ?? '') === '';
            const patched = floor?.match !== undefined && bare
                ? {
                    ...row,
                    match: floor.match,
                    matchResolved: resolveRange(floor.match, roots),
                    deleteSelf: floor.deleteSelf,
                    // 兜底行的人写副本也要带「兜底」身份——漏了它，`*` 会替非 shell
                    // 工具（write／read／mcp…）说话，普通写也会被拖成交 AI。
                    fallback: floor.fallback === true,
                }
                : row;
            return { ...named(patched), origin: 'user' };
        });
    // 已写进配置的预设行（用户调过档或调过序）按配置里的位置排；没碰过的预设行补在末尾。
    const builtins = FLOOR_ROWS.filter(row => row.plane === plane)
        .filter(row => !overrides.has(row.preset))
        .map((row) => {
            // 旧的大包覆盖行：拆开后每一行都沿用它的档位（读的时候折，保存时自然写散）。
            const legacy = overrides.get(LEGACY_PARENT.get(row.preset));
            if (legacy !== undefined)
                return { ...legacy, id: `builtin-${row.preset}`, preset: row.preset, label: row.label, match: row.note, origin: 'builtin' };
            // 出厂行的匹配式有两种写法——非预设行必须自带 `match`（写族／进程装包具名行，
            // 否则永远命不中任何东西）；预设行默认按事实命中表匹配（`match` 只是页面占位 note），
            // 但显式写了 `match` 的预设行按自己的匹配式走（本版的 `workspace`）。
            const builtinMatch = row.preset === '' || row.match !== undefined
                ? String(row.match ?? '') : row.note;
            // `workspace` 是「当前工作区」这个范围代词：读表时展开成本次会话的绝对路径，
            // 于是「填一个目录就管整片」这同一条语义对它也成立。展不开（调用方没给 roots，
            // 如 floorActions 只读档位）就留原样＝永不命中，不会误放。
            const builtinResolved = row.match !== undefined
                ? resolveRange(builtinMatch, roots) : builtinMatch;
            const builtin = {
                id: `builtin-${row.preset || row.label}`, plane, preset: row.preset, label: row.label,
                action: row.action, enabled: true,
                // 预设行的匹配由事实命中表给出，`match` 只是占位（note）；**非预设**的出厂行
                // （写族具名行／进程装包具名行）必须用行自己的匹配式，否则它永远命不中任何东西。
                match: builtinMatch,
                matchResolved: builtinResolved,
                deleteSelf: row.deleteSelf,
                // 命令面执行族由事实层贴标签（`segment.execFamily`），这里只按标签具名。
                execFamily: row.execFamily,
                execDynamic: row.execDynamic,
                // 命令面的命令行（与 `match` 同字）与兜底身份——判定按命令名匹配、
                // 兜底只对 shell 段生效；`note` 供设置页在命令行下方显示一句说明。
                command: row.command,
                fallback: row.fallback === true,
                note: row.note,
                // `re:` 前缀在这条路上也要编译成 regex：裸出厂行不经过 `toRule`，
                // 不编译就会把 `re:^(?:systemctl…)` 当成一个词去和程序名比。
                regex: row.preset === '' && builtinMatch.startsWith('re:') ? compile(builtinMatch.slice(3)) : undefined,
                origin: 'builtin',
            };
            if (plane === 'file')
                // 每面只认自己那格。以前这里是 `row.ops?.[op] ?? row.action`——没有 `ops` 的行
                // 拿整行档折成三格同档，于是同一张表并存两种写法：一种逐格写，一种一个值顶三面。
                // 两种写法就要两套读法（`ops` 还是 `action`？空格算不管还是算同档？），
                // 现在收起：文件面每行必须逐格写，漏写留空＝这一面本行不管，由清单的形状检查红。
                for (const op of FILE_OPS) builtin[op] = row.ops?.[op];
            return builtin;
        });
    return [...visible, ...builtins];
}

/** * 事实族的**下界档位**：这六族＋提权／破坏／外传的 preset 不再各自占一行表行
 * （它们按命令名折进了命令清单），但事实层仍按这些 preset 记账、算目的地闸。给它们原来
 * 的出厂档位，行为才与改前逐格同：远端执行 ask；上行／下载／只读查询 ai；提权／破坏 ask；
 * 外传 ai（公网／判不出由目的地闸升 ask）。**不可配**——要改档就改那几条命令自己的行。
 */
const INTERNAL_FACT_ACTIONS = new Map([
    ['remote-execute', 'ask'],
    ['remote-upload', 'ai'],
    ['remote-download', 'ai'],
    ['remote-read', 'ai'],
    ...ELEVATED_ROWS.map(row => [row.preset, 'ask']),
    ...DESTROY_ROWS.map(row => [row.preset, 'ask']),
    ...EXFIL_ROWS.map(row => [row.preset, 'ai']),
    // 脚本正文里发包：与其余外传族同一档——出厂交模型，目的地是公网／判不出时由
    // 目的地闸升人工；只送自己的机器不弹框。
    ['exfil:script-upload', 'ai'],
]);

/** 预设行的当前档位：`grant.js` 用它决定「这条理由还拉不拉高」。 */
export function floorActions(config) {
    const out = new Map();
    // 11 条结果行不再是表行——它们的档位由内部下界给，只影响判定、不进表、不可配。
    // 纯读／读类举不出证／命令看不懂＝交 AI（与今天同档）；解释不了的删除参数＝人工。
    for (const [preset, action] of INTERNAL_FACT_ACTIONS)
        out.set(preset, action);
    for (const [preset, action] of INTERNAL_RESULT_ACTIONS)
        out.set(preset, action);
    // 按平面各建一次「preset → 生效行」，不再对每一行重扫整张表（行数从 49 涨到 90+）。
    for (const plane of RULE_PLANES) {
        const merged = new Map(effectiveRows(config, plane)
            .filter(item => item.preset !== '')
            .map(item => [item.preset, item]));
        for (const row of FLOOR_ROWS) {
            if (row.plane !== plane || row.preset === '')
                continue;
            const hit = merged.get(row.preset);
            if (hit === undefined || hit.enabled === false) {
                out.set(row.preset, 'off');
                continue;
            }
            // 文件面的预设行按操作给档位。空列＝这一行对该操作不表态（「读类不拉高」
            // 就靠它），不再一律回落成「人工」——回落会把行上的 `不表态` 又变成框。
            out.set(row.preset, row.plane === 'file'
                ? { read: hit.read ?? row.ops?.read ?? 'ask', write: hit.write ?? row.ops?.write ?? 'ask', delete: hit.delete ?? row.ops?.delete ?? 'ask' }
                : hit.action);
        }
    }
    return out;
}

// Which segment op classes a rule op covers. `exec`/`other` count as a write:
// an unclassified state change must not slip through a "read" row.
const OP_CLASSES = {
    read: new Set(['read']),
    write: new Set(['write', 'rename', 'exec', 'privilege', 'history-rewrite', 'other']),
    delete: new Set(['delete', 'destroy']),
};

// 取最严的那一档：拒绝 > 人工 > 交 AI > 直接放行。
// 「直接放行」压在最后＝任何一行不同意都放不了；它是**真放行**（人自己拍的板）。
// 强弱序只有一处定义：RULE_ACTIONS 的顺序就是强弱顺序（弱 → 强），下面按它算权重。
const STRICTNESS = Object.fromEntries(RULE_ACTIONS.map((action, index) => [action, index + 1]));
const URL_PATTERN = /\bhttps?:\/\/[^\s"'`)]+/gi;

// 词表：旧的 `allow`（本层不拦、继续交 AI）折进 `ai`，`ask` 现在读作「人工」。
// 「放行」这两个字从 allow 挪到 release：表里「允许」就是直接放行，不调模型。
export const ACTION_WORDS = {
    release: ['release', 'permit', '允许', '直接放行', '放行'],
    ai: ['ai', 'allow', '模型', '交ai', '评审'],
    // `redact` 是旧配置里的第四档，已删：命中就遮不是选项，折回「人工」。
    ask: ['ask', 'human', 'confirm', 'redact', '人工', '询问', '确认'],
    deny: ['deny', 'block', '拒绝', '拦截', '禁止'],
};

const OP_WORDS = {
    read: ['read', 'r', '读取', '读'],
    write: ['write', 'w', '写入', '写'],
    delete: ['delete', 'del', 'd', '删除', '删'],
    all: ['all', '*', '全部'],
};

export const OP_LABEL = { read: '读取', write: '写入', delete: '删除' };

function word(value, table) {
    const text = String(value ?? '').trim().toLowerCase();
    for (const [canonical, words] of Object.entries(table))
        if (words.includes(text))
            return canonical;
    return undefined;
}

/** `deny rm -rf` / `ask curl` / `allow ~/.dsh/skills/`; `re:` marks a raw regex. */
function legacyRow(raw) {
    const text = String(raw ?? '').trim();
    if (text === '' || text.startsWith('#'))
        return undefined;
    const match = /^([A-Za-z\u4e00-\u9fff]+)\s+(.+)$/.exec(text);
    if (match === null)
        return undefined;
    const action = word(match[1], ACTION_WORDS);
    if (action === undefined)
        return undefined;
    return { action, match: match[2].trim() };
}

export const FILE_OPS = ['read', 'write', 'delete'];

/** * 无 `id` 的行：内容派生的确定性 id（判据 1／2）。
 *
 * 旧形 `rule-${plane}-${rowSeq += 1}` 用模块级自增：同内容两次解析拿到不同号，于是
 * `configVersionOf`（哈希的是解析产物，含 id）算出两个版本——告知每次启动都响、规则缓存
 * 每次重编译、台账里「哪个配置版本批准的」事后不可比。
 *
 * 新形把「这一行是什么」写进 id：内容（plane／pattern／preset／label）取 10 位 sha256，
 * 再带**同内容行在表内的第几次出现**（occurrence，由 `parseRules` 按表内顺序数，与解析
 * 次数无关）。于是：同内容 ⇒ 同 id ⇒ 同版本；两条内容完全相同的行仍各自有身份，
 * 判定链不把重复行合并；删行／改档 ⇒ 表内容变 ⇒ 版本变；重排 ⇒ 数组顺序变 ⇒ 版本变。
 * 插一行不会让后面所有行的 id 一起抖（内容没变、出现序号也没变）。
 */
export function derivedRowId(plane, pattern, preset, label, occurrence = 1) {
    const digest = createHash('sha256')
        .update(JSON.stringify([plane, pattern, preset, label]))
        .digest('hex')
        .slice(0, 10);
    return `rule-${plane}-${occurrence}-${digest}`;
}

/** 范围变量表：`~`／`home`／`workspace` 只有这一处定义，判定时取当前会话的值。 */
const RANGE_VARS = new Map([
    ['workspace', roots => roots?.workspace],
    ['home', roots => roots?.home],
    ['~', roots => roots?.home],
]);

function resolveRange(pattern, roots) {
    const text = String(pattern ?? '');
    const key = text.trim().toLowerCase();
    if (RANGE_VARS.has(key))
        return String(RANGE_VARS.get(key)(roots) ?? '');
    // 没有 roots 的只读调用（floorActions）保持原样：不是变量就不归一。
    if (roots === undefined)
        return text;
    return normalizePath(text, roots.workspace, roots.home);
}

/** * One stored row.
 *
 * A file row carries an action **per operation** (`read`/`write`/`delete`, empty
 * = 不表态), which is what the operator actually decides: this tree may be read
 * but never deleted. The older `{action, ops}` shape and `deny <pattern>` strings
 * both fold into it. Every other plane has one action per row.
 */
export function toRule(raw, plane, roots, occurrence = 1) {
    const source = typeof raw === 'string' ? legacyRow(raw) : raw;
    const preset = String(source?.preset ?? '');
    const storedPattern = String(source?.match ?? source?.pattern ?? '').trim();
    // 敏感面的条件值落盘是密文：在这里就地解开，页面与匹配拿到的仍是明文。
    // 解不开＝这一行标停用并写明原因（不丢行、不猜、也绝不把密文当模式去匹配）。
    let pattern = storedPattern;
    let sealedError = '';
    if (isSealed(storedPattern)) {
        try {
            pattern = openText(storedPattern);
        }
        catch {
            sealedError = '条件打不开（钥匙或文件损坏）';
            pattern = '';
        }
    }
    // 文件行的匹配式与目标的归一化必须走同一把尺：`~/.ssh/**`、相对路径只有先展开成
    // 绝对路径才可能命中绝对目标，否则页面让人写、后端永远对不上（F13）。
    // `workspace` 是范围代词（当前工作区），配置里存的是词本身，展开时才落到本次的绝对路径；
    // 当普通相对路径展开会变成 `<ws>/workspace`，那条行就永远命不中——页面写得出、后端对不上。
    const matchResolved = plane === 'file' && pattern !== '' && roots !== undefined && !pattern.startsWith('re:')
        ? resolveRange(pattern, roots)
        : pattern;
    if (sealedError !== '') {
        const id = String(source?.id ?? derivedRowId(plane, storedPattern, preset, String(source?.label ?? ''), occurrence));
        const row = {
            id, plane, match: '', matchResolved: '', regex: undefined, preset,
            label: String(source?.label ?? ''), enabled: false, invalid: sealedError,
            callRegex: false, action: 'ask',
        };
        if (plane === 'file')
            for (const op of FILE_OPS) row[op] = '';
        return row;
    }
    // 预设行的覆盖只带档位与开关：它的匹配由 `grant.js` 的事实判断给出，
    // 所以它**没有匹配式**，也绝不被当匹配式用（否则那串说明文字会变成一条模式）。
    if (pattern === '' && preset === '')
        return undefined;
    if (preset !== '' && pattern === '') {
        const base = word(source?.action, ACTION_WORDS) ?? FLOOR_BY_PRESET.get(preset)?.action ?? 'ask';
        const row = {
            id: String(source?.id ?? `builtin-${preset}`),
            plane, preset, label: String(source?.label ?? ''),
            action: base, match: '', matchResolved: '', regex: undefined,
            enabled: source?.enabled !== false,
            removed: source?.removed === true,
        };
        // 文件面的预设行和用户行一样按读／写／删分别表态；老配置只有单档时三列同折。
        // 默认值来自行自己的 `ops`（读类不再一律拉高），没有 ops 才折到单档。
        // B12：**显式空列是用户表过的态（A13），不许被 defaults 悄悄填回**——
        // 键存在（哪怕值是空串）就以行上为准，键不在才落默认档；否则一次空列往返
        // 就把用户的「不表态」偷换成默认档位（状态丢失＝四态保形被打破）。
        if (plane === 'file') {
            const defaults = FLOOR_BY_PRESET.get(preset)?.ops;
            for (const op of FILE_OPS)
                row[op] = Object.hasOwn(source, op)
                    ? (word(source?.[op], ACTION_WORDS) ?? '')
                    : (defaults?.[op] ?? base);
        }
        return row;
    }
    const id = String(source?.id ?? derivedRowId(plane, pattern, preset, String(source?.label ?? ''), occurrence));
    // 命令面的正则**默认逐段匹配**（A04）：拿整条 command 给每一段作匹配，排在前面的
    // `re:^echo ok` 会替后面另一个程序段作主。要按整次调用匹配就显式写 `call-re:`。
    const wholeCall = pattern.startsWith('call-re:');
    const isRegex = wholeCall || pattern.startsWith('re:');
    const regex = isRegex ? compile(pattern.slice(wholeCall ? 8 : 3)) : undefined;
    // 读不出来的行**不许消失**：一条打错的拒绝行如果被静默丢掉，等于悄悄放开了它拦的东西。
    // 留着、标上原因、按停用处理——页面上看得见这一行没生效，判定链不替人猜。
    const badAction = plane === 'file'
        ? FILE_OPS.map(op => String(source?.[op] ?? '').trim())
            .find(value => value !== '' && word(value, ACTION_WORDS) === undefined)
        : (word(source?.action, ACTION_WORDS) === undefined ? String(source?.action ?? '').trim() : undefined);
    const invalid = isRegex && regex === undefined ? '正则编译不出来'
        : badAction !== undefined && badAction !== '' ? '档位认不出来' : '';
    if (invalid !== '') {
        const row = {
            id, plane, match: pattern, matchResolved, regex: undefined, preset,
            label: String(source?.label ?? ''), enabled: false, invalid, callRegex: wholeCall,
            removed: source?.removed === true, action: 'ask',
        };
        if (plane === 'file')
            for (const op of FILE_OPS) row[op] = '';
        return row;
    }
    if (plane !== 'file') {
        // `preset` 非空＝这一行是预设项的用户副本（换档位／关掉它）；
        // `enabled:false` 只是这一行不表态——不删行也能关。
        return {
            id, plane, action: word(source?.action, ACTION_WORDS), match: pattern, matchResolved, regex,
            preset, callRegex: wholeCall,
            label: String(source?.label ?? ''),
            enabled: source?.enabled !== false,
            removed: source?.removed === true,
        };
    }
    const legacyAction = word(source?.action, ACTION_WORDS);
    const legacyOps = Array.isArray(source?.ops) && source.ops.length > 0
        ? [...new Set(source.ops.map(item => word(item, OP_WORDS)).filter(Boolean))]
        : null;
    const row = {
        id, plane, match: pattern, matchResolved, regex, callRegex: wholeCall,
        preset, label: String(source?.label ?? ''), enabled: source?.enabled !== false,
        removed: source?.removed === true,
    };
    for (const op of FILE_OPS) {
        const explicit = word(source?.[op], ACTION_WORDS) ?? '';
        const folded = legacyAction !== undefined
            && (legacyOps === null || legacyOps.includes('all') || legacyOps.includes(op))
            ? legacyAction
            : '';
        row[op] = explicit !== '' ? explicit : folded;
    }
    // 四态保形（A13）：缺省／显式空列／停用／删除。显式空列（`read: ''`）也是用户
    // 表过态的一行——它「不表态」，但不能在再解析时被整行丢掉（丢行＝状态丢失，
    // 往返就不可能逐字节一致）；删除行（removed）同理要留住。
    const explicitColumn = FILE_OPS.some(op => source?.[op] !== undefined);
    if (FILE_OPS.some(op => row[op] !== '') || explicitColumn || preset !== '' || row.removed === true)
        return row;
    return undefined;
}

export function parseRules(list, plane, roots) {
    const out = [];
    // 判据 2②：occurrence = 同内容行在**表内**的第几次出现，与解析次数无关。
    // 所以两次解析同一份配置得到同一串 id；两条内容完全相同的行仍各有身份（1／2）；
    // 表内顺序本身也进版本（configVersionOf 哈希有序数组）⇒ 用户重排照旧反映到版本。
    const seen = new Map();
    for (const raw of Array.isArray(list) ? list : []) {
        const source = typeof raw === 'string' ? legacyRow(raw) : raw;
        const key = JSON.stringify([
            plane,
            String(source?.match ?? source?.pattern ?? '').trim(),
            String(source?.preset ?? ''),
            String(source?.label ?? ''),
        ]);
        const occurrence = (seen.get(key) ?? 0) + 1;
        seen.set(key, occurrence);
        const rule = toRule(raw, plane, roots, occurrence);
        if (rule !== undefined)
            out.push(rule);
    }
    return out;
}

/** * B12 判据 2：保存侧的逐行闸（与 `toRule` 的运行期兜底是**两把尺**，不许合并）。
 * `toRule` 遇到读不出来的行只能「留行标停用」——那是给历史配置的兜底；保存／写配置
 * 那一步必须**拒绝**并把行号与原因递回去，不许坏形状再悄悄进表退化成 `enabled:false`。
 * 三种在保存就该被拒的形状：坏正则、档位不在册、缺 `match` 的显式空列（既无预设归属
 * 又无条件，`toRule` 会整行丢掉＝用户写的行凭空消失）。
 * 旧形整串行（`legacyRow` 管）与 null 槽位放行——它们不是本次要拦的形状。
 */
export function validateRuleRows(list, plane) {
    const errors = [];
    const rows = Array.isArray(list) ? list : [];
    for (let index = 0; index < rows.length; index += 1) {
        const raw = rows[index];
        if (raw === null || raw === undefined || typeof raw === 'string')
            continue;
        if (typeof raw !== 'object') {
            errors.push({ index, plane, reason: `行既不是对象也不是旧形字符串：${String(raw).slice(0, 40)}` });
            continue;
        }
        const preset = String(raw.preset ?? '').trim();
        const pattern = String(raw.match ?? raw.pattern ?? '').trim();
        // 档位不在册：file 面查三列，其余面查 action。空串不算（＝显式不表态）。
        if (plane === 'file') {
            for (const op of FILE_OPS) {
                const value = String(raw?.[op] ?? '').trim();
                if (value !== '' && word(value, ACTION_WORDS) === undefined)
                    errors.push({ index, plane, reason: `档位认不出来：${op}='${value}'（在册档位：release／ai／ask／deny）` });
            }
        }
        else {
            const value = String(raw?.action ?? '').trim();
            if (value !== '' && word(value, ACTION_WORDS) === undefined)
                errors.push({ index, plane, reason: `档位认不出来：action='${value}'（在册档位：release／ai／ask／deny）` });
        }
        // 坏正则：`re:`／`call-re:` 前缀的行，模式必须编译得出来。
        const wholeCall = pattern.startsWith('call-re:');
        const isRegex = wholeCall || pattern.startsWith('re:');
        if (isRegex && compile(pattern.slice(wholeCall ? 8 : 3)) === undefined)
            errors.push({ index, plane, reason: plane === 'sensitive'
                ? '正则编译不出来（敏感条件不回显）'
                : `正则编译不出来：${pattern.slice(0, 60)}` });
        // 缺 match 的显式空列：没有预设归属、没有匹配条件，行上却带了任何键——
        // 这行会被 `toRule` 整行丢掉，保存就得拦下来让人补条件或挂预设。
        if (preset === '' && pattern === '') {
            const hasKeys = Object.keys(raw).length > 0;
            if (hasKeys)
                errors.push({ index, plane, reason: '缺 match：这行没有预设归属也没有匹配条件，保存会被整行丢弃；补 match 或挂到 preset 上再存' });
        }
    }
    return { ok: errors.length === 0, errors };
}

/** * 敏感面的条件值：盘上是密文、内存里是明文。解不开的行原样留着（`toRule` 会标停用），
 * 不在这里抹掉——抹掉等于把「打不开」伪装成「没有这条规则」。
 * 旧编号的密文解得出，但顺手记一笔，让迁移路径用当前钥匙重新封（旧钥匙永远留着）。
 */
export function openSensitiveRows(rows) {
    let needsSeal = false;
    let sealedCount = 0;
    const failed = [];
    const opened = (Array.isArray(rows) ? rows : []).map((row, index) => {
        if (row === null || typeof row !== 'object')
            return row;
        const match = String(row.match ?? row.pattern ?? '');
        if (isSealed(match)) {
            sealedCount += 1;
            try {
                const result = openSealed(match);
                if (result.keyId !== CURRENT_KEY_ID)
                    needsSeal = true;
                return { ...row, match: result.text };
            }
            catch {
                failed.push(index);
                return row;
            }
        }
        // 预设行盖的是内置形状（`re:...`），不封；只有用户自己写的条件值才封。
        if (String(row.preset ?? '') === '' && match.trim() !== '')
            needsSeal = true;
        return row;
    });
    return { rows: opened, needsSeal, sealedCount, failed };
}

/** 只封用户行（`preset` 为空）；预设行、空条件、已经是密文的原样留下。 */
export function sealSensitiveRows(rows) {
    return (Array.isArray(rows) ? rows : []).map((row) => {
        if (row === null || typeof row !== 'object')
            return row;
        const match = String(row.match ?? '');
        if (match === '' || isSealed(match) || String(row.preset ?? '') !== '')
            return row;
        return { ...row, match: sealText(match) };
    });
}

function compile(source) {
    try {
        return new RegExp(source, 'i');
    }
    catch {
        return undefined;
    }
}

function globToRegex(glob) {
    let out = '';
    for (let index = 0; index < glob.length; index += 1) {
        const char = glob[index];
        if (char === '*') {
            if (glob[index + 1] === '*') {
                out += '.*';
                index += 1;
            }
            else
                out += '[^/]*';
        }
        else if (char === '?')
            out += '.';
        else
            out += char.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp(`^${out}$`, 'i');
}

const isGlob = pattern => pattern.includes('*') || pattern.includes('?');
const slashes = text => String(text ?? '').replaceAll('\\', '/');

/** Text matcher shared by the tool, network and sensitive planes. */
function matchText(rule, value) {
    const text = slashes(value);
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(text);
    const pattern = slashes(rule.match);
    // 空模式不是「匹配一切」：只有档位、没有条件的行（预设覆盖行）不该命中任何文本，
    // 否则清空一次条件输入就会把整段结果都算成敏感。
    if (pattern === '')
        return false;
    if (pattern === '*')
        return true;
    if (isGlob(pattern))
        return globToRegex(pattern).test(text);
    return text.toLowerCase() === pattern.toLowerCase()
        || text.toLowerCase().includes(pattern.toLowerCase());
}

/** * 敏感平面的**唯一一张表**：预设形状＋用户自己的行。
 * 预设形状不是硬编码的第二套检测——它铺成行，用户改的就是同一行（同 `preset` 的行
 * 覆盖预设行），关掉它就是把那一行 `enabled:false`。`sensitiveDetect` 是卡头总闸。
 */
export function sensitiveRows(config) {
    if (config?.sensitiveDetect === false)
        return [];
    const stored = parseRules(config?.sensitiveRules, 'sensitive');
    const overrides = new Map(stored.filter(row => row.preset !== '').map(row => [row.preset, row]));
    const visible = stored
        .filter(row => !(row.preset !== '' && row.removed === true))
        .map((row) => {
            // 熵行的用户副本解析后同样没有匹配式：补上判定开关与默认标签，
            // 否则用户改一次档位，这行就成了「空匹配式」的死行（「同一张表」要防的正是这个）。
            if (row.preset !== ENTROPY_PRESET || row.match !== '' || row.entropy === true)
                return row;
            return { ...row, label: row.label || ENTROPY_LABEL, entropy: true };
        });
    const builtins = DETECTOR_SHAPES.filter(shape => !overrides.has(shape.id)).map((shape) => {
        return {
            id: `builtin-${shape.id}`, plane: 'sensitive', preset: shape.id, label: shape.label,
            action: 'ask', enabled: true, match: `re:${shape.source}`, regex: compile(shape.source),
        };
    });
    // 最后那一行不是第 10 条形状：`DETECTOR_SHAPES` 是 9 条，熵行只在这张生效表里（生效表共 10 行）。
    if (!overrides.has(ENTROPY_PRESET)) {
        builtins.push({
            id: `builtin-${ENTROPY_PRESET}`, plane: 'sensitive', preset: ENTROPY_PRESET, label: ENTROPY_LABEL,
            action: 'release', enabled: true, match: '', matchResolved: '', regex: undefined, entropy: true,
        });
    }
    return [...visible, ...builtins];
}

/** * 一行在一段文本里命中的所有区间。
 * 定位不到就不遮：通配行（`pass*`）与 `*` 表达的是「这段文本算敏感」，不是「哪一段」，
 * 拿整条结果去铸 token 等于毁掉整条输出——所以这类行只参与 拒绝/询问/允许。
 */
function matchRanges(rule, value) {
    const text = String(value ?? '');
    if (text === '')
        return [];
    // 熵行没有匹配式：区间由同一套 `highEntropyRanges` 给出（台账侧也调它）。
    if (rule.entropy === true)
        return highEntropyRanges(text).map(range => [range.from, range.to]);
    if (rule.regex !== undefined) {
        const flags = rule.regex.flags.includes('g') ? rule.regex.flags : `${rule.regex.flags}g`;
        const re = new RegExp(rule.regex.source, flags);
        const out = [];
        let found;
        while ((found = re.exec(text)) !== null) {
            if (found[0] === '') {
                re.lastIndex += 1;
                continue;
            }
            out.push([found.index, found.index + found[0].length]);
        }
        return out;
    }
    const pattern = String(rule.match ?? '');
    if (pattern === '' || pattern === '*' || isGlob(pattern))
        return [];
    const hay = text.toLowerCase();
    const needle = pattern.toLowerCase();
    const out = [];
    for (let index = hay.indexOf(needle); index !== -1; index = hay.indexOf(needle, index + needle.length))
        out.push([index, index + needle.length]);
    return out;
}

/** * 扫一段文本（结果侧用它决定遮哪些、出参侧用它决定拦不拦）。
 * 动作取最严：任一 `deny` 命中就整段不给模型；否则按 ask／ai／release 排。
 * **所有档位都先遮**——遮是这一层自己的事，不是选项：命中就换成占位符，
 * 档位只决定遮完之后还要不要再问／再判／整段拦掉。
 * `ranges` 是所有档位的命中区间（`{from,to,label,detector}`，重叠只留先命中的
 * 那一行，且已按起点降序——替换用它做）。
 *
 * `known` 是值身份这一路：调用方从秘密表拿「已登记明文在这段文本里的区间」传进来。
 * 它不认键名、不认长度、不认熵——只认「这段值我们铸过 token」。只遮不问（release）：
 * 模型本来就有那枚 token，换回占位符继续对话，不该再弹一次框。
 */
export const KNOWN_SECRET_PRESET = 'known-secret';
export const KNOWN_SECRET_LABEL = '已登记明文';

export function scanSensitive(text, rows, known = []) {
    const hits = [];
    for (const row of rows) {
        if (row.enabled === false)
            continue;
        const ranges = matchRanges(row, text);
        if (ranges.length > 0 || matchText(row, text))
            hits.push({ row, ranges });
    }
    if (Array.isArray(known) && known.length > 0) {
        hits.push({
            row: { id: `builtin-${KNOWN_SECRET_PRESET}`, action: 'release', preset: KNOWN_SECRET_PRESET, label: KNOWN_SECRET_LABEL },
            // 整段原文带自己的 token；单值（换键名后剩下的那截）没有 token，
            // 由出口按「值」再铸一枚——拿整段的 token 去遮单值，回写会把键名一起写回去。
            ranges: known,
        });
    }
    if (hits.length === 0)
        return { action: '', hits: [], ranges: [], unlocated: [] };
    let action = 'release';
    for (const hit of hits)
        if (STRICTNESS[hit.row.action] > STRICTNESS[action])
            action = hit.row.action;
    const spans = [];
    // 命中就遮：任何一档（含「允许」）都先遮；只有拒绝那一档由处置侧整段拦掉，遮不遮已无意义。
    // 重叠必须**取并集**（合成一整段），不是"后来者丢"：先命中的窄区间若把后面更宽的区间吃掉，
    // 留下的就是原样可见的尾巴（F07——自定义 `re:password` 在前、默认整段赋值在后时尤其明显）。
    const intervals = [];
    for (const hit of hits) {
        if (hit.row.enabled === false)
            continue;
        const detector = hit.row.preset || hit.row.id;
        const label = hit.row.label || hit.row.preset || hit.row.match;
        for (const item of hit.ranges) {
            const from = Array.isArray(item) ? item[0] : item.from;
            const to = Array.isArray(item) ? item[1] : item.to;
            const token = Array.isArray(item) ? undefined : item.token;
            intervals.push({ from, to, detector, label, token });
        }
    }
    intervals.sort((a, b) => a.from - b.from || b.to - a.to);
    for (const item of intervals) {
        const last = spans.at(-1);
        if (last !== undefined && item.from <= last.to) {
            // 有重叠或首尾相接 ⇒ 并进同一段；并集只会让遮住的范围变大，不会变小。
            last.to = Math.max(last.to, item.to);
            if (!last.detectors.includes(item.detector))
                last.detectors.push(item.detector);
            if (!last.labels.includes(item.label))
                last.labels.push(item.label);
            // 合并进来的区间来源不同／token 不同：这一段不能直接复用某一枚 token，
            // 清掉让出口按整段重新铸（否则回写出来的内容会比原文少一截）。
            if (last.token !== item.token)
                last.token = undefined;
            continue;
        }
        spans.push({
            from: item.from, to: item.to, detectors: [item.detector], labels: [item.label],
            token: item.token,
        });
    }
    const merged = spans.map(range => ({
        from: range.from,
        to: range.to,
        detector: range.detectors.join('＋'),
        label: range.labels.join('＋'),
        ...(range.token !== undefined ? { token: range.token } : {}),
    }));
    merged.sort((a, b) => b.from - a.from);
    // 「命中了但定位不到那一段」（通配／整行形状的行）要显式说出来：出口那一侧照此 fail-closed，
    // 不能因为拿不到区间就把原文当"没命中"发出去（F07）。
    const unlocated = hits
        .filter(hit => hit.row.action !== 'deny' && hit.ranges.length === 0)
        .map(hit => hit.row.preset || hit.row.label || hit.row.match);
    return {
        action, hits, ranges: merged, unlocated,
        rules: [...new Set(hits.map(hit => hit.row.id))],
    };
}

function programName(text) {
    const base = slashes(String(text ?? '')).split('/').filter(Boolean).pop() ?? '';
    return nativeNameOf(base.toLowerCase().replace(/\.exe$/, ''));
}

/** `git push` matches `git push origin main`, not `git pull`. */
export function matchCommand(rule, segment) {
    const text = slashes(segment?.program ?? '');
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test([segment.program, ...(segment.words ?? [])].join(' '));
    // 整行星号＝所有命令（README 承诺过这一种写法；漏了它，用户写的 `deny *` 是条空行）。
    if (rule.match.trim() === '*')
        return true;
    const tokens = rule.match.split(/\s+/).filter(Boolean);
    // `mkfs` 是一族程序（mkfs.ext4／mkfs.xfs／mkfs.vfat…），表里只登记族名：
    // 逐字比较会把 `mkfs.ext4 /dev/sdb` 判成表外命令、落兜底交模型。
    const familyOf = name => (/^mkfs\.[\w-]+$/.test(name) ? 'mkfs' : name);
    if (familyOf(programName(tokens[0])) !== familyOf(programName(segment.program)))
        return false;
    const words = (segment.words ?? []).map(String);
    for (let index = 1; index < tokens.length; index += 1) {
        const want = tokens[index];
        const got = words[index - 1];
        if (got === undefined)
            return false;
        if (want === '*')
            continue;
        if (want !== got && !(isGlob(want) && globToRegex(want).test(got)))
            return false;
    }
    return true;
}

/** * 这一段是不是一条真命令。
 * shell 段带逐词表（`wordsBare`，facts 按 argv 一列一列给）；非 shell 工具的合成段没有，
 * 它不是「命令」——兜底行不许替它说话，否则 write／read／mcp 这类工具调用会被一律拖成交 AI。
 */
function isCommandSegment(segment) {
    return Array.isArray(segment?.wordsBare) || segment?.shell === true;
}

/** * 事实下界：算法算出的结果只许把行档位**加严**，不许放宽。
 * 只看原来就住在命令面的那几族事实（远端四方向／提权／破坏／外传）——它们今天不再各自
 * 占一行，但事实层仍按这些 preset 记账、算目的地闸；这一格就是把它们的结果并回命令行的
 * 档位上（公网上行、`--force`、`DROP TABLE`、`system prune`…）。文件面的理由不在这里并，
 * 它由文件面自己的行序说话（工作区行在前）。
 */
function factActionOf(scope, baseAction) {
    if (!(scope instanceof Map))
        return baseAction;
    let action = baseAction;
    for (const [preset, entry] of scope) {
        if (!INTERNAL_FACT_ACTIONS.has(preset))
            continue;
        const value = entry?.write ?? entry?.all;
        if (typeof value === 'string' && value !== '' && STRICTNESS[value] > STRICTNESS[action])
            action = value;
    }
    return action;
}

/** * 结果行整类拿掉之后，原来那三条 `ask` 改由事实层的内部下界直接保：
 * ① 来源不可举证的内联代码／管道进解释器；② 框架解释不了的删除参数。
 * 它们不进表、不可配，只影响判定（与改前逐格同 `ask`）。
 */
function internalCommandFloor(segment, scope) {
    if (!isCommandSegment(segment))
        return undefined;
    const family = String(segment?.execFamily ?? '');
    if ((family === 'inline' || family === 'piped') && segment?.execDynamic === true) {
        return {
            plane: 'command', layer: 'fact', action: 'ask',
            text: `事实下界：${family === 'inline' ? '内联代码' : '管道进解释器'}（来源不可举证）＝问人`,
        };
    }
    if (scope instanceof Map && scope.get('unrecognized-delete-flag') !== undefined) {
        return {
            plane: 'command', layer: 'fact', action: 'ask',
            text: '事实下界：框架解释不了的删除参数（真实操作数集合看不见）＝问人',
        };
    }
    return undefined;
}

/** Which file operation a segment class falls under (undefined = none). */
export function opOf(opClass) {
    for (const op of FILE_OPS)
        if (OP_CLASSES[op].has(String(opClass)))
            return op;
    return undefined;
}

/** The action this row takes on one operation; `''` = 这一行对它不表态。 */
export function actionFor(rule, opClass) {
    const op = opOf(opClass);
    if (op === undefined)
        return '';
    return rule?.[op] !== undefined && rule[op] !== '' ? rule[op] : '';
}

function pathMatches(rule, path) {
    const target = slashes(path);
    if (target === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(target);
    // `~`／相对路径在读取时已经按同一把尺展开（toRule 的 matchResolved）；
    // 拿原模式对绝对目标是永远对不上的——那正是「UI 支持写、后端不认」的裂缝。
    const pattern = slashes(rule.matchResolved ?? rule.match);
    // 空模式不是「匹配一切」：预设覆盖行只有档位、没有匹配式，不能当通配规则用
    // （POSIX 上任何绝对路径都以 / 开头，旧写法会把整张表变成 match-all）。
    if (pattern === '')
        return false;
    if (pattern === '*')
        return true;
    if (isGlob(pattern))
        return globToRegex(pattern).test(target);
    const trimmed = pattern.replace(/\/+$/, '');
    return target.toLowerCase() === trimmed.toLowerCase()
        || target.toLowerCase().startsWith(`${trimmed.toLowerCase()}/`);
}

function samePath(a, b) {
    const left = slashes(a).replace(/\/+$/, '').toLowerCase();
    const right = slashes(b).replace(/\/+$/, '').toLowerCase();
    return left !== '' && left === right;
}

/** Path matcher used by the trust floor: does this row excuse `opClass` here? */
export function matchPath(rule, path, opClass) {
    return pathMatches(rule, path) && actionFor(rule, opClass) !== '';
}

function matchHost(rule, value) {
    const text = String(value ?? '').toLowerCase();
    if (text === '')
        return false;
    if (rule.regex !== undefined)
        return rule.regex.test(text);
    const pattern = rule.match.toLowerCase().replace(/^\*\./, '.');
    if (pattern === '*' || pattern === 'http://' || pattern === 'https://')
        return true;
    const bare = text.replace(/^https?:\/\//, '').split('/')[0];
    if (isGlob(rule.match))
        return globToRegex(rule.match).test(bare) || globToRegex(rule.match).test(text);
    return bare === pattern || bare.endsWith(`.${pattern}`);
}

function matchTool(rule, toolName) {
    return matchText(rule, toolName);
}

/** URLs and bare hosts mentioned by the action, for the network plane. */
export function networkTargets(command) {
    const text = typeof command === 'string' ? command : '';
    const urls = text.match(URL_PATTERN) ?? [];
    const hosts = [];
    for (const url of urls) {
        try {
            hosts.push(new URL(url).hostname);
        }
        catch {
            // A malformed URL still matched the plane's text pattern below.
        }
    }
    return [...new Set([...urls, ...hosts])];
}

function firstHit(rules, test) {
    for (const rule of rules)
        if (rule.enabled !== false && test(rule))
            return rule;
    return undefined;
}

function planeHit(plane, rules, test) {
    const rule = firstHit(rules, test);
    return rule === undefined
        ? undefined
        : { plane, action: rule.action, rule: rule.match, text: `${rule.action} ${rule.match}` };
}

/** * Evaluate every plane over one action. `segments` and `targets` come from the
 * fact layer (targets carry `path` and `opClass`); `urls` are optional.
 */
export function evaluatePolicies({ toolName, command, segments, targets, urls, payloads, config, roots, hits = new Map(),
    segmentScopes = [], targetScopes = [] }) {
    // 一张表、一套顺序：预设行与用户行在同一张有序表里走，谁先表态谁算，AI 档不拍板。
    // F03：首条命中在**每个作用项内部**执行——这一段、这个路径、这个主机各自走一遍表，
    // 再把所有作用项取最严合成整次调用。并集会让 `release echo` 替同一条命令里的
    // `node 脚本` 作主，那是「一条规则替整次调用作主」，不是用户写的允许。
    const pick = (scope, preset, op) => {
        const entry = (scope === undefined || scope === null ? hits : scope).get(preset);
        if (entry === undefined)
            return undefined;
        return entry[op] ?? entry.write ?? entry.all;
    };
    const rowsOf = (plane) => {
        const base = effectiveRows(config, plane, roots);
        // 工作区内写／改名的具名结论已落进 FLOOR_ROWS（`workspace-plain-write`），
        // 这里不再临时拼行——出厂行只允许一个出处，否则台账读到一行、设置页读到另一行。
        return base;
    };
    const decisions = [];
    const citedHits = [];
    let aiRow;
    const noteAi = (plane, layer, row, text) => {
        if (aiRow === undefined)
            aiRow = { plane, layer, row, text };
    };
    const nameOf = (row, fallback) => String(row.label || row.preset || fallback(row));
    /** * 走一个作用项的一张表：表内按行序，第一条命中的行就是这个作用项的结论。
     * 表外（不同作用项、不同面之间）取最严：拒绝 > 人工 > 交模型 > 直接放行。
     */
    // 判据 1：**一次有序求值**。`ai` 也是结论（命中即终局路由），不再往下找后面的
    // 放行／人工；旧形「AI 不拍板、继续走」会让「设了 AI」既不被审、也不解除人工（报告 B05）。
    // 表内不再有任何吃序的特判。以前有三处：`deny` 不看行序、命令面按命令名词数重排
    // （`commandRowRank`）、内置凭据目录行在凭据文件名行命中时让位。它们都是在替一张没排好
    // 的出厂表打补丁——出厂表已按「范围从小到大、并列范围敏感在前」重排，窄行天然排在宽行
    // 之前，所以三处一起删掉，判定只看行序。
    const walkOne = (plane, scope, decide) => {
        let first;
        for (const row of rowsOf(plane)) {
            if (row.enabled === false)
                continue;
            const isPreset = row.preset !== '';
            let action;
            if (isPreset)
                action = pick(scope, row.preset, decide.op ?? 'write');
            // 显式带 `match` 的预设行按自己的匹配式走——它的范围是「路径落在工作区内」，
            // 不是事实层贴的标签，光靠 hits 永远命不中。只对 `match` 有值的行开口，现有 111 行
            // 没有一行带 `match`（它们靠 note 占位），所以这条兜底对既有行为零影响。
            if (action === undefined && row.match !== undefined && decide.matches(row))
                action = decide.action ? decide.action(row) : row.action;
            if (action === undefined || action === '')
                continue;
            if (first !== undefined)
                continue;   // 第一条命中的行已经说话，后面的行不再看
            const layer = isPreset ? 'floor' : 'rules';
            const text = decide.text(row, action, isPreset);
            const preset = String(row?.preset ?? '');
            first = {
                plane, layer, action, row, text,
                op: decide.op ?? '',
                id: preset !== '' && decide.op !== undefined ? `${preset}: ${decide.op}: ${action}` : '',
            };
            if (action === 'ai')
                noteAi(plane, layer, row, text);
        }
        return first;
    };
    const stronger = (a, b) => {
        if (b === undefined)
            return a;
        if (a === undefined)
            return b;
        if (STRICTNESS[b.action] > STRICTNESS[a.action])
            return b;
        // 同档时让「工作区外」这条目标面说话：awk 只是命令形状，实际读的是区外文件，
        // 卡面与台账应指「工作区外」。只收窄到区外**读**，其余同档面仍保持先到。
        if (STRICTNESS[b.action] === STRICTNESS[a.action]) {
            const outsideRead = hit => String(hit?.row?.preset ?? '') === 'path-outside-trusted-roots'
                && hit?.op === 'read';
            if (outsideRead(b) && !outsideRead(a))
                return b;
            if (outsideRead(a) && !outsideRead(b))
                return a;
            // 同为非目标面时，用户显式那条更该被看见。
            if (a.layer === 'floor' && b.layer === 'rules')
                return b;
        }
        return a;
    };

    const commandText = (row, action, isPreset) => `${action} ${isPreset ? nameOf(row, r => r.match) : (row.label || row.match)}`;

    const targetList0 = (Array.isArray(targets) ? targets : [])
        .filter(target => target !== undefined && target !== null)
        .map(target => typeof target === 'string' ? { path: target, opClass: 'other' } : target);
    // 本会话绑定的源根其内的读＝任务资源（用户点过名的那个目录），
    // 不再落「读的目标不在任务资源范围内」那条降级（B01）。
    // 区外读不再有任何代码层降级：读成哪一档由文件面那几行预设说话
    // （「工作区外」读格＝ai）。这里刻意不保留范围判定，免得再长出一层改档。

    // 解析不出段但有命令原文 ⇒ 合成一个 shell 段（`wordsBare: []` 让它算「命令」，
    // 末行兜底照旧替它说话）；命令原文为空＝不是命令（非 shell 工具的调用），兜底不参与。
    const segmentList = Array.isArray(segments) && segments.length > 0
        ? segments
        : [{
            program: String(command ?? '').split(/\s+/)[0] ?? '',
            words: String(command ?? '').split(/\s+/).slice(1),
            ...(String(command ?? '').trim() === '' ? {} : { wordsBare: [] }),
        }];
    // 命令面正则逐段匹配（A04）：`re:` 只看**这一段**的 program＋words；
    // 要替整次调用作主就显式写 `call-re:`。
    const segmentTextOf = segment => [segment?.program ?? '', ...(segment?.words ?? [])].join(' ');
    // 每一段各自走一遍命令面：结论留在这一段上，供「整次调用有没有被逐段说住」判定。
    const segmentConclusions = segmentList.map(() => undefined);
    // 命令面／工具面／网络面有没有替这一段表态（合并目标结论之前记=命令面；
    // 工具与网络合并处补记）。执行段（opClass=exec＝跑一个没被归类的程序）若这些面都无行，
    // 文件面的 release 不许替它背书——见文件末尾的兜底。
    const surfaceStated = segmentList.map(() => false);
    segmentList.forEach((segment, index) => {
        const commandHit = walkOne('command', segmentScopes[index], {
            matches: (row) => {
                // 兜底行（`其他命令`）只对 shell 段说话——非 shell 工具的合成段
                // 不是命令，不能因为「表里没有它」就被一律拖成交 AI。
                if (row.fallback === true)
                    return isCommandSegment(segment);
                // 执行族行按事实层贴的标签说话（`interpreter`／`inline`／`piped`／`process`／`package`），
                // 行上的 `execDynamic: true` 只认「来源不可举证」的那一半。
                if (row.execFamily !== undefined) {
                    if (segment?.execFamily !== row.execFamily)
                        return false;
                    return row.execDynamic === undefined || (segment?.execDynamic === true) === (row.execDynamic === true);
                }
                return row.regex !== undefined
                    ? row.regex.test(row.callRegex === true ? String(command ?? '') : segmentTextOf(segment))
                    : matchCommand(row, segment);
            },
            // 命令行自己的档位是基线；事实层算出的结果只许把它加严（公网上行、提权、
            // 破坏族、发布都在这一格升档）。
            action: row => factActionOf(segmentScopes[index], row.action),
            text: commandText,
        });
        // 命令面命中单独留一份：同档时它可能被「工作区外」代表，但引用它仍应成立。
        segmentConclusions[index] = commandHit;
        if (commandHit !== undefined)
            citedHits.push(commandHit);
        // 结果行拿掉后由事实层直接保住的内部下界（原 ask 三格：动态内联／动态管道／
        // 解释不了的删除参数）。只加严，不占表位、不可配。
        const floor = internalCommandFloor(segment, segmentScopes[index]);
        if (floor !== undefined)
            segmentConclusions[index] = stronger(segmentConclusions[index], floor);
        surfaceStated[index] = segmentConclusions[index] !== undefined;
    });

    const targetList = targetList0;
    // 逐作用项定局（A04）：同一段的两个文件，一个被允许、另一个没有任何行表态时，
    // 后者不能被前者的允许顺带放过。每个目标自己留一份结论，最后看有没有落空的。
    const targetConclusions = targetList.map(() => undefined);
    targetList.forEach((target, index) => {
        if (target.dynamic === true)
            return;
        const op = opOf(target.opClass) ?? 'write';
        // 词法路径与真实路径都要过表（A02）：父目录是链接时，规则要能看见真身那一侧。
        const paths = [target.path ?? target.input, target.realPath]
            .filter(text => typeof text === 'string' && text !== '');
        const hit = walkOne('file', targetScopes[index], {
            op,
            matches: (row) => {
                // 目录行默认管整棵子树（含自身）；声明 `deleteSelf:false` 的行只管里面的东西——
                // 删／搬这个节点本身不由它表态，交给别的行（工作区根就是这么落到根下界的）。
                if (row.deleteSelf === false
                    && (op === 'delete' || String(target.opClass) === 'rename')
                    && paths.some(text => samePath(row.matchResolved, text)))
                    return false;
                return paths.some(text => pathMatches(row, text));
            },
            action: row => actionFor(row, target.opClass),
            text: (row, action, isPreset) => `${OP_LABEL[op] ?? op}·${action} `
                + `${isPreset ? nameOf(row, r => r.match) : (row.label || row.match)}`,
        });
        // 工作区根本体：删／搬／销毁这个目录本身一律问人。这是**单条事实闸**
        // （目标就是这个目录、动作是删／搬／销毁），不是第四步：不收集别的命中行、
        // 也不改判别的目标。`git add .`／`eslint .` 这种「以 . 为操作数」的写／执行不算
        // 删根——它们动的是里面的东西，仍按表判。
        // README 不变量 1（工作区根本身）与「rm -rf <ws> 仍是根级下界」靠它兑现。
        const rootGate = ['delete', 'rename', 'destroy'].includes(String(target.opClass))
            && paths.some(text => samePath(roots?.workspace, text))
            ? {
                plane: 'file', layer: 'fact', action: 'ask', op,
                row: { id: 'workspace-root', label: '工作区根本体', plane: 'file' },
                text: `事实闸：工作区根本体（${OP_LABEL[op] ?? op}）＝问人`,
                id: 'workspace-root',
            }
            : undefined;
        let conclusion = hit;
        if (rootGate !== undefined)
            conclusion = stronger(conclusion, rootGate);
        targetConclusions[index] = conclusion;
        if (conclusion === undefined)
            return;
        citedHits.push(conclusion);
        // 路径上的意见并进产生它的那一段：「读的是凭据」压过「这一段是只读」就是这么生效的。
        // 没有 segmentIndex 的调用方（手搓 targets）沿用全表并集，行为不降级。
        const at = target.segmentIndex;
        if (typeof at === 'number' && at < segmentConclusions.length) {
            // 凭据行是这一条命令里**最具体**的证据（`perl -e '…读 .env…'` 既是内联代码，也确实在读凭据）。
            // 同档或更严时让它说话，台账才会指到凭据；档位不因这条规则改变。
            const preset = String(conclusion.row?.preset ?? '');
            const preferEvidence = preset.startsWith('credential-')
                && STRICTNESS[conclusion.action] >= STRICTNESS[segmentConclusions[at]?.action ?? 'release'];
            segmentConclusions[at] = preferEvidence ? conclusion : stronger(segmentConclusions[at], conclusion);
        }
        else
            decisions.push(conclusion);
    });
    // 工具面讲的是「这是哪个工具」，对整次调用的每一段都成立（非 shell 只有一个合成段）。
    const toolHit = walkOne('tool', undefined, {
        matches: row => matchTool(row, toolName),
        text: commandText,
    });
    if (toolHit !== undefined) {
        citedHits.push(toolHit);
        for (let index = 0; index < segmentConclusions.length; index += 1) {
            segmentConclusions[index] = stronger(segmentConclusions[index], toolHit);
            surfaceStated[index] = true;
        }
    }
    // 一段一个结论，全部进合并表（`ai` 也是结论：它把别段给的「放行」降成「交模型」）。
    for (const conclusion of segmentConclusions)
        if (conclusion !== undefined) {
            decisions.push(conclusion);
            citedHits.push(conclusion);
        }
    const hosts = Array.isArray(urls) && urls.length > 0 ? urls : networkTargets(command);
    // 网络面的兜底行只对**往外送**的目的地说话：上行／远端执行，且目的地是公网或判不出
    // 落在谁的机器上。下载与只读查询不在此列（没有内容离开本机），仍由命令／文件面判。
    const outboundHosts = new Set();
    for (const segment of segmentList) {
        const direction = String(segment?.remoteDirection ?? '');
        const outbound = segment?.scriptUpload === true
            || (Array.isArray(segment?.exfil) && segment.exfil.length > 0)
            || direction === 'upload' || direction === 'remote-exec' || direction === 'remote';
        if (!outbound)
            continue;
        for (const destination of segment?.destinations ?? []) {
            if (destination.kind === 'public' || destination.kind === 'unknown')
                outboundHosts.add(String(destination.text ?? '').toLowerCase());
        }
    }
    const isOutbound = host => outboundHosts.has(String(host ?? '').toLowerCase());
    // 网络面逐个主机走：一条允许的主机不能替同一次调用里另一台主机作主。
    // 事实层给了逐段主机清单就按段算（这一段的主机结论并进这一段）；
    // 没有清单的调用方（手搓 segments）退回整次调用一条结论，行为不降级。
    const perSegmentHosts = segmentList.some(segment => Array.isArray(segment.hosts));
    const networkDecide = {
        matches: row => matchHost(row, ''),
        text: commandText,
    };
    const walkHost = (host, scope) => {
        const decide = {
            ...networkDecide,
            // 兜底行（「未知外发」）不按主机名匹配，只认方向：外送的目的地才归它管；
            // 下载／查询的主机不因为「表里没写」被它拖到人工。
            matches: row => row.fallback === true ? isOutbound(host) : matchHost(row, host),
        };
        return walkOne('network', scope, decide);
    };
    segmentList.forEach((segment, index) => {
        const segHosts = perSegmentHosts ? (segment.hosts ?? []) : (index === 0 ? hosts : []);
        for (const host of segHosts) {
            const hostHit = walkHost(host, undefined);
            if (hostHit !== undefined) {
                surfaceStated[index] = true;
                citedHits.push(hostHit);
            }
            segmentConclusions[index] = stronger(segmentConclusions[index], hostHit);
        }
    });
    for (const host of hosts) {
        const hit = walkHost(host, undefined);
        if (hit !== undefined) {
            decisions.push(hit);
            citedHits.push(hit);
        }
    }

    // 敏感面读得到的文本＝命令原文＋目标路径＋**非 shell 参数的正文**（写入内容、patch 新串、
    // 工具参数）——只拼前两者时，`write` 往文件里写的密钥这一层看不见（F04/F07）。
    const sensitiveText = [String(command ?? ''),
        ...targetList.map(target => String(target.path ?? target.input ?? '')),
        ...(Array.isArray(payloads) ? payloads.map(text => String(text ?? '')) : [])].join(' ');
    const sensitiveScan = scanSensitive(sensitiveText, sensitiveRows(config));
    if (sensitiveScan.action !== '') {
        const names = [...new Set(sensitiveScan.hits.map(hit => hit.row.label || hit.row.preset || hit.row.match))];
        const deciding = sensitiveScan.hits.reduce((best, hit) =>
            best === undefined || STRICTNESS[hit.row.action] > STRICTNESS[best.row.action] ? hit : best, undefined);
        const sensitiveHit = {
            plane: 'sensitive',
            layer: deciding?.row.preset ? 'floor' : 'rules',
            action: sensitiveScan.action,
            row: deciding?.row,
            text: `敏感：${names.join('、')}`,
            detectors: sensitiveScan.hits.map(hit => hit.row.preset || hit.row.id),
        };
        decisions.push(sensitiveHit);
        citedHits.push(sensitiveHit);
    }

    // 同档命中的行都算数：判定只显示最严的那条，但引用同档任一条都应成立。
    const citedAt = action => {
        const want = STRICTNESS[action];
        const seen = new Set();
        const out = [];
        for (const hit of citedHits) {
            if (hit === undefined || want === undefined || STRICTNESS[hit.action] !== want)
                continue;
            const key = `${hit.plane}|${hit.action}|${hit.text}|${hit.id ?? ''}`;
            if (seen.has(key))
                continue;
            seen.add(key);
            out.push(hit);
        }
        return out;
    };
    // 每个作用项自己定局，整次调用取最严：拒绝 > 人工 > 交模型 > 直接放行。
    let best;
    for (const item of decisions)
        best = stronger(best, item);
    // 同档时让**证据面**说话——`perl -e '…读 .env…'` 既是内联代码（ask）又读到凭据（ask），
    // 台账该指到那条凭据行，不能只写「内联代码（来源不可读）」。只在同档或更严时接管，不改档位。
    const sensitiveHit = decisions.find(item => item.plane === 'sensitive');
    if (sensitiveHit !== undefined && best !== undefined
        && STRICTNESS[sensitiveHit.action] >= STRICTNESS[best.action])
        best = sensitiveHit;
    // 没有任何一行说住的段／目标＝不算被别的段顺带放行（F03／A04 的核心）：整次调用降成交模型判。
    const silent = segmentList.filter((segment, index) => segmentConclusions[index] === undefined);
    const uncoveredTargets = targetList
        .filter((target, index) => target.dynamic !== true && targetConclusions[index] === undefined);
    const coverage = {
        covered: targetList.map((target, index) => target.dynamic !== true && targetConclusions[index] !== undefined ? index : -1).filter(index => index >= 0),
        uncovered: targetList.map((target, index) => target.dynamic !== true && targetConclusions[index] === undefined ? index : -1).filter(index => index >= 0),
    };
    // 作用项没被任何一行说住 ⇒ 不能靠**文件行**的允许顺带放行（A04 判据 5）：
    // 允许是逐目标表态的，一个目标被允许不代表同段另一个目标也被允许。
    // 命令行／工具行的「允许」是对整次调用的表态，不按这条降级。
    // 卡片上只写「哪条规则、给了什么结果」——规则路线没有理由可讲，解释句一律不写
    // （自造句＝甩锅、挑衅）。序号取该行在设置页列表里的位次，
    // 与页面同源（effectiveRows），不写死、不另算一套。
    const TIER_TEXT = { release: '允许', ai: 'AI', ask: '人工', deny: '拒绝' };
    // 五张表各自从 1 数起，光写「1」用户翻哪张表都对得上、等于没说。所以卡上带面名，
    // 面名用设置页那几条标题（命令安全／文件安全／网络安全／工具规则／检测规则）的短称。
    const PLANE_TITLE = { command: '命令安全', file: '文件安全', network: '网络安全', tool: '工具规则', sensitive: '检测规则' };
    let rowSeat;
    const seatOf = (hit) => {
        const row = hit?.row ?? hit;
        if (row === undefined || row === null) return '';
        if (rowSeat === undefined) {
            rowSeat = new Map();
            for (const plane of RULE_PLANES)
                effectiveRows(config, plane, roots).forEach((item, at) => rowSeat.set(item.id, at + 1));
        }
        const seat = rowSeat.get(row.id);
        const name = String(row.label || row.match || '').trim();
        // 「网络安全「第1条 未知外发」」：面名直接贴框，框里是「第N条 名字」。
        // 序号不许写成 `121-python`——两个拉丁串中间一根短横，读出来像 kebab-case 变量名，
        // 不像位次；带上「条」字之后，后面接中文还是英文都不会被读成一串。
        const plane = PLANE_TITLE[row.plane] ?? '';
        const inside = [seat === undefined ? '' : `第${seat}条`, name]
            .filter(part => part !== '').join(' ');
        if (inside === '') return plane;
        return plane === '' ? `「${inside}」` : `${plane}「${inside}」`;
    };
    // 一次调用常常同时命中好几条行（命令面、文件面、网络面、工具面各说各的），但卡上
    // 只该出现**判出这一档的那条**——把命中的行全列出来是流水账，把次要的排在前面又会栽错人。
    // 同档还有别的行时只报个数（「等 N 条」），不逐个点名。
    const cardOf = (decided, action, extra = 0) => {
        const row = decided?.row ?? decided;
        const finalTier = TIER_TEXT[action] ?? action;
        if (row === undefined || row === null)
            return `命中规则 无 ｜ 规则结果 ${finalTier}`;
        const tail = extra > 0 ? ` 等 ${extra + 1} 条` : '';
        return `命中规则 ${seatOf(decided)}${tail} ｜ 规则结果 ${finalTier}`;
    };
    // 判出这一档的那条：自己的表态就是最终档位。找不到（如「这一段没有行说话」抬到 AI）
    // 就退回最强的那条，仍按它的名字写。
    const deciderOf = (action, fallback) => {
        const same = decisions.filter(item => {
            const row = item?.row;
            return row !== undefined && row !== null
                && (row.action ?? item.action) === action;
        });
        if (same.length === 0)
            return { decided: fallback, extra: 0 };
        return { decided: same[0], extra: same.length - 1 };
    };
    // 外项目根硬闸——读目标落在别的项目根下、用户消息里没点名 ⇒ 一律 ask。
    // 位置在模型之前：这里返回 ask，ladder 不会走 review，模型判 allow 也没有机会。
    // deny 仍更严（不放宽）；已经落 ask 的保留它自己的说法（那条规则更具体）。
    const foreignReads = targetList.filter(target =>
        target !== undefined && target !== null && target.dynamic !== true
        && opOf(target.opClass) === 'read'
        && target.foreignProject === true && target.namedByUser !== true
        // 只带回目录结构的读不为它弹框（判据 2.1）；带回正文的一律照旧（判据 2.2／2.3）。
        // 这一格由事实层说（structureOnlyOf），这里只把它加进**同一条闸的触发条件**——不新增分支、不改档。
        && target.structureOnly !== true);
    // 只在**整条调用都是读**时接管：`mv`／`cp`／`cat … > out` 把自己的读目标也算读，
    // 但它们写在那儿——本版「只管读面」，写／删／外传仍按现行行判（判据 2.4）。
    const pureReadCall = segmentList.every(segment => opOf(segment.opClass) === 'read')
        && targetList.every(target => target?.dynamic !== true && opOf(target?.opClass) === 'read');
    if (pureReadCall && foreignReads.length > 0
        && (best === undefined || STRICTNESS[best.action] < STRICTNESS.ask)) {
        // 提示要说自己的话：这一档是「外项目闸」抬上来的，不是那条行判的——照抄行名会读成
        // 「工作区外＝人工」，而行上写的是交 AI，行与结论对不上。
        const names = [...new Set(foreignReads.map(target =>
            String(target.foreignRoot ?? target.path ?? '').replaceAll('\\', '/').split('/').filter(Boolean).pop() ?? ''))]
            .filter(Boolean).slice(0, 3);
        return {
            decision: 'ask', plane: 'file', layer: 'fact', hit: best,
            rule: `这条调用在读别的项目 ${names.join('、')}${foreignReads.length > names.length ? ' 等' : ''}`
                + `，你的话里没点名它 ⇒ 先问你要不要读。`
                + (best === undefined ? '' : `（表里 ${seatOf(best)} 给的是「${best.action === 'ai' ? '交 AI' : TIER_TEXT[best.action] ?? best.action}」，外项目这条闸把它抬到人工）`),
            sensitiveHits: decisions.find(item => item.plane === 'sensitive')?.detectors ?? [],
            hits: decisions, cited: citedAt('ask'), coverage,
        };
    }
    // 事实层说「看不清」（opaque：目标靠运行时展开，`cat $(ls)`／`cat $NOPE`）：允许行不替它背书。
    // 11 条结果行拿掉后，这一格原由 `opaque-command` 结果行承担，现在只剩内部下界，必须在这里接住。
    const opaqueAction = pick(undefined, 'opaque-command', 'write');
    if (best !== undefined && best.action === 'release' && opaqueAction === 'ai') {
        return {
            decision: 'ai', plane: 'fact', layer: 'fact', hit: best,
            rule: `看不清目标：命令里的目标靠运行时展开，批准前给不出具体路径 ⇒ 交模型判一次`
                + `（表里 ${seatOf(best)} 给的是「${TIER_TEXT[best.action] ?? best.action}」，这一闸抬到交 AI）`,
            sensitiveHits: decisions.find(item => item.plane === 'sensitive')?.detectors ?? [],
            hits: decisions, cited: citedAt('ai'), coverage,
        };
    }
    const uncoveredBlocksRelease = uncoveredTargets.length > 0 && best?.plane === 'file';
    // 执行段（跑一个未归类程序）在命令面没有任何行 ⇒ 文件面的 release 不算它的表态。
    // 「某一段无任何行表态时，整条不得放行」——这里把「表态」限定在命令面，避免目标文件
    // 命中工作区行就把一段没被认过的可执行程序顺带放走。
    const execUnstated = segmentList
        .map((segment, index) => ({ segment, index }))
        .filter(({ segment, index }) => String(segment?.opClass) === 'exec'
            && surfaceStated[index] !== true && segmentConclusions[index] !== undefined)
        .map(({ segment }) => String(segment.program ?? '').split(/[\\/]/).pop());
    if (best !== undefined && best.action === 'release'
        && (silent.length > 0 || execUnstated.length > 0 || uncoveredBlocksRelease)) {
        return {
            decision: 'ai', plane: 'command', layer: null, hit: best,
            rule: cardOf(best, 'ai'),
            sensitiveHits: decisions.find(item => item.plane === 'sensitive')?.detectors ?? [],
            hits: decisions, cited: citedAt('ai'), coverage,
        };
    }
    if (best !== undefined) {
        const { decided, extra } = deciderOf(best.action, best);
        return {
            decision: best.action, plane: best.plane, rule: cardOf(decided, best.action, extra), layer: best.layer, hit: best,
            sensitiveHits: decisions.find(item => item.plane === 'sensitive')?.detectors ?? [],
            hits: decisions, cited: citedAt(best.action), coverage,
        };
    }
    if (aiRow !== undefined) {
        return {
            decision: 'ai', plane: aiRow.plane, rule: cardOf(aiRow, 'ai'), layer: aiRow.layer, hit: aiRow,
            sensitiveHits: [], hits: decisions, cited: citedAt('ai'), coverage,
        };
    }
    return { decision: 'pass', plane: null, rule: null, layer: null, sensitiveHits: [], hits: decisions, cited: [], coverage };
}

/** Rows that declare trust: a file row that does not stop this operation (gate.js reads these). */
export function trustRules(config) {
    const out = [];
    for (const rule of parseRules(config?.fileRules, 'file')) {
        if (rule.enabled === false)
            continue;
        // 旧的 `allow` 现在折进 `ai`；`release`（允许＝直接放行）同样声明信任。
        const allowed = FILE_OPS.filter(op => rule[op] === 'ai' || rule[op] === 'release');
        if (allowed.length === 0)
            continue;
        const entry = { ...rule };
        for (const op of FILE_OPS)
            if (!allowed.includes(op))
                entry[op] = '';
        out.push(entry);
    }
    return out;
}






