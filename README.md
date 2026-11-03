# dsh-auto-approval-frame

[English summary](#english) · 中文完整说明（默认）

DeepSeek Harness 的拦截与审计框架。每次工具调用走一条拦截梯，全部事件进同一本可校验的审计库。

本包是独立实现，只保留一条判定轴：事实取证 → 一张有序表（预设行＋你的行；命令面是一条命令一行＋末行兜底）→ AI 快判 → AI 深评 → 人工 → 结果脱敏。「免模型费直接放行」不是链尾的代码特权，它就是这张表里的一行——能停用、能换档、能调序，台账里说得出是哪一行放的。
17. **AI 层**：提示词「规则先行」——先列命中的规则行（原文逐字，多行全列、取最严），再给用户原话、卡、证据、硬底线，最后判「这次动作在不在规则允许的范围内」；AI 只回 `card + verdict` 一个 JSON，`reasonCode` 四出口：`no_material_risk`（放行）／`not_necessary`（缩范围回执行端）／`authorization_not_covering`（要授权回执行端）／`safeguards_insufficient`（兜不住也回执行端），`unable` 只留证据不足、仍问人。三问由结论反推（`allow→三真`、各 block 把对应那问答 false），授权来源只认「算法路由到 AI＋allow＋依据有效＋grant auto＋算得稳（非不可逆、无动态目标、无运行时展开、非解释器族）」，台账记 `safeguardedBy=authorization`／`safeguardFact=user-words+rule-row`。任务卡由评审端抽（可做／在哪／不可做／单独授权，每项带用户原话逐字引文≥12 字），插件按会话存、下次带上；引文核不过的项丢弃并计数，卡只收窄不放宽。

18. **命令面**：一条命令一行，行上只有四件——`command`／`action`／`enabled`／`note`；`verbs`／`flags`／`statements`／`pairs`／`history`／`ops`／`execFamily`／`execDynamic`／`scope` 这些条件与范围字段一个都不进表。**算法根据这次调用算出的结果只影响判定、不再冒充表行**（原 11 条结果行整类拿掉）：`proven-read`／`unproven-read`／`interpreter`／`inline`／`piped`／`process`／`package`／`opaque-command` 落末行兜底交 AI；来源不可举证的内联／管道与框架解释不了的删除参数由事实层内部下界保 `ask`（不进表、不可配）。同一段命中多行时取**最长命令名**（具体压泛化，如 `git push` 压 `git`、`docker system prune` 压 `docker`）；多段命令各自命中、合成取最严。末行「其他命令」固定最后、可改档、可停用、不可删、不可上移：前面所有命令一个都没命中时，这次调用交 AI 判，绝不空放。出厂命令面没有 `release` 行；文件面／工具面／网络面的行与档一格未动。


## 安装

- 在 DSH 插件市场搜索「自动审批框架」→ 安装 → 重启。
- 或 `dsh plugin --profile <profile> add dsh-auto-approval-frame`。
- 安装后打开「设置 → 插件 → 自动审批框架」确认启用；在会话权限菜单里选择「自动审批」档。

## 权限档

本插件只接管 `gatedPresets` 里的权限档，默认 `auto-approval`。这个档由本包的 bundle patch 提供（`danger-full-access` + `approval: ask`，见 `cordis.patch.yml`）；全新 profile 装完就能在权限菜单选到。

如果你的 profile 自己定义了 `permission` 表，它会整行覆盖本包的表（同 id 不深合并）。这时保留你已有的档，并把 `auto-approval` 加进去；或者直接在设置页的「受管权限档」里勾选你已有的档（`gatedPresets` 现在可写）。受管档不存在时，启动日志会写 `missingGatedPresets`，设置页的「接管与模式」卡会红字报出名字并给出可复制的 profile 片段——在它出现之前，插件不接管任何会话。

> 前提：宿主审批策略必须是 `ask`。`DSH_PERMISSION_MODE=danger-full-access` 会把宿主钉成 `never`，此时没有审批请求，本插件也不接管。

## 拦截梯

```
tools/pre-execute(exec, next)
 ├ L0 下界    facts → grant：never / confirm / auto          lib/frame/{paths,parse,facts,grant,gate}.js
 ├ L1 规则    tool → command → file → network → sensitive     lib/frame/policy.js
 │            四档：拒绝 > 人工 > AI > 允许；**AI 是终局路由**——命中即交模型，
 │            不再往下找放行／人工（设了 AI 就不会被后面某条允许行悄悄放掉）；
 │            唯一例外是拒绝：任一命中即拒，与它排在第几行无关
 │            首条命中在**每个作用项内部**算（这一段／这个路径／这个主机各走一遍表），
 │            整次调用取最严；没被任何一行说住的段，不算被别的段顺带放行
 │            允许＝真放行（不调模型、不弹面板，但台账必须写得下去）；
 │            命令行的「允许」不替**区外读**背书：读的目标不在任务资源范围内、
 │            文件面又没有明确说法 ⇒ 问人（表间取最严）
 │            读落在**别的项目根**（同层或向上有 AGENTS.md／.git）且你的消息里没点名该路径
 │            ⇒ 直接人工；这道闸在模型之前，模型判 allow 也不放行
 │            消息里只有名字（如「原项目在workbuddy」）时，名字解析到**唯一存在**的目录
 │            ⇒ 绑成本会话源根：根内的读取直接放行，写／删／敏感面照旧
 │            命令面出厂不预置任何「允许」行（纯读也交 AI）；工具面的「会话内部工具」
 │            是唯一直放行的那一行（默认可停用）
 ├ L2 快判    单段写/删 × grant=auto：allow 或升级            lib/frame/{review,verdict}.js
 ├ L3 深评    一次模型调用：allow / block / unable            lib/frame/{evidence,review,verdict}.js
 ├ L4 人工    交宿主官方审批面板，不自研倒计时                 lib/index.js
 └ L5 脱敏    结果侧命中就遮成确定性 token；明文只落本机映射表  lib/frame/{sensitive,vault}.js
        ↓ 按 callId + actionHash 存一条 pending
session/event(approval/asked → approval/decided)  只读 pending，不重新推导
                                                  lib/frame/pending.js
```
> 人工答复为什么挂在 `session/event` 而不是 `approval/request`：后者是宿主**跨进程转发**的
> waterfall，宿主自己的应答器先把它终结，插件监听排在后面根本进不去（实测台账
> 138 条里 38 次 ask、0 条 `approval.answer` 的成因）。而宿主强制 `approval/asked` ＋
> `approval/decided` 成对提交，`session/event` 是「每个监听都跑、没有否决权」的 emit，
> 所以观测点只有这一处可靠。

上面这条链只有**一份实现**：`lib/frame/ladder.js` 的 `walkLadder()`。`tools/pre-execute`（真判定）
与 `GET /api/auto-approval-frame/explain`（设置页的模拟审批）都吃它，步骤文案与结论由 `ladderSteps()`／
`ladderVerdict()` 从同一个 walk 派生——模拟不可能对同一件事说两套话。`test/wiring.test.mjs` 里另有一条
差分锁：逐条比较「模拟给出的落点」与「真判定写进台账的第一条定局行」。

一处例外要说清：层级名字有两份表——`lib/frame/audit.js` 的 `LAYER_TEXT`（导出件用，node 侧）和
`lib/client.js` 的 `LAYER_LABEL`（页面用，webview 侧，运行时拿不到 node 模块）。`test/client.test.mjs`
按字面比对两张表，键值必须逐字相同；启动／配置／迁移这些行用 `layer=lifecycle|config`，不冒充预设行。
模拟审批还照例标一句判定所依据的目录：真判定按各会话的 `cwd` 解析路径，模拟只能按宿主进程目录，
不说就会被当成「模拟和实际不一样」。

审计不在这条梯上，而是包住它：每个事件（含 delegated／规则／人工／配置／启停／迁移／脱敏／清空）
都写进 `lib/frame/audit.js`。

## 不变量（回归锁死）

1. `never` 不进模型：凭据树、系统关键树、`.git` 内、DSH_HOME 状态树（未被允许行开口）、工作区根本身。
2. 静态规则四档：`deny`／`ask` 只往严的方向决定；`ai`＝命中即终局（交模型判一次，后面的行不再表态；任一 `deny` 命中即拒，与先后无关）；`release`（允许）＝**真放行**，不调模型、不弹面板，但必须先写得下一条可追责的台账，写不下就降级人工。
3. ALLOW 只在 `grant=auto × mode=auto` 有释放力；`confirm` 档的 ALLOW 只作为建议随弹窗展示。
4. `allow ⇔ reasonCode=no_material_risk`；矛盾即改写为 block。快判的 block 只表示「升级到深评」。
5. `unable`（超时/坏 JSON/路由不可用/证据过大）的落点分两档：**证据过大（context_too_large）仍一律回落人工**——模型根本没看全，不许静默放行；**纯读**（面集合全为读、目标集已确定、无机械下界理由）改由「unable 兜底」放行，台账记 `layer=deep`＋`unableTier` 与原因，指得出是哪一次评审举不出结论。其余（含任何副作用面）仍回落人工。
6. 人工答复那一侧不调用 L0/L1：`session/event` 只按 `approval/asked` 的 callId 取 pending，pending 按 `actionHash` 绑定，动作漂了不继承判决。
7. 放行写不进审计库 ⇒ 降级为人工（表里的「允许」行、只读／内部工具举证行、快判与深评四个放行出口同一约束：本插件放行的，都要有账可查）。
8. **纯读不再直放**。`proven-read` 不是表行了——证据照旧由事实层举（台账里读得出），但「这条调用能不能免审」只能由命令清单里的一行「允许」拍板；出厂不预置任何允许行，所以 `cat`／`ls`／`git status` 这类纯读落末行「其他命令」交 AI 判（不弹人）。要免审，就在命令表里给自己加一行「允许」并把档位改成允许。`compress`／`decompress`／`acp_status`／`acp_cache`／`todo_write` 这类只编辑会话的内部工具仍走「会话内部工具」那一行。
9. 语气不构成授权证据：情绪化语句降级进非授权背景块，内容照录、授权标签摘除。
10. 结果侧命中就遮，**与档位无关**：任何一档（含允许）先换成确定性 token `[[SEC-<12 hex>]]`，档位只决定遮完之后是问你、放行还是整段不给模型。明文只落本机 `secrets.json`（200 条／30 天），列表默认不出明文，查看明文单独取一次并入账。
11. 人工答复与工具结果都入账：`approval.answer` 记宿主那四个结局——已批准（`allowed-once`）／已拒绝（`rejected`）／没答（`cancelled`）／没有应答通道（`unavailable`），并带上它批的那条动作；`tool.result` 记成功／失败＋结果首段。所以一条 ask 不会在列表里留下没有结局的悬尾。
12. 自动回写只发生在**文件层**且只换本表铸出的 token：写完后读回、原子重写，跳过凭据／系统树、符号链接、超 4 MB 与读不出的文件；命令参数里的 token 换不了（宿主契约禁止改写参数）。
13. 落在本机之外的操作数不当本机路径看：`ssh`／`scp`／`sftp`／`rsync`／`nc`／`telnet` 的远端主机与远端命令进 `remoteHosts`（不再折成「工作区内的假路径」），并且喂给网络平面——用户写一行 `deny prod.example` 就拦得住 `scp out.txt user@prod.example:/tmp`。外传一族（`git push`／`curl -T`／`aws s3 cp`／`docker push`／`npm publish`／`gh release create`…）一族一行。**这两类都把 grant 压到 `confirm`**：事实层看不见机器外面发生了什么，所以模型无权单独放行，只能问人（行本身仍可改档或停用）。
14. 目标提取只认真实操作数：词首 `#` 之后是注释，`<<`／`<<-`／`<<<` 的标记与 heredoc 正文整体消失（正文是数据、不是命令），不像路径的词（`--line 10`、`--label 决定·面板`、纯符号）不折成路径——但**以文件为操作对象的程序除外**（`rm -f junk` 里没有点也真是文件，这格一丢删除下界就没了）。判据是「这条命令要动的东西」，不是「命令行里出现了什么字」：正文词 `token` 曾被折成 `…\面板.md\token` 命中凭据名，把一条往受管文档追加表格行的命令降成「模型无权放行」。「事实层被截断」也因此单独成行（`facts-truncated`，默认 `ai`＝送去判），不再冒充「一次动得太多」。
15. 默认档不靠顺序、靠**作用面**：预设行的文件面带 `read`／`write`／`delete` 三列默认值，`''`＝对该操作不表态（不再一律回落成人工）。所以「读类不再逐次问人」是在表上解的，`walkLadder` 的步骤次序一步没动——把只读门前移会让 `cat ~/.ssh/id_ed25519` 静默放行（实测三条反例）。豁免只有两条行、四道闸口：目录属于客户端状态族（`~/.dsh`・`~/.workbuddy`・`~/.qoder`・`~/.copilot`）、不是 `profiles`／`bin`、整条路径里没有任何凭据形状的段、不是目录本体下直接摆的文件；`skills`／`docs` 子树的读默认放行，其余子树的读默认交模型判。**`~/.gnupg/skills` 这类「凭据目录里恰好叫 skills」不放**——按目录名放行就是把自己骗过去。`.workbuddy`／`.qoder`／`.copilot` 三行按**家目录直接子段**匹配（`homeOnly`）：客户端还会在每个会话工作区注入一份同名目录，那不是 `~/.workbuddy`，不该拿它当理由文案；这三行的读默认交模型判，写与删仍人工。`~/.dsh`（`profiles` 是宿主配置）与 `~/.ssh` 的读**不随这次降档**。
16. **参数位语义**：只读证里「哪个词是路径」按**位**判，位只在 `lib/frame/positions.js` 一张表里定义（124 只读族程序 × 八位：`read`／`write`／`exec`／`take`／`key`／`pattern`／`nopath`／`nav`，每行带 `evidence`）。`facts.js` 只查表，段上落一列 `wordRoles`（`flag`／`path`／`nopath`）；`write` 位的取值只进写面（不再记一份读）；`exec` 位的后随程序按同一张表再查（内层是读族⇒本段仍算读），`{}`／`\;` 是占位符不是路径；表外程序不产读证、目标面保持保守（表外程序与表外旗标的词按 `path`）；未引用的通配在当前目录有界展开（≤20）后名字进目标，**判读与程序名无关**——展开成功（含 0 命中）就是目标集确定，任一读族程序同判（`head *.md` 与 `cat *.md` 同）；引号里的 `*` 是字面字符、0 命中是空集，两者都仍是读（只是目标为空），不铸假目标；只有「列不出／触顶／不支持」才按「参数含通配」否证；没有路径参数的读（`grep TODO` 读 stdin）仍算「读面为空」、不换已证明只读；命令替换（`$(`／反引号）仍扫全部词，不按位置放宽；整词 `$名`／`${名}` 只在**读族 + 路径位**、且整条命令没有运行时改名写法（`X=…`／`${X:=…}`／`read X`／`eval`／`source`／`for X in …`／`select X in …`／算术 `((`）时，按判定这一刻的环境值算死——未设／空值＝空串（读、目标为空），非空值必须是真实存在的路径（只 `lstat`、不读正文），argv 仍留原文、环境变量的值不进证据；目标集按「段＋路径＋动作」去重。
    **续**：读再分两面——`name`（只回名字／计数／元数据，正文不进会话）与 `body`（回正文片段，走敏感面严审）；`positions.js` 每只程序带 `face`，`grep -l/-L/-c/-q` 切 name、`grep -n/-o` 切 body。组合按三类判：`-exec` 与 `xargs` 把内层程序按同一张表再查、内层面决定本段面；管道各段取最严且**流不洗面**（上游只回名字⇒整条 name，上游读正文⇒整条 body）；重定向是段与文件绑定，不参与组合。facts 产出 `readFace` 一列。

17. **子命令键名位**：`git config` 后面那个点分词（`user.name`／`core.excludesfile`）是**配置键**，不是文件——按「表里登记的子命令 ＋ 键名形状」两条**同时成立**才判 `nonpath`，形状是 `段.名`（不以点开头的点分词）。取值位、旗标取值位、表外程序、非 `config` 子命令一律照旧 `path`。清假目标的边界＝不把真目标一起清掉：`--file <路径>`／`-C <目录>` 的取值必须照旧进目标集，`git config --get user.name` 这类已放行的读也不许因为键位消失而改弹人。
18. **「保障」这一问只在算法量得出「动不掉任何已有东西」时代填**：量得出的只有两件事——`proven-read`（整段已证只读）与 `target-absent`（**全部**目标都是 `write` 面、落点在 `workspace`／`trusted`／`dsh-open` 之一、且 `kind` 全是 `absent`）。删除／改名／销毁／提权／历史改写／执行／读面掺进来／落点读不出／动态目标一律不代填，「已被 git 跟踪且干净」「有第二份副本」两格还没测得出，因此也不代填。代填**只发生在模型已判 allow 那格**：它判 block 时第三问的答否是它拒的一部分，抹掉会把台账里的拒因换掉（实测对照那一格 `ask`→`blocked`，往严）。台账按格署名 `checksBy`（`ai` 或 `algorithm:<事实>`），`safeguardedBy` 的取值不变（两把锁判据读它）。
19. **没有可对证依据的 allow 不释放**：模型要放行必须交出两样机器验得了的东西——`basis.rule` 逐字等于本次证据块 `decidedBy[].rule` 里的一个行名（一行都没表态时，那一行就是「无行表态：默认交模型判」这句事实本身），`basis.quote` 逐字出现在它读到的那份证据里，字数只对技术碎片设限（不短于 12 字）——引的是**你的原话**（证据块 `trusted_user_intent`／`prior_user_context` 里实际送达的文本）时不设下限，你回「可以」两个字就够当授权证据。引用要照展示形态抄（证据是 JSON 文本，自行解开转义就不再逐字相同）。验不出 ⇒ 不释放、落「问人」，**不改判成 block**（那是模型的话，框架不替它改结论）；代价是多问一次人，拿没见过的话作保才是事故。老调用方不传 `basis` ⇒ 维持原判据（`mayRelease` 的兼容口），生产调用点一律传。
20. **本机以外的破坏族是硬闸行，不是模型的话**：云控制面／IaC／集群／库表语句／容器产物／账号／计划任务的销毁动作（`DESTROY_ROWS` 八行，出厂 `ask`）按「程序名＋子命令词／旗标／语句形状」认，**不按 `opClass` 认**——`aws s3 rm`、`terraform destroy` 在事实层没有可 `lstat` 的目标，只看 opClass 会整族漏掉。判定链在这一步就把人抬出来（实测这些形状 `review=0`，走不到模型），所以 AI 的 allow 与任何上层的代放都碰不到它；要放宽只能由操作者自己改这一行。代价与边界一起记：命中靠程序名白名单，白名单外的同类工具（如自研 CLI）不在这一族；读类与本机文件面一格未动（实测对照 15 格逐格同）。
21. **人工放行只按「类」沿用，且同类沿用有帽**：第三把键＝会话｜工具｜本次真命中的规则行｜面集合（读／写／删）｜目标根类别（`classkey.js`），仍不跨会话、不跨配置版本、不活过 TTL。删除／改名／销毁／提权／历史改写／执行／未归类工具，`elevated:`／`destroy:`／`exfil:`／`credential-`／`remote-` 任一理由，进程族与装包族，区外目标，跨项目读，动态目标，无目标事实，以及 `unrecoverable-content`／`batch-too-large`／`facts-truncated`／`opaque-command`／`symlink-operand` 等逐条排除项——**一律不建键、不回放**（`classOf` 回原因，落进 `approval.answer` 行的 `classReceipt.skip`）。同一类键沿用到 `CLASS_REUSE_CAP`（＝8）次后这一格重新问人，弹框写明「已沿用 N 次＋最初批准时刻」＝重复调用升级；每次重新批准把计数归零。实测对照：无批准时 17 格与改前逐格同（类键没新增任何放行），批准后只有「区内 git 写子命令」由 `ask`→`allow`，排除格零回放。
22. **目标集为空就没有退化键（实测对照抓出来的洞）**：`targetDigestOf([])` 对所有无路径命令算出同一个值，旧形制下一次 `allowed-once` 就让 `git push`／`systemctl restart`／`npm install`／`aws ec2 terminate-instances`／`mysql -e "DROP TABLE"` 互相顶替（改前实测 6 格 `ask`→`allow`）。现在空摘要＝退化键不成立，这些命令各问各的；宿主给了 `actionHash` 时按动作键照旧沿用，与目标集空不空无关。

## 配置（23 个可写键 + 1 个补丁专属键）

| 键 | 默认 | 含义 |
|---|---|---|
| `enabled` | true | 总开关：**只关判定**（拦／问／放）；结果脱敏与台账照常（见「边界」第 7 条） |
| `mode` | `auto` | `off` 全交宿主面板／`advise` AI 只建议不释放／`auto` ALLOW 可释放 |
| `gatedPresets` | `['auto-approval']` | 受管权限档；设置页只列 `auto-approval` 与自定义档（内置只读／工作区写／完全权限不列），按会话原始权限身份判定，不看折叠后的 current() |
| `reviewerSource` | `session` | `session`＝跟随会话（用当前对话同一个模型）／`preset`＝指定预设（从宿主已注册的 provider＋model 里挑，页面是一行下拉） |
| `reviewerProvider` `reviewerModel` | `''` | `preset` 来源时必填 |
| `reviewerMaxTokens` | 2048 | 深评输出上限，64–4096（512 容易截断 verdict，别往下调） |
| `reviewerTimeoutMs` | 20000 | 深评硬超时，1s–120s，单次调用不重试 |
| `evidenceBudget` | 16000 | 深评证据总预算；分块上限 8000/4000/1000/2000，超出按优先级从低到高裁 |
| `reviewRules` | `[]` | 操作员附加规则，作为**数据**随深评提示，只能收窄 |
| `commandRules` `networkRules` `toolRules` | `[]` | 每行 `{action, match}`，action＝`release`／`ai`／`ask`／`deny`，按数组顺序首条命中即停；预设行用户副本另带 `preset` |
| `fileRules` | `[]` | 每行 `{match, read, write, delete}`，三列各选四档之一或空（＝不表态） |
| `sensitiveRules` | `[]` | 检测规则表：预设 10 行（9 条形状＋1 条高熵令牌，`preset` 覆盖行可改正则／档位／停用）＋自己的行；命中取最严，不看先后 |
| `sensitiveDetect` | true | 检测与处置总闸；关掉＝这张表不表态，工具结果原样进模型 |
| `autoRestoreSecrets` | true | 写文件后把本表铸出的 token 换回明文（仅文件层，跳过凭据／系统树与符号链接）；**默认开但仍需回写证**，无证一律跳过 |
| `fastJudge` | true | 单段写/删 × auto 先问快判 |
| `fastJudgeMaxTokens` | 256 | 快判输出上限，64–1024 |
| `fastJudgeTimeoutMs` | 3000 | 快判超时，500–30000ms；超时即升级深评 |
| `retentionDays` | 90 | 审计段保留天数，超龄整段裁剪并留墓碑 |
| `maxTotalBytes` | 512MB | 审计库总大小上限，超限从最旧段裁 |
| `maxSegmentBytes` | 50MB | 单段上限，写满换下一个序号 |
| `debug` ⓟ | false | 保留位 |

ⓟ = 补丁专属，设置页只读。

### 规则行的匹配写法

- 命令：`程序名 + 参数前缀`（`git push` 命中 `git push origin main`，不命中 `git pull`）；单独的 `*` 匹配一个参数，整行只写 `*` 匹配所有命令；`re:` 开头按正则。
- 文件：路径，`~` 表示家目录，`*` 只匹配当前一级、`**` 匹配任意层级，以 `/` 或 `\` 结尾表示该目录及其内容；读／写／删三列各自表态，留空＝这一行不管这个操作（后面那行仍可管）。
- 网络：主机名或 IP（`api.example.com`、`*.example.com`、`*`），不支持端口与路径。
- 工具：工具名通配（`mcp:*`）。
- 旧的 `trustedDirs`／`dshOpen`／`neverAutoExtra` 三键在启动时一次性迁成 `fileRules` 行（禁放行排在允许行之前），之后不再是配置键。
- **所有行（用户／预设）同表同序**：自上而下，命中第一条给出结论的行即停；预设行在事实命中时算命中，**AI 档命中即终局**（交模型判一次，不再往下找；任一拒绝行命中即拒，与先后无关）。想放开某条预设，把一条允许行放在它上面，或直接改那条预设；把它拖回上面就恢复保守。
  页面「安全规则」的说明与这条同步：设置页会在还有 AI 行时给出一次可见告知——旧配置里的 AI／allow 行语义已变，行内容不会被自动改写。判定记录的 `configVersion` 带语义纪元前缀（`2:<hash>`），旧版本串不再命中新语义的批准。

升级到本版后，AI 档从「本层不拦、继续往下走」变成「交模型判一次、命中即终局」，这是**语义**变化而不是内容变化——所以你配置里的 `ai`／`allow` 行一个字都不会被自动改写，插件也不会替你降档或删行（`lib/frame/record.js` 的 `migrationNoticeOf()` 只给告知与 `keep` 判断，不回写行内容）。它会做的是**告知一次**：还有 AI 行时设置页出现一条可见告知（`GET /api/auto-approval-frame/frame` 的 `migrationNotice`），说明旧行的含义已经变了；同一个版本对只递一次（台账里已落过就不再刷屏），改不改、改成什么档由你自己决定。

判定记录里也留了凭据：`configVersion` 带语义纪元前缀（`2:<12hex>`，`lib/frame/record.js` 的 `CONFIG_EPOCH`），同一份配置在纪元变化前后拿到不同的版本串，所以**旧语义下发出的批准不会命中新语义**；读到比自己更新的纪元时保留上一份合法配置、页面只读提示，不清空你的规则（`acceptConfigVersion()`）。同一次判定里，`frame` 接口的 `configVersion`、审计库判定行的 `configVersion`、证据块的 `recordIdentity.configVersion` 是**同一个串**（回归锁在 `test/config-evidence.test.mjs`），要核「这次是按哪份配置算的」，读一处就够。

一句话：升级不会改你的行，只会告诉你 AI 行的意思变了；版本串带 `2:` 前缀就是新语义。

### 允许行能开到哪一步

允许是真放行：命中即不调模型、不弹面板，但仍要写一条规则层台账（写不进去就降级人工）。
预设行不再高于你的行：文件面按「会独立触发的一条理由」拆成一行一条（每个目录一行、每类目录／文件名一行，共 63 行），命令面 318 行（按命令名一条命令一行：提权／销毁类一程序一行，容器销毁精确到子命令，外传与发布类一程序一行，远端四方向按程序名折开；末行固定是兜底「其他命令」），加工具 3 行与 10 行检测规则（9 条形状＋高熵令牌），全部铺在表里；换档位、停用、改敏感面正则、文件行按读／写／删分别表态都算数——**这四处计数的真源是预设表本身：`test/_preset-snapshot.mjs` 的快照锁会让「改了表没重拍快照」当场变红；README 里这几个数字目前没有测试在读，改动时按实测写。**
盘根与家目录**不单列**：它们就是普通目录，删／改／读一律按「工作区外」与各删除族的通用下界同判——`rm -rf C:\` 与 `rm -rf ~` 都落「删除·ask 工作区外」，`mv ~ <目录>`／`chmod 000 ~`／`cat ~` 与区外普通目录一样交模型；要更严就写一条**普通路径行**（`deny`／`ask` 都行，盘根写成 `C:\`），没有单独的「盘根开关」。
把「凭据与客户端目录」改成允许或停用，这一条就不再拉高。哪些行**不该**允许（真正危险的名单）留待后续讨论，本版不设特例。
允许行同时是信任声明：命中的路径不再算「工作区外」，其删除也不再算「内容不可恢复」，`~/.dsh` 的子树也可以被开口；
但整棵 `~/.dsh` 与含凭据段的子树仍会被拒收成信任根（`GET /api/auto-approval-frame/frame` 把被拒的行连同原因报给页面）。
敏感面的允许只放这次调用，结果该遮还是遮。

### 默认档现在把什么交给模型

改工作区根、改到信任区之外、改符号链接目标：现在先交 AI 判；而改 `~/.dsh` 档位配置／审计台账／审批记录（审批器自身）仍然必问你。
客户端产物目录的读不再无条件放行。

### 存不进去的规则，与坏掉的配置

保存不是「尽力而为」。一次提交里只要有任意一行**档位不在册**（file 面看 `read`／`write`／`delete` 三列，其余面看 `action`；不在 `release`／`ai`／`ask`／`deny` 里就算非法），或 `re:`／`call-re:` 行的正则编译不出来，或一行既没挂 `preset` 也没写 `match` 却带了别的键（这种行解析时会被整行丢掉），这次保存就**整单拒绝**——盘上那份配置原样保留，不会半途写进去一半（`configDamage.reason = 'save-rejected'`，被拒的行连表名 `key`、`plane`、`index`、`reason` 一起进 `violations`，指到第几行为什么）。留空是合法的：空列＝这一行对该操作不表态，不会被默认档填回。想只改一行就只提交那一行，别拿「整份覆盖」去试。

读进来时同理，但后果更重：解析失败（`unparsable`），或解析成功而有任意一行带无效标记（`rules-invalid`），整份配置按**损坏**处理——**保持上一次合法配置生效，坏配置不采用**（`safeResolve`）。这不是「悄悄退回默认档」：默认档可能比你原来的配置更松，所以宁可退回你自己上一份合法配置。

损坏是页面上看得见的**显式状态**，不是日志里的一句话：设置页读 `GET /api/auto-approval-frame/frame`，返回体里的 `configDamage` 非空即表示**当前生效的是上一次合法配置**（带 `reason`、坏在哪几行、`at`）。同一份载荷在审计库只落一条 `config.damaged`，载荷不变不重复刷；恢复合法后 `configDamage` 归 `null`，也不补一条「恢复」件。坏行本身不会被静默丢掉：`rows` 里仍列出该行，只是带 `invalid` 原因，页面照实显示——静默丢一行，等于悄悄放开它本来拦的东西。

一句话：保存被拒＝这份配置一行都没改；页面出现损坏提示＝现在生效的是你上一份合法配置，把它修好再保存。

## 审计库

`~/.dsh/auto-approval-frame/audit/`：

```
state.json                 序号 / 链尾指针 / 当前段
manifest.jsonl             segment-closed · retention-pruned · audit-cleared（含 sha256、条数、首尾 hash）
2026-10-27.jsonl           当天的条目（一行一条 JSON，含 hash 链）
2026-10-27.1.jsonl         同一天超过 maxSegmentBytes 后的下一段
legacy/                    0.5 之前单文件台账，迁移时原样移入
```

- 每条记录：`id / schemaVersion / sequence / timestamp / category / eventType / decision / layer`，外加该事件的字段（`commandPreview`、`grant`、`reasons`、`rule`、`reasonCode`、`durationMs`、`message`、`prevHash`、`hash` 等）。
- `verify()`：manifest sha256／条数／链尾、逐行 hash、prevHash、sequence 连续性；分段即使被保留策略裁掉，也靠墓碑继续校验。
- 旧 `decisions.jsonl` 在启动时自动迁移（记 `lifecycle.migrate` 与旧文件 sha256），原文件移入 `legacy/`。
- 设置页的审计中心不落副本：宿主读同一份库，经 `GET /api/auto-approval-frame/audit`（同源、只回环）交给页面；
  导出与清空分别走 `/audit/export` 与 `/audit/clear`；判定链读侧（预设保护／生效信任与开口／被拒的允许行）走 `/frame`。
  页面在 webview 里，没有 `fs`。
- 审计中心默认隐藏两类簿记：`lifecycle.boot`（启动）、`config.changed`（配置变更）；**人工答复默认就显示**——
  这张页的正事就是「你亲手答的是同意还是拒绝」。三个开关都还在，选对应分类时也照常显示；隐藏只影响列表与导出，记录照常入账。

## 效果分类

事实层（`lib/frame/parse.js`／`facts.js`）把一次调用拆成**作用项**，每项带一个角色；档位不在这里定，
这里只说「实际会发生什么」。角色一共十种，台账与证据块都按它显示：

| 角色 | 含义 | 例子 |
|---|---|---|
| `executable` | 被执行的那个程序本体（带路径时才记） | `/usr/bin/python3 -V` |
| `script-read` | 解释器读进来执行的脚本（**读**，不是写目标） | `python -S sync_docs.py --help` |
| `read-source` | 被读的文件 | `cat a.md`、`cp a.md x` 的源 |
| `stdin` | 输入重定向／here-string 的数据源 | `cat < in.txt` |
| `read-manifest` | 一张「文件清单」本身 | `wc --files0-from=list`、`tar -T list`、`xargs -a list` |
| `write-destination` | 真正的写目的 | `> out`、`sort -o out`、`cp a.md dir/` 的 `dir/a.md` |
| `directory-container` | 当作容器读的目录 | `grep -r x .`、`ls dir` |
| `delete` | 删除目标 | `rm -f a.md` |
| `network-source` / `network-destination` | 网络面的「取回」／「送出·远端执行」 | `curl URL`／`scp a.txt host:/` |

四条容易算错的形状，现在按真实效果记：

1. **解释器 + 脚本**：`python -S …/sync_docs.py --help` 的脚本是 `script-read`。旧形按「像路径」把它当写目标，
   于是整条只读命令落进写档、理由还指向 `~/.dsh`。
2. **输入重定向**：`cat < in.txt` 的 `<` 是 `stdin`（读），不把整段变成写；`>`／`>>`／`2>` 仍是写目的。
3. **cp／mv 到已存在的目录**：真正被写的是「目录 + 源文件名」（`cp a.md .` ⇒ `<ws>/a.md`），
   容器目录单列在 `container`，不会再让 `.` 本身命中「工作区根本体」。反向：`rm -rf <ws>` 仍是根级下界。
4. **清单旗标**：`--files0-from`／`-T`／`-a` 的取值按 `read-manifest` 读，列出的名字展开成读面；
   `xargs -a list rm` 的内层是删除程序时，展开项仍按 `delete` 记、整段仍走删除档。

**读的举证要看得见全貌**（`completeness`）。递归读（`grep -r`、`rg`、`find`）会把读面枚举进目标集，上限
深度 4／访问 800／条数 20；任一触顶记 `truncated`，读目录或 `lstat` 失败记 `error`，两者都**不许**走
「已证明只读」那行。没有列出任何目标的调用同样不换免检；扫描报错不当「没发现」。
宿主原生读工具（`read`／`grep`／`glob`／`ls`）省略 path 时，读面是宿主默认 cwd，会把这一格展开成
真实作用项，不再出现「作用项空、照样放行」。`sed -n 1p file` 这类纯打印也举得出只读证（脚本只认
行号＋p／d／n，且不带 `-i`／`-e`／`-f`）；换成 `python -c open()` 则仍交模型——差在事实层，
不在路由层。
方言按归一 basename 分档（`Get-ChildItem`／`findstr.exe` 与 `ls`／`grep` 同一套判据），
单引号里的 `*`、`;`、`$` 是字面量，不当通配／分段／展开（未加引号的照旧算）；双引号里的 `$` 仍会展开，整词环境变量按判定这一刻的取值算死（见不变量 16）。
`proven-read` 还要过**任务资源范围**：本项目与已装技能的说明读直放；别的项目的业务／架构／
面板／配置档案即使只读也交模型判必要性（人写的允许行仍可显式开口）。

## 它到底看什么（隐私边界）

- **命令与工具入参原文**：解析出目标路径、程序名、操作维度。写进台账前经过脱敏与截断（`commandPreview`＝脱敏后 400 字），但**本机绝对路径会原样入库**——台账是明文 JSONL，路径本身按敏感件对待。
- **目标的元数据，不读内容**：对解析出的目标做一次 `lstat`，只取「存在／类型／字节数」三个字段（用来判「删的是不是普通文件」「内容有没有第二份副本」）；另外在工作区内跑三条只读 `git`（`rev-parse`／`ls-files`／`status`）。**没有任何文件内容被打开**。命中 `credential-dir:*`／`credential-file:*` 的路径在**读操作**上不查（存在性与大小对密钥类文件也是信息，而那一档的判定不需要它），证据里如实写 `kind: unchecked`；写／删照旧查——那两档要靠 `kind`/`bytes` 才能判。
- **送给模型的内容**：命令、目标与元数据、信任区状态、最近的用户意图，按 `evidenceBudget` 裁剪；超预算＝`unable` 转人工，绝不做半截审查。证据块发出前也过一遍凭据形状扫描，命中即替换成 `[[SEC-…]]`。
- **⚠ 这一条会离开本机**：审查请求经宿主的 LLM 通道发往**你配置的 provider**（`reviewerSource: session` 跟随当前会话的模型，`preset` 用你填的 provider/model）。也就是说证据文本（含路径与命令）会到达那个模型服务。不能让内容出机器的场景，把 `mode` 设成 `off` 或不要把 `auto-approval` 档接给远端模型。
- **工具返回结果**：结果侧脱敏（凭据形状 → `[[SEC-…]]`，映射表落 `~/.dsh/auto-approval-frame/secrets.json`，上限 200 条），脱敏后的文本才回给模型；扫描本身需要读结果文本。`autoRestoreSecrets` 默认开，但只把**有证**的写入换回明文（无证跳过），命令参数里的占位符仍换不了。
- **结构化内容与文本同一把尺**：工具返回里的结构化 `value`、嵌套对象、`decision.value` 替换，与文本块走同一张敏感表、同一个检测结果——`{password: "…"}` 和文本 `password=…` 遮出同一个占位符，键名命中你自己加的规则时值也会被遮。唯一挡不住的是宿主在插件投影**之后**自己拼进最终结果的那部分（见边界第 11 条）。
- **不存的东西**：文件内容、工具结果的完整原文（只留截断摘要）、密钥明文（映射表只在本机，且导出台账时不带上）。
- **保留**：`retentionDays`（默认 90 天）与 `maxTotalBytes`（默认 512 MB）到点整段裁剪，裁剪记录进 `manifest.jsonl` 的 sha256 墓碑，链仍可校验。
- **本包不联网**：除宿主 LLM 调用外无任何外部请求；诊断路由只回环（非 `127.0.0.1` 直接 403）。

## 边界：这个插件保证什么、不保证什么

这一节每句都能指到实现处，能改、也能核。把它当成装机前必读：把「我不拦」读成「系统安全」是要出事的。

1. **「允许」说的是本插件不拦，不等于宿主一定放行。** 本插件的结局记在自己的那一格，宿主的返回另记一格（`lib/index.js` 里 `layer:'host'` 那格）；本插件交出结论之后，宿主自己的策略与 guard 仍可能再问一次或直接拒（`lib/frame/ladder.js` 的 `walkLadder()`，人工档交给宿主面板）。所以台账里两格结论不一致是正常的——记的就是"谁说了什么"。
2. **本插件跑在应用层，不是 OS 隔离。** 它接管的是审批这道门，不是进程的权限边界：`auto-approval` 这个档本身就是宿主给的 `danger-full-access` ＋ `approval: ask`（`cordis.patch.yml`），在它下面命令照样能读写你整个用户目录。本插件能做的只是"在它发生之前问你"；宿主把档钉成 `never` 的会话它不接管，也就一个字都拦不住。要真隔离请用沙箱／容器／只读挂载，不是装这个插件。
3. **遮掉的明文靠 token 占位，裸值本身遮不住。** 脱敏只发生在两处：命令进台账前换的是**副本**（`lib/index.js` 的 `commandPreview ＝ sanitizeText(redactSecrets(command), 400)`），工具结果回给模型前换成 `[[SEC-<12 hex>]]`（`maskBlocks()`／`scanBlocks()`）。而已经到模型手里的原文、以及命令参数里的 token（宿主契约禁止插件改写参数）都换不回来——值一旦以明文进了一条命令，就按已经泄露处理，别指望台账能替你收回。
4. **二进制与超长载荷未扫描，台账会如实写"未扫"。** 超过 `MAX_SCANNED_CHARS` 的块由 `tooBigToScan()` 判出、不进检测面，`unscanned` 计数随台账一起写进审计库。"链可校验"不等于"内容都看过"。
5. **敏感判据靠文件名与形状，改名就绕得过。** 检测是形状＋名字两张表（`lib/frame/sensitive.js` 的 `DETECTOR_SHAPES`、`lib/frame/grant.js` 的 `isSensitiveBasename()`）：把 `id_rsa` 改名成 `key.txt`，名字那一档就不再命中。它接得住常见泄露形态，不是内容分类器。
7. **你自己加的允许行会盖住预设行。** 用户行与预设行同表同序，命中第一条给出结论的行即停（`lib/frame/policy.js` 的 `effectiveRows()` 与 `walkOne()`）。把一条允许行拖到"凭据目录"那一行的上面，那条下界就对你这台机器失效——这是设计（表本来就是给你改的），也是你要自己承担的那部分。
9. **回填的"哪些文件真的写成"没有宿主通道。** `ToolExecutionResult` 只有 `isError`／`value`／`content`／`error`／`meta`／`additionalContexts`／`concludesTurn`，没有"实际写入的文件集合"（宿主 `packages/core/tools/src/index.ts` 的类型定义）。所以自动回写（默认开）只能按插件自己事实层的**写目标**推断，再去读回文件核对版本；它不保证"执行器确认每个中间目标都落地了"——后台命令成功、脚本最后一行成功，都不等于每个中间目标写成。要更硬的保证，需要宿主在执行侧报告写入集合。

8. **总开关的字面义＝只关判定，不关遮罩。** `enabled: false`（或 `mode: off`）停掉的是"拦／问／放"这套判定（`lib/index.js` 的 pre-execute 第一行就交回宿主）；**结果脱敏与台账照常跑**——它不拦不问，只把命中换成占位符并记账（`tools/post-execute` 没有开关闸，这是有意的：安全设施不跟判定档一起拆）。要"结果原样进模型"，得卸载插件，不是关开关。

10. **"用户批准"只有一种可信来源：他自己打的字。** 授权来源表在 `lib/frame/gate.js` 的 `AUTHORIZING_SOURCES`，当前只有 `user`。`tool/result` 里的 `answers`（工具的问答回传）是**结果**，不是批准——远端工具可以伪造它，所以它既不进 `userIntents()`，也不参与放行；`test/authority.test.mjs` 有一条显式用例：伪造 `answers` ＋助手自称"用户同意了" ⇒ 判不出授权、外传行仍是 `ask`。宿主的"计划批准"（approve-plan 那类）若将来要算数，必须先在 `AUTHORIZING_SOURCES` 里登记成一种带凭据的来源，再由 `userIntents()` 收；在那之前它只能当背景。**这就是宿主缺的那块能力**：宿主不提供"这次问答的批准是一次可验证的用户决定"的记录，本插件只能退回到"只认用户原话"，于是"用户已经在计划里点过同意"这件事在判定层是隐形的。

11. **回填只能绑到"哪一次调用"，绑不到"执行器确认哪些目标真的落地"。** `lib/index.js` 两处同批接线：签发时把 `callId` 与效果 hash 写进证（`vault.grantUse()`），回填时把同一个 `callId` 传下去（`restoreVaultedWrites()`）；只接一侧会让所有消费判 `grant.call`（`test/authority.test.mjs` 有这条负例）。但宿主仍不提供"实际写入的文件集合"，所以"这次调用确实写了这个文件"只能靠插件读完文件核对版本——这是上面第 8 条同一个缺口，这次没有把它补上，也不假装补上了。
12. **插件遮的是副本，宿主最终组包仍是原件。** 结果脱敏发生在插件的 `tools/post-execute`：它改写的是交给宿主的 decision 副本；宿主把最终结果组装出去（`packages/core/tools/src/index.ts:1807` 一带的 `markCanonical`）时，还有 finalization 等宿主自己的环节可以往结果里加内容——那部分插件看不见也拦不住，只能在 `tools/result` 观察冻结结果、发现凭据形状时如实记账（`sensitive.final-hit`）。要把这最后一道口也封上，需要宿主在执行器层提供最终投影点；在那之前，"结果绝对干净"这个说法不成立。

## 秘密回填：三条承诺各靠什么

回填（`autoRestoreSecrets`）默认开。它承诺三件事，每件都能指到实现处，也都有用例能把它打破。

- **默认开但要有证**：缺省值是 `true`（`lib/index.js` 的 `autoRestoreSecrets: z.boolean().default(true)`，设置页同一个开关在 `lib/client.js`）。**开只代表允许尝试**：`restoreVaultedWrites()` 仍逐字段验回写证（会话＋目的文件＋用途＋callId＋effectHash＋一次性），无证或证不合 ⇒ `sensitive.restore-skipped`，明文一个字节都不落盘——不是「回了但被拦」，也不是「默认开＝默认放」。
- **一次性**：同一张证只兑现一次，靠 `lib/frame/vault.js` 的 `consumeGrant()` 走 `transact()`——**取锁后重读盘面再判**，判与写在同一个临界区里。两个实例各持同一张证同时消费时，只有一个能进锁看见「还没用过」；另一个进锁后看到 `consumedAt` 已是数字，回 `grant.consumed`。旧实现把「判」放在内存快照上、只在写盘时合并，两边都会成功而盘上只留一份——那不是一次性，是巧合。
- **跨实例**：删除与整表清空写的是**墓碑**（`{tombstone:{deletedAt,version}}`），不是把条目抹掉；合并按状态机的档位取严（墓碑 > 已消费 > 已撤销／过期 > 有证 > 无证）。持旧快照的实例再保存时，看见盘上档位更高就不会把旧副本塞回去——没有墓碑时，旧实例一次 save 就能把删掉的明文带回表里。墓碑另算配额（50 条），不挤活条目的 200 条上限。

三条都有对应读数在 `test/vault-tx.test.mjs`：真并发（两个子进程同毫秒抢同一张证）、墓碑两轮往返（A→B→A）、状态机表驱动。把 `consumeGrant` 的重读挪回锁外、把 `remove` 退回物理删、把 rename 前的版本复检去掉，各自会让对应用例转红。

## 评审契约：批准＝必要 ∧ 已授权 ∧ 有保障

放行不再等于「模型没看出风险」。`lib/frame/verdict.js` 的 `REVIEW_QUESTIONS` 要求评审逐项回答三问——效果是否必要（`necessary`）、是否被用户的话有效覆盖（`authorized`）、保障是否满足（`safeguarded`）。三问任一为假时，`decision` 写 `allow` 也不成立：`parseVerdict()` 当场改成 `block`，理由码换成 `not_necessary`／`authorization_not_covering`／`safeguards_insufficient`；`mayRelease()` 在 `mode=auto ∧ grant.state=auto ∧ reviewed/allow` 之后再加这一道。

- **证据不完整就不配自动批准**：`projectEvidence()` 把每一处裁剪记成 `{field, kept, lost}`（`clip()`），`incomplete` 由这本账生成，`completeness` 只有 `full`／`partial`／`too-large` 三档。`lib/index.js` 的 `evidenceComplete` 只认 `full`——4500 字正文被裁到 4000 时，即使评审说 allow，结果也落人工，台账写 `evidenceCompleteness:"partial"` 和丢了哪一段。改前这一格是 `tooLarge:false / incomplete:[]`，尾部标记根本不在证据里，评审在残片上照批。
- **没给的部分是未知，不是无害**：被裁的正文旁边给 `payloadDigests`（原文字数／行数／保留多少／丢了多长／首尾各一段／有没有 diff 头）。两处提示都写明不许补猜；判断依赖未见部分时必须回 `unable`。
- **区外不再自动等于未授权**：删掉「落在信任区外 ⇒ `outside_authorized_scope`」这条硬映射，改由覆盖判。证据里给每个目标的 `scope`、`scopeFields`（范围算没算过）、`grantBinding`（目的／资源／排除项／最新撤销／一次性），模型照着算覆盖；范围字段缺席时它只能报缺，不许从「区外」反推「未授权」。
- **一次判定优先**：证据不完整不跑快判（省掉那次必然无收益的调用）；快判 `allow` 即放行，只付一次；只有快判不过才升级深评——升级触发条件就这一条。

读数在 `test/evidence.test.mjs`。把 `clip()` 的记账关掉，判据 1 立刻红（`completeness` 退回 `full`）；把 `mayRelease()` 的三问退回只认 `no_material_risk`，真值表那一行红。

**兼容期**：模型没给 `checks` 时 `mayRelease()` 不额外拒（`contract.known=false`），台账照记这一格，可在审计页筛。要把它收紧成「缺三问也不算批准」，需要新增一档配置——本版没做，记在未闭环清单里。

## 明确不做

自研倒计时（人工档直接用宿主面板）、斜杠命令、学习/熔断、快判的专门分类器、
产物溯源。每条需要判定的调用都付一次快判或深评——这是换取「判定权单一」的代价。

宿主契约不允许插件改写工具参数（`Input rewriting is excluded`），所以：出参侧只做**拒绝／允许**两问，
脱敏只在结果侧发生；模型把 token 写进文件后的修正在**文件层**做（可关，默认开但要有证），命令参数里的 token 换不了。

设置页在 `lib/client.js`，页面顶部是一条判定链（0 是否接管 → 1 安全规则（预设行＋你的有序表；命令面一条命令一行＋末行兜底）→ 2 快判 → 3 深评 → 4 人工 → 5 脱敏，
标出哪几步可配、哪几步固定，点一格跳到对应卡片），卡片顺序就是执行顺序：**接管与模式**（开关／模式／受管权限档）、
**安全规则**（两级页面：默认四行摘要——命令安全／文件安全／网络安全／工具规则，各带一句说明与条数；点一行进明细，`‹ 返回` 回列表。
明细页自上而下＝表头（图标＋标题＋条数）→ 一条工具行（条件输入框／新规则默认动作／＋ 添加）→ 一条说明 → 一张表（用户行与预设行同一个列表，行首「用户／预设」片区分，都可改、都能调序）、
**AI 审查**（模型／快判／自定义审查规则，超时与预算收进「高级」）、**敏感保护**（一张卡两行并列：**检测规则** 走同样两级——摘要行→明细表；**敏感信息** 记着遮出来的占位符，可看明文／开关回写／清空；总闸 `启用检测与脱敏` 画在卡头右侧，
不占一行——`启用本插件` 同形制）、
**审计中心**（保留策略在「高级」，加查询／导出／清空）。一张卡只有一个容器（`.dsa-card`），卡内一律 `.dsa-item` 一种行（字段行／摘要行／规则行／审计条目同形制）。分层靠三档边框＋有色行底：卡框 `border-l3` → 行框 `l2` → 控件 `l1`，行底用自定一档 `--dsa-row`（浅色＝黑 2.2%／深色＝白 4.5%，按宿主主题选择器 `body[data-ds-dark-theme]` 各给一档，只比卡底深一点点）——宿主的 `bg-layer-1/2/3` 在浅色主题下**全是 `#fff`**，靠它拉层级无效，而 `bg-module-platform` 又太深；也不许用投影，分层要有梯度而不是靠影子糊。规则行分两层：上层是编号｜来源片（用户／预设）｜主语与条件｜行操作（拖动把手／启停／删除），下层是读／写／删的动作片（片内＝操作图标＋操作名＋彩色圆点＋档位）——动作片靠右、略小，五张表同一把尺。行首编号只是序号，敏感面命中取最严、不看先后；每行都有启用开关；删除按钮对用户行直接删、对预设行写 `removed` 标记（不显示、不再拉高）。文件／网络／工具面的预设行**条件列是说明文字**（命中由事实层给，改了字也改不了命中范围）；命令面的条件列就是**命令名**（一条命令一行，算法算出的结果只许把档位加严），末行「其他命令」固定末位、没有删除入口与拖动把手；敏感面的条件列才是可改的正则；文件面的预设行与用户行同形制：读／写／删三颗档位片各自表态（只放行 `~/.ssh` 的读、`~/.aws` 仍必人工，就是这个粒度才做得到）；路径说明可换行显示全。动作片统一带一枚动作色点（行内与工具条「新规则默认」同一套片子，四档只靠彩点区分：拒绝红／人工黄／AI 靛蓝／允许绿（片子白底，不再整片染色）；不带操作名的单动作片统一最小宽度，AI 不会比「人工」窄一截），**不嵌原生 `<select>`**（系统弹出层比片子窄一圈、字也更小，点开就风格断档），也不是摊在行里的一排按钮：点片子弹出一个**贴在片子正下方的浮层菜单**（宽度不小于片子、l3 边框＋实底、无投影），选项行 30px 高、按动作着色、当前项打勾，点外面或选中即收起，一屏只开一个。文件行的读／写／删三颗片在第二行右对齐；拖动把手排序，拖到预设行之间时会整表物化一次以持久化顺序。保存／撤销：干净态只是页尾一行，**有待保存改动才**升格成粘底悬浮条（`.dsa-footer.is-dirty`），按钮靠右＝说明在左 → 撤销 → 保存最右。
样式集中在 `settingsCss()` 注入的一张 `<style>`：内联 style 给不了
`:hover` 与 `disabled` 两态，而这套页面全靠这两态才看得清；颜色全部走宿主设计令牌，深浅色自动跟随。宿主本来会给没注册自定义页的插件**自动生成一张表单**（`autoGenerate`：
"Generate a page if no custom page is registered for this instance"，见 `@deepseek-ai/dsh-api-remotes`
客户端），那张表直接用 schema 键名当标签 ⇒ 没有客户端半时看到的就是英文键名页。注册自定义页后由本文件接管。
写入只经 `form.mutate([{op:'set',path:[key],value}])`，且只能点名 volatile 字段（＝`EDITABLE_KEYS`）；
`debug` 在卡片上只读，改动走 profile 补丁；`gatedPresets` 在「接管与模式」卡按宿主 live 权限目录勾选。预设保护与生效的信任／开口／被拒行由
`GET /api/auto-approval-frame/frame` 从宿主读回，页面不自己复算。
规则行写成**一句话**：`当 命令 匹配 [git push --force] → [拒绝]`；文件面在同一句里嵌 读／写／删 三颗片（留空＝不表态，后面那行仍可管）。
读序＝语法序，不需要读者去对列，条件还能就地改。页面顶部的**模拟审批**（原名「试算」→「模拟执行」→「模拟审批」，名字都由用户定；按钮「模拟一下」，输入框 460px 一行高；`GET /api/auto-approval-frame/explain`，同源只回环）把一条命令喂给判定链，
逐步回落在哪一关、为什么，决定步之后一律标「不再走」；它不调模型、不执行任何东西，答的是「为什么会这样」而不是「AI 会不会同意」。

**会话侧只做两件事：预设文案与 aria 按界面语言改写、给本档补图标**（在本机跑通的判据：
图标只加在宿主确实给其他档位画图标的面——权限菜单行与输入框触发器；弹层行与设置选择器只改文案；
纯文本列表不塞孤立图标；原文留档以便语言切换还原；每轮清孤儿图标）。

**不劫持宿主点击。** 上一版在这里加了「启用前风险确认」：捕获阶段 preventDefault 拦下对「自动审批」行的
点击，事后再对该节点补发一次 click —— 但宿主菜单一关，节点已脱离文档，补发的点击走不到宿主挂在容器上的
委托监听，结果是**确认了却切不过去**。插件不该假借宿主的交互通道，故这道门整段移除；
高风险档的把关回到预设下界与判定链本身。回归里锁了一条硬判据：点击「自动审批」必须直达宿主。

---

## English

An interception and audit frame for DeepSeek Harness. It manages one permission tier (`auto-approval` by default): every tool call walks preset protections, the ordered rule table, a read-only fact gate, AI fast/deep review, human approval, and result redaction. Every event is written to a hash-chained, day-segmented audit store.

### Install

- Install from the DSH plugin market, or `dsh plugin --profile <profile> add dsh-auto-approval-frame`.
- Restart DSH, open Settings → Plugins → Auto Approval Frame, and choose the managed tier(s) under **Managed permission tiers** — normally only **Auto approval**.

### Managed permission tiers

The bundle patch ships `auto-approval` (`danger-full-access` sandbox + `approval: ask`). A profile-level `permission` row overrides the whole table; if you own one, add `auto-approval` there or select an existing custom tier in the page.

The page lists only `auto-approval` plus custom tiers. Read-only / workspace-write / danger-full-access are not listed: read-only has nothing to release, workspace-write's grant is `confirm` (AI cannot release), and danger-full-access pins approval to `never` (no prompt). A saved legacy choice stays visible so you can switch it off. When a managed tier is missing, the page reports it with a copyable profile snippet.

### What it writes

- `~/.dsh/auto-approval-frame/audit/`: hash-chained day segments, manifest, state, legacy imports.
- `~/.dsh/auto-approval-frame/`: the local reversible token vault (secrets are masked before they reach the model).

### Language

The settings page follows the host locale (`<html lang>`): Chinese clients get Chinese, English clients get English. README Chinese is the full reference; this section is the English summary. Audit messages are stored as generated.

### Tests

```bash
node test/frame.test.mjs && node test/effects.test.mjs && node test/wiring.test.mjs && node test/client.test.mjs
```

Not affiliated with DeepSeek.

