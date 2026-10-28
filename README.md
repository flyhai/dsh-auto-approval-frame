# dsh-auto-approval-frame

DeepSeek Harness 的拦截与审计框架。每次工具调用走一条拦截梯，全部事件进同一本可校验的审计库。

本包是独立实现，只保留一条判定轴：内置保护 → 有序规则 → 事实门 → AI 快判 → AI 深评 → 人工 → 结果脱敏。

## 安装

- 在 DSH 插件市场搜索「自动审批框架」→ 安装 → 重启。
- 或 `dsh plugin --profile <profile> add dsh-auto-approval-frame`。
- 安装后打开「设置 → 插件 → 自动审批框架」确认启用；在会话权限菜单里选择「自动审批」档。

## 权限档

本插件只接管 `gatedPresets` 里的权限档，默认 `auto-approval`。这个档由本包的 bundle patch 提供（`danger-full-access` + `approval: ask`，见 `cordis.patch.yml`）；全新 profile 装完就能在权限菜单选到。

如果你的 profile 自己定义了 `permission` 表，它会整行覆盖本包的表（同 id 不深合并）。这时保留你已有的档，并把 `auto-approval` 加进去；或者把 `gatedPresets` 改成你已有的档。受管档不存在时，启动日志会写 `missingGatedPresets`，设置页的「接管与模式」卡会红字报出名字并给出可复制的 profile 片段——在它出现之前，插件不接管任何会话。

> 前提：宿主审批策略必须是 `ask`。`DSH_PERMISSION_MODE=danger-full-access` 会把宿主钉成 `never`，此时没有审批请求，本插件也不接管。

## 拦截梯

```
tools/pre-execute(exec, next)
 ├ L0 下界    facts → grant：never / confirm / auto          lib/frame/{paths,parse,facts,grant,gate}.js
 ├ L1 规则    tool → command → file → network → sensitive     lib/frame/policy.js
 │            四档：拒绝 > 人工 > AI > 允许
 │            平面内首条命中即停；跨平面取最严
 │            允许＝真放行（不调模型、不弹面板，但台账必须写得下去）
 ├ 事实门     纯只读 → 直接放行（留 fact 记录，不付费）
 ├ L2 快判    单段写/删 × grant=auto：allow 或升级            lib/frame/{review,verdict}.js
 ├ L3 深评    一次模型调用：allow / block / unable            lib/frame/{evidence,review,verdict}.js
 ├ L4 人工    交宿主官方审批面板，不自研倒计时                 lib/index.js
 └ L5 脱敏    结果侧命中就遮成确定性 token；明文只落本机映射表  lib/frame/{sensitive,vault}.js
        ↓ 按 callId + actionHash 存一条 pending
approval/request(req, next)  只读 pending，不重新推导          lib/frame/pending.js
```

上面这条链只有**一份实现**：`lib/frame/ladder.js` 的 `walkLadder()`。`tools/pre-execute`（真判定）
与 `GET /api/auto-approval-frame/explain`（设置页的模拟审批）都吃它，步骤文案与结论由 `ladderSteps()`／
`ladderVerdict()` 从同一个 walk 派生——模拟不可能对同一件事说两套话。`test/wiring.test.mjs` 里另有一条
差分锁：逐条比较「模拟给出的落点」与「真判定写进台账的第一条定局行」。

一处例外要说清：层级名字有两份表——`lib/frame/audit.js` 的 `LAYER_TEXT`（导出件用，node 侧）和
`lib/client.js` 的 `LAYER_LABEL`（页面用，webview 侧，运行时拿不到 node 模块）。`test/client.test.mjs`
按字面比对两张表，键值必须逐字相同；启动／配置／迁移这些行用 `layer=lifecycle|config`，不冒充内置行。
模拟审批还照例标一句判定所依据的目录：真判定按各会话的 `cwd` 解析路径，模拟只能按宿主进程目录，
不说就会被当成「模拟和实际不一样」。

审计不在这条梯上，而是包住它：每个事件（含 delegated／规则／人工／配置／启停／迁移／脱敏／清空）
都写进 `lib/frame/audit.js`。

## 不变量（回归锁死）

1. `never` 不进模型：凭据树、系统关键树、`.git` 内、DSH_HOME 状态树（未被允许行开口）、家目录/盘根/工作区根本身。
2. 静态规则四档：`deny`／`ask` 只往严的方向决定；`ai`＝这一行不拦、继续往下判；`release`（允许）＝**真放行**，不调模型、不弹面板，但必须先写得下一条可追责的台账，写不下就降级人工。
3. ALLOW 只在 `grant=auto × mode=auto` 有释放力；`confirm` 档的 ALLOW 只作为建议随弹窗展示。
4. `allow ⇔ reasonCode=no_material_risk`；矛盾即改写为 block。快判的 block 只表示「升级到深评」。
5. `unable`（超时/坏 JSON/路由不可用/证据过大）一律回落人工，绝不静默放行。
6. `approval/request` 不调用 L0/L1；pending 按 `actionHash` 绑定，动作漂了不继承判决。
7. 放行写不进审计库 ⇒ 降级为人工（规则「允许」、事实门、快判与深评四个放行出口同一约束：本插件放行的，都要有账可查）。
8. 只读命令走事实门：不送模型；但留一条 `layer=fact` 记录（全事件可审计）。`compress`／`decompress`／`acp_status`／`acp_cache`／`todo_write` 这类只编辑会话的内部工具同样走事实门。
9. 语气不构成授权证据：情绪化语句降级进非授权背景块，内容照录、授权标签摘除。
10. 结果侧命中就遮，**与档位无关**：任何一档（含允许）先换成确定性 token `[[SEC-<12 hex>]]`，档位只决定遮完之后是问你、放行还是整段不给模型。明文只落本机 `secrets.json`（200 条／30 天），列表默认不出明文，查看明文单独取一次并入账。
11. 人工答复与工具结果都入账：`approval.answer`（已批准／已拒绝／已取消）与 `tool.result`（成功／失败＋结果首段），所以一条 ask 不会在列表里留下没有结局的悬尾。
12. 自动回写只发生在**文件层**且只换本表铸出的 token：写完后读回、原子重写，跳过凭据／系统树、符号链接、超 4 MB 与读不出的文件；命令参数里的 token 换不了（宿主契约禁止改写参数）。

## 配置（22 个可写键 + 2 个补丁专属键）

| 键 | 默认 | 含义 |
|---|---|---|
| `enabled` | true | 总开关 |
| `mode` | `auto` | `off` 全交宿主面板／`advise` AI 只建议不释放／`auto` ALLOW 可释放 |
| `gatedPresets` ⓟ | `['auto-approval']` | 按会话原始权限身份判定，不看折叠后的 current() |
| `reviewerSource` | `session` | `session`＝跟随会话（用当前对话同一个模型）／`preset`＝指定预设（从宿主已注册的 provider＋model 里挑，页面是一行下拉） |
| `reviewerProvider` `reviewerModel` | `''` | `preset` 来源时必填 |
| `reviewerMaxTokens` | 512 | 深评输出上限，64–4096 |
| `reviewerTimeoutMs` | 20000 | 深评硬超时，1s–120s，单次调用不重试 |
| `evidenceBudget` | 16000 | 深评证据总预算；分块上限 8000/4000/1000/2000，超出按优先级从低到高裁 |
| `reviewRules` | `[]` | 操作员附加规则，作为**数据**随深评提示，只能收窄 |
| `commandRules` `networkRules` `toolRules` | `[]` | 每行 `{action, match}`，action＝`release`／`ai`／`ask`／`deny`，按数组顺序首条命中即停；内置行用户副本另带 `preset` |
| `fileRules` | `[]` | 每行 `{match, read, write, delete}`，三列各选四档之一或空（＝不表态） |
| `sensitiveRules` | `[]` | 检测规则表：内置 7 条形状（`preset` 覆盖行可改正则／档位／停用）＋自己的行；命中取最严，不看先后 |
| `sensitiveDetect` | true | 检测与处置总闸；关掉＝这张表不表态，工具结果原样进模型 |
| `autoRestoreSecrets` | false | 写文件后把本表铸出的 token 换回明文（仅文件层，跳过凭据／系统树与符号链接） |
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

### 允许行能开到哪一步

允许是真放行：命中即不调模型、不弹面板，但仍要写一条规则层台账（写不进去就降级人工）。
内置行不再高于你的行：21 条内置行（文件 14／命令 6／工具 1）与 7 条检测形状都铺在表里，换档位、停用、改敏感面正则都算数——
把「凭据与客户端目录」改成允许或停用，这一条就不再拉高。哪些行**不该**允许（真正危险的名单）留待后续讨论，本版不设特例。
允许行同时是信任声明：命中的路径不再算「工作区外」，其删除也不再算「内容不可恢复」，`~/.dsh` 的子树也可以被开口；
但整棵 `~/.dsh` 与含凭据段的子树仍会被拒收成信任根（`GET /api/auto-approval-frame/frame` 把被拒的行连同原因报给页面）。
敏感面的允许只放这次调用，结果该遮还是遮。

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
  导出与清空分别走 `/audit/export` 与 `/audit/clear`；判定链读侧（内置保护／生效信任与开口／被拒的允许行）走 `/frame`。
  页面在 webview 里，没有 `fs`。
- 审计中心默认隐藏 `lifecycle.boot`（每次重启一条的启动记录）；筛选行的「隐藏启动记录」开关可关，
  或把分类选成「生命周期」直接看。隐藏只影响列表与导出，记录照常入账。

## 明确不做

自研倒计时（人工档直接用宿主面板）、斜杠命令、学习/熔断、快判的专门分类器、
产物溯源。每条需要判定的调用都付一次快判或深评——这是换取「判定权单一」的代价。

宿主契约不允许插件改写工具参数（`Input rewriting is excluded`），所以：出参侧只做**拒绝／允许**两问，
脱敏只在结果侧发生；模型把 token 写进文件后的修正在**文件层**做（可关，默认关），命令参数里的 token 换不了。

设置页在 `lib/client.js`，页面顶部是一条判定链（0 是否接管 → 1 安全规则（内置行＋你的有序表）→ 2 事实门 → 3 快判 → 4 深评 → 5 人工 → 6 脱敏，
标出哪几步可配、哪几步固定，点一格跳到对应卡片），卡片顺序就是执行顺序：**接管与模式**（开关／模式／受管权限档）、
**安全规则**（两级页面：默认四行摘要——命令安全／文件安全／网络安全／工具规则，各带一句说明与条数；点一行进明细，`‹ 返回` 回列表。
明细页自上而下＝表头（图标＋标题＋条数）→ 一条工具行（条件输入框／新规则默认动作／＋ 添加）→ 一条说明 → 「自定义（N）」组 → 「内置（N）」组，两组同形制、都可改）、
**AI 审查**（模型／快判／自定义审查规则，超时与预算收进「高级」）、**敏感保护**（一张卡两行并列：**检测规则** 走同样两级——摘要行→明细表；**敏感信息** 记着遮出来的占位符，可看明文／开关回写／清空；总闸 `启用检测与脱敏` 画在卡头右侧，
不占一行——`启用本插件` 同形制）、
**审计中心**（保留策略在「高级」，加查询／导出／清空）。一张卡只有一个容器（`.dsa-card`），卡内一律 `.dsa-item` 一种行（字段行／摘要行／规则行／审计条目同形制）。分层靠三档边框＋有色行底：卡框 `border-l3` → 行框 `l2` → 控件 `l1`，行底用自定一档 `--dsa-row`（浅色＝黑 2.2%／深色＝白 4.5%，按宿主主题选择器 `body[data-ds-dark-theme]` 各给一档，只比卡底深一点点）——宿主的 `bg-layer-1/2/3` 在浅色主题下**全是 `#fff`**，靠它拉层级无效，而 `bg-module-platform` 又太深；也不许用投影，分层要有梯度而不是靠影子糊。规则行是**固定六列网格**（编号｜句子｜条件｜时｜动作片｜操作），内置行走同一套列——所以「拒绝／人工／AI／允许」在五张表里都竖着排成一条线。行首编号只是序号，敏感面命中取最严、不看先后；内置行不能删，只能停用（档位、启用开关都在行上）。命令／文件／网络／工具面的内置行**条件列是说明文字**（命中由事实层给，改了字也改不了命中范围），敏感面的条件列才是可改的正则；文件面的内置行只画一颗档位片（事实层给的理由不分读／写／删）。动作片**不嵌原生 `<select>`**（系统弹出层比片子窄一圈、字也更小，点开就风格断档），也不是摊在行里的一排按钮：点片子弹出一个**贴在片子正下方的浮层菜单**（宽度不小于片子、l3 边框＋实底、无投影），选项行 30px 高、按动作着色、当前项打勾，点外面或选中即收起，一屏只开一个。文件行的读／写／删三颗片不换行。保存／撤销：干净态只是页尾一行，**有待保存改动才**升格成粘底悬浮条（`.dsa-footer.is-dirty`），按钮靠右＝说明在左 → 撤销 → 保存最右。
样式集中在 `settingsCss()` 注入的一张 `<style>`：内联 style 给不了
`:hover` 与 `disabled` 两态，而这套页面全靠这两态才看得清；颜色全部走宿主设计令牌，深浅色自动跟随。宿主本来会给没注册自定义页的插件**自动生成一张表单**（`autoGenerate`：
"Generate a page if no custom page is registered for this instance"，见 `@deepseek-ai/dsh-api-remotes`
客户端），那张表直接用 schema 键名当标签 ⇒ 没有客户端半时看到的就是英文键名页。注册自定义页后由本文件接管。
写入只经 `form.mutate([{op:'set',path:[key],value}])`，且只能点名 volatile 字段（＝`EDITABLE_KEYS`）；
`gatedPresets`/`debug` 在卡片上只读，改动走 profile 补丁。内置保护与生效的信任／开口／被拒行由
`GET /api/auto-approval-frame/frame` 从宿主读回，页面不自己复算。
规则行写成**一句话**：`当 命令 匹配 [git push --force] 时 → [拒绝]`；文件面在同一句里嵌 读／写／删 三颗片（留空＝不表态，后面那行仍可管）。
读序＝语法序，不需要读者去对列，条件还能就地改。页面顶部的**模拟审批**（原名「试算」→「模拟执行」→「模拟审批」，名字都由用户定；按钮「模拟一下」，输入框 460px 一行高；`GET /api/auto-approval-frame/explain`，同源只回环）把一条命令喂给判定链，
逐步回落在哪一关、为什么，决定步之后一律标「不再走」；它不调模型、不执行任何东西，答的是「为什么会这样」而不是「AI 会不会同意」。

**会话侧只做两件事：预设文案与 aria 按界面语言改写、给本档补图标**（在本机跑通的判据：
图标只加在宿主确实给其他档位画图标的面——权限菜单行与输入框触发器；弹层行与设置选择器只改文案；
纯文本列表不塞孤立图标；原文留档以便语言切换还原；每轮清孤儿图标）。

**不劫持宿主点击。** 上一版在这里加了「启用前风险确认」：捕获阶段 preventDefault 拦下对「自动审批」行的
点击，事后再对该节点补发一次 click —— 但宿主菜单一关，节点已脱离文档，补发的点击走不到宿主挂在容器上的
委托监听，结果是**确认了却切不过去**。插件不该假借宿主的交互通道，故这道门整段移除；
高风险档的把关回到内置下界与判定链本身。回归里锁了一条硬判据：点击「自动审批」必须直达宿主。

