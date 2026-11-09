// AI生成
window.__ModuleLoader__.load({
	id: "dsh-auto-approval-frame",
	factory: (require) => {
		const module = { exports: {} };
		const exports = module.exports;
		const react = require("react");
		const primitives = require("@deepseek-ai/dsh-client-ui-primitives");
		const { Button, Input, Switch, SegmentedControl } = primitives;

		const name = "dsh-auto-approval-frame";
		const inject = ["slots", "locale", "configForms"];
		const PACKAGE_NAME = "dsh-auto-approval-frame";
		const PLUGIN_NAME = "dsh-auto-approval-frame";
		const ROW_ID = "auto-approval-frame";
		const ROW_CONFIG_KEY = `${PACKAGE_NAME}#${ROW_ID}`;
		const LOCALE_NS = "dsh-auto-approval-frame";
		const AUDIT_ROUTE = "/api/auto-approval-frame/audit";
		const AUDIT_EXPORT_ROUTE = "/api/auto-approval-frame/audit/export";
		const AUDIT_CLEAR_ROUTE = "/api/auto-approval-frame/audit/clear";
		const FRAME_ROUTE = "/api/auto-approval-frame/frame";
		const MODELS_ROUTE = "/api/auto-approval-frame/models";
		const SECRETS_ROUTE = "/api/auto-approval-frame/secrets";
		const EXPLAIN_ROUTE = "/api/auto-approval-frame/explain";
		const EXPLAIN_COMMAND_ROUTE = "/api/auto-approval-frame/explain-command";
		// apply() 时留住宿主上下文：会话「审计」标签里的「设置」按钮要用它的导航服务。
		// 插槽组件本身拿不到 ctx，宿主也不把 ctx 透传给 conversation.view 的贡献。
		let hostCtx = null;
		// 卡头只有一行且不认换行，出处／目标／评审原话／评审看到从这里按 callId 取。
		const CARD_DETAIL_ROUTE = "/api/auto-approval-frame/card-detail";
		// 审计卡上就地加一条工具规则（只写用户行）。
		const TOOL_RULE_ROUTE = "/api/auto-approval-frame/tool-rule";
		const RULES_CODEC_ROUTE = "/api/auto-approval-frame/rules/codec";
		// 敏感规则的条件值落盘是密文（`enc:v1:`）：页面显示明文，保存前再封回去。
		const SEALED_PREFIX = "enc:v1:";
		const isSealedValue = value => typeof value === "string" && value.startsWith(SEALED_PREFIX);
		const hasSealedRows = rows => Array.isArray(rows) && rows.some(row => isSealedValue(row?.match));
		async function codecSensitiveRows(op, rows) {
			const response = await fetch(RULES_CODEC_ROUTE, {
				method: "POST",
				credentials: "same-origin",
				cache: "no-store",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ op, plane: "sensitive", rows }),
			});
			const body = await response.json().catch(() => ({}));
			if (!response.ok || body.ok !== true)
				throw new Error(body.error || `HTTP ${response.status}`);
			// 宿主回什么都不能把「不是行数组」写进配置：这不是类型洁癖，是防一次静默清空。
			if (!Array.isArray(body.rows))
				throw new Error('规则封装接口没有返回行数组');
			return body.rows;
		}

		const ICON_ATTRIBUTE = "data-frame-icon";
		const LABEL_ATTRIBUTE = "data-frame-label";
		const ORIGINAL_LABEL_ATTRIBUTE = "data-frame-original-label";
		const ORIGINAL_ARIA_ATTRIBUTE = "data-frame-original-aria";
		const PERMISSION_LABEL_SETS = {
			readOnly: ["Read Only", "仅可查看"],
			workspaceWrite: ["Workspace Write", "工作区内修改"],
			auto: ["Auto approval", "自动审批"],
			fullAccess: ["Full access", "完全权限"],
		};
		const SHIELD_PATH = "M6.59624 2.14853C7.50155 1.80917 8.49914 1.80919 9.40444 2.14859L13.9245 3.84317V7.11961C13.9245 11.6089 10.5565 13.5975 8.00035 14.5779C5.44423 13.5975 2.07544 11.6089 2.07544 7.11961V3.84317L6.59624 2.14853Z";
		const BOLT_PATH = "M8.692 5.152 6.074 8.231 8.019 8.231 7.289 11.039 9.926 7.724 8.103 7.724Z";
		const CONFIGURED_AUTO_NAME = "Auto approval";
		const languageOf = (doc) => String(doc?.documentElement?.lang || doc?.defaultView?.navigator?.language || "");
		const autoName = (doc) => (/^zh(?:-|$)/i.test(languageOf(doc)) ? "自动审批" : CONFIGURED_AUTO_NAME);
		// ── page copy: Chinese source, English overlay ───────────────────────
		// The settings page is built from plain React elements. `h` is the one
		// place that turns the tree into elements, so UI strings are translated
		// here (children and the handful of display props) instead of at 200+
		// call sites. Unknown strings — paths, commands, audit messages — pass
		// through unchanged; the dictionary only matches known UI copy.
		const hostCreateElement = react["createElement"];
		const uiEnglish = () => /^en(?:-|$)/i.test(languageOf(globalThis.document));
		const UI_EN = {};
		const UI_DYNAMIC = [];
		const uiText = (text) => {
			if (!uiEnglish() || typeof text !== "string" || text === "") return text;
			const exact = UI_EN[text];
			if (exact !== undefined) return exact;
			const fragments = text
				.replace(/命中规则 /g, "Rule hit ")
				.replace(/规则结果 /g, "Result ")
				.replace(/(^|· )工具 /g, "$1Tool ")
				.replace(/(^|· )权限 /g, "$1Grant ")
				.replace(/(^|· )理由 /g, "$1Reasons ")
				.replace(/(^|· )耗时 /g, "$1Duration ")
				.replace(/(^|· )规则 /g, "$1Rule ")
				.replaceAll("宿主未提供该接口", "the host did not provide the endpoint");
			for (const [pattern, replace] of UI_DYNAMIC) {
				const match = pattern.exec(fragments);
				if (match !== null) return replace(match);
			}
			return fragments;
		};
		const uiChild = (child) => Array.isArray(child)
			? child.map(uiChild)
			: (typeof child === "string" ? uiText(child) : child);
		const uiProps = (props) => {
			if (props === null || typeof props !== "object") return props;
			let out;
			const put = (key, value) => {
				if (value === props[key]) return;
				out ??= { ...props };
				out[key] = value;
			};
			for (const key of ["label", "hint", "title", "desc", "placeholder", "aria-label", "ariaLabel"]) {
				if (typeof props[key] === "string") put(key, uiText(props[key]));
			}
			if (Array.isArray(props.options)) {
				put("options", props.options.map((option) => {
					if (typeof option === "string") return uiText(option);
					if (option !== null && typeof option === "object" && typeof option.label === "string")
						return { ...option, label: uiText(option.label) };
					return option;
				}));
			}
			if (typeof props.children === "string") put("children", uiText(props.children));
			else if (Array.isArray(props.children)) put("children", props.children.map(uiChild));
			return out ?? props;
		};
		const h = (type, props, ...children) => hostCreateElement(type, uiProps(props), ...children.map(uiChild));

		Object.assign(UI_EN, {
			"允许": "Release",
			"人工": "Human",
			"拒绝": "Deny",
			"直接放行：不调模型、不弹面板，这一步就此定掉（结果该遮还是遮）": "Release now: no model call, no prompt; this step is final (results are still masked).",
			"直接弹给你确认，AI 不再判": "Ask you directly; AI does not decide.",
			"直接拒绝，工具收到拒绝原因": "Deny directly; the tool receives the reason.",
			"读取": "Read",
			"写入": "Write",
			"删除": "Delete",
			"命令": "command",
			"路径": "path",
			"域名或 IP": "host or IP",
			"工具": "tool",
			"内容": "content",
			"命令安全": "Command safety",
			"一条命令一行：命令名＋四档＋开关。表内自上而下，先命中那条说话。": "One command per row: command name, tier, on/off. Rows are checked top down; the first row that speaks wins.",
			"这一张表只看程序名，不看这次动的是哪个文件；动的是哪儿由文件表判，两张表取最严。": "This table looks only at the program name, not at which file the call touches; where it lands is decided by the file table, and the stricter of the two applies.",
			"文件安全": "File safety",
			"表内自上而下，先命中那条说话；每条路径按读／写／删三格各点一档。": "Rows are checked top down; the first row that speaks wins. Each path sets its own read, write and delete tier.",
			"~ ＝家目录；单个 * 只匹配一级，连续两个 * 匹配任意层级；以 / 或 \\ 结尾＝该目录及其全部内容。路径行只接受这几种写法，不能写正则。": "~ is the home directory; a single * matches one level, a double * matches any depth; a trailing / or \\ means that directory and everything under it. Path rows accept only these patterns — no regular expressions.",
			"网络安全": "Network safety",
			"按优先级控制 URL 和域名访问。": "Control URL/host access by priority.",
			"按主机名或 IP 匹配：api.example.com、*.example.com、*；不支持端口、路径和局部通配。": "Matches hostname or IP: `api.example.com`, `*.example.com`, `*`; ports, paths and partial wildcards are not supported.",
			"工具规则": "Tool rules",
			"按工具名控制，例如整个 MCP 工具族。": "Control by tool name, e.g. the whole MCP family.",
			"按工具名匹配：bash、write、mcp:*（整个 MCP 族）。": "Matches tool names: `bash`, `write`, `mcp:*` (the whole MCP family).",
			"源根搜索目录": "Source-root search folders",
			"一行一个绝对路径，最多 20 条；只列每处第一层的目录名，不进去、不读文件；每处超过 200 条会提示「可能没扫全」": "One absolute path per line, up to 20; only first-level directory names are listed (no traversal, no file reads); more than 200 entries at a location shows “may be incomplete”.",
			"检测规则": "Detection rules",
			"认出内容里的凭据形状，命中就先遮成占位符，再按档位处置。": "Recognize credential shapes; mask a hit into a placeholder first, then apply the action.",
			"预设 9 条形状（私钥／JWT／AWS key／Bearer／服务密钥／凭据赋值／连接串／邮箱／身份证号）就在这张表里，改正则、换动作、停用都在行上动。脱敏顶掉的是这一行匹配到的整段，要只遮值就把正则写成只匹配值；带 * 的通配行定位不到具体一段，只能拒绝或允许。": "The nine built-in shapes (private key / JWT / AWS key / Bearer / service key / credential assignment / connection string / email / ID number) are rows in this table; edit the regex, action or disable them in the row. Redaction removes the matched span; to mask only the value, write a value-only regex. Wildcard rows cannot locate a span, so they can only deny or allow.",
			"预设行": "Preset rows",
			"你的规则": "Your rules",
			"事实闸": "Fact gate",
			"AI 快判": "AI fast review",
			"AI 深评": "AI deep review",
			"结果脱敏": "Result redaction",
			"生命周期": "Lifecycle",
			"配置变更": "Config change",
			"未判定": "Not decided",
			"是否接管": "Managed?",
			"会话权限档": "Session permission tier",
			"安全规则": "Safety rules",
			"预设行＋你的有序表": "Preset rows + your ordered table",
			"只读·会话内部工具": "Read-only / session-internal tools",
			"小模型": "Small model",
			"跟随会话／指定预设": "Session / selected preset",
			"宿主审批面板": "Host approval panel",
			"检测规则命中→先遮，再按档位问／放／拦": "Detection hit → mask first, then ask/release/deny",
			"评审模型": "Review model",
			"接管与模式": "Takeover & mode",
			"用「自动审批」权限档干活时，AI 先审再放行：模型没有结论、或必须强制人工，仍然回到你手上确认。": "In the \"Auto approval\" tier, AI reviews before release: if the model has no answer or a human is required, it still comes back to you.",
			"启用本插件": "Enable this plugin",
			"关掉后所有操作走 DSH 自带审批面板，本插件不拦也不判": "When off, every action goes through DSH's own approval panel; this plugin neither blocks nor judges.",
			"审批模式": "Approval mode",
			"关闭＝全部由你确认；仅风险提示＝AI 只给意见不放行；自动审批＝AI 可直接放行低风险操作": "Off = you decide everything; advise = AI only gives advice and cannot release; auto = AI can release low-risk actions.",
			"关闭": "Off",
			"仅风险提示": "Advise only",
			"自动审批": "Auto approval",
			"表内自上而下，先命中那条说话；表间取最严：拒绝＞人工＞交 AI＞允许。一张表全没命中＝没人放行，交模型判。": "Within a table, rows are checked top down and the first row that speaks wins. Across tables the strictest tier applies: deny > human > AI > allow. If no row speaks, nobody released it — the model decides.",
			"规则没定论时由模型判断：证据（事实、目标、git 状态、你说过的授权）交给它，它只能说放行、否决或升级。开启后每次审查有少量 token 消耗。": "When rules do not decide, the model judges: facts, targets, git state and your authorization go to it; it can only allow, block or escalate. Each review costs a small number of tokens.",
			"谁来做评审": "Who reviews",
			"跟随会话＝用当前对话同一个模型；指定预设＝从下面挑一个已配好的模型": "Session = use the same model as this conversation; preset = pick a configured model below.",
			"跟随会话": "Follow session",
			"指定预设": "Selected preset",
			"手填：宿主注册名，如 deepseek": "Manual: host provider id, e.g. deepseek",
			"手填：模型 id，如 deepseek-chat": "Manual: model id, e.g. deepseek-chat",
			"AI 解读跳过思考": "Skip thinking for AI explanations",
			"给解释调用补 reasoning_effort: none，不让模型先跑思维链；用户已配的档位或写入冲突一律放弃注入、回到宿主默认。关掉＝完全跟随宿主配置": "Adds reasoning_effort: none to explanation calls so the model does not run a chain of thought first; an existing user level or a settings write conflict makes the frame back off and use the host default. Off = follow the host configuration entirely.",
			"启用 AI 快判": "Enable AI fast review",
			"单目标的写入／删除先问一次小模型；它只能说放行或升级，升级后走深评": "Ask a small model once for single-target writes/deletes; it can only allow or escalate; escalation goes to deep review.",
			"自定义审查规则": "Custom review rules",
			"每行一条，追加给模型的提示词末尾；只能加限制，不能放宽。例：禁止删除 .git 目录": "One per line, appended to the reviewer prompt; they can only narrow, never widen. Example: never delete .git.",
			"深评输出上限（token）": "Deep review output limit (tokens)",
			"要装下 verdict（依据＋理由）和任务卡；512 容易截断，2048 起；调大只多花输出费": "Must fit the verdict (basis + reason) and the task card; 512 often truncates; 2048 or more is recommended. Larger only costs more output.",
			"深评超时（毫秒）": "Deep review timeout (ms)",
			"超过就算评审失败，转人工确认；20000＝20 秒": "Exceeding this counts as a failed review and falls back to a human; 20000 = 20 s.",
			"证据预算（字符）": "Evidence budget (chars)",
			"送给深评的上下文上限；越大越准但越贵": "Context cap sent to deep review; larger is more accurate but costs more.",
			"快判输出上限（token）": "Fast review output limit (tokens)",
			"快判只回一个 JSON，256 够用": "Fast review returns one JSON object; 256 is enough.",
			"快判超时（毫秒）": "Fast review timeout (ms)",
			"超时即升级到深评，不拦人": "Timeout escalates to deep review; it does not block.",
			"AI 解读输出上限（token）": "AI explanation output limit (tokens)",
			"一次解读最多说这么多；1024 的下限是给思考留余量，调大只多花输出费": "The most one explanation may say; the 1024 floor leaves room for thinking. Larger only costs more output.",
			"敏感保护": "Sensitive protection",
			"这一卡两件事，平行看：「检测规则」认出内容里的凭据形状，「敏感信息」记着遮出来的占位符。命中就先遮，再按档位处置——默认问你拒绝还是允许。": "Two halves, side by side: 'Detection rules' recognize credential shapes; 'Sensitive data' keeps the placeholders that masking produced. A hit is masked first, then the action applies — by default it asks you to deny or allow.",
			"启用检测与处置": "Enable detection & handling",
			"关掉＝整张检测规则表不再表态，工具返回原样进模型上下文": "When off, the whole detection table says nothing and tool results go to the model unchanged.",
			"自动回写占位符": "Auto-restore placeholders",
			"自动回写": "Auto-restore",
			"写之前问要不要还原占位符": "Ask before write-back, per file",
			"允许还原": "Allow restore",
			"写文件之后，把文件里「本表铸出的」占位符换回明文；凭据/系统目录不回填。命令参数里的占位符换不了（宿主禁止插件改写参数）；edit 的 old_string 也一样——它比的是磁盘明文，带占位符会 not found": "After a file write, replace the placeholders this vault minted in the file with plaintext; credential and system directories are not restored. Placeholders in command arguments cannot be restored (the host forbids rewriting arguments); the same goes for edit's old_string — it matches on-disk plaintext, so a placeholder will not be found.",
			"审计中心": "Audit center",
			"每次调用、每条规则命中、每个人工答复和工具最终结果都进哈希链台账（按天分段）；下面每条的「层级」就是它在判定链上的第几步。": "Every call, rule hit, human answer and final tool result goes into the hash-chained ledger (day segments); each entry's layer is its step on the ladder.",
			"保留天数": "Retention days",
			"超过天数的已封存段会被裁剪，并留 retention-pruned 墓碑": "Sealed segments older than this are pruned, leaving a retention-pruned tombstone.",
			"总大小上限（字节）": "Total size limit (bytes)",
			"超限从最旧的段开始裁；默认 512MB": "Over the limit, the oldest segments are pruned first; default 512 MB.",
			"单段上限（字节）": "Segment size limit (bytes)",
			"当天段写到这个大小就换下一个序号；默认 50MB": "When today's segment reaches this size, the next sequence number starts; default 50 MB.",
			"全部时间": "All time",
			"今天": "Today",
			"近 7 天": "Last 7 days",
			"近 30 天": "Last 30 days",
			"全部结果": "All results",
			"已放行": "Allowed",
			"转人工": "Asked",
			"已拦截": "Blocked",
			"已批准": "Approved",
			"已拒绝": "Rejected",
			"失败": "Failed",
			"未接管": "Delegated",
			"信息": "Info",
			"命令结果": "Result",
			"收起命令结果": "Hide result",
			"交 AI": "AI decides",
			"添加规则": "Add rule",
			"保存修改": "Save changes",
			"写入中…": "Saving…",
			"插件工具不限于搜索——它也可能写盘、读文件、把内容发出去；放行之后这些都不再单独问你。": "A plugin tool is not limited to searching — it may also write files, read files and send content out; once released, none of that asks you again.",
			// 末句是独立节点（要加粗），所以单独一条：末尾留空格，拼起来才不断字。
			"请认真识别。": " Look closely before you decide.",
			// 会话头「审计」标签
			"会话标签": "Session tab",
			"在会话头部加一个「审计」标签，只列这个会话的判定记录；关掉只影响这个入口，台账照旧写": "Adds an \"Audit\" tab to the session header that lists only this session's decisions; turning it off hides the entry, the ledger is still written.",
			"这个会话还没有判定记录。": "No decisions recorded in this session yet.",
			"没有当前会话，读不到它的审计。": "No current session, so there is no audit to read.",
			"全部分类": "All categories",
			"工具调用": "Tool calls",
			"审批": "Approval",
			"审计": "Audit",
		});

		Object.assign(UI_EN, {
			"自动审批框架": "Auto Approval Frame",
			"本页只配 DSH 的「自动审批」这一档。一次调用依次经过下面几步：前一步没给出结论，才轮到下一步。点一格跳到对应卡片。": "This page configures the Auto approval tier only. Each call walks the steps below; the next step runs only when the previous one has no verdict. Click a step to jump to its card.",
			"配置暂不可读（该 profile 未激活本插件）。页面只展示，不接收写入。": "Configuration is not readable right now (this profile has not activated the plugin). The page is read-only.",
			"没有改动": "No changes",
			"撤销": "Undo",
			"恢复默认": "Restore defaults",
			"只清你对预设的改动，你自己写的行不动": "Only clears your changes to preset rows; the rows you wrote yourself stay.",
			"保存中…": "Saving…",
			"保存": "Save",
			"不表态": "No opinion",
			"已停用": "Disabled",
			"启用中": "Enabled",
			"上移（更先命中）": "Move up (matches earlier)",
			"下移": "Move down",
			"删除这一行": "Delete this row",
			"按住拖动排序": "Drag to reorder",
			"预设": "Preset",
			"当": "When",
			"命中": "Hit",
			"匹配": "Matches",
			"这串是说明：命中由事实层判定，能改的是档位和启用开关": "This text is explanatory: the fact layer decides hits; you can change the action and the enable switch.",
			"新增行的默认动作": "Default action for new rows",
			"新规则默认": "New rule default",
			"＋ 添加": "＋ Add",
			"还没有自己的规则": "No custom rules yet",
			"‹ 返回": "‹ Back",
			"这一条现在不算数，点它启用": "This row is inactive; click to enable it",
			"这一条读不出来：改对正则或档位才会生效": "This row can't be parsed: fix the regex or the tier to make it apply.",
			"读不出来": "Unreadable",
			"让这一条先不表态（预设形状不能删，只能关）": "Make this row say nothing (built-in shapes can only be disabled, not deleted)",
			"让这一条不再拉高（预设行不能删，只能关）": "Stop this row from raising the tier (preset rows can only be disabled, not deleted)",
			"判定记录": "Decision log",
			"读取中…": "Loading…",
			"刷新": "Refresh",
			"导出 JSONL": "Export JSONL",
			"导出 Markdown": "Export Markdown",
			"清空中…": "Clearing…",
			"确认清空": "Confirm clear",
			"清空": "Clear",
			"搜索动作 / 工具 / 规则": "Search action / tool / rule",
			"启动/配置等非判定事件不进列表；选「生命周期」分类时仍可见": "Boot/config events are hidden from this list; choose the Lifecycle category to see them.",
			"隐藏启动记录": "Hide boot records",
			"隐藏配置变更": "Hide config changes",
			"隐藏人工答复": "Hide human answers",
			"正在读取…": "Loading…",
			"没有符合条件的记录。": "No matching entries.",
			"上一页": "Previous",
			"下一页": "Next",
			"0 条": "0 entries",
			"检查宿主的 audit 路由是否已挂载（connection.fetch），或重启 DSH 后再看。": "Check that the host's audit route is mounted (connection.fetch), or restart DSH and try again.",
			"哈希链校验通过": "Hash chain verified",
			"断了": "broken",
			"敏感信息": "Sensitive data",
			"正在读取敏感信息表…": "Loading the secret vault…",
			"还没有占位符——脱敏过一次才会有。": "No placeholders yet — they appear after the first redaction.",
			"显示这一条完整明文（会记一笔台账）": "Show the full plaintext (this is audited)",
			"收起明文": "Hide plaintext",
			"显示": "Show",
			"收起": "Hide",
			"这条占位符会在写文件后被换回明文，点它关掉": "This placeholder is restored to plaintext after a file write; click to turn it off.",
			"这条不参与自动回写，点它打开": "This placeholder is not auto-restored; click to turn it on.",
			"回写开": "Restore on",
			"回写关": "Restore off",
			"删掉这条映射（占位符从此换不回明文）": "Delete this mapping (the placeholder can no longer be restored).",
			"清空后所有占位符都换不回明文，确定？": "After clearing, no placeholder can be restored. Continue?",
			"取消": "Cancel",
			"清空映射表": "Clear vault",
			"模拟审批": "Simulate approval",
			"把要核的动作粘进来，宿主按当前配置走一遍判定链，逐步回它会怎么被处置。不调模型、不执行任何东西。": "Paste the action; the host walks the current ladder and shows where it lands. No model call, nothing executed.",
			"粘贴一条命令，或一个路径（按删除试）": "Paste a command, or a path (tested as a deletion)",
			"模拟中…": "Simulating…",
			"模拟一下": "Simulate",
			"结论": "Verdict",
			"（按删除该路径试）": " (tested as a deletion)",
			"判定链": "Ladder",
			"可配": "configurable",
			"固定": "fixed",
			"宿主未提供判定链接口": "The host did not provide the frame endpoint.",
			"宿主未提供模型目录接口": "The host did not provide the model catalog endpoint.",
			"宿主读审计失败": "The host failed to read the audit store.",
			"宿主读敏感表失败": "The host failed to read the secret vault.",
			"清空失败": "Clear failed",
			"审计已清空（保留清空标记）": "Audit cleared (the clear marker is kept).",
			"读不到": "Unavailable",
			"每行一个": "One per line",
			"要写绝对路径或 ~ 开头的路径": "Use an absolute path or a path starting with ~",
			"不能是盘根": "Cannot be a filesystem root",
			"不能是家目录本身": "Cannot be the home directory itself",
			"太宽（至少到家目录下一层）": "Too broad (must be at least one level below the home directory)",
			"不能是工作区根本身": "Cannot be the workspace root itself",
			"落在凭据／客户端目录里": "Falls inside a credential/client directory",
			"像凭据文件": "Looks like a credential file",
			"系统关键目录": "OS-critical directory",
			"不能整棵打开 ~/.dsh，只能开子目录": "Cannot open the whole ~/.dsh tree; open a subtree instead",
			"信任行要写路径，不支持正则": "Trust rows take paths, not regexes",
			"空路径": "Blank path",
			"正在读宿主已配置的模型…": "Loading the host's configured models…",
			"宿主没注册任何可列出的模型，请改用手填的 Provider／Model": "The host has no listable models; fill in Provider/Model manually.",
			"已导出": "Exported",
			"预设行＋你的有序表（含只读举证行）": "Preset rows + your ordered table (incl. read-only evidence rows)",
			"宿主组合点": "Host composition point",
			"AI 快判（未送）": "AI fast pass (not sent)",
			"AI 深评（未送）": "AI deep review (not sent)",
			"这条不参与自动回写，点开关打开": "This row does not take part in write-back; switch it on to include it",
			"这条占位符会在写文件后被换回明文，点开关关掉": "This placeholder is restored to plaintext after a file write; switch it off to stop that",
			"为这一次回写签发授权（会话＋目的＋用途＋期限）": "Issue a grant for this write-back (session + target + purpose + lifetime)",
			"会话 ID（台账里的 sessionId）": "Session ID (the sessionId in the audit log)",
			"目的文件绝对路径": "Absolute path of the target file",
			"有效分钟": "Valid minutes",
			"签发": "Issue",
			"一次性": "One-time",
			"未知原因": "unknown reason",
			"宿主未提供审计接口": "the host did not provide the audit endpoint",
			"兜底行固定最后：不可删、不可上移": "The fallback row stays last: it cannot be deleted or moved up",
		});

		UI_DYNAMIC.push(
			[/^(\d+) 项待保存$/, m => `${m[1]} unsaved change${m[1] === "1" ? "" : "s"}`],
			[/^保存（(\d+)）$/, m => `Save (${m[1]})`],
			[/^已保存 (\d+) 项$/, m => `Saved ${m[1]} item${m[1] === "1" ? "" : "s"}`],
			[/^链上第 (.+) 步$/, m => `Chain step ${m[1]}`],
			[/^第 (\d+) 条：自上而下匹配，命中的第一条生效$/, m => `Row ${m[1]}: top-down; the first match wins`],
			[/^(\d+) 条 · 明文只在本机映射表，查看会记一笔台账$/, m => `${m[1]} entries · plaintext stays in the local vault; viewing one is audited`],
			[/^(.+)····（(\d+) 字）$/, m => `${m[1]}···· (${m[2]} chars)`],
			[/^(\d+) 次 · 出处 (.+)$/, m => `${m[1]} hits · source ${m[2]}`],
			[/^匹配 (\d+) \/ 共 (\d+) 条审批 · (\d+) 段$/, m => `Matched ${m[1]} / ${m[2]} approvals · ${m[3]} segments`],
			// 会话标签那一行：会话内条数与全机总数分开写，不然「共 N 条」会被当成这个会话的。
			[/^本会话 (\d+) 条 · 全机共 (\d+) 条审批 · (\d+) 段$/, m => `This session: ${m[1]} · ${m[2]} approvals on this machine · ${m[3]} segments`],
			[/^本会话 (\d+) 条 · 全机共 (\d+) 条审批 · (\d+) 段 · 哈希链校验通过$/, m => `This session: ${m[1]} · ${m[2]} approvals on this machine · ${m[3]} segments · hash chain verified`],
			[/^(\d+)–(\d+) \/ (\d+) 条$/, m => `${m[1]}–${m[2]} / ${m[3]} approvals`],
			[/^(\d+) 条$/, m => `${m[1]} entries`],
			[/^自定义（(\d+)）· 命中取最严的一档，不看先后$/, m => `Custom (${m[1]}) · strictest action wins, order does not matter`],
			[/^自定义（(\d+)）· 自上而下匹配，命中第一条后停止$/, m => `Custom (${m[1]}) · top-down; stop at the first match`],
			[/^预设（(\d+)）· 全部可改：改内容、换档位、停用都在这里$/, m => `Presets (${m[1]}) · all editable: content, action and enable/disable`],
			[/^预设（(\d+)）· 全部可改：换档位、停用都在这里，停用＝这一条不再拉高$/, m => `Presets (${m[1]}) · all editable: action and enable/disable; disabled = this row no longer raises the tier`],
			[/^(\d+) 条 · 预设形状也在这一张表里，可改可停用；命中取最严的一档，不看先后$/, m => `${m[1]} entries · built-in shapes are rows too; edit or disable them; the strictest action wins, order does not matter`],
			[/^(\d+) 条 · 自上而下匹配，命中第一条后停止$/, m => `${m[1]} entries · top-down; stop at the first match`],
			[/^这些路径没被当成信任根：(.+)$/, m => `These paths are not trust roots: ${m[1]}`],
			[/^模拟审批失败：(.+)$/, m => `Simulation failed: ${m[1]}`],
			[/^已列出 (\d+) 个提供方；(.+) 读不到模型$/, m => `Loaded ${m[1]} providers; ${m[2]} unavailable`],
			[/^已列出 (\d+) 个模型；选一个＝同时写回 provider 与 model$/, m => `Loaded ${m[1]} models; selecting one writes both provider and model`],
			[/^没读到模型目录（(.+)），请改用手填的 Provider／Model$/, m => `Cannot read the model catalog (${m[1]}); fill in Provider/Model manually.`],
			[/^没读到宿主配好的模型（(.+)），请手填下面两项。$/, m => `Cannot read the host's configured models (${m[1]}); fill in the two fields below.`],
			[/^受管权限档 (.+) 不在宿主当前权限表里：本插件不会接管任何会话。把下面这段加进你 profile 的 permission.presets（保留已有档），或把 gatedPresets 改成宿主已有的档，重启后生效。$/, m => `Managed permission tier(s) ${m[1]} are not in the host's catalog: this plugin will not manage any session. Add the snippet below to your profile's permission.presets (keep your existing tiers), or change gatedPresets to a tier the host has, then restart.`],
			[/^▲ 收起高级项（(\d+) 项）$/, m => `▲ Hide advanced (${m[1]})`],
			[/^▼ 高级（(\d+) 项）$/, m => `▼ Advanced (${m[1]})`],
			[/^共 (\d+) 条$/, m => `Total ${m[1]} entries`],
			[/^(\d+) 项$/, m => `${m[1]} items`],
			[/^规则 (.+)$/, m => `Rule ${m[1]}`],
			[/^工具 (.+)$/, m => `Tool ${m[1]}`],
			[/^权限 (.+)$/, m => `Grant ${m[1]}`],
			[/^理由 (.+)$/, m => `Reasons ${m[1]}`],
			[/^耗时 (.+)$/, m => `Duration ${m[1]}`],
			[/^已导出 (.+)$/, m => `Exported ${m[1]}`],
		);

		Object.assign(UI_EN, {
			"受管权限档": "Managed permission tiers",
			"只接管勾选的权限档；通常只勾「自动审批」。只读／工作区写／完全权限默认不接管。": "Only the checked tiers are managed; normally only Auto approval. Read-only / Workspace write / Full access are not managed by default.",
			"宿主没有返回权限目录；保存过的档仍会显示在这里。": "The host returned no permission catalog; saved tiers are still shown here.",
			"没有可接管的权限档；内置只读／工作区写／完全权限默认不接管。": "No manageable permission tiers; read-only / workspace-write / danger-full-access are not managed by default.",
			"隐藏配置变更": "Hide config changes",
			"隐藏人工答复": "Hide human answers",
			"开＝这一类不显示（默认开）；按分类筛选时照常显示": "On = this kind is hidden (default on); filtering by category shows it anyway.",
			"你亲手答的那一行：同意还是拒绝（默认显示）": "The row for what you answered yourself: approved or rejected (shown by default).",
			"没答": "Not answered",
			"无应答通道": "No channel",
			"用户": "User",
			"内置": "Built-in",
			"未设置": "Not set",
			"AI 审查": "AI review",
			"脱敏遮出来的占位符都记在这里，可显示明文、可开关回写、可清空。": "Placeholders produced by redaction are listed here; show plaintext, toggle restore, or clear them.",
			"这张表里标着「预设」的行数：默认就在，能换档位、能停用": "Rows marked Preset in this table: present by default; change the action or disable them.",
			"哈希链校验通过": "hash chain verified",
			"宿主未提供该接口": "the host did not provide the endpoint",
			"MCP 工具": "MCP tools",
			"mcp:* 工具默认交 AI 审查；可在表里改档或停用": "mcp:* tools go to AI review by default; change the action or disable this row in the table.",
			"非 shell 且框架无法归类（MCP 工具见下一行）": "Non-shell tools the frame cannot classify (MCP tools have their own row below).",
		});
		UI_DYNAMIC.push(
			[/^(\d+) 条 · 用户行自上而下首条命中；预设行由事实触发，顺序不影响判定$/, m => `${m[1]} entries · user rows match top-down; preset rows are fact-triggered; order does not affect the verdict.`],
			[/^预设 (\d+)$/, m => `Presets ${m[1]}`],
			[/^(.+)：(.+)（可配）$/, m => `${uiText(m[1])}: ${uiText(m[2])} (configurable)`],
			[/^(.+)：(.+)（固定）$/, m => `${uiText(m[1])}: ${uiText(m[2])} (fixed)`],
			[/^匹配 (\d+) \/ 共 (\d+) 条 · (\d+) 段 · 哈希链校验通过$/, m => `Matched ${m[1]} / ${m[2]} entries · ${m[3]} segments · hash chain verified`],
			[/^人工答复：(.+)$/, m => `Answered by you: ${({ "同意（仅此一次）": "approved", "拒绝": "rejected", "没答（取消／关窗）": "not answered", "没有应答通道": "no approval channel" })[m[1]] ?? m[1]}`],
			[/^读不到审计：(.+)$/, m => `Audit unavailable: ${uiText(m[1])}`],
			[/^读不到敏感信息表：(.+)$/, m => `Sensitive vault unreadable: ${uiText(m[1])}`],
			[/^给 (.+) 签发一次回写$/, m => `Issue one write-back for ${m[1]}`],
			[/^没签成：(.+)$/, m => `Not issued: ${uiText(m[1])}`],
			// 审计卡上处理陌生工具的入口：工具名是动态的，只能按整句认。
			// 「放行」＝表里还没有这个工具，加一行；「修改」＝已有行，换档。
			[/^放行：(.+)$/, m => `Release: ${m[1]}`],
			[/^修改：(.+)$/, m => `Change: ${m[1]}`],
			[/^已添加：(.+)$/, m => `Added: ${uiText(m[1])}`],
			[/^已修改：(.+)$/, m => `Changed: ${uiText(m[1])}`],
		);
		const PRESET_LABEL_ZH = {
			"read-only": "仅可查看",
			"workspace-write": "工作区内修改",
			"auto-approval": "自动审批",
			"auto": "自动审查",
			"danger-full-access": "完全权限",
		};
		const presetLabel = (name, fallback) => (uiEnglish() ? fallback : (PRESET_LABEL_ZH[name] ?? fallback));
		const normalizedText = (element) => String(element?.textContent ?? "").replace(/\s+/g, " ").trim();
		const directText = (element) => {
			const parts = [];
			for (const node of element?.childNodes ?? []) if (node.nodeType === 3) {
				const text = node.data.trim();
				if (text) parts.push(text);
			}
			return parts.join(" ");
		};

		function isPermissionMenu(menu) {
			const labels = new Set(Array.from(menu.querySelectorAll("button[role=\"menuitem\"]"), normalizedText));
			return Object.values(PERMISSION_LABEL_SETS).every(variants => variants.some(label => labels.has(label)));
		}
		function menuDrawsPresetGlyphs(menuItems) {
			const autoNames = PERMISSION_LABEL_SETS.auto;
			return menuItems.some(item => !autoNames.includes(normalizedText(item))
				&& Array.from(item.children ?? []).some(child => child.tagName === "SPAN" && child.querySelector("svg") !== null));
		}
		function isAutoMenuItem(element) {
			if (!element.matches("button[role=\"menuitem\"]") || !PERMISSION_LABEL_SETS.auto.includes(normalizedText(element))) return false;
			const menu = element.closest("[role=\"menu\"]");
			return menu !== null && isPermissionMenu(menu);
		}
		function isAutoTrigger(element) {
			if (!element.matches("button[aria-label]")) return false;
			const label = element.getAttribute("aria-label") ?? "";
			return /(?:访问模式|Access mode)[\s\S]*(?:Auto approval|自动审批)\s*$/i.test(label);
		}
		function createAutoGlyph(doc) {
			const span = doc.createElement("span");
			span.className = "dsa-frameAutoIcon";
			span.setAttribute("aria-hidden", "true");
			span.innerHTML = `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="${SHIELD_PATH}" stroke="currentColor" stroke-width="1" stroke-linejoin="round"/><path d="${BOLT_PATH}" fill="currentColor"/></svg>`;
			return span;
		}
		function decorateSurface(doc, container, label, kind) {
			if (kind !== "option" && container.querySelector(".dsa-frameAutoIcon") === null) {
				container.insertBefore(createAutoGlyph(doc), container.firstChild);
			}
			if (label === null) return;
			if (!label.hasAttribute(ORIGINAL_LABEL_ATTRIBUTE)) label.setAttribute(ORIGINAL_LABEL_ATTRIBUTE, label.textContent ?? "");
			label.setAttribute(LABEL_ATTRIBUTE, "");
			const text = autoName(doc);
			if (label.textContent !== text) label.textContent = text;
		}
		function decorateSelector(doc, button) {
			if (PERMISSION_LABEL_SETS.auto.includes(directText(button))) {
				if (!button.hasAttribute(ORIGINAL_LABEL_ATTRIBUTE)) button.setAttribute(ORIGINAL_LABEL_ATTRIBUTE, directText(button));
				const text = autoName(doc);
				for (const node of button.childNodes) {
					if (node.nodeType === 3 && node.data.trim() !== "") {
						if (node.data !== text) node.data = text;
						break;
					}
				}
				button.setAttribute(LABEL_ATTRIBUTE, "");
			}
		}

		function decorateAutoPermissionIcons(doc) {
			const autoNames = PERMISSION_LABEL_SETS.auto;
			for (const marked of doc.querySelectorAll(`[${ICON_ATTRIBUTE}]`)) {
				const kind = marked.getAttribute(ICON_ATTRIBUTE);
				if ((kind === "menu" && !isAutoMenuItem(marked)) || (kind === "trigger" && !isAutoTrigger(marked))) {
					marked.removeAttribute(ICON_ATTRIBUTE);
					for (const glyph of Array.from(marked.children).filter(child => child.classList?.contains("dsa-frameAutoIcon"))) glyph.remove();
					for (const label of marked.querySelectorAll(`[${LABEL_ATTRIBUTE}]`)) label.removeAttribute(LABEL_ATTRIBUTE);
				}
			}
			for (const menu of doc.querySelectorAll("[role=\"menu\"]")) {
				if (!isPermissionMenu(menu)) continue;
				const items = Array.from(menu.querySelectorAll("button[role=\"menuitem\"]"));
				const drawsGlyphs = menuDrawsPresetGlyphs(items);
				for (const item of items) {
					if (!autoNames.includes(normalizedText(item))) continue;
					const label = Array.from(item.children).find(child => child.tagName === "SPAN"
						&& child.querySelector("svg") === null && autoNames.includes(normalizedText(child))) ?? null;
					if (drawsGlyphs) {
						item.setAttribute(ICON_ATTRIBUTE, "menu");
						decorateSurface(doc, item, label, "menu");
					}
					else {
						item.removeAttribute(ICON_ATTRIBUTE);
						for (const glyph of Array.from(item.children).filter(child => child.classList?.contains("dsa-frameAutoIcon"))) glyph.remove();
						if (label !== null) decorateSurface(doc, item, label, "option");
					}
				}
			}
			for (const button of doc.querySelectorAll("button[aria-label]")) {
				if (!isAutoTrigger(button)) continue;
				button.setAttribute(ICON_ATTRIBUTE, "trigger");
				decorateSurface(doc, button, Array.from(button.children).find(child => child.tagName === "SPAN"
					&& child.querySelector("svg") === null && autoNames.includes(normalizedText(child))) ?? null, "trigger");
				const aria = button.getAttribute("aria-label") ?? "";
				if (!button.hasAttribute(ORIGINAL_ARIA_ATTRIBUTE)) button.setAttribute(ORIGINAL_ARIA_ATTRIBUTE, aria);
				const localized = String(button.getAttribute(ORIGINAL_ARIA_ATTRIBUTE)).replace(/(?:Auto approval|Auto|自动审批)\s*$/i, autoName(doc));
				if (localized !== aria) button.setAttribute("aria-label", localized);
			}
			for (const listbox of doc.querySelectorAll("[role=\"listbox\"][aria-label]")) {
				if (!/^\/permission\s+(?:matches|匹配项)$/i.test((listbox.getAttribute("aria-label") ?? "").trim())) continue;
				for (const option of listbox.querySelectorAll("[role=\"option\"]")) {
					const label = option.firstElementChild && option.firstElementChild.tagName === "SPAN" ? option.firstElementChild : null;
					if (label === null || !autoNames.includes(normalizedText(label))) continue;
					decorateSurface(doc, option, label, "option");
				}
			}
			for (const button of doc.querySelectorAll("button[aria-haspopup=\"menu\"]")) {
				if (button.getAttribute("aria-label") !== null) continue;
				if (PERMISSION_LABEL_SETS.auto.includes(directText(button))) decorateSelector(doc, button);
			}
			for (const glyph of doc.querySelectorAll(".dsa-frameAutoIcon")) {
				const owner = glyph.parentElement;
				if (owner === null) continue;
				const kind = owner.getAttribute(ICON_ATTRIBUTE);
				if (!((kind === "menu" && isAutoMenuItem(owner)) || (kind === "trigger" && isAutoTrigger(owner)))) glyph.remove();
			}
		}

		function iconStyles() {
			return ".dsa-frameAutoIcon{display:inline-flex;flex:none;width:14px;height:14px;align-items:center;justify-content:center;color:var(--dsw-alias-menu-icon, currentColor)}";
		}

		function installAutoPermissionIcon(doc) {
			if (doc == null) return () => { };
			for (const existing of doc.querySelectorAll("style[data-plugin]")) {
				if (existing.getAttribute("data-plugin") === PLUGIN_NAME) existing.remove();
			}
			const style = doc.createElement("style");
			style.setAttribute("data-plugin", PLUGIN_NAME);
			style.setAttribute("data-plugin-css", `${PLUGIN_NAME}/permission-icon`);
			style.textContent = iconStyles();
			doc.head?.appendChild(style);
			let active = true;
			let queued = false;
			const scan = () => {
				if (!active || queued) return;
				queued = true;
				globalThis.requestAnimationFrame(() => {
					queued = false;
					if (active) decorateAutoPermissionIcons(doc);
				});
			};
			decorateAutoPermissionIcons(doc);
			const observer = globalThis.MutationObserver == null ? null : new globalThis.MutationObserver(scan);
			observer?.observe(doc.documentElement, {
				attributes: true, attributeFilter: ["aria-label", "lang"], characterData: true, childList: true, subtree: true,
			});
			return () => {
				active = false;
				observer?.disconnect();
				style.remove();
			};
		}

		// ── 配置页 ──────────────────────────────────────────────────────────
		// DEFAULTS 必须与 lib/index.js 的 Config schema 默认值一致。
		// form.state.value 是 host 解析后的值（schema 默认 → 组合基线 → 用户层），
		// 正常情况下每个字段都有值；DEFAULTS 只兜底极端缺失。
		// 🔴 浏览器半边 require 不到 lib/frame/config-defaults.js（宿主 __ModuleLoader__ 只给宿主包），
		// 所以下面这些数字是那张表的**第二份字面量**——逐键对拍＝test/unit/config-defaults.test.mjs，
		// 漂了那儿红。字段上的 min／max 同理。
		const DEFAULTS = {
			enabled: true,
			mode: "auto",
			gatedPresets: ["auto-approval"],
			reviewerSource: "session",
			reviewerProvider: "",
			reviewerModel: "",
			reviewerMaxTokens: 2048,
			reviewerTimeoutMs: 20000,
			evidenceBudget: 16000,
			reviewRules: [],
			commandRules: [],
			fileRules: [],
			networkRules: [],
			toolRules: [],
			sensitiveRules: [],
			sensitiveDetect: true,
			autoRestoreSecrets: true,
			fastJudge: true,
			fastJudgeMaxTokens: 256,
			fastJudgeTimeoutMs: 3000,
			explainMaxTokens: 2048,
			retentionDays: 90,
			maxTotalBytes: 536870912,
			maxSegmentBytes: 52428800,
			auditTab: true,
			explainNoThinking: true,
		};

	// 一张表一个平面，行＝{action, match, ops}。四档对每个平面都一样：
	// `release` 是真放行（人拍的板），`ai` ＝交模型判一次、命中即终局，`ask` ＝问你，
	// `deny` ＝直接拒。遮不遮与档位无关：敏感面命中就遮，档位只管遮完之后怎么处置。
		const ACTION_META = {
			release: { label: "允许", tone: "chipAllow", note: "直接放行：不调模型、不弹面板，这一步就此定掉（结果该遮还是遮）" },
			ai: { label: "AI", tone: "chipAsk", note: "交模型判一次：命中即终局，模型否决或没把握时转人工；后面的行不再表态" },
			ask: { label: "人工", tone: "chipAsk", note: "直接弹给你确认，AI 不再判" },
			deny: { label: "拒绝", tone: "chipBlock", note: "直接拒绝，工具收到拒绝原因" },
		};
		// 旧配置里存的档位名往现在这套折：allow 折成 ai，而 ai 自 0.6.3 起是**终局路由**
		//（交模型判一次、命中即终局），不是「不拦、继续往下走」；redact 那一档已删
		//（命中就遮是这一层自己在做的事，不再是选项）。
		// 旧档位名与同义写法折成现在的四档。这张表必须和 lib/frame/policy.js 的
		// ACTION_WORDS 同义——宿主认得的词，页面也必须认得，否则手写的行会被显示成
		// 另一档、再保存一次就把原意改掉。回归 client.test 按字面锁住两侧。
		const FOLD_ACTION = {
			allow: "ai", redact: "ask", permit: "release", block: "deny", confirm: "ask", human: "ask",
			允许: "release", 直接放行: "release", 放行: "release",
			模型: "ai", 交ai: "ai", 评审: "ai",
			人工: "ask", 询问: "ask", 确认: "ask",
			拒绝: "deny", 拦截: "deny", 禁止: "deny",
		};
		// 省略档位词（ai/ask/deny/release）与同义词一起构成字符串规则的动词表。
		const RULE_VERB = new RegExp(`^\\s*(${Object.keys(FOLD_ACTION).join("|")}|ai|ask|deny|release)\\s+(.*)$`, "i");
		const OP_LABEL = { read: "读取", write: "写入", delete: "删除" };
		// 一句话规则行的主语：读出来就是规则本身的意思，不需要读者去对列。
		const SENT_NOUN = { command: "命令", file: "路径", network: "域名或 IP", tool: "工具", sensitive: "内容" };
		// 摘要列表按这条顺序展示四张表；sensitive 表直接嵌在「敏感保护」卡里。
		const RULE_KEYS = [
			{ plane: "command", key: "commandRules" },
			{ plane: "file", key: "fileRules" },
			{ plane: "network", key: "networkRules" },
			{ plane: "tool", key: "toolRules" },
		];
		const RULE_KEY_OF = {
			command: "commandRules", file: "fileRules", network: "networkRules", tool: "toolRules", sensitive: "sensitiveRules",
		};
		// 兜底行的 preset 键（与 lib/frame/policy.js 的 `COMMAND_FALLBACK_PRESET`／
		// 网络面那条 `network:unlisted-egress` 逐字相同）。键是稳定标识，**不是显示名**：
		// 显示名随时会改，键一动用户改过的档位就对不上号。它们固定末位、可改档、不可删、不可上移——
		// 页面上没有删除入口，也没有拖动把手。
		const FALLBACK_PRESET_OF = {
			command: "command:fallback",
			network: "network:unlisted-egress",
		};
		const isFallbackRow = (plane, row) => FALLBACK_PRESET_OF[plane] !== undefined
			&& row?.preset === FALLBACK_PRESET_OF[plane];
		const PLANES = {
			command: {
				title: "命令安全", placeholder: "git push",
				desc: "一条命令一行：命令名＋四档＋开关。表内自上而下，先命中那条说话。",
				tip: "这一张表只看程序名，不看这次动的是哪个文件；动的是哪儿由文件表判，两张表取最严。",
			},
			file: {
				title: "文件安全", placeholder: "%USERPROFILE%\\.cache\\myapp\\", ops: true,
				desc: "表内自上而下，先命中那条说话；每条路径按读／写／删三格各点一档。",
				tip: "~ ＝家目录；单个 * 只匹配一级，连续两个 * 匹配任意层级；以 / 或 \\ 结尾＝该目录及其全部内容。路径行只接受这几种写法，不能写正则。",
			},
			network: {
				title: "网络安全", placeholder: "*.example.com",
				desc: "按优先级控制 URL 和域名访问。",
				tip: "按主机名或 IP 匹配：api.example.com、*.example.com、*；不支持端口、路径和局部通配。",
			},
			tool: {
				title: "工具规则", placeholder: "mcp:*",
				desc: "按工具名控制，例如整个 MCP 工具族。",
				tip: "按工具名匹配：bash、write、mcp:*（整个 MCP 族）。",
			},
			sensitive: {
				title: "检测规则", placeholder: "re:\\bAKIA[0-9A-Z]{16}\\b",
				desc: "认出内容里的凭据形状，命中就先遮成占位符，再按档位处置。",
				tip: "预设 9 条形状（私钥／JWT／AWS key／Bearer／服务密钥／凭据赋值／连接串／邮箱／身份证号）就在这张表里，改正则、换动作、停用都在行上动。脱敏顶掉的是这一行匹配到的整段，要只遮值就把正则写成只匹配值；带 * 的通配行定位不到具体一段，只能拒绝或允许。",
			},
		};
		// 审计里的 `layer` 字段和页面用同一套名字，跑一次就能对上第几步。
		// 这份表必须和 lib/frame/audit.js 的 LAYER_TEXT 逐字相同——导出件和页面说两套
		// 名字就等于「一个层级两个编号」。回归 client.test 里按字面比对两份表锁住。
		const LAYER_LABEL = {
			floor: "预设行", rules: "你的规则", fact: "事实闸", host: "宿主组合点",
			fast: "AI 快判", deep: "AI 深评", human: "人工", redact: "结果脱敏",
			lifecycle: "生命周期", config: "配置变更", none: "未判定",
		};
		// 证据装不下而转人工的那条**根本没调过模型**，界面却按 layer=deep
		// 显示「AI 深评」——等于替一次不存在的调用立牌子。台账 aiCalls 记的是真实调用次数，
		// 为 0 就把这格如实标成「未送」，层名本身不动（不新增层值，免得两套表对不上）。
		const LAYER_UNSENT = { fast: "AI 快判（未送）", deep: "AI 深评（未送）" };
		const layerTextOf = entry => {
			if (entry?.aiCalls === 0 && LAYER_UNSENT[entry.layer] !== undefined)
				return LAYER_UNSENT[entry.layer];
			return LAYER_LABEL[entry.layer] ?? entry.layer ?? "";
		};
		// 判定链：卡片按这条链排，流程条先告诉用户「哪一步可配、哪一步说了算」。
		// 预设行不再单列一格——它在页面上就是每张规则表置顶那几行标着「预设」的行，
		// 单列一格会让人以为是另一套规则，还会让页面链／台账／模拟审批出现两套编号。
		const LADDER = [
			{ step: "0", name: "是否接管", who: "会话权限档", card: "preset", configurable: true },
			{ step: "1", name: "安全规则", who: "预设行＋你的有序表（含只读举证行）", card: "rules", configurable: true },
			{ step: "2", name: "AI 快判", who: "小模型", card: "review", configurable: true },
			{ step: "3", name: "AI 深评", who: "跟随会话／指定预设", card: "review", configurable: true },
			{ step: "4", name: "人工", who: "宿主审批面板", card: "preset", configurable: false },
			{ step: "5", name: "结果脱敏", who: "检测规则命中→先遮，再按档位问／放／拦", card: "sensitive", configurable: true },
		];
		// 「评审模型」一行：从宿主已注册的模型里挑，选完写回 reviewerProvider＋reviewerModel。
		// 没有 key ⇒ 不登记进 FIELDS（否则草稿里多一枚 undefined 键）。
		const MODEL_PICKER_FIELD = {
			type: "modelPicker", label: "评审模型",
			dependsOn: { key: "reviewerSource", value: "preset" },
		};
		const SECTIONS = [
			{
				id: "preset",
				title: "接管与模式",
				desc: "用「自动审批」权限档干活时，AI 先审再放行：模型没有结论、或必须强制人工，仍然回到你手上确认。",
				fields: [
					{ key: "enabled", type: "switch", head: true, label: "启用本插件", hint: "关掉后所有操作走 DSH 自带审批面板，本插件不拦也不判" },
							{
						key: "mode", type: "segmented", label: "审批模式",
						hint: "关闭＝全部由你确认；仅风险提示＝AI 只给意见不放行；自动审批＝AI 可直接放行低风险操作",
						options: [{ value: "off", label: "关闭" }, { value: "advise", label: "仅风险提示" }, { value: "auto", label: "自动审批" }],
					},
				],
			},
			{
				id: "rules",
				title: "安全规则",
				desc: "表内自上而下，先命中那条说话；表间取最严：拒绝＞人工＞交 AI＞允许。一张表全没命中＝没人放行，交模型判。",
				fields: [
					{ key: "commandRules", type: "rules", plane: "command" },
					{ key: "fileRules", type: "rules", plane: "file" },
					{ key: "networkRules", type: "rules", plane: "network" },
					{ key: "toolRules", type: "rules", plane: "tool" },
					{ key: "sourceRootDirs", type: "list", label: "源根搜索目录", hint: "一行一个绝对路径，最多 20 条；只列每处第一层的目录名，不进去、不读文件；每处超过 200 条会提示「可能没扫全」" },
				],
			},
			{
				id: "review",
				title: "AI 审查",
				desc: "规则没定论时由模型判断：证据（事实、目标、git 状态、你说过的授权）交给它，它只能说放行、否决或升级。开启后每次审查有少量 token 消耗。",
				fields: [
					{
						key: "reviewerSource", type: "segmented", label: "谁来做评审",
						hint: "跟随会话＝用当前对话同一个模型；指定预设＝从下面挑一个已配好的模型",
						options: [{ value: "session", label: "跟随会话" }, { value: "preset", label: "指定预设" }],
					},
					// 选「指定预设」时优先给这一行：从宿主已注册的 provider＋model 里挑。
					MODEL_PICKER_FIELD,
					// 目录读不到时才退回到手填（两条自由文本，值仍写回同一对键）。
					{ key: "reviewerProvider", type: "text", label: "Provider", hint: "手填：宿主注册名，如 deepseek", dependsOn: { key: "reviewerSource", value: "preset" }, fallbackOnly: true },
					{ key: "reviewerModel", type: "text", label: "Model", hint: "手填：模型 id，如 deepseek-chat", dependsOn: { key: "reviewerSource", value: "preset" }, fallbackOnly: true },
					{ key: "explainNoThinking", type: "switch", label: "AI 解读跳过思考", hint: "给解释调用补 reasoning_effort: none，不让模型先跑思维链；用户已配的档位或写入冲突一律放弃注入、回到宿主默认。关掉＝完全跟随宿主配置" },
					{ key: "fastJudge", type: "switch", label: "启用 AI 快判", hint: "单目标的写入／删除先问一次小模型；它只能说放行或升级，升级后走深评" },
					{ key: "reviewRules", type: "list", label: "自定义审查规则", hint: "每行一条，追加给模型的提示词末尾；只能加限制，不能放宽。例：禁止删除 .git 目录" },
					{ key: "reviewerMaxTokens", type: "number", label: "深评输出上限（token）", min: 64, max: 4096, hint: "要装下 verdict（依据＋理由）和任务卡；512 容易截断，2048 起；调大只多花输出费", advanced: true },
					{ key: "reviewerTimeoutMs", type: "number", label: "深评超时（毫秒）", min: 1000, max: 120000, hint: "超过就算评审失败，转人工确认；20000＝20 秒", advanced: true },
					{ key: "evidenceBudget", type: "number", label: "证据预算（字符）", min: 2000, max: 48000, hint: "送给深评的上下文上限；越大越准但越贵", advanced: true },
					{ key: "fastJudgeMaxTokens", type: "number", label: "快判输出上限（token）", min: 64, max: 1024, hint: "快判只回一个 JSON，256 够用", advanced: true },
					{ key: "fastJudgeTimeoutMs", type: "number", label: "快判超时（毫秒）", min: 500, max: 30000, hint: "超时即升级到深评，不拦人", advanced: true },
					{ key: "explainMaxTokens", type: "number", label: "AI 解读输出上限（token）", min: 1024, max: 2048, hint: "一次解读最多说这么多；1024 的下限是给思考留余量，调大只多花输出费", advanced: true },
				],
			},
			{
				id: "sensitive",
				title: "敏感保护",
				desc: "这一卡两件事，平行看：「检测规则」认出内容里的凭据形状，「敏感信息」记着遮出来的占位符。命中就先遮，再按档位处置——默认问你拒绝还是允许。",
				fields: [
					{ key: "sensitiveDetect", type: "switch", head: true, label: "启用检测与处置", hint: "关掉＝整张检测规则表不再表态，工具返回原样进模型上下文" },
					{ key: "autoRestoreSecrets", type: "switch", label: "写之前问要不要还原占位符", hint: "每次要把本表铸出的占位符写进文件之前，问你一句「要不要换成真值」：答还原才签这一次的证、写完那一刻换进去；答保持就在文件里留占位符。凭据/系统目录不问也不回填。命令参数里的占位符换不了；edit 的 old_string 比的是磁盘明文，带占位符会 not found" },
					{ key: "sensitiveRules", type: "rules", plane: "sensitive" },
				],
			},
			{
				id: "audit",
				title: "审计中心",
				desc: "每次调用、每条规则命中、每个人工答复和工具最终结果都进哈希链台账（按天分段）；下面每条的「层级」就是它在判定链上的第几步。",
				fields: [
					{ key: "auditTab", type: "switch", label: "会话标签", hint: "在会话头部加一个「审计」标签，只列这个会话的判定记录；关掉只影响这个入口，台账照旧写" },
					{ key: "retentionDays", type: "number", label: "保留天数", min: 1, max: 3650, hint: "超过天数的已封存段会被裁剪，并留 retention-pruned 墓碑", advanced: true },
					{ key: "maxTotalBytes", type: "number", label: "总大小上限（字节）", min: 1048576, hint: "超限从最旧的段开始裁；默认 512MB", advanced: true },
					{ key: "maxSegmentBytes", type: "number", label: "单段上限（字节）", min: 1048576, hint: "当天段写到这个大小就换下一个序号；默认 50MB", advanced: true },
				],
			},
		];
		// 「评审模型」不是一枚配置键：它一次写回 reviewerProvider ＋ reviewerModel 两个键，
		// 所以不登记进 FIELDS——登记了草稿里会多出一个 undefined 键，保存时凭空写坏一项。
		const FIELDS = SECTIONS.flatMap(section => section.fields).filter(field => field.key !== undefined);

		const RANGE_OPTIONS = [
			{ value: "all", label: "全部时间" },
			{ value: "today", label: "今天" },
			{ value: "7d", label: "近 7 天" },
			{ value: "30d", label: "近 30 天" },
		];
		const DECISION_OPTIONS = [
			{ value: "", label: "全部结果" },
			// 这一项筛的不是「结果」而是「谁判的」：同一个结果可能来自预设行，也可能来自
			// AI 深评，混在一起就看不出这一步是不是模型给的。前缀 `layer:` 把它和下面的
			// 结果档区分开（查询串里走 `layer` 参数，不进 `decision`）。
			{ value: "layer:deep", label: "AI 深评" },
			{ value: "allowed", label: "已放行" },
			{ value: "ask", label: "转人工" },
			{ value: "blocked", label: "已拦截" },
			{ value: "approved", label: "已批准" },
			{ value: "rejected", label: "已拒绝" },
			{ value: "cancelled", label: "没答" },
			{ value: "unavailable", label: "无应答通道" },
			{ value: "failed", label: "失败" },
			{ value: "delegated", label: "未接管" },
			{ value: "info", label: "信息" },
		];
		const CATEGORY_OPTIONS = [
			{ value: "", label: "全部分类" },
			{ value: "tool", label: "工具调用" },
			{ value: "command", label: "命令安全" },
			{ value: "file", label: "文件安全" },
			{ value: "network", label: "网络安全" },
			{ value: "sensitive", label: "敏感保护" },
			{ value: "approval", label: "审批" },
			{ value: "config", label: "配置变更" },
			{ value: "lifecycle", label: "生命周期" },
			{ value: "audit", label: "审计" },
		];
		const DECISION_LABEL = Object.fromEntries(DECISION_OPTIONS.map(item => [item.value, item.label]));
		const CATEGORY_LABEL = Object.fromEntries(CATEGORY_OPTIONS.map(item => [item.value, item.label]));

		/** Same filter object + anchor → same query string, so the effect can key on it. */
		// `extra` 只给会话标签用：`sessionId` 把范围收到一个会话，`limit` 一次读全（那里不分页）。
		// 不传就是设置页那套默认（50 条／一页），两个调用点共用一份拼参逻辑，不会各写一份漂掉。
		function auditQuery(filters, anchor, extra) {
			const params = new URLSearchParams();
			const now = Number(anchor) || Date.now();
			if (filters.range === "today") {
				const start = new Date();
				start.setHours(0, 0, 0, 0);
				params.set("from", String(start.getTime()));
			}
			else if (filters.range === "7d")
				params.set("from", String(now - 7 * 86400000));
			else if (filters.range === "30d")
				params.set("from", String(now - 30 * 86400000));
			if (filters.decision.startsWith("layer:")) params.set("layer", filters.decision.slice(6));
			else if (filters.decision) params.set("decision", filters.decision);
			if (filters.category) params.set("category", filters.category);
			// Boot / config / human rows are bookkeeping, not the decisions the operator
			// comes here to read: hidden by default, each with its own switch. Choosing
			// any category explicitly shows that category unfiltered.
			const hidden = [];
			if (filters.hideBoot !== false) hidden.push("lifecycle.boot");
			if (filters.hideConfig !== false) hidden.push("config.changed");
			if (filters.hideHuman !== false) hidden.push("approval.answer");
			if (hidden.length > 0 && !filters.category) params.set("hide", hidden.join(","));
			if (filters.q.trim()) params.set("q", filters.q.trim());
			if (typeof extra?.sessionId === "string" && extra.sessionId !== "") params.set("sessionId", extra.sessionId);
			params.set("offset", String(filters.offset || 0));
			params.set("limit", String(extra?.limit ?? 50));
			return params.toString();
		}

		/** * 敏感信息表：脱敏换来的占位符。
		 * 明文默认不出这行——只给头 4 字与长度，点「显示」才单条取一次（宿主那边记一条
		 * sensitive.revealed，谁看过哪条凭据是可查的）。「回写」是这一条能不能被换回明文。
		 */
		// 浅蓝开关：规则行的「启用中／已停用」与敏感信息行的「自动回写」共用同一颗。
		// 不用 <button>：宿主给 button 的基线样式（方角／内边距）会盖掉胶囊形；
		// 几何与颜色一律写成行内样式，宿主样式表压不到它。
		function Toggle({ id, checked, onChange, disabled, title, className }) {
			const on = checked === true;
			const off = disabled === true;
			// 用 SVG 画：圆角写在 <rect rx>、圆写在 <circle r>，宿主样式表改不动图形本身。
			return h("span", {
				id, title,
				role: "switch",
				tabIndex: off ? -1 : 0,
				"aria-checked": on ? "true" : "false",
				className: `dsa-switch${on ? " is-on" : ""}${className ? ` ${className}` : ""}`,
				style: {
					display: "inline-flex", alignItems: "center", flex: "none",
					cursor: off ? "default" : "pointer", opacity: off ? 0.45 : 1,
					verticalAlign: "middle",
				},
				onClick: () => { if (!off) onChange(!on); },
				onKeyDown: event => {
					if (off || (event.key !== "Enter" && event.key !== " "))
						return;
					event.preventDefault();
					onChange(!on);
				},
			}, h("svg", { width: 44, height: 24, viewBox: "0 0 44 24", style: { display: "block" } },
				h("rect", {
					x: 0.5, y: 0.5, width: 43, height: 23, rx: 11.5, ry: 11.5,
					fill: on ? "#5A9BE8" : "#E5E7EB",
					stroke: on ? "#5A9BE8" : "#D7DADE",
				}),
				// 粒子半径 9、圆心 12/32：距轨道内沿左右各 2px、上下各 2px，不会探出框外。
				h("circle", { cx: on ? 32 : 12, cy: 12, r: 9, fill: "#fff", stroke: "rgba(0,0,0,.12)" })));
		}

		function SecretVault({ secrets, onReveal, onHide, onRestore, onRemove, onGrant, onClear, confirmClear, onConfirmClear, onBack }) {
			const rows = Array.isArray(secrets.entries) ? secrets.entries : [];
			// A13：页面不再提供「手填会话 ID／目的路径／分钟数」的签发入口。
			// 证由写盘那一刻的询问自己签（index.js 的 offerRestoreBeforeWrite）——
			// 在设置页手工签的对象是「一次已经错过的写」，签完也不会回头重试。
			// 明细页的头和规则表明细同一形制：返回、图标、标题、计数。
			// 「敏感信息」是卡片里的一张明细，不是一张独立页——没有返回键就走不回上一层的摘要。
			const head = h("div", { className: "dsa-detailHead" },
				onBack === undefined ? null : h("button", {
					type: "button", className: "dsa-back", onClick: onBack,
				}, "‹ 返回"),
				h(PlaneIcon, { plane: "secrets" }),
				h("span", { className: "dsa-detailTitle" }, "敏感信息"),
				h("span", { className: "dsa-detailCount" },
					`${rows.length} 条 · 明文只在本机映射表，查看会记一笔台账`));
			const wrap = body => h("div", { className: "dsa-detail is-embedded" }, head, body);
			if (secrets.status === "loading")
				return wrap(h("div", { className: "dsa-readonly" }, "正在读取敏感信息表…"));
			if (secrets.status === "failed")
				return wrap(h("div", { className: "dsa-warn" }, `读不到敏感信息表：${secrets.error}`));
			return wrap(h("div", { className: "dsa-secretList" },
				rows.length === 0
					? h("div", { className: "dsa-readonly" }, "还没有占位符——脱敏过一次才会有。")
					: rows.map(row => h(react.Fragment, { key: row.token },
						h("div", {
							className: "dsa-item dsa-secret",
							},
							h("code", { className: "dsa-secretToken" }, row.token),
							h("span", { className: "dsa-secretLabel" }, row.label),
							h("span", { className: "dsa-secretPlain" },
							secrets.revealed[row.token] ?? `${row.head}····（${row.chars} 字）`),
							h("span", { className: "dsa-secretMeta" },
							`${row.hits} 次 · 出处 ${row.source || "—"}`),
							h("button", {
							type: "button", className: "dsa-iconBtn",
							title: secrets.revealed[row.token] === undefined ? "显示这一条完整明文（会记一笔台账）" : "收起明文",
							onClick: () => (secrets.revealed[row.token] === undefined
							? onReveal(row.token) : onHide(row.token)),
							}, secrets.revealed[row.token] === undefined ? "显示" : "收起"),
							// 开关比「回写开／回写关」这种三个字更像控件，也不会被挤成竖排。
							h("span", {
							className: "dsa-secretRestore",
							title: row.restore ? "问到你时可以把这条换成真值，点开关关掉" : "这条不问也不还原，点开关打开",
							},
							h("span", { className: "dsa-secretRestoreLabel" }, "允许还原"),
							h(Toggle, {
							id: `frame-secret-restore-${row.token}`,
							checked: row.restore === true,
							onChange: value => onRestore(row.token, value),
							})),
							h("button", {
							type: "button", className: "dsa-iconBtn is-danger", title: "删掉这条映射（占位符从此换不回明文）",
							onClick: () => onRemove(row.token),
							}, "✕"),
						))),
				rows.length === 0 ? null : h("div", { className: "dsa-secretFoot" },
					confirmClear
						? h(react.Fragment, null,
							h("span", { className: "dsa-status" }, "清空后所有占位符都换不回明文，确定？"),
							h(Button, { variant: "primary", size: "sm", onClick: onClear }, "确认清空"),
							h(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(false) }, "取消"))
						: h(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(true) }, "清空映射表"))));
		}

		// `embedded`：会话头的「审计」标签复用这一套卡片，但不要页面级那套东西——
		// 那里没有「导出整本台账」「清空」「按时间挑范围」的位置，也不该分页（一次读本会话全部）。
		// 只留搜索框与刷新，其余照旧，两处渲染的卡片因此是同一份代码，不会各自漂。
		function AuditCenter({ audit, filters, onFilter, onRefresh, onExport, onClear, confirmClear, onConfirmClear, clearing, toolRows, embedded, onOpenSettings, emptyText }) {
			// 哪几张卡的「命令结果」被点开了。状态按卡片键存在这一层：卡片是 map 出来的，
			// 展开态挂在这里才不会被下一张卡借走（也不用为每张卡造一个组件）。
			const [openResults, setOpenResults] = react.useState({});
			const toggleResult = key => setOpenResults(previous => ({ ...previous, [key]: previous[key] !== true }));
			// 「给它定个规则」的展开态与落盘结果，同样按卡片键存在这一层。
			// 每个工具只挂最新一条日志：写在卡上的是「这个工具以后怎么对待」，不是「这一次怎么办」。
			const STRANGER_ROW = "认不出操作类型的工具";
			const RULE_TIERS = [
				{ value: "release", label: "允许" },
				{ value: "ai", label: "交 AI" },
				{ value: "deny", label: "拒绝" },
			];
			const TIER_WORD = { release: "允许", ai: "交 AI", ask: "人工", deny: "拒绝" };
			const [ruleCards, setRuleCards] = react.useState({});
			const ruleStateOf = key => ruleCards[key] ?? {};
			const toggleRule = key => setRuleCards(previous => ({
				...previous,
				[key]: { ...(previous[key] ?? {}), open: (previous[key]?.open ?? false) !== true, action: previous[key]?.action ?? "release", error: "" },
			}));
			const pickTier = (key, action) => setRuleCards(previous => ({
				...previous, [key]: { ...(previous[key] ?? {}), action, error: "" },
			}));
			const closeRule = key => setRuleCards(previous => ({
				...previous, [key]: { ...(previous[key] ?? {}), open: false, error: "" },
			}));
			const submitRule = async (key, toolName, action) => {
				setRuleCards(previous => ({ ...previous, [key]: { ...(previous[key] ?? {}), busy: true, error: "" } }));
				try {
					const response = await fetch(TOOL_RULE_ROUTE, {
						method: "POST",
						credentials: "same-origin",
						cache: "no-store",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({ toolName, action }),
					});
					const body = await response.json().catch(() => ({}));
					if (!response.ok || body.ok !== true)
						throw new Error(body.error || `HTTP ${response.status}`);
					// 落盘成功才把卡片改成「已加规则」：没写进去就报错，不假装成功。
					setRuleCards(previous => ({
						...previous,
						[key]: { open: false, busy: false, error: "", saved: { action, created: body.created === true } },
					}));
				}
				catch (cause) {
					setRuleCards(previous => ({
						...previous,
						[key]: { ...(previous[key] ?? {}), busy: false, open: true, error: String(cause?.message ?? cause) },
					}));
				}
			};
			const status = audit?.status ?? "loading";
			const entries = Array.isArray(audit?.entries) ? audit.entries : [];
			const chain = audit?.chain;
			const when = value => {
				const date = new Date(Number(value));
				return Number.isFinite(date.getTime()) && date.getTime() > 0
					? date.toLocaleString("zh-CN", { hour12: false })
					: "-";
			};
			const total = audit?.total ?? 0;
			const matched = audit?.matched ?? 0;
			const offset = filters.offset || 0;
			const pageEnd = Math.min(offset + 50, matched);
			// 每个陌生工具只给最新那一条日志挂入口：同一工具在一屏里出现几十次，
			// 每条都挂一颗「放行」纯属噪音，点哪条效果还都一样。
			const strangerLatest = new Map();
			for (const entry of entries) {
				const toolName = String(entry?.toolName ?? "").trim();
				if (toolName === "" || String(entry?.rule ?? "").includes("认不出操作类型的工具") === false) continue;
				const at = Number(entry?.sequence ?? entry?.timestamp ?? 0);
				if (strangerLatest.has(toolName) !== true || at > strangerLatest.get(toolName))
					strangerLatest.set(toolName, at);
			}
			// 工具规则表里已经有这个工具的用户行 ⇒ 按钮是「修改」而不是「放行」。
			// 返回整行而不是 bool：悬浮文案要说出现在是哪个档，不能只说「改一下」。
			const toolRowOf = toolName => (Array.isArray(toolRows) ? toolRows : []).find(row =>
				row !== null && typeof row === "object"
				&& String(row.preset ?? "") === "" && String(row.match ?? "").trim() === toolName
				&& row.enabled !== false);

			const tone = entry => {
				if (entry.decision === "allowed" || entry.decision === "approved") return "t-allow";
				// 拒绝与「没答成」都是非放行，同一色；只有真放行是绿。
				if (["blocked", "rejected", "failed", "cancelled", "unavailable"].includes(entry.decision)) return "t-deny";
				if (entry.decision === "ask") return "t-ask";
				return "t-silent";
			};
			// 卡片只写「命中规则（序号＋名字）｜规则结果」，工具与权限收进括号；
			// 规则路线没有理由码，理由只在 AI 判过之后才有（那是 AI 路线的东西）。
			const metaOf = entry => {
				const inner = [
					entry.toolName ? `工具 ${entry.toolName}` : "",
					entry.grant ? `权限 ${entry.grant}` : "",
				].filter(Boolean).join(" · ");
				return [
					entry.rule ? String(entry.rule) : "",
					inner === "" ? "" : `（${inner}）`,
					Array.isArray(entry.reasons) && entry.reasons.length > 0 ? `理由 ${(entry.reasonLabels ?? entry.reasons).join("、")}` : "",
					entry.durationMs !== undefined ? `耗时 ${(Number(entry.durationMs) / 1000).toFixed(1)}s` : "",
				].filter(Boolean).join(" · ");
			};
			// 一次调用在账本里是好几行（命中→判定→答复→结果），原样铺开就是密麻一屏。
			// 列表按 toolCallId 折成一张卡：原始台账与导出不动，只是页面按命令看。
			const groupEntries = list => {
				const groups = [];
				const at = new Map();
				for (const entry of Array.isArray(list) ? list : []) {
					if (entry === null || entry === undefined)
						continue;
					const key = entry.toolCallId ?? entry.actionHash;
					if (key === undefined || key === null) {
						groups.push([entry]);
						continue;
					}
					const found = at.get(key);
					if (found !== undefined) {
						groups[found].push(entry);
						continue;
					}
					at.set(key, groups.length);
					groups.push([entry]);
				}
				return groups;
			};
			const DECISION_RANK = { blocked: 5, ask: 4, allowed: 3, failed: 2, info: 1 };
			const headOf = group => group.reduce((best, item) =>
				(DECISION_RANK[item.decision] ?? 0) > (DECISION_RANK[best.decision] ?? 0) ? item : best, group[0]);
			// 「转人工」之后又沿用了人工回执放行：这次调用的实际结局是放行，卡头徽标跟着结局走。
			// 只认 approval.receipt 这一种；真转人工的组没有它，仍按最严行显示。
			const badgeOf = (group, head) => head.decision !== "ask" ? head
				: group.find(entry => entry.eventType === "approval.receipt" && entry.decision === "allowed") ?? head;
			// heredoc 的正文是数据不是命令：页面上只留命令行＋行数，否则一次写入看起来像好几条命令摞在一起。
			// 台账与导出仍是原文，这里只动显示。
			const previewOf = text => {
				const raw = String(text ?? "");
				const newline = raw.indexOf("\n");
				if (newline === -1 || !/<<-?\s*['"]?[A-Za-z_][A-Za-z0-9_]*/.test(raw.slice(0, newline)))
					return raw;
				const lines = raw.slice(newline + 1).split("\n").filter(line => line.trim() !== "");
				return `${raw.slice(0, newline)} …（heredoc 正文 ${lines.length} 行已折叠；全文见导出台账）`;
			};
			return h("div", { className: "dsa-audit" },
				h("div", { className: "dsa-auditHead" },
					h("span", { className: "dsa-auditTitle" },
						"判定记录",
						// 会话标签里标题旁就是本会话的条数；写全量会让人以为这个会话有那么多。
						h("span", { className: "dsa-sectionCount" }, String(embedded === true ? matched : total))),
					h("span", { className: "dsa-auditBtns" },
						h(Button, { variant: "ghost", size: "sm", onClick: onRefresh, disabled: status === "loading" },
							status === "loading" ? "读取中…" : "刷新"),
						// 「设置」只给会话标签：审计中心本身就长在设置页里，再摆一个跳设置的按钮是绕圈。
						embedded === true ? h(Button, {
							variant: "ghost", size: "sm", onClick: onOpenSettings,
							title: "打开自动审批框架设置",
						}, "设置") : null,
						embedded === true ? null : h(Button, { variant: "ghost", size: "sm", onClick: () => onExport("jsonl") }, "导出 JSONL"),
						embedded === true ? null : h(Button, { variant: "ghost", size: "sm", onClick: () => onExport("md") }, "导出 Markdown"),
						embedded === true ? null : (confirmClear
							? h(Button, { variant: "ghost", size: "sm", onClick: onClear, disabled: clearing }, clearing ? "清空中…" : "确认清空")
							: h(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(true) }, "清空")))),
				h("div", { className: "dsa-auditBar" },
					// 会话标签里只有一个搜索框：时间范围／结果／分类这些是「翻整本账」的工具，
					// 在一个会话里挑范围不如直接搜。
					embedded === true ? null : h(SegmentedControl, {
						id: "frame-audit-range", value: filters.range, label: "", options: RANGE_OPTIONS,
						onChange: value => onFilter({ range: value }),
					}),
					embedded === true ? null : h("select", {
						className: "dsa-filterSelect", value: filters.decision,
						onChange: event => onFilter({ decision: event.target.value }),
					}, ...DECISION_OPTIONS.map(item => h("option", { key: item.value, value: item.value }, item.label))),
					embedded === true ? null : h("select", {
						className: "dsa-filterSelect", value: filters.category,
						onChange: event => onFilter({ category: event.target.value }),
					}, ...CATEGORY_OPTIONS.map(item => h("option", { key: item.value, value: item.value }, item.label))),
					h(Input, {
						// 会话标签只有一个搜索框，占满这一行才方便搜；审计中心里它要和
						// 旁边的时间／结果／分类三件并排，所以仍按定宽走。
						style: embedded === true ? { flex: "1 1 260px", maxWidth: 520 } : { width: 220 },
						value: filters.q, placeholder: "搜索动作 / 工具 / 规则",
						onChange: event => onFilter({ q: event.target.value }),
					}),
					embedded === true ? null : h("span", { className: "dsa-toggles" },
						[["hideBoot", "frame-audit-hide-boot", "隐藏启动记录", "开＝这一类不显示（默认开）；按分类筛选时照常显示"],
							["hideConfig", "frame-audit-hide-config", "隐藏配置变更", "开＝这一类不显示（默认开）；按分类筛选时照常显示"],
							["hideHuman", "frame-audit-hide-human", "隐藏人工答复", "你亲手答的那一行：同意还是拒绝（默认显示）"]].map(([key, id, label, hint]) =>
							h("label", { key: id, className: "dsa-toggle", title: hint },
								h(Switch, {
									id, checked: filters[key] !== false, label: "",
									onChange: value => onFilter({ [key]: value }),
								}),
								h("span", { className: "dsa-toggleText" }, label))))),
				h("div", { className: "dsa-summaryBand" },
					status === "failed"
						? `读不到审计：${audit?.error || "宿主未提供审计接口"}`
						// 会话标签里「共 N 条」指的是全机，不是本会话：不写清就会被读成
						// 「这个会话有 344 条，只显示了 129 条」。
						: (embedded === true
							? `本会话 ${matched} 条 · 全机共 ${total} 条审批 · ${audit?.segments ?? 0} 段`
							: `匹配 ${matched} / 共 ${total} 条审批 · ${audit?.segments ?? 0} 段`) +
							(chain ? ` · ${chain.ok === true ? "哈希链校验通过" : `链在第 ${chain.brokenAt ?? "?"} 处断了`}` : "")),
				status === "failed"
					? h("div", { className: "dsa-emptyList" }, "检查宿主的 audit 路由是否已挂载（connection.fetch），或重启 DSH 后再看。")
					: entries.length === 0
						? h("div", { className: "dsa-emptyList" }, status === "loading" ? "正在读取…" : (emptyText ?? "没有符合条件的记录。"))
						: h("div", { className: "dsa-entries" },
							...groupEntries(entries).map(group => {
								const head = headOf(group);
								const badge = badgeOf(group, head);
								// 子行读它自己的 message；没有 message 的记录（AI 档命中那行）读 rule——
								// 规则文案自带整句，「命中哪条、给了什么结果」靠它说，不必再补一句解释。
								const subTextOf = entry => String(entry.message ?? entry.rule ?? "");
								// 子行按时间正序读（命中→答复→结果），与卡头的判定拼成一条线。
								const rest = group
									.filter(entry => entry !== head && subTextOf(entry) !== "")
									.filter(entry => subTextOf(entry) !== String(head.message ?? ""))
									.sort((left, right) => (left.sequence ?? 0) - (right.sequence ?? 0));
								// 工具输出（tool.result）不进子行正文：它落成卡片右下角的「命令结果」按钮，
								// 点开才展开。一屏几十张卡，正文摊开就看不见判定。失败的那份也是这次调用的返回
								// （报错原文同样是结果），一并收进同一个按钮，只在按钮底色上标红——文案与成功时一致，不另起一行摊进正文。
								const results = rest.filter(entry => entry.eventType === "tool.result");
								const resultFailed = results.some(entry => entry.decision === "failed");
								const spoke = rest.filter(entry => results.includes(entry) === false);
								const resultText = results.map(entry => String(entry.message ?? "")).filter(Boolean).join("\n");
								// 卡片下半段：判定过程子行（左）＋命令结果按钮（右）。按钮不进正文流，
								// 它跟在最后一条子行右边——和 allow 那行同一水平线，这就是「集成到最后一行」。
								const resultKey = head.id ?? `${head.sequence}-${head.timestamp}`;
								const resultOpen = openResults[resultKey] === true;
								const resultButton = h("button", {
									type: "button", className: "dsa-resultBtn" + (resultFailed ? " is-failed" : ""),
									onClick: () => toggleResult(resultKey),
								}, resultOpen ? "收起命令结果" : "命令结果");
								// 只给「认不出操作类型的工具」这一档开入口：它判的是工具本身（这一档是「交 AI」，
								// 模型放行时人看不到卡），所以入口挂在事后的日志卡上——看到那条记录才想起来管它。
								const strangerHits = group.filter(entry => String(entry.rule ?? "").includes(STRANGER_ROW));
								const strangerTool = strangerHits.map(entry => String(entry.toolName ?? "").trim()).find(name => name !== "")
									?? String(head.toolName ?? "").trim();
								const strangerAt = strangerHits.reduce((at, entry) => Math.max(at, Number(entry.sequence ?? entry.timestamp ?? 0)), -1);
								const stranger = strangerTool === "" || strangerLatest.get(strangerTool) !== strangerAt ? null : strangerTool;
								const ruleKey = `${resultKey}-rule`;
								const ruleState = ruleStateOf(ruleKey);
								// 表里已经有这个工具的用户行 ⇒ 按钮是「修改」且要说出现在的档，
								// 没有才是「放行」。两态的悬浮文案各写各的：一句通用的
								// 「定一条规则」让人分不清点下去是新建还是覆盖。
								const rowNow = stranger === null ? undefined : toolRowOf(stranger);
								const nowWord = rowNow === undefined ? "" : (TIER_WORD[String(rowNow.action ?? "")] ?? String(rowNow.action ?? "未表态"));
								const ruleButton = stranger === null ? null : (ruleState.saved !== undefined
									? h("span", { className: "dsa-ruleSaved" }, `${ruleState.saved.created === true ? "已添加" : "已修改"}：${TIER_WORD[ruleState.saved.action] ?? ruleState.saved.action}`)
									: h("button", {
										type: "button", className: "dsa-ruleBtn",
										title: rowNow === undefined
											? `给 ${stranger} 加一条放行规则：以后这个工具不再逐次问你`
											: `改 ${stranger} 的处理方式：现在是「${nowWord}」，点开可换一档`,
										onClick: () => toggleRule(ruleKey),
									}, `${rowNow === undefined ? "放行" : "修改"}：${stranger}`));
								// 点开才出现风险说明与三档，按「添加」才落盘——误点一次不会悄悄改掉规则。
								// 风险那句是固定的：工具叫 search 也只说它「可能写盘、读文件、把内容发出去」。
								const rulePanel = (stranger !== null && ruleState.open === true) ? h("div", { className: "dsa-rulePanel" },
									// 末句单独加粗：前面是条件，最后四个字是人真正要做的动作，混在一段灰字里
									// 等于没强调。
									h("div", { className: "dsa-ruleRisk" },
										"插件工具不限于搜索——它也可能写盘、读文件、把内容发出去；放行之后这些都不再单独问你。",
										h("strong", null, "请认真识别。")),
									h("div", { className: "dsa-ruleTiers" }, ...RULE_TIERS.map(tier => h("button", {
										key: tier.value, type: "button",
										className: "dsa-ruleTier" + ((ruleState.action ?? "release") === tier.value ? " is-on" : ""),
										onClick: () => pickTier(ruleKey, tier.value),
									}, tier.label))),
									h("div", { className: "dsa-ruleFoot" },
										h(Button, {
											variant: "primary", size: "sm", disabled: ruleState.busy === true,
											onClick: () => void submitRule(ruleKey, stranger, ruleState.action ?? "release"),
										}, ruleState.busy === true ? "写入中…" : rowNow === undefined ? "添加规则" : "保存修改"),
										h(Button, {
											variant: "ghost", size: "sm", disabled: ruleState.busy === true,
											onClick: () => closeRule(ruleKey),
										}, "取消")),
									ruleState.error ? h("div", { className: "dsa-ruleError" }, ruleState.error) : null) : null;
								// 卡尾两颗按钮同占一个右对齐槽：命令结果在左、放行／修改在右。有子行时
								// 挂在最后一条子行上，没有子行就自己占一行——两种情形的右边距一致，
								// 「放行」不会因为多了个命令结果就换行掉到下面去。
								const tailSlot = (resultText === "" && ruleButton === null) ? null
									: h("span", { key: "tail", className: "dsa-resultSlot" },
										resultText === "" ? null : resultButton,
										ruleButton);
								const subs = spoke.map((entry, at) => h("div", {
									key: entry.id ?? `${entry.sequence}`, className: "dsa-entrySub",
								},
									h("span", { className: "dsa-chip " + tone(entry) }, DECISION_LABEL[entry.decision] ?? entry.decision ?? "-"),
									h("span", { className: "dsa-entrySubText" }, subTextOf(entry)),
									(at === spoke.length - 1) ? tailSlot : null));
								const more = (subs.length > 0 || tailSlot !== null) ? h("div", { className: "dsa-entryMore" },
									...subs,
									// 没有子行时按钮单独占一行，仍靠右，位置不乱跳。
									(subs.length === 0 && tailSlot !== null)
										? h("div", { key: "tailRow", className: "dsa-entrySub is-tail" }, tailSlot) : null,
									(resultOpen && resultText !== "") ? h("div", { key: "text", className: "dsa-resultText" + (resultFailed ? " is-failed" : "") }, resultText) : null) : null;
								return h("div", {
									key: head.id ?? `${head.sequence}-${head.timestamp}`,
									// 色条与胶囊同一判据：两处各写一遍迟早对不上。
									className: `dsa-item dsa-entry tone-${tone(badge).slice(2)}`,
								},
									h("div", { className: "dsa-entryHead" },
										h("span", { className: "dsa-chip " + tone(badge) }, DECISION_LABEL[badge.decision] ?? badge.decision ?? "-"),
										h("span", { className: "dsa-entryCategory" }, CATEGORY_LABEL[head.category] ?? head.category ?? "-"),
										h("span", { className: "dsa-entryLayer" }, layerTextOf(head)),
										h("span", { className: "dsa-entryTime" }, when(head.timestamp))),
									head.commandPreview ? h("div", { className: "dsa-entryAction", title: head.commandPreview }, previewOf(head.commandPreview)) : null,
									metaOf(head) ? h("div", { className: "dsa-entryMeta" }, metaOf(head)) : null,
									head.message ? h("div", { className: "dsa-entrySummary" }, head.message) : null,
									more,
									rulePanel);
							})),
				// 会话标签一次读全会话（上限在请求里给），没有第二页可翻。
				embedded === true ? null : h("div", { className: "dsa-pager" },
					h(Button, { variant: "ghost", size: "sm", disabled: offset <= 0, onClick: () => onFilter({ offset: Math.max(0, offset - 50) }) }, "上一页"),
					h("span", { className: "dsa-pagerInfo" }, matched === 0 ? "0 条" : `${offset + 1}–${pageEnd} / ${matched} 条`),
					h(Button, { variant: "ghost", size: "sm", disabled: pageEnd >= matched, onClick: () => onFilter({ offset: offset + 50 }) }, "下一页")));
		}


		// 审计标签里那条 3px 浅灰竖线不是本插件画的：是宿主 ConversationRoot 的
		// 「内容列宽拖柄」[data-width-handle]（z-index:8，渐变实段跟鼠标 Y），
		// 正好压在「刷新」按钮上。抬本卡片的层叠去盖它是死路——composer 输入框
		// z-index 7／弹菜单时 9，能盖住拖柄的层必然同时盖住输入框（记忆闸 0.2.7
		// 早就量过这条 z 序死锁）。所以由本标签在「挂载＝标签激活」期间自己注入一条
		// 全局样式把拖柄藏起来，切走即恢复；只认自己的 data-handle-guard，不碰别人的。
		const HANDLE_GUARD_ID = "dsh-auto-approval-frame";
		function guardWidthHandle() {
			const doc = globalThis.document;
			if (doc == null || typeof doc.querySelector !== "function")
				return;
			if (doc.querySelector(`style[data-handle-guard="${HANDLE_GUARD_ID}"]`) != null)
				return;
			const tag = doc.createElement("style");
			tag.setAttribute("data-plugin", PLUGIN_NAME);
			tag.setAttribute("data-handle-guard", HANDLE_GUARD_ID);
			tag.textContent = "[data-width-handle]{display:none!important}";
			doc.head?.appendChild(tag);
		}
		function unguardWidthHandle() {
			const doc = globalThis.document;
			if (doc == null || typeof doc.querySelector !== "function")
				return;
			const tag = doc.querySelector(`style[data-handle-guard="${HANDLE_GUARD_ID}"]`);
			if (tag != null)
				tag.remove();
		}
		// 「设置」直达的目标是宿主 RowDetail（plugins.row.config 的 view:"page"），
		// 不是组合包详情页。宿主公开的 pluginNavigation 只有 openList/openBundle，
		// openBundle 只把视图推到 kind:"package"，包页上还得再点一次行「配置」。
		// 宿主把导航 store 挂在 main 面板注册项的 options.store 上，store.create()
		// 返回注册时那个固定 instance，所以可以直接 setView 选到「某一行」。
		// 还有个坑：ctx.layout 没写进 inject 时是 undefined（死链），服务要用
		// cordis 的 ctx.get 读（"without the inject requirement"），且 pluginNavigation
		// 只在插件页有权限时提供 —— 所以先选中插件面板，再读服务与 store。
		const PLUGIN_PANEL = "plugins";
		const ROW_DETAIL_SELECTOR = `[data-plugin-row-detail="${ROW_CONFIG_KEY}"]`;
		const PACKAGE_CARD_SELECTOR = `[data-plugin-package="${PACKAGE_NAME}"]`;

		function hostService(ctx, name) {
			let value = null;
			try {
				if (typeof ctx?.get === "function")
					value = ctx.get(name);
			}
			catch {
				// 老宿主的 get 可能对未提供的服务抛错：退回属性读取。
			}
			// 有些宿主把服务直接挂在 ctx 上（写进 inject 才会出现），一并认。
			return value ?? ctx?.[name] ?? null;
		}

		function pluginViewStore(ctx) {
			try {
				const entries = typeof ctx?.slots?.entries === "function" ? ctx.slots.entries("main") : null;
				const panel = (entries ?? []).find(entry => entry?.options?.key === PLUGIN_PANEL);
				if (panel == null)
					return null;
				// StoredEntry 把 store 放在顶层，renderer 的 erased options 里也留了一份；
				// 两种形状都试，取第一个真能 setView 的实例，不赌宿主的存放位置。
				for (const raw of [panel.store, panel.options?.store]) {
					const handle = typeof raw === "function" ? raw() : raw;
					const instance = typeof handle?.create === "function" ? handle.create() : handle;
					if (typeof instance?.actions?.setView === "function")
						return instance;
				}
				return null;
			}
			catch {
				return null;
			}
		}

		function selectPluginRow(store) {
			try {
				if (typeof store.actions.setTab === "function")
					store.actions.setTab("installed");
				store.actions.setView({ kind: "row", name: PACKAGE_NAME, rowId: ROW_ID });
				return true;
			}
			catch {
				return false;
			}
		}

		// 拿不到 store 时借宿主自己那颗「配置」按钮完成跳转：pkgOrigin／returnTab
		// 由宿主自己算，不去猜内部 view 形状。返回 true＝已到目标页或点中行按钮。
		function clickPluginRow() {
			const doc = globalThis.document;
			if (doc == null || typeof doc.querySelectorAll !== "function")
				return false;
			if (typeof doc.querySelector === "function" && doc.querySelector(ROW_DETAIL_SELECTOR) != null)
				return true;
			const rows = doc.querySelectorAll("[data-plugin-row]");
			for (const row of rows) {
				const id = row.getAttribute("data-plugin-row");
				// 精确认本行；包详情页只列出本包的行时，单行即本行（entryId 可能带前缀）。
				if (id !== ROW_ID && id !== PACKAGE_NAME && rows.length !== 1)
					continue;
				const config = row.querySelectorAll("button[aria-label]")
					.find(btn => btn.getAttribute("role") !== "switch");
				if (config != null && typeof config.click === "function") {
					config.click();
					return true;
				}
			}
			// 还停在列表页：先点本包卡片进详情，下一轮再点行。
			if (typeof doc.querySelector === "function") {
				const card = doc.querySelector(PACKAGE_CARD_SELECTOR);
				const open = card?.querySelectorAll?.("button[aria-label]")
					?.find(btn => btn.getAttribute("role") !== "switch");
				if (open != null && typeof open.click === "function")
					open.click();
			}
			return false;
		}

		function drivePluginRow(attempt = 0) {
			if (clickPluginRow() === true)
				return;
			if (attempt >= 12)
				return;
			setTimeout(() => drivePluginRow(attempt + 1), 50);
		}

		function openPluginSettings() {
			const ctx = hostCtx;
			if (ctx == null)
				return false;
			let opened = false;
			// 先选中插件面板：它一挂上，pluginNavigation 与 main 面板的 store 才存在。
			const layout = hostService(ctx, "layout");
			if (typeof layout?.selectPanel === "function") {
				try {
					layout.selectPanel(PLUGIN_PANEL);
					opened = true;
				}
				catch {
					// 面板还没注册：后面还有导航服务和 DOM 兜底。
				}
			}
			const nav = hostService(ctx, "pluginNavigation");
			if (typeof nav?.openBundle === "function") {
				try {
					nav.openBundle(PACKAGE_NAME);
					opened = true;
				}
				catch {
					// 服务在但抛错：别把按钮做成死链。
				}
			}
			const store = pluginViewStore(ctx);
			if (store !== null && selectPluginRow(store))
				return true;
			if (opened) {
				drivePluginRow();
				return true;
			}
			return false;
		}

		// 会话头的「审计」标签：只列**这个会话**的判定记录。数据面就一个请求——
		// `/audit?sessionId=…&limit=200`，服务端按整串相等筛（`lib/frame/audit.js` 的 filterEntries）。
		// 卡片与全局审计中心共用同一份渲染（embedded），所以「放行／修改」在这里一样能用。
		// 关掉这个入口只影响标签本身，台账照写（开关在设置页-审计中心，默认开）。
		function ConversationAudit(props) {
			react.useEffect(() => settingsStylesheet("dsh-auto-approval-frame/audit-tab"), []);
			// 本视图在 DOM 中 ⇔ 审计标签激活；激活期间藏宿主列宽拖柄，切走恢复。
			react.useEffect(() => { guardWidthHandle(); return unguardWidthHandle; }, []);
			const sessionId = typeof props?.sessionId === "string" ? props.sessionId : "";
			const [q, setQ] = react.useState("");
			const [tick, setTick] = react.useState(0);
			const [toolRows, setToolRows] = react.useState([]);
			const [audit, setAudit] = react.useState({
				status: "loading", entries: [], matched: 0, total: 0, segments: 0, chain: null, error: "",
			});
			// 会话里不看「哪段时间」，也不按结果／分类分栏：范围已经收到一个会话，
			// 剩下的只有搜索。人工答复要留着——它正是这个会话里最该被看见的一行。
			const filters = { range: "all", decision: "", category: "", q, offset: 0,
				hideBoot: true, hideConfig: true, hideHuman: false };
			const query = auditQuery(filters, null, { sessionId, limit: 200 });
			react.useEffect(() => {
				if (sessionId === "") return undefined;
				let alive = true;
				setAudit(current => ({ ...current, status: "loading", error: "" }));
				fetch(`${AUDIT_ROUTE}?${query}`, { credentials: "same-origin", cache: "no-store" })
					.then(response => {
						if (!response.ok) throw new Error(`HTTP ${response.status}`);
						return response.json();
					})
					.then(body => {
						if (!alive) return;
						if (body?.ok !== true) throw new Error(body?.error ?? "宿主读审计失败");
						setAudit({
							status: "ready",
							entries: Array.isArray(body.entries) ? body.entries : [],
							matched: Number(body.matched ?? 0),
							total: Number(body.total ?? 0),
							segments: Number(body.segments ?? 0),
							chain: body.chain ?? null,
							error: "",
						});
					})
					.catch(cause => {
						if (alive)
							setAudit({ status: "failed", entries: [], matched: 0, total: 0, segments: 0, chain: null,
								error: String(cause?.message ?? cause) });
					});
				return () => { alive = false; };
			}, [query, sessionId]);
			// 工具规则表：卡上的「放行／修改」要靠它判有没有这一行、现在停在哪个档。
			// 刷新时一并重读——刚在这里定完规则，回来这里要能看出「修改」而不是「放行」。
			react.useEffect(() => {
				let alive = true;
				fetch(FRAME_ROUTE, { credentials: "same-origin", cache: "no-store" })
					.then(response => response.json())
					.then(body => { if (alive) setToolRows(Array.isArray(body?.rows?.tool) ? body.rows.tool : []); })
					.catch(() => { });
				return () => { alive = false; };
			}, [tick]);
			if (sessionId === "")
				return h("div", { className: "dsa-convAudit" },
					h("div", { className: "dsa-emptyList" }, "没有当前会话，读不到它的审计。"));
			return h("div", { className: "dsa-convAudit" },
				h(AuditCenter, {
					audit, filters, toolRows, embedded: true,
					onFilter: next => { if (typeof next?.q === "string") setQ(next.q); },
					onRefresh: () => setTick(value => value + 1),
					onOpenSettings: openPluginSettings,
					emptyText: "这个会话还没有判定记录。",
				}));
		}

		// 规则表、判定链条、摘要列表的样式集中在这里：内联 style 给不了 :hover
		// 和 disabled 态，而这套页面全靠这两态才看得清。全部走宿主设计令牌，
		// 深浅色自动跟随。
		function settingsCss() {
			// 梯度的三层必须都能在浅主题下现形：宿主的 bg-layer-1/2/3 在浅色下全是 #fff
			// （实测 theme.css：layer-1＝layer-2＝layer-3＝neutral-bluish-00），靠它拉层级等于没拉，
			// 这就是"卡深行淡、一片白"的根因。所以：底用极浅一档（浅＝黑 2.2%／深＝白 4.5%，
			// 靠主题选择器分开，只比卡底深一点点），框用 l3（卡）→l2（行）→l1（控件）三档，
			// 片用半灰——投影一律不上。
			const line = "var(--dsw-alias-border-l1)";
			const edge = "var(--dsw-alias-border-l2)";
			const frame = "var(--dsw-alias-border-l3)";
			const chip = "rgba(127,127,127,.14)";
			const fill = "var(--dsw-alias-bg-layer-2)";
			const mute = "var(--dsw-alias-label-tertiary)";
				return [
				// 排版系统（自定标尺，4px 节奏）：
				// 一套 4px 节奏 + 五级字阶（19/15/14/13/12）+ 三级色阶（primary/secondary/tertiary）。
				// 区分度靠"字号×字重×色阶"三者同时拉开，卡与行各用一档边框色。
				".dsa-page{--r1:4px;--r2:8px;--r3:12px;--r4:16px;--r5:24px;--dsa-row:rgba(0,0,0,.022);display:flex;flex-direction:column;gap:32px;padding:4px 0 24px;max-width:820px}",
					// 行底只比卡底深一点点：再深就变成“灰块套白卡”，读起来反而累。
					// 深浅主题各自定一档（宿主的主题选择器＝body[data-ds-dark-theme]）。
					"body[data-ds-dark-theme] .dsa-page{--dsa-row:rgba(255,255,255,.045)}",
				// 会话头的「审计」标签：同一个变量集（卡片的圆角／行底都读它们），
				// 换一处挂载点必须重声明一次，否则卡片会掉回宿主默认值。
				// 会话标签的宽度取中间值：贴着左边会显得歪（右侧空一大片），撑满整窗又太散。
				// 定一个上限再水平居中，宽屏下两侧留白对称，窄屏下自动退回全宽。
				".dsa-convAudit{--r1:4px;--r2:8px;--r3:12px;--r4:16px;--r5:24px;--dsa-row:rgba(0,0,0,.022);box-sizing:border-box;width:100%;max-width:1080px;margin-inline:auto;display:flex;flex-direction:column;gap:12px;padding:16px 20px 24px}",
				"body[data-ds-dark-theme] .dsa-convAudit{--dsa-row:rgba(255,255,255,.045)}",
					".dsa-pageHead{display:flex;flex-direction:column;gap:10px}",
					".dsa-pageTitle{font-size:19px;font-weight:650;letter-spacing:-.015em;line-height:1.35;color:var(--dsw-alias-label-primary)}",
					".dsa-pageDesc{font-size:12.5px;line-height:1.75;color:" + mute + ";max-width:calc(100% - 4em);margin-left:2em}",
					".dsa-card{display:flex;flex-direction:column;gap:12px;padding:16px 18px;border:1px solid " + frame + ";border-radius:16px;background:var(--dsw-alias-bg-layer-1)}",
					".dsa-cardHead{display:flex;align-items:center;gap:var(--r2)}",
					".dsa-cardBar{width:3px;height:15px;border-radius:2px;flex:none;background:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-cardTitle{font-size:15px;font-weight:650;letter-spacing:-.01em;color:var(--dsw-alias-label-primary)}",
					".dsa-cardBadge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:" + chip + ";color:" + mute + "}",
					".dsa-cardSwitch{display:inline-flex;align-items:center;gap:8px;margin-left:auto}",
					".dsa-cardSwitchLabel{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-cardDesc{font-size:12.5px;line-height:1.75;color:" + mute + ";max-width:calc(100% - 4em);margin-left:2em}",
					".dsa-body{display:flex;flex-direction:column;gap:8px}",
					".dsa-item{display:flex;align-items:center;gap:12px;padding:12px 14px;border:1px solid " + edge + ";border-radius:12px;background:var(--dsa-row)}", 
					".dsa-field{justify-content:space-between;gap:var(--r4)}",
					".dsa-field.is-wide{align-items:stretch;flex-direction:column;gap:10px}",
					".dsa-field.is-disabled{opacity:.6}",
					".dsa-fieldText{display:flex;flex-direction:column;gap:3px;min-width:0;flex:1 1 auto}",
					".dsa-fieldLabel{font-size:14px;font-weight:600;letter-spacing:-.005em;line-height:1.45;color:var(--dsw-alias-label-primary)}",
					".dsa-fieldHint{font-size:12px;font-weight:400;line-height:1.7;color:" + mute + "}",
					".dsa-fieldControl{flex:0 0 auto;display:flex;align-items:center;gap:var(--r2);justify-content:flex-end;min-width:200px}",
					".dsa-field.is-wide .dsa-fieldControl{min-width:0;width:100%;justify-content:stretch}",
					".dsa-number{width:120px}",
					".dsa-text{width:220px}",
					".dsa-list{width:100%;min-height:88px;padding:10px 12px;box-sizing:border-box;resize:vertical;font-family:var(--dsw-font-markdown-code-block,ui-monospace,monospace);font-size:12.5px;line-height:1.75;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-1);border:1px solid var(--dsw-alias-border-l2);border-radius:10px}",
					".dsa-list:focus{outline:none;border-color:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-readonly{padding:2px 2px 0;font-size:11.5px;line-height:1.8;color:" + mute + "}",
					".dsa-advBtn{align-self:flex-start;padding:5px 12px;border-radius:999px;border:1px solid " + edge + ";background:var(--dsw-alias-bg-layer-1);cursor:pointer;font-size:11.5px;font-weight:500;color:var(--dsw-alias-label-secondary)}",
					".dsa-advBtn:hover{border-color:var(--dsw-alias-border-brand,#6366f1);color:var(--dsw-alias-label-primary)}",
					".dsa-notice{padding:12px 14px;border-radius:12px;background:rgba(210,153,34,.12);border:1px solid rgba(210,153,34,.35);font-size:12px;line-height:1.7;color:var(--dsw-alias-state-warning-primary,#d29922)}",
					".dsa-noticeCode{margin:8px 0 0;padding:8px 10px;border-radius:8px;background:rgba(127,127,127,.10);font:11px/1.6 var(--dsw-font-markdown-code-block,ui-monospace,monospace);white-space:pre-wrap;color:var(--dsw-alias-label-primary);overflow:auto}",
					".dsa-presetPicker{display:flex;flex-direction:column;gap:8px}",
					// 保存条：干净态只是页尾一行，不必一直压在页面上；只有确实有改动待保存时才升格成
					// 粘在视口下沿的悬浮条。按钮靠右（次要的撤销在左、主操作保存落最右），说明文字留在左侧。
					".dsa-footer{justify-content:flex-end;align-items:center;gap:12px;padding:2px 0;display:flex}",
					".dsa-status,.dsa-error,.dsa-ok{margin-right:auto}",
					".dsa-footer.is-dirty{position:sticky;bottom:12px;z-index:4;padding:10px 14px;border:1px solid " + frame + ";border-radius:14px;background:var(--dsw-alias-bg-layer-1)}",
					".dsa-status{font-size:12px;color:" + mute + "}",
					".dsa-error{font-size:12px;color:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-ok{font-size:12px;color:var(--dsw-alias-state-success-primary,#2ea043)}",
					// 判定链条
					".dsa-ladder{display:flex;flex-wrap:wrap;gap:6px}",
					".dsa-step{display:inline-flex;align-items:center;gap:6px;padding:4px 10px 4px 5px;border-radius:999px;border:1px solid " + edge + ";background:var(--dsw-alias-bg-layer-1);cursor:pointer;font-size:11.5px;color:var(--dsw-alias-label-secondary)}",
					".dsa-step:hover{border-color:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-stepNo{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:999px;background:" + chip + ";font-size:10.5px;font-weight:700;color:" + mute + "}",
					".dsa-stepName{font-size:12px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-stepTag{font-size:10.5px;color:" + mute + "}",
					".dsa-stepTag.is-on{color:var(--dsw-alias-state-success-primary,#2ea043)}",
					// 试算
					".dsa-dry{display:flex;flex-direction:column;gap:10px;padding:16px 18px;border:1px solid var(--dsw-alias-border-brand,rgba(99,102,241,.45));border-radius:16px;background:var(--dsw-alias-bg-layer-1)}",
					".dsa-dryTop{align-items:baseline;gap:10px;flex-wrap:wrap;display:flex}",
					".dsa-dryBar{align-items:center;gap:10px;display:flex}",
					".dsa-dryInputWrap{flex:1 1 auto;min-width:0;display:block}",
					// 宿主的输入框自带宽度（甚至可能是行内样式），不给 !important 就还是那一小截。
					// 顺手把它加高加大：一行命令七八十个字符，太小根本没法核对粘进来的东西。
					// 顶住宿主输入框的自带宽度（不给 !important 就压不过），但封顶在 460px：
					// 铺满整行太长、42px 太高，两样都不合适。
					".dsa-dryInputWrap>*,.dsa-dryInputWrap input{box-sizing:border-box;min-width:0}",
					".dsa-dryInputWrap input{width:100%!important;max-width:460px}",
					".dsa-dryInputWrap input{min-height:32px;padding:0 10px;font-size:12.5px;line-height:1.4}",
					".dsa-dryPrompt{font-size:12.5px;font-weight:600;color:var(--dsw-alias-label-secondary);flex:none}",
					".dsa-dryHint{font-size:12px;line-height:1.7;color:" + mute + "}",
					".dsa-dryOut{display:flex;flex-direction:column;gap:10px}",
					".dsa-dryVerdict{display:flex;align-items:baseline;gap:8px;font-size:14px;font-weight:650;line-height:1.5;color:var(--dsw-alias-label-primary)}",
					".dsa-dryVerdictLabel{font-size:11px;font-weight:600;letter-spacing:.04em;color:" + mute + "}",
					".dsa-dryAs{font-size:11.5px;font-weight:400;color:" + mute + "}",
					".dsa-drySteps{display:flex;flex-direction:column;gap:2px;margin:0;padding:0;list-style:none}",
					".dsa-dryStep{display:grid;grid-template-columns:26px 88px 68px minmax(0,1fr);align-items:baseline;gap:10px;padding:6px 8px;border-radius:8px;font-size:12.5px}",
					".dsa-dryStep:nth-child(odd){background:var(--dsa-row)}",
					".dsa-dryStepNo{font-size:11px;font-weight:700;color:" + mute + "}",
					".dsa-dryStepName{font-weight:600;color:var(--dsw-alias-label-primary)}",
					".dsa-dryStepState{font-size:11.5px;font-weight:650}",
					".dsa-dryStep.t-allow .dsa-dryStepState{color:var(--dsw-alias-state-success-primary,#2ea043)}",
					".dsa-dryStep.t-ask .dsa-dryStepState{color:var(--dsw-alias-state-warning-primary,#d29922)}",
					".dsa-dryStep.t-deny .dsa-dryStepState{color:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-dryStep.t-silent .dsa-dryStepState{color:" + mute + "}",
					".dsa-dryStepWhy{font-size:12px;line-height:1.6;color:var(--dsw-alias-label-secondary);overflow-wrap:anywhere}",
					// 摘要列表
					".dsa-summary{display:flex;flex-direction:column;gap:8px}",
										".dsa-summaryItem{display:flex;align-items:stretch;gap:8px}",
					".dsa-summaryItem .dsa-summaryRow{flex:1 1 auto;width:auto;min-width:0}",
					".dsa-resetPlane{flex:none;display:inline-flex;align-items:center;white-space:nowrap;min-height:30px;padding:0 14px;border-radius:8px;border:1px solid " + edge + ";background:var(--dsw-alias-bg-layer-1);cursor:pointer;font-size:12.5px;font-weight:500;line-height:1.2;color:" + mute + "}",
					".dsa-resetPlane:hover{border-color:var(--dsw-alias-border-brand,#6366f1);color:var(--dsw-alias-label-primary)}",
					".dsa-summaryRow{width:100%;text-align:left;gap:14px;cursor:pointer;transition:border-color .12s ease}",
					".dsa-summaryRow:hover{border-color:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-tile{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;flex:none;border-radius:9px;background:" + chip + ";color:var(--dsw-alias-label-secondary)}",
					".dsa-summaryRow:hover .dsa-tile{color:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-summaryText{display:flex;flex-direction:column;gap:2px;flex:1 1 auto;min-width:0}",
					".dsa-summaryTitle{font-size:14px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-summaryDesc{font-size:12px;line-height:1.6;color:" + mute + "}",
					".dsa-summaryCount{flex:none;font-size:11.5px;font-weight:650;padding:3px 9px;border-radius:999px;background:" + chip + ";color:var(--dsw-alias-label-secondary)}",
					".dsa-summaryCount.is-set{color:var(--dsw-alias-label-primary)}",
					".dsa-summaryPreset{flex:none;font-size:11px;padding:3px 9px;border-radius:999px;border:1px dashed var(--dsw-alias-border-l2);color:" + mute + "}",
					".dsa-chevron{flex:none;font-size:17px;line-height:1;color:" + mute + "}",
					// 明细页
					".dsa-detail{display:flex;flex-direction:column;gap:2px}",
					".dsa-detailHead{display:flex;align-items:center;gap:10px;padding-bottom:10px;border-bottom:1px solid " + line + "}",
					".dsa-detail.is-embedded .dsa-detailHead{padding:4px 0 10px}",
					".dsa-back{border:1px solid " + edge + ";background:var(--dsw-alias-bg-layer-1);cursor:pointer;font-size:12px;border-radius:8px;padding:3px 9px;color:var(--dsw-alias-label-secondary)}",
					".dsa-back:hover{color:var(--dsw-alias-label-primary);border-color:var(--dsw-alias-border-l2)}",
					".dsa-detailTitle{font-size:15px;font-weight:650;letter-spacing:-.01em;color:var(--dsw-alias-label-primary)}",
					".dsa-detailCount{font-size:11.5px;color:" + mute + "}",
					// 工具条是一行，也是这页唯一的"动手处"；说明退成一条带左线的灰字。
					".dsa-tool{gap:10px;flex-wrap:wrap;padding:10px 12px;border-color:" + frame + ";background:var(--dsw-alias-bg-layer-1)}",
					".dsa-addWrap{flex:1 1 240px;min-width:200px}",
					".dsa-toolDefaults{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap}",
					".dsa-defaultsLabel{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-note{margin:2px 0 10px;padding:2px 0 2px 10px;border-left:2px solid " + edge + ";font-size:11.5px;line-height:1.75;color:" + mute + ";max-width:calc(100% - 4em);margin-left:2em}",
					".dsa-emptyList{padding:14px 16px;border:1px dashed " + edge + ";border-radius:12px;font-size:12px;color:" + mute + "}",
					".dsa-sectionCount{font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;background:" + chip + ";color:var(--dsw-alias-label-secondary)}",
					// 一句话规则行：读序＝语法序（当 X 匹配 Y 时 → 动作）
					".dsa-rules{display:flex;flex-direction:column;gap:8px}",
					// 一行＝一行网格：编号｜句子｜条件｜动作片｜操作。列固定，所以「人工／拒绝」
					// 在五张表里都竖着排齐；预设行也走同一套列、同样编号，只是不能删／调序。
					// 一行分两层：上层是编号／主语／条件／行操作，下层是读／写／删的动作片。
					".dsa-sent{align-items:stretch;flex-direction:column;gap:8px;display:flex;box-shadow:inset 3px 0 0 var(--dsw-alias-border-l2,rgba(127,127,127,.3))}",
					".dsa-sentTop{align-items:center;gap:8px;display:flex}",
					".dsa-sentGap{flex:1 1 auto;min-width:0}",
					".dsa-sentBottom{align-items:center;gap:16px;display:flex;flex-wrap:wrap}",
					".dsa-ruleNo{justify-self:center;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:7px;background:" + chip + ";font-size:11.5px;font-weight:700;color:var(--dsw-alias-label-primary)}",
					".dsa-ruleNo.is-blank{background:0 0}",
					".dsa-sent.tone-ask{box-shadow:inset 3px 0 0 var(--dsw-alias-state-warning-primary,#d29922)}",
					".dsa-sent.tone-deny{box-shadow:inset 3px 0 0 var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-sent.tone-release{box-shadow:inset 3px 0 0 var(--dsw-alias-state-success-primary,#2ea043)}",
					".dsa-sent.tone-ai{box-shadow:inset 3px 0 0 #6366F1}",
					".dsa-groupTitle{font-size:12px;font-weight:650;color:" + mute + ";margin:12px 0 2px}",
					".dsa-sent.is-preset{border-style:dashed;box-shadow:none;background:transparent}",
					".dsa-sentHead{white-space:nowrap;align-items:center;gap:6px;display:inline-flex}",
					".dsa-sentLead{font-size:12.5px;color:var(--dsw-alias-label-secondary)}",
					".dsa-sentNoun{font-size:13px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-sentTag{font-size:10.5px;font-weight:650;padding:2px 7px;border-radius:6px;border:1px dashed var(--dsw-alias-border-l2);color:" + mute + "}",
					".dsa-blank{flex:1 1 auto;min-width:0;margin-right:24px;border-bottom:1px dashed var(--dsw-alias-border-l2)}",
					// 输入框别顶到启用区：命令行给它留 ~180px、文件行（三颗片）留 ~380px。
					".dsa-sentBottom.is-command .dsa-blank{max-width:calc(100% - 260px)}",
					".dsa-sentBottom.is-file .dsa-blank{max-width:calc(100% - 440px)}",
					// 工具／网络／敏感面也同样要给动作片留位：只给命令面留过，这三面的片被挤到下一行。
					".dsa-sentBottom.is-tool .dsa-blank,.dsa-sentBottom.is-network .dsa-blank,.dsa-sentBottom.is-sensitive .dsa-blank{max-width:calc(100% - 260px)}",
					".dsa-blank>*{width:100%}",
					// 预设行的条件列：说明文字，不是可编辑的匹配式——不给输入框那种「能改」的暗示。
					".dsa-sentNote{display:block;min-width:0;padding:4px 0;font-size:11.5px;line-height:1.5;color:" + mute + ";white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
					// 文件预设行的路径说明要能看全（~/.ssh ~/.gnupg …），不截成省略号。
					".dsa-sentNote.is-wrap{white-space:normal;overflow:visible;text-overflow:clip}",
					".dsa-sentOps{align-items:center;gap:6px;display:flex;flex-wrap:wrap;justify-content:flex-end;padding-right:0;padding-left:4px;margin-left:auto;flex:none}",
					".dsa-sentOps .dsa-pill{gap:5px;padding:0 7px 0 8px}",
					".dsa-sentWhy{min-width:0;font-family:var(--dsw-font-markdown-code-block,ui-monospace,monospace);font-size:11.5px;line-height:1.6;color:" + mute + ";white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
					".dsa-sentBtns{align-items:center;justify-content:flex-end;gap:6px;display:flex;flex:none}",
					// 启用开关：一颗有边框的胶囊按钮，白底、字不换行。别塞进 26×26 的图标钮里。
					// 启用档位统一用一颗浅蓝开关（规则行与敏感信息同一形状）；轨道收起时是浅灰。
					".dsa-rowEnable{display:inline-flex;align-items:center;gap:6px;flex:none}",
					".dsa-rowEnableLabel{font-size:11.5px;color:" + mute + ";white-space:nowrap}",
					// 兜底行固定末位的标记（没有删除入口、没有拖动把手）。
					".dsa-rowFixed{font-size:11.5px;padding:2px 7px;border-radius:999px;border:1px dashed " + mute + ";color:" + mute + ";white-space:nowrap}",
					// transform 也走过渡：让位靠位移表达，过渡负责把「换位」补成滑动。
					// 曲线先快后缓，跟手一点；180ms 太长会显得拖泥带水。
					".dsa-sent{transition:background .12s ease,opacity .12s ease,border-color .12s ease,transform .18s cubic-bezier(.2,.7,.3,1)}",
					// 被拖的那一行必须**没有**过渡：它要贴着指针走，带 180ms 尾巴就成了「拖着拖着追不上」。
					// 抬到上层＋描一圈品牌色：滑动时压在别的行上面，才看得出是谁在动。
					// 不投影分层（规矩），用 outline：不占布局，也不改行高。
					".dsa-sent.is-dragging{transition:none;position:relative;z-index:3;opacity:.96;outline:1px solid var(--dsw-alias-border-brand,#6366f1);outline-offset:-1px;cursor:grabbing}",
					// touch-action 关掉：不然触屏上按住把手是滚动页面，不是拖行。
					".dsa-drag{cursor:grab;touch-action:none;user-select:none}",
					".dsa-grip,.dsa-trash{display:inline-flex;align-items:center;justify-content:center;line-height:0}",
					// 宽度跟随文字：固定 26px 时「显示」「回写开」会被挤成竖排（真机截图投诉）。
					".dsa-iconBtn{width:auto;min-width:26px;height:26px;padding:0 8px;border-radius:7px;border:1px solid transparent;background:transparent;cursor:pointer;font-size:12px;white-space:nowrap;color:" + mute + "}",
					// 图标钮定宽 26：宽度跟着图标走（12px 与 14px）会让两个按钮宽度不同，
					// 中间那 6px 空隙看上去就一边宽一边窄。定宽、图标居中，三颗才等距。
					".dsa-iconBtn.dsa-drag,.dsa-iconBtn.is-danger{width:26px;min-width:26px;padding:0;display:inline-flex;align-items:center;justify-content:center}",
					".dsa-iconBtn:hover:not(:disabled){background:" + chip + ";color:var(--dsw-alias-label-primary)}",
					".dsa-iconBtn:disabled{opacity:.3;cursor:default}",
					".dsa-iconBtn.is-danger:hover:not(:disabled){color:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-lock{font-size:11px;line-height:1;color:" + mute + "}",
					// 动作片：整片按动作着色
					".dsa-pill{display:inline-flex;align-items:center;gap:5px;height:26px;padding:0 8px 0 9px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);font:inherit;color:inherit}",
					".dsa-pill.is-disabled{opacity:.72}",
					".dsa-pill.is-picker{cursor:pointer;text-align:left}",
					// 单动作片（不带操作名）统一最小宽度：AI 不会比「人工」窄一截。
					".dsa-pill.is-solo{min-width:78px;justify-content:center}",
					".dsa-pill-op{font-size:11.5px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-dot{width:7px;height:7px;border-radius:999px;flex:none;background:" + mute + "}",
					".dsa-pillIcon{display:inline-flex;align-items:center;justify-content:center;flex:none;color:" + mute + "}",
					".dsa-pill.t-release .dsa-dot,.dsa-dot.dot-release{background:var(--dsw-alias-state-success-primary,#2ea043)}",
					
					".dsa-pill.t-ask .dsa-dot,.dsa-dot.dot-ask{background:var(--dsw-alias-state-warning-primary,#d29922)}",
					
					".dsa-pill.t-deny .dsa-dot,.dsa-dot.dot-deny{background:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-pill.t-ai .dsa-dot,.dsa-dot.dot-ai{background:#6366F1}",
					".dsa-sent.is-off{opacity:.56}",
					".dsa-secretList{display:flex;flex-direction:column;gap:4px;margin-top:6px}",
					".dsa-secret{display:flex;align-items:center;gap:8px;flex-wrap:nowrap}",
					".dsa-secretToken{font-size:11.5px;font-weight:650;color:var(--dsw-alias-label-primary);white-space:nowrap}",
					".dsa-secretLabel{font-size:12px;color:" + mute + ";white-space:nowrap}",
					".dsa-secretPlain{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--dsw-alias-label-primary)}",
					".dsa-secretMeta{font-size:11px;color:" + mute + ";white-space:nowrap}",
					".dsa-secretRestore{display:inline-flex;align-items:center;gap:6px;flex:none}",
					".dsa-secretRestoreLabel{font-size:11.5px;color:" + mute + ";white-space:nowrap}",
					// A13：手填签发的面板已移除——证由写盘那一刻的询问自己签，样式一并删干净。
					".dsa-secretFoot{display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-top:6px}",
					
					".dsa-pill.t-silent{background:transparent;border-style:dashed}",
					// 动作名统一占位：「AI」与「人工」同宽，片子不会因为字少就窄一截。
					".dsa-pill-text{display:inline-block;min-width:2.3em;text-align:center;font-size:11.5px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					// 文件行的短片：字与彩点贴紧、内边距收窄（「写」与「允」中间不再空一大截）。
					".dsa-pill.is-compact{gap:4px;padding:0 6px 0 8px}",
					".dsa-pill.is-compact .dsa-pill-text{min-width:0;text-align:left}",
					".dsa-pill-caret{font-size:9px;line-height:1;color:" + mute + "}",
					".dsa-pill.is-picker:hover{border-color:" + frame + "}",
					".dsa-pill.is-picker[aria-expanded='true']{border-color:var(--dsw-alias-border-brand,#6366f1)}",
					// 动作片的下拉：浮层贴在片子正下方，宽度不小于片子；分层靠 l3 边框＋实底，不靠投影。
					".dsa-pillCell{position:relative;display:inline-flex}",
					".dsa-menu{position:absolute;top:calc(100% + 4px);right:0;z-index:8;min-width:100%;flex-direction:column;gap:2px;padding:4px;border:1px solid " + frame + ";border-radius:12px;background:var(--dsw-alias-bg-layer-1);display:flex}",
					".dsa-menu.is-compact{width:auto;min-width:118px;box-sizing:border-box}",
					".dsa-menu.is-compact .dsa-menuItem{padding:0 8px}",
					".dsa-menuItem{align-items:center;gap:8px;width:100%;height:30px;padding:0 10px;border:1px solid transparent;border-radius:9px;background:transparent;cursor:pointer;font:inherit;font-size:12.5px;font-weight:600;color:var(--dsw-alias-label-primary);white-space:nowrap;text-align:left;display:flex}",
					".dsa-menuItem:hover{border-color:" + edge + ";background:var(--dsa-row)}",
					".dsa-menuItem.is-current{border-color:" + frame + ";background:var(--dsa-row)}",
					".dsa-menuCheck{margin-left:auto;font-size:11px;line-height:1}",
					".dsa-warn{margin-top:10px;padding:10px 12px;border-radius:10px;font-size:11.5px;line-height:1.7;color:var(--dsw-alias-state-warning-primary,#d29922);background:rgba(210,153,34,.1)}",
					// 审计中心（同一套字阶，判定记录是卡内小节，不是第二张卡）
					".dsa-audit{display:flex;flex-direction:column;gap:10px}",
					".dsa-auditHead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:14px}",
					".dsa-auditTitle{display:flex;align-items:center;gap:8px;font-size:13px;font-weight:700;letter-spacing:.02em;color:var(--dsw-alias-label-primary)}",
					".dsa-auditBtns{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}",
					// 四个工具动作要有按钮形：纯白文字看不出是可点的控件（真机截图投诉）。
					".dsa-auditBtns>*{border:1px solid " + edge + "!important;border-radius:999px!important;background:var(--dsw-alias-bg-layer-1)!important;padding:3px 12px!important;font-size:12px!important;line-height:1.6!important;color:var(--dsw-alias-label-secondary)!important;cursor:pointer}",
					".dsa-auditBtns>*:hover{border-color:var(--dsw-alias-border-brand,#6366f1)!important;color:var(--dsw-alias-label-primary)!important}",
					".dsa-auditBtns>*:disabled{opacity:.55;cursor:default}",
					".dsa-auditBar{display:flex;align-items:center;gap:10px;flex-wrap:wrap}",
					".dsa-filterSelect{height:32px;padding:0 10px;border-radius:8px;font-size:12.5px;color:var(--dsw-alias-label-primary);background:" + fill + ";border:1px solid " + edge + "}",
					// 模型那一栏要撑满控件列，不然选项是宿主给的长名字，窄一条看着就像没填。
					".dsa-modelSelect{width:100%;min-width:250px;max-width:340px}",
					".dsa-toggles{display:inline-flex;align-items:center;gap:12px;flex-wrap:wrap}",
					".dsa-toggle{display:inline-flex;align-items:center;gap:6px;cursor:pointer}",
					".dsa-toggleText{font-size:12px;color:var(--dsw-alias-label-secondary);white-space:nowrap}",
					".dsa-summaryBand{padding:8px 12px;border-radius:10px;background:var(--dsa-row);border:1px solid " + edge + ";font-size:11.5px;line-height:1.7;color:" + mute + "}",
					".dsa-entries{display:flex;flex-direction:column;gap:6px;max-height:420px;overflow-y:auto}",
					".dsa-entry{flex-direction:column;align-items:stretch;gap:6px;padding:11px 14px;box-shadow:inset 3px 0 0 var(--dsw-alias-border-l2)}",
					".dsa-entry.tone-allow{box-shadow:inset 3px 0 0 var(--dsw-alias-state-success-primary,#2ea043)}",
					".dsa-entry.tone-ask{box-shadow:inset 3px 0 0 var(--dsw-alias-state-warning-primary,#d29922)}",
					".dsa-entry.tone-deny{box-shadow:inset 3px 0 0 var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-entryHead{display:flex;align-items:center;gap:8px}",
					".dsa-chip{display:inline-flex;align-items:center;font-size:11.5px;font-weight:650;line-height:1.4;padding:2px 9px;border-radius:999px;color:var(--dsw-alias-label-primary)}",
					".dsa-chip.t-allow{background:rgba(46,160,67,.16)}",
					".dsa-chip.t-ask{background:rgba(210,153,34,.16)}",
					".dsa-chip.t-deny{background:rgba(248,81,73,.16)}",
					".dsa-chip.t-silent{background:" + chip + "}",
					".dsa-entryCategory{font-size:11px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-entryLayer{font-size:11px;font-weight:650;padding:1px 7px;border-radius:6px;background:var(--dsw-alias-bg-layer-1);color:var(--dsw-alias-label-secondary)}",
					".dsa-entryTime{font-size:11.5px;color:" + mute + ";flex:none;margin-left:auto}",
					".dsa-entryAction{font-family:var(--dsw-font-markdown-code-block,ui-monospace,monospace);font-size:12.5px;font-weight:500;line-height:1.7;color:var(--dsw-alias-label-primary);overflow-wrap:anywhere}",
					".dsa-entryMeta{font-size:11.5px;line-height:1.6;color:" + mute + "}",
					".dsa-entrySummary{font-size:12.5px;line-height:1.7;color:var(--dsw-alias-label-secondary)}",
					// 同一次调用后续发生的行（命中／答复／结果）：折在卡里，缩一号字、按时间正序。
					".dsa-entryMore{display:flex;flex-direction:column;gap:6px;margin-top:8px;padding-top:8px;border-top:1px dashed " + edge + "}",
					".dsa-entrySub{display:flex;align-items:baseline;gap:8px;min-width:0}",
					".dsa-entrySubText{font-size:11.5px;line-height:1.65;color:" + mute + ";overflow-wrap:anywhere}",
					// 命令结果按钮贴在最后一条子行右端：与那行同一条水平线、同一副「胶囊」形状
					// （allow 那种浅底圆角），一眼看得出是能点的地方，不是一行说明文字。
					".dsa-resultSlot{margin-left:auto;flex:none;display:inline-flex;align-items:center;gap:8px}",
					// 与 .dsa-chip 逐字对齐：同字号、同字重、同行高、同 padding、同圆角、无边框。
					// 差 1px 边框或 1px padding，和 allow 并排就能看出来，所以这里不另立一套尺寸。
					".dsa-resultBtn{display:inline-flex;align-items:center;font-family:inherit;font-size:11.5px;font-weight:650;line-height:1.4;padding:2px 9px;border-radius:999px;border:0;background:rgba(46,160,67,.16);color:var(--dsw-alias-label-primary);cursor:pointer}",
					".dsa-resultBtn:hover{background:rgba(46,160,67,.26)}",
					".dsa-resultBtn.is-failed{background:rgba(248,81,73,.16)}",
					".dsa-resultBtn.is-failed:hover{background:rgba(248,81,73,.26)}",
					".dsa-entrySub.is-tail{justify-content:flex-end}",
					// 审计卡上的「放行／修改」入口：折叠态只有一颗按钮，展开后才是风险说明＋三档。
					// 它和「命令结果」同占一个右对齐槽（见 tailSlot），不再单独占一行。
					".dsa-ruleBtn{display:inline-flex;align-items:center;font-family:inherit;font-size:11.5px;font-weight:650;line-height:1.4;padding:2px 9px;border-radius:999px;border:0;background:rgba(56,139,253,.16);color:var(--dsw-alias-label-primary);cursor:pointer;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}",
					".dsa-ruleBtn:hover{background:rgba(56,139,253,.26)}",
					".dsa-ruleSaved{font-size:11.5px;font-weight:650;color:var(--dsw-alias-label-secondary)}",
					".dsa-rulePanel{margin-top:6px;padding:10px 12px;border:1px solid " + line + ";border-radius:10px;background:rgba(56,139,253,.05)}",
					".dsa-ruleRisk{font-size:11.5px;line-height:1.6;color:var(--dsw-alias-label-secondary)}",
					// 末句「请认真识别。」加重：灰字一整段里，人只会扫过去。
					".dsa-ruleRisk strong{font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-ruleTiers{display:flex;gap:6px;margin-top:8px}",
					".dsa-ruleTier{font-family:inherit;font-size:11.5px;font-weight:600;line-height:1.4;padding:3px 12px;border-radius:999px;border:1px solid " + edge + ";background:transparent;color:var(--dsw-alias-label-secondary);cursor:pointer}",
					".dsa-ruleTier.is-on{border-color:transparent;background:rgba(56,139,253,.22);color:var(--dsw-alias-label-primary)}",
					".dsa-ruleFoot{display:flex;gap:8px;align-items:center;margin-top:8px}",
					".dsa-ruleError{font-size:11.5px;line-height:1.5;margin-top:6px;color:var(--dsw-alias-label-secondary)}",
						".dsa-resultText{padding:10px 12px;border:1px solid " + edge + ";border-left:3px solid rgba(46,160,67,.65);border-radius:8px;background:var(--dsw-alias-bg-layer-1);font:11.5px/1.7 var(--dsw-font-markdown-code-block,ui-monospace,monospace);white-space:pre-wrap;overflow-wrap:anywhere;color:var(--dsw-alias-label-primary);max-height:360px;overflow:auto}",
						".dsa-resultText.is-failed{border-left-color:rgba(248,81,73,.7)}",
					".dsa-pager{display:flex;align-items:center;justify-content:flex-end;gap:10px;padding-top:2px}",
					".dsa-pagerInfo{font-size:12px;color:" + mute + "}",
			].join("");
		}

		function settingsStylesheet(name) {
			const doc = globalThis.document;
			if (doc == null)
				return () => { };
			const id = name ?? "dsh-auto-approval-frame/settings";
			for (const existing of doc.querySelectorAll("style[data-plugin]")) {
				if (existing.getAttribute("data-plugin-css") === id) existing.remove();
			}
			const style = doc.createElement("style");
			style.setAttribute("data-plugin", "dsh-auto-approval-frame");
			style.setAttribute("data-plugin-css", id);
			style.textContent = settingsCss();
			doc.head?.appendChild(style);
			return () => style.remove();
		}

		function draftOf(value) {
			const draft = {};
			for (const field of FIELDS) {
				const raw = value?.[field.key];
				const fallback = DEFAULTS[field.key];
				if (field.type === "list" || field.type === "rules" || field.type === "presetPicker")
					draft[field.key] = Array.isArray(raw) ? [...raw] : (Array.isArray(fallback) ? [...fallback] : []);
				else if (field.type === "number") draft[field.key] = Number.isFinite(raw) ? raw : fallback;
				// 缺键时跟 opsFrom 一样问 DEFAULTS：不然旧配置里没写过的新开关会被
				// 草稿当成 false、又和 DEFAULTS 的 true 比出一条假的「待保存」。
				else if (field.type === "switch") draft[field.key] = raw === undefined ? fallback === true : raw === true;
				else draft[field.key] = typeof raw === "string" && raw !== "" ? raw : (typeof fallback === "string" ? fallback : "");
			}
			return draft;
		}

		/** One stored row, whatever shape it arrived in (string / ops-era object / per-op). */
		function rowOf(raw, plane) {
			let source = raw;
			if (typeof raw === "string") {
				// 与宿主同一套词：permit＝允许（release）、block＝拒绝，其余同义词走 FOLD_ACTION。
				const matched = RULE_VERB.exec(raw);
				source = {
					action: matched === null ? "deny" : matched[1].toLowerCase(),
					match: matched === null ? raw : matched[2],
				};
			}
			const match = String(source?.match ?? source?.pattern ?? "");
			if (plane !== "file")
				return {
					action: ACTION_META[FOLD_ACTION[source?.action] ?? source?.action] !== undefined
						? (FOLD_ACTION[source?.action] ?? source.action) : "ask",
					match,
					// 检测规则的两枚随行字段：preset＝它盖住哪条预设形状；enabled=false＝这行不表态。
					preset: String(source?.preset ?? ""),
					label: String(source?.label ?? ""),
					// 命令面一行一条命令，说明从宿主那一行走（`note`），不再拿 match 冒充。
					note: String(source?.note ?? ""),
					enabled: source?.enabled !== false,
					removed: source?.removed === true,
				};
			const folded = ACTION_META[FOLD_ACTION[source?.action] ?? source?.action] !== undefined
				? (FOLD_ACTION[source?.action] ?? source.action) : "";
			const legacyOps = Array.isArray(source?.ops) ? source.ops : [];
			const covers = op => folded !== "" && (legacyOps.length === 0 || legacyOps.includes("all") || legacyOps.includes(op));
			const opAction = op => (ACTION_META[FOLD_ACTION[source?.[op]] ?? source?.[op]] !== undefined
				? (FOLD_ACTION[source?.[op]] ?? source[op]) : covers(op) ? folded : "");
			const ops = { read: opAction("read"), write: opAction("write"), delete: opAction("delete") };
			// 预设行的档位是**一条**（事实层只认这一条），不是读／写／删三格：
			// 旧草稿里可能只剩三格，就按最严的那一格折成一条，免得页面显示成「不表态」。
			const preset = String(source?.preset ?? "");
			const action = folded !== "" ? folded
				: (preset === "" ? "" : ACTION_CHOICES.find(item => Object.values(ops).includes(item.value))?.value ?? "ask");
			return {
				match: match,
				read: ops.read, write: ops.write, delete: ops.delete,
				action,
				preset,
				label: String(source?.label ?? ""),
				enabled: source?.enabled !== false,
					removed: source?.removed === true,
			};
		}

		const blankRow = (plane, row) => plane === "file"
			? !row.read && !row.write && !row.delete
			: false;

		/** A half-typed row is never written: no condition, or a file row that says nothing. */
		const valueOf = (field, value) => {
			if (field.type !== "rules") return value;
			if (!Array.isArray(value)) return [];
			const rows = [];
			for (const raw of value) {
				const row = rowOf(raw, field.plane);
				// 预设行没有匹配式（命中由事实层给出），所以它**不能**被「空条件」这道闸丢掉，
				// 否则改一次档位就把整排预设行从配置里抹掉了。
				if (row.preset !== "") {
					const kept = {
						id: `builtin-${row.preset}`,
						preset: row.preset,
						label: row.label,
						enabled: row.enabled !== false,
					};
					// 文件面的预设行按读／写／删三列存，和用户行同形制；其余平面一个档位。
					if (field.plane === "file") {
						kept.read = row.read;
						kept.write = row.write;
						kept.delete = row.delete;
					} else {
						kept.action = row.action;
					}
					if (row.removed === true) kept.removed = true;
					// 检测规则的内容就是这一段正则：预设行同样可改，所以必须随行存回去。
					if (field.plane === "sensitive" && row.match !== "") kept.match = row.match;
					rows.push(kept);
					continue;
				}
				const match = row.match.trim();
				if (match === "" || blankRow(field.plane, row)) continue;
				if (field.plane === "file") {
					rows.push({ match, read: row.read, write: row.write, delete: row.delete, ...(row.enabled === false ? { enabled: false } : {}) });
					continue;
				}
				const out = { action: row.action, match };
				// 只有检测规则这张表带这三枚随行字段；其余平面写出去的形状一个字节都不变。
				// `id` 与宿主预设行同名（`builtin-<形状>`），台账里指认的是同一条。
				if (row.preset !== "") {
					out.id = `builtin-${row.preset}`;
					out.preset = row.preset;
					out.label = row.label;
				}
				if (row.enabled === false)
					out.enabled = false;
				rows.push(out);
			}
			return rows;
		};

		function opsFrom(draft, stored) {
			const ops = [];
			for (const field of FIELDS) {
				const next = valueOf(field, draft[field.key]);
				if (next === undefined) continue;
				const base = valueOf(field, stored?.[field.key] !== undefined ? stored[field.key] : DEFAULTS[field.key]);
				const same = field.type === "list" || field.type === "rules" || field.type === "presetPicker"
					? JSON.stringify(next) === JSON.stringify(base ?? [])
					: next === base;
				if (same) continue;
				ops.push({ op: "set", path: [field.key], value: next });
			}
			return ops;
		}

		// 保存前把敏感条件封成密文：宿主配置从第一次写入起就没有明文。
		// 封不成就整次不保存（宁可不存，也不把明文交给宿主）。
		async function sealOpsForSave(ops) {
			const target = ops.find(item => item?.path?.[0] === "sensitiveRules");
			if (target === undefined) return ops;
			const sealed = await codecSensitiveRows("seal", target.value);
			return ops.map(item => (item === target ? { ...item, value: sealed } : item));
		}

		// 四个平面同一套档位，没有第五档：命中就遮是敏感那一层自己在做的事，不是选项。
		const ACTION_DOT = { release: "dot-release", ai: "dot-ai", ask: "dot-ask", deny: "dot-deny" };
		// 读／写／删的线性小图标：片子里先图标、再操作名、再色点＋档位。
		const OP_ICON = {
			read: '<circle cx="8" cy="8" r="2.4"/><path d="M1.8 8c2.1-3.1 4-4.6 6.2-4.6S12.1 4.9 14.2 8c-2.1 3.1-4 4.6-6.2 4.6S3.9 11.1 1.8 8z"/>',
			write: '<path d="M3 13h2.4l7.3-7.3-2.4-2.4L3 10.6z"/><path d="M10.8 2.9l2.3 2.3"/>',
			delete: '<path d="M3.5 4.5h9"/><path d="M5.5 4.5V3h5v1.5"/><path d="M4.5 4.5l.6 9h5.8l.6-9"/><path d="M6.8 7v4.5M9.2 7v4.5"/>',
		};
		const ACTION_CHOICES = [
			{ value: "deny", label: "拒绝" },
			{ value: "ask", label: "人工" },
			{ value: "ai", label: "AI" },
			{ value: "release", label: "允许" },
		];
		const choicesFor = () => ACTION_CHOICES;

		/** * 一颗动作片 ＋ 它自己的下拉菜单。
		 * 不用原生 <select>（系统弹层比片子窄一圈、字也更小），也不再摊成一行按钮：
		 * 点片子就在片子正下方弹出一个浮层菜单，宽度不小于片子，选项按动作着色、当前项打勾。
		 */
		function ActionPill({ label, value, choices, disabled, title, open, onToggle, onPick, icon, text, compact }) {
		const tone = ACTION_DOT[value] ? value : "silent";
		const shown = text ?? (choices.find(item => item.value === (value ?? "")) ?? { label: "不表态" }).label;
		const solo = label === null || label === undefined;
		const inner = [
			icon === undefined ? null : h("span", { key: "i", className: "dsa-pillIcon", "aria-hidden": "true", dangerouslySetInnerHTML: { __html: `<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round">${icon}</svg>` } }),
			label === null || label === undefined ? null : h("span", { key: "l", className: "dsa-pill-op" }, label),
			h("span", { key: "d", className: "dsa-dot dot-" + tone }),
			h("span", { key: "t", className: "dsa-pill-text" }, shown),
		];
		const compactCls = compact === true ? " is-compact" : "";
		if (disabled === true || onPick === undefined)
			return h("span", { className: "dsa-pillCell" },
				h("span", { className: "dsa-pill t-" + tone + (solo ? " is-solo" : "") + " is-disabled" + compactCls, title }, ...inner));
		return h("span", { className: "dsa-pillCell" },
			h("button", {
				type: "button", className: "dsa-pill t-" + tone + (solo ? " is-solo" : "") + " is-picker" + compactCls, title,
				"aria-haspopup": "listbox", "aria-expanded": open === true, onClick: onToggle,
			}, ...inner, compact === true ? null : h("span", { className: "dsa-pill-caret", "aria-hidden": "true" }, open === true ? "▴" : "▾")),
			open === true ? h("span", { className: `dsa-menu${compactCls}`, role: "listbox" },
				...choices.map(item => {
					const itemTone = ACTION_DOT[item.value] ? item.value : "silent";
					const current = item.value === (value ?? "");
					return h("button", {
						key: item.value || "silent", type: "button", role: "option", "aria-selected": current,
						className: "dsa-menuItem t-" + itemTone + (current ? " is-current" : ""),
						onClick: () => onPick(item.value),
					}, h("span", { className: "dsa-dot dot-" + itemTone }), item.label,
						current ? h("span", { className: "dsa-menuCheck" }, "✓") : null);
				})) : null);
		}


		// 平面图标：16px 线性图标，描边走 currentColor，深浅色都跟得上。
		// 之前用「命／文」这类首字缩略，看着像缺字的占位符 —— 要么是真图标，要么就别放。
		const PLANE_ICON = {
			command: "<rect x=\"1.6\" y=\"2.6\" width=\"12.8\" height=\"10.8\" rx=\"2\"/><path d=\"M4.4 6.2 6.8 8 4.4 9.8\"/><path d=\"M8.6 10.4h4.2\"/>",
			file: "<path d=\"M4.2 1.9h5.2L12.8 5v9.1H4.2z\"/><path d=\"M9.2 2.1v3.4h3.4\"/><path d=\"M6.2 8.4h4.6M6.2 11h3.2\"/>",
			network: "<circle cx=\"8\" cy=\"8\" r=\"6.2\"/><path d=\"M1.9 8h12.2\"/><path d=\"M8 1.8c2.4 3.2 2.4 9.2 0 12.4M8 1.8c-2.4 3.2-2.4 9.2 0 12.4\"/>",
			tool: "<path d=\"M2.6 5.2h10.8M2.6 10.8h10.8\"/><circle cx=\"10.2\" cy=\"5.2\" r=\"1.9\"/><circle cx=\"5.6\" cy=\"10.8\" r=\"1.9\"/>",
			sensitive: "<path d=\"M8 1.9 13.4 4v4.3c0 3.2-2.4 5.2-5.4 6.1-3-.9-5.4-2.9-5.4-6.1V4z\"/><path d=\"M8 6.2v2.4\"/><circle cx=\"8\" cy=\"10.7\" r=\".6\"/>",
			// 敏感信息＝占位符的钥匙环：它是卡片里与「检测规则」平行的一行，不能没有图标。
			secrets: "<circle cx=\"5.3\" cy=\"5.3\" r=\"2.7\"/><path d=\"M7.3 7.3 13.2 13.2\"/><path d=\"M10.6 10.6l1.4-1.4M12.2 12.2l1.3-1.3\"/>",
		};

		function PlaneIcon({ plane }) {
			const body = PLANE_ICON[plane];
			if (body === undefined)
				return null;
			return h("span", {
				className: "dsa-tile", "aria-hidden": "true",
				dangerouslySetInnerHTML: {
					__html: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`,
				},
			});
		}

		/** 摘要列表：一行一个平面，点进去才是编辑页（不四表平铺）。 */
		const RESET_PLANE_TIP = "只清你对预设的改动，你自己写的行不动";

		// 一面「恢复默认」只做一件事——把该面里带 `preset` 的行整批撤下（含已停用
		// 但留行的 `removed:true`），人写行（`preset === ""`）原样留在原位。
		// 撤掉之后 builtins 整面回到出厂表，判定链上的「只读／询问」也回到出厂那条。
		// 纯函数：页面按钮与回归测试共用同一口径，不许有两份剔除条件。
		function restorePlaneRows(rows) {
			return (Array.isArray(rows) ? rows : []).filter(row => String(row?.preset ?? "") === "");
		}

		function RuleSummary({ planes, counts, presets, onOpen, onReset }) {
			return h("div", { className: "dsa-summary" },
				...planes.map(plane => h("div", { key: plane.key, className: "dsa-summaryItem" }, h("button", {
					key: plane.key,
					type: "button",
					className: "dsa-item dsa-summaryRow",
					onClick: () => onOpen(plane.plane),
				},
					h(PlaneIcon, { plane: plane.plane }),
					h("span", { className: "dsa-summaryText" },
						h("span", { className: "dsa-summaryTitle" }, plane.title),
						h("span", { className: "dsa-summaryDesc" }, plane.desc)),
					h("span", {
						className: "dsa-summaryCount" + (counts[plane.plane] > 0 ? " is-set" : ""),
					}, counts[plane.plane] > 0 ? `${counts[plane.plane]} 条` : "未设置"),
					// 没有预设项的概念就不画这枚片（敏感信息表是账，不是规则表）。
					presets[plane.plane] === undefined ? null : h("span", { className: "dsa-summaryPreset", title: "这张表里标着「预设」的行数：默认就在，能换档位、能停用" },
						`预设 ${presets[plane.plane] ?? 0}`),
					h("span", { className: "dsa-chevron" }, "›")))));
		}

		// 横向跟手的位移上限。行是满宽的，指针左右跑多少就移多少会顶出面板、
		// 顶出一条横向滚动条；18px 落在面板内边距里，够看出「卡片跟着手动」，又不出界。
		const DRAG_X_LIMIT = 18;
		const clampDragX = value => Math.max(-DRAG_X_LIMIT, Math.min(DRAG_X_LIMIT, value));
		/** 明细页：表头 → 工具条（一行）→ 说明 → 自定义行 → 预设行（同表同形制，可改可停用），全部同一套列。 */
		function RuleDetail({ plane, rows, defaults, onDefaults, onChange, frame, onBack, onReset, embedded, disabled }) {
			const meta = PLANES[plane];
			const [pending, setPending] = react.useState("");
			// 展开的动作选择器：一屏只开一个，键＝「行:操作」或「defaults:操作」。
			const [open, setOpen] = react.useState("");
			// 拖动＝自己接管指针，不用 HTML5 draggable。
			// 为什么不用：draggable 只有一个「浏览器画的快照」跟着鼠标，DOM 里的行原地不动；
			// 让位又只能靠换 DOM 顺序，而浏览器对重排不做过渡——两件事叠起来就是「不跟手 + 硬跳」。
			// 自己接管后：DOM 顺序整个拖动期间不变，被拖行用 transform 跟指针走（横竖都跟），
			// 其余行用 transform 让位（只有竖），位移全部走 transform 过渡，才可能顺滑。
			// drag = { from, to, dx, dy, startX, startY, rows:[{at,top,height}], gap }
			const [drag, setDrag] = react.useState(null);
			// 可变引用＋state 双份：state 负责触发重渲染，引用负责给 document 上的监听器读最新值
			// （宿主这套 react 只有 useState，没有 useRef，用惰性初始化的对象当 ref 使）。
			const [dragBox] = react.useState(() => ({ current: null }));
			const [detach] = react.useState(() => ({ current: null }));
			const putDrag = next => { dragBox.current = next; setDrag(next); };
			const toggle = key => setOpen(current => (current === key ? "" : key));
			// 菜单是浮层：点到它外面就该收起；点在自己那颗片上由 toggle 说了算。
			react.useEffect(() => {
				if (open === "" || typeof globalThis.document?.addEventListener !== "function") return undefined;
				const dismiss = event => {
					const node = event?.target;
					if (typeof node?.closest === "function" && node.closest(".dsa-pillCell") != null) return;
					setOpen("");
				};
				globalThis.document.addEventListener("click", dismiss, true);
				return () => globalThis.document.removeEventListener("click", dismiss, true);
			}, [open]);
			const draftRaw = Array.isArray(rows) ? rows : [];
			const draftRows = draftRaw.map(row => rowOf(row, plane));
			// 检测规则这一张表＝「预设形状＋用户自己的行」。预设形状不是页面上另画的一排只读行：
			// 它们和用户的行同表同形制，改内容／换动作／停用都写回同一份 sensitiveRules
			// （`preset` 标出它盖住哪条预设）。读侧用宿主 `frame.rows`（同一份生效表），
			// 页面不再自己拼第二份预设清单。
			// 草稿是唯一的编辑真相：用户行＋已物化的预设行都取自草稿；
			// 宿主 `frame.rows` 只用来补出**还没被碰过**的预设行（预设清单只有一份，住在宿主）。
			const hostRows = Array.isArray(frame?.rows?.[plane]) ? frame.rows[plane] : [];
			const ownPresets = new Set(draftRows.filter(row => row.preset !== "").map(row => row.preset));
			const hostOnly = hostRows
				.filter(row => row.preset !== "" && !ownPresets.has(row.preset))
				.map(row => rowOf(row, plane));
			// 已删除的预设行（removed:true）留在配置里但不显示；列表只排可见行，操作按原索引写回。
			const shownIndexes = [];
			draftRows.forEach((row, at) => {
				if (!(row.preset !== "" && row.removed === true)) shownIndexes.push(at);
			});
			const draftShown = shownIndexes.map(at => draftRows[at]);
			const list = [...draftShown, ...hostOnly];
			// 只写草稿：宿主那几条没被碰过的预设行留在宿主默认值里，
			// 不然点一下任何行都会把整排预设行抄进配置文件。
			const write = next => onChange(next);
			const patch = (index, changes) => {
				if (index < draftShown.length) {
					const rawAt = shownIndexes[index];
					write(draftRaw.map((raw, at) => (at === rawAt ? { ...draftRows[rawAt], ...changes } : raw)));
					return;
				}
				const hostRow = hostOnly[index - draftShown.length];
				if (hostRow === undefined) return;
				write([...draftRaw, { ...hostRow, ...changes }]);
			};
			// 拖动排序：整表物化一次，顺序随配置持久化。
			const moveTo = (from, to) => {
				if (from === null || from === undefined || from === to || to < 0 || to >= list.length) return;
				// 兜底行固定末位——它自己不挪，别的行也不能挪到它后面。
				if (FALLBACK_PRESET_OF[plane] !== undefined) {
					const fallbackAt = list.findIndex(row => isFallbackRow(plane, row));
					if (fallbackAt >= 0) {
						if (from === fallbackAt) return;
						if (to >= fallbackAt) to = fallbackAt - 1;
					}
				}
				// 两行都在草稿里（都是你加的行）⇒ 只动草稿，不把预设行抄进配置。
				if (from < draftShown.length && to < draftShown.length) {
					const next = [...draftRaw];
					const [moved] = next.splice(shownIndexes[from], 1);
					next.splice(shownIndexes[to], 0, moved);
					write(next);
					return;
				}
				// 跨到预设行 ⇒ 整表物化一次，顺序才能持久化；已删除的预设行照旧留在末尾。
				const hidden = draftRaw.filter((raw, at) => draftRows[at].preset !== "" && draftRows[at].removed === true);
				const next = list.map(row => ({ ...row }));
				const [moved] = next.splice(from, 1);
				next.splice(to, 0, moved);
				write([...next, ...hidden]);
			};
			const remove = index => {
				const target = list[index];
				if (target === undefined) return;
				// 兜底行删不掉（页面上也没有删除入口）。
				if (isFallbackRow(plane, target)) return;
				if (target.preset === "") {
					const rawAt = draftRaw.findIndex(raw => JSON.stringify(rowOf(raw, plane)) === JSON.stringify(target));
					if (rawAt >= 0) write(draftRaw.filter((_, at) => at !== rawAt));
					return;
				}
				// 预设行不从代码清单里消失，只标成已删除（不显示、不拉高）。
				const rawAt = draftRaw.findIndex(raw => String(raw?.preset ?? "") === target.preset);
				if (rawAt >= 0) write(draftRaw.map((raw, at) => (at === rawAt ? { ...target, removed: true } : raw)));
				else write([...draftRaw, { ...target, removed: true }]);
			};
			const add = () => {
				const match = pending.trim();
				if (match === "") return;
				const row = plane === "file" ? { match, ...defaults.file } : { match, action: defaults.single };
				write([{ ...row }, ...draftRaw]);
				setPending("");
			};
			// 拖动三件事：按下量几何、移动算「插到第几位」、松手提交一次。
			// 几何只在按下那一刻量一次：拖动期间行高不会变（只是位移），量一次就够，
			// 每帧重排再去 getBoundingClientRect 会强制同步布局，反而卡。
			const measureRows = () => {
				const doc = globalThis.document;
				if (typeof doc?.querySelectorAll !== "function") return null;
				const nodes = Array.from(doc.querySelectorAll(".dsa-sent"));
				const found = [];
				const seen = new Set();
				for (const node of nodes) {
					const at = Number(node.getAttribute?.("data-at"));
					const box = typeof node.getBoundingClientRect === "function" ? node.getBoundingClientRect() : null;
					// 同一个下标只认第一个：页面里若同时挂着两块明细（嵌入式预览），
					// 两处都渲染了同一批行，混在一起量会让「一格厚度」算错，让位就会错行。
					if (!Number.isFinite(at) || box === null || box === undefined || seen.has(at)) continue;
					seen.add(at);
					found.push({ at, top: box.top, height: box.height });
				}
				found.sort((left, right) => left.at - right.at);
				if (found.length === 0) return null;
				const gap = found.length > 1 ? Math.max(0, found[1].top - found[0].top - found[0].height) : 0;
				return { rows: found, gap };
			};
			// 插到第几位：被拖行的中线越过谁的中线，就排在谁那儿——跟手感和让位灵敏度都取决于这一格。
			const targetFor = (state, dy) => {
				const self = state.rows.find(row => row.at === state.from);
				if (self === undefined) return state.from;
				const center = self.top + self.height / 2 + dy;
				for (const row of state.rows) {
					if (row.at < state.from && center < row.top + row.height / 2) return row.at;
				}
				let below = state.from;
				for (const row of state.rows) {
					if (row.at > state.from && center > row.top + row.height / 2) below = row.at;
				}
				return below;
			};
			const beginDrag = (index, event) => {
				if (disabled === true) return;
				const geometry = measureRows();
				// 量不到几何（还没落到 DOM 上）就不启动：宁可没拖动，也不给一个会错位的假拖动。
				if (geometry === null) return;
				event?.preventDefault?.();
				putDrag({ from: index, to: index, dx: 0, dy: 0, startX: Number(event?.clientX ?? 0), startY: Number(event?.clientY ?? 0), rows: geometry.rows, gap: geometry.gap });
				event?.currentTarget?.setPointerCapture?.(event?.pointerId);
				// 兜底：把 move／up 也挂到 document 上。指针捕获在宿主里不一定生效，
				// 一旦不生效，指针滑出那颗把手就再收不到事件，拖动会卡在原地——就是「彻底拖不动」。
				const doc = globalThis.document;
				if (typeof doc?.addEventListener !== "function") return;
				detach.current?.();
				const stop = () => {
					doc.removeEventListener("pointermove", onMove, true);
					doc.removeEventListener("pointerup", onUp, true);
					doc.removeEventListener("pointercancel", onCancel, true);
					detach.current = null;
				};
				const onMove = moveEvent => moveDrag(moveEvent);
				const onUp = () => { stop(); endDrag(true); };
				const onCancel = () => { stop(); endDrag(false); };
				doc.addEventListener("pointermove", onMove, true);
				doc.addEventListener("pointerup", onUp, true);
				doc.addEventListener("pointercancel", onCancel, true);
				detach.current = stop;
			};
			const moveDrag = event => {
				// 读可变引用而不是渲染期的 `drag`：document 上那个监听器是按下时注册的，
				// 闭包里拿的永远是按下那一刻的值，读 state 只会读到 null。
				const state = dragBox.current;
				if (state === null) return;
				const dy = Number(event?.clientY ?? state.startY) - state.startY;
				// 左右也要跟：只算竖轴时，手在晃、卡片钉在原横位，看着就是「不跟手」。
				// 插到第几位仍只看 dy——横移不改优先级。
				const dx = clampDragX(Number(event?.clientX ?? state.startX) - state.startX);
				const to = targetFor(state, dy);
				// 位移每帧都要换（跟手），目标位置只在真跨过中线时才变。
				if (dx === state.dx && dy === state.dy && to === state.to) return;
				putDrag({ ...state, dx, dy, to });
			};
			// 松手这一帧必须「瞬时」：DOM 顺序一提交，行的内容就换了位（key 是下标），
			// 若这时 transform 还带着过渡，会看到两张卡各自穿过去找位子。先冻住过渡再清位移，画面就只是落定。
			const freezeRows = () => {
				const doc = globalThis.document;
				if (typeof doc?.querySelectorAll !== "function") return;
				const nodes = Array.from(doc.querySelectorAll(".dsa-sent"));
				for (const node of nodes) {
					if (node !== null && node !== undefined && node.style !== undefined) node.style.transition = "none";
				}
				const raf = globalThis.requestAnimationFrame;
				if (typeof raf !== "function") return;
				raf(() => raf(() => {
					for (const node of nodes) {
						if (node !== null && node !== undefined && node.style !== undefined) node.style.transition = "";
					}
				}));
			};
			const endDrag = apply => {
				const state = dragBox.current;
				detach.current?.();
				if (state === null) return;
				if (apply !== true) { putDrag(null); return; }
				freezeRows();
				if (state.to !== state.from) moveTo(state.from, state.to);
				putDrag(null);
			};
			// 让位用的是「把一行整块抽走再插回去」的位移量：一次只挪一个元素，
			// 所以区间里每一行恰好平移一个被拖行的厚度，与它自己多高无关。
			const dragSlot = drag === null ? 0 : (() => {
				const self = drag.rows.find(row => row.at === drag.from);
				return self === undefined ? 0 : self.height + drag.gap;
			})();
			const dyOf = at => {
				if (drag === null) return 0;
				if (at === drag.from) return drag.dy;
				if (drag.from < drag.to && at > drag.from && at <= drag.to) return -dragSlot;
				if (drag.from > drag.to && at >= drag.to && at < drag.from) return dragSlot;
				return 0;
			};
			// 横移只算在被拖的那一行上：其余行是在给它让位，跟着左右跑就成了整张表在晃。
			const dxOf = at => (drag !== null && at === drag.from ? drag.dx : 0);
			// 拖动中编号跟着「松手后会排第几」走：编号是命中优先级，位置变了就得变。
			const seatOf = at => {
				if (drag === null) return at + 1;
				const order = list.map((_, pos) => pos).filter(pos => pos !== drag.from);
				order.splice(drag.to, 0, drag.from);
				const seat = order.indexOf(at);
				return seat < 0 ? at + 1 : seat + 1;
			};
			// 预设行的条件列：命令／文件／网络／工具面是说明文字（命中由事实层给），
			// 敏感面是真正可改的匹配式。覆盖行只带档位与开关，缺失的内容从宿主那同一行借回来。
			const noteOf = row => {
				if (row.preset === "") return row.match;
				// 命令面的预设行＝一条命令：说明用宿主给的 `note`（配置里只存档位与开关，
				// 人改过的副本从宿主同一行借回来），不再把命令名当说明重复一遍。
				if (plane === "command") {
					const host = hostRows.find(item => item.preset === row.preset);
					return String(row.note || host?.note || host?.match || row.match || "");
				}
				if (row.match !== "") return row.match;
				const host = hostRows.find(item => item.preset === row.preset);
				return String(host?.match ?? "");
			};
			// 预设行只有一档（事实层给的理由不分读／写／删），所以文件面的预设行也只画一颗片。
			// 文件面一律按读／写／删三列表态——预设行和用户行同一把尺。
			const opsOf = () => (plane === "file" ? ["read", "write", "delete"] : ["action"]);
			const rejected = Array.isArray(frame?.rejected) ? frame.rejected : [];
			// 一行一个色条：整行最严的那个动作决定颜色，扫列表时先看到红／黄。
			const rowTone = row => {
				const values = plane === "file" && row.preset === "" ? [row.read, row.write, row.delete] : [row.action];
				for (const action of ["deny", "ask", "ai", "release"])
					if (values.includes(action)) return action;
				return "silent";
			};
			const pillKey = (index, op) => `${index}:${op}`;
			const choose = (index, op, value) => {
				patch(index, op === "action" ? { action: value } : { [op]: value });
				setOpen("");
			};
			const pillFor = (row, op, index) => h(ActionPill, {
				key: op,
				label: op === "action" ? null : OP_LABEL[op],
				icon: OP_ICON[op],
				value: op === "action" ? row.action : row[op],
				choices: ACTION_CHOICES,
				title: op === "action" ? (ACTION_META[row.action]?.note ?? "") : (ACTION_META[row[op]]?.note ?? ""),
				open: open === pillKey(index, op),
				onToggle: () => toggle(pillKey(index, op)),
				onPick: picked => choose(index, op, picked),
				disabled,
			});

			// 预设行／用户行同一套操作：启用开关（预设行与敏感面）＋拖动把手＋删除（仅用户行）。
			// 排序改成拖动，不再放 ↑↓ 两个按钮 —— 一行两层的布局里那两个箭头既挤又难按。
			const stepButtons = (row, index) => {
				const preset = row.preset !== "";
				const canToggle = true;
				// 兜底行（命令面的「其他命令」、网络面的「未知外发」）固定末位——
				// 没有删除入口、没有拖动把手；档位与开关照旧可动（可改档、可停用）。
				const fallback = isFallbackRow(plane, row);
				return h("span", { className: "dsa-sentBtns" },
					canToggle ? h("span", { className: "dsa-rowEnable" },
						// 启用态不再写「启用中」三个字：开关本身就是状态；只有停用／读不出来时才给字。
						row.enabled === false
							? h("span", { className: "dsa-rowEnableLabel" }, row.invalid ? "读不出来" : "已停用")
							: null,
						h(Toggle, {
							id: `frame-rule-enable-${row.id ?? index}`,
							className: "dsa-stateBtn",
							checked: row.enabled !== false,
							disabled: disabled === true,
							title: row.invalid ? "这一条读不出来：改对正则或档位才会生效"
								: row.enabled === false ? "这一条现在不算数，点它启用" : "这一条正在生效，点它停用",
							onChange: value => patch(index, { enabled: value }),
						})) : null,
					fallback ? h("span", { className: "dsa-rowFixed", title: "兜底行固定最后：不可删、不可上移" }, "固定末位") : null,
					// 顺序：开关 → 删除 → 拖动。删除靠里、拖动收在最右，和常见列表编辑器一致：
					// 拖动是最高频的手，占最外侧；删除是破坏性动作，夹在中间不至于手滑点到。
					fallback ? null : h("button", {
						type: "button", className: "dsa-iconBtn is-danger", title: "删除这一行",
						disabled,
						onClick: () => remove(index),
					}, h("span", { className: "dsa-trash", "aria-hidden": "true", dangerouslySetInnerHTML: {
						__html: '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round" stroke-linejoin="round"><path d="M3.5 4.5h9"/><path d="M5.5 4.5V3h5v1.5"/><path d="M4.5 4.5l.6 9h5.8l.6-9"/></svg>',
					} })),
					fallback ? null : h("button", {
						type: "button", className: "dsa-iconBtn dsa-drag", title: "按住拖动排序",
						disabled,
						// 自己接管指针：按下记几何，移动跟手＋让位，抬起提交。
						// 捕获指针后即使指针滑出行外，move／up 也还落在这颗把手上，不会拖一半断掉。
						onPointerDown: event => beginDrag(index, event),
						onPointerMove: event => moveDrag(event),
						onPointerUp: () => endDrag(true),
						onPointerCancel: () => endDrag(false),
					}, h("span", { className: "dsa-grip", "aria-hidden": "true", dangerouslySetInnerHTML: {
						__html: '<svg width="12" height="14" viewBox="0 0 12 14" fill="currentColor"><circle cx="3" cy="3" r="1.1"/><circle cx="9" cy="3" r="1.1"/><circle cx="3" cy="7" r="1.1"/><circle cx="9" cy="7" r="1.1"/><circle cx="3" cy="11" r="1.1"/><circle cx="9" cy="11" r="1.1"/></svg>',
					} })));
			};
			// 一句话规则行：读序＝语法序——「当 命令 匹配 X → 拒绝」。
			// 表格要靠列对齐才读得懂，句子不用；条件还能就地改，不必删了重加。
			// 行首编号＝命中优先级，是这张表唯一真正要紧的信息，得第一眼看见。
			// 编号＝命中优先级，所以拖动中要跟着新位置走（`displayNo`），不能用行在 list 里的原下标。
			// 行的操作仍按原下标（`index`）：改档、删除都是对着同一行，跟它现在排第几无关。
			const sentence = (row, index, displayNo = index + 1, shift = 0, offsetX = 0) => h("div", {
				// data-at＝这一行在 list 里的真实下标，按下量几何时靠它认身份（编号会随位置变，不能当身份）。
				key: index, "data-at": index,
				// 位移写在这层：拖动中谁该让位、被拖的行跟到哪儿，全由 transform 表达，DOM 顺序一动不动。
				// 横竖同一个公式：被拖的行 x≠0 就是「跟着手左右走」，让位的行只有 y。
				style: shift === 0 && offsetX === 0 ? undefined : { transform: `translate(${offsetX}px, ${shift}px)` },
				className: `dsa-item dsa-sent tone-${rowTone(row)}${row.enabled === false ? " is-off" : ""}${drag !== null && drag.from === index ? " is-dragging" : ""}`,
			},
				// P1：上一行只放句子＋行操作（启用／删除／拖动）；下一行＝条件输入框（左）＋动作片（右）。
				// 文件行有三颗动作片，合成一行会把条件挤没。
				h("div", { className: "dsa-sentTop" },
					h("b", { className: "dsa-ruleNo", title: `第 ${displayNo} 条：自上而下匹配，命中的第一条生效` }, displayNo),
					h("span", { className: "dsa-sentHead" },
						row.preset !== ""
							? h("span", { className: "dsa-sentTag" }, "预设")
							: h("span", { className: "dsa-sentTag is-user" }, "用户"),
						h("span", { className: "dsa-sentLead" }, "当"),
						h("b", { className: "dsa-sentNoun" }, row.label !== "" ? row.label : SENT_NOUN[plane]),
						row.preset !== "" && plane !== "sensitive"
							? null
							: h("span", { className: "dsa-sentLead" }, plane === "sensitive" ? "命中" : "匹配")),
					h("span", { className: "dsa-sentGap" }),
					stepButtons(row, index)),
				h("div", { className: `dsa-sentBottom is-${plane}` },
					h("span", { className: "dsa-blank" },
						plane === "sensitive" || row.preset === ""
							? h(Input, {
								value: noteOf(row), placeholder: meta.placeholder, disabled,
								onChange: event => patch(index, {
									match: typeof event === "string" ? event : String(event?.target?.value ?? ""),
								}),
							})
							: h("span", { className: "dsa-sentNote" + (plane === "file" ? " is-wrap" : ""), title: "这串是说明：命中由事实层判定，能改的是档位和启用开关" },
								noteOf(row) === "" ? "—" : noteOf(row))),
					h("div", { className: "dsa-sentOps" }, ...opsOf(row).map(op => pillFor(row, op, index)))));
			const head = h("div", { className: "dsa-detailHead" },
				onBack === undefined ? null : h("button", {
					type: "button", className: "dsa-back", onClick: onBack,
				}, "‹ 返回"),
				h(PlaneIcon, { plane }),
				h("span", { className: "dsa-detailTitle" }, meta.title),
				h("span", { className: "dsa-detailCount" },
					plane === "sensitive"
						? `${list.length} 条 · 预设形状也在这一张表里，可改可停用；命中取最严的一档，不看先后`
						: `${list.length} 条`),
				// 恢复默认跟着这一面的标题走：列表页每张卡右侧挂一块方形按钮既重复又难看。
				onReset === undefined ? null : h("button", {
					type: "button", className: "dsa-resetPlane",
					style: { marginLeft: "auto" },
					title: RESET_PLANE_TIP, onClick: () => onReset(),
				}, "恢复默认"));
			// 工具条合成一行：条件输入框（这页的主角，占满剩余宽度）→ 新行的默认动作 → 添加。
			// 上一版把「添加」「新规则默认」拆成两行细颗粒，和正文一样重，看不出哪句是给你动手的。
			const defaultKeys = plane === "file" ? ["read", "write", "delete"] : ["single"];
			const defaultPill = (key, label, value) => h(ActionPill, {
				key, label, value, choices: choicesFor(plane), title: "新增行的默认动作",
				open: open === `defaults:${key}`, onToggle: () => toggle(`defaults:${key}`),
				onPick: picked => pickDefault(key, picked), disabled,
			});
			const pickDefault = (key, value) => {
				onDefaults(key === "single"
					? { ...defaults, single: value }
					: { ...defaults, file: { ...defaults.file, [key]: value } });
				setOpen("");
			};

			const tool = h("div", { className: "dsa-item dsa-tool" },
				h("span", { className: "dsa-addWrap" },
					h(Input, {
						value: pending, placeholder: `新增一行：例如 ${meta.placeholder}`,
						onChange: event => setPending(typeof event === "string" ? event : String(event?.target?.value ?? "")),
					})),
				h("span", { className: "dsa-toolDefaults" },
					h("span", { className: "dsa-defaultsLabel" }, "新规则默认"),
					...(plane === "file"
						? defaultKeys.map(op => defaultPill(op, OP_LABEL[op], defaults.file[op]))
						: [defaultPill("single", null, defaults.single)])),
				h(Button, {
					variant: "ghost", size: "sm", disabled: disabled === true || pending.trim() === "", onClick: add,
				}, "＋ 添加"));
			// 一张明细页两块：**自定义**（你加的行，自上而下命中即停）与**预设**（判定链会拉高的
			// 那些理由）。两块同形制、同列，也**同样可改**——换档位、停用都在行上动，
			// 不再有一排带 🔒 的只读预设行（那是「另一套规则」的错觉来源）。
			// 一张表、一套顺序：用户行与预设行不再分两块，靠行首「用户／预设」片区分。
			// 预设行不参与「首条命中」——它由事实层触发；顺序对判定无影响，只影响阅读与调序。
			const ownCount = list.filter(row => row.preset === "").length;
			const body = h("div", { className: "dsa-rules" },
				ownCount === 0 ? h("div", { key: "empty", className: "dsa-emptyList" },
					"还没有自己的规则") : null,
				// 顺序＝表本身的顺序，拖动期间也不改：换位靠 transform 位移表达。
				// 一旦在这层重排，浏览器会把整块重画，位移过渡全丢——那才是「硬跳」的来源。
				// 传下去的是行在 list 里的真实下标，改档／删除才能对得上人；编号另给，按松手后的位次数。
				...list.map((row, at) => sentence(row, at, seatOf(at), dyOf(at), dxOf(at))));
			const warn = rejected.length === 0 ? null : h("div", { className: "dsa-warn" },
				`这些路径没被当成信任根：${rejected.map(item => `${item.dir}（${REJECTION_LABEL[item.reason] ?? item.reason}）`).join("；")}`);
			// 一行介绍就够：顺序语义已经在表头那条计数里，这里只讲匹配语法。
			const note = h("div", { className: "dsa-note" }, meta.tip);
			return h("div", { className: "dsa-detail" + (embedded ? " is-embedded" : "") },
				head,
				tool,
				note,
				body,
				warn);
		}

		// 试算结果的中文状态：每一步只说它会干什么，不猜模型的意见。
		const STATE_LABEL = {
			pass: "通过", stop: "不判", auto: "可自动", pending: "等模型", fallback: "兜底", info: "执行后",
			confirm: "只给建议", never: "只能你确认", skip: "不适用", "n/a": "不再走",
			deny: "拒绝", ask: "问你", release: "直接放行",
		};
		const STATE_TONE = {
			deny: "t-deny", never: "t-deny", ask: "t-ask", confirm: "t-ask", pending: "t-ask", info: "t-silent",
			release: "t-allow", auto: "t-allow", pass: "t-silent", skip: "t-silent", "n/a": "t-silent",
			stop: "t-silent", fallback: "t-silent",
		};

		/** * 试算：粘一条命令，看它在哪一步被定掉。
		 * 这页最难讲清的不是某个开关，而是「规则、下界、AI、人工」谁先谁后——
		 * 讲不清就让人配一堆自己都不确定的东西，所以给一个不会说谎的验证口。
		 */
		function DryRun() {
			const [text, setText] = react.useState("");
			const [out, setOut] = react.useState(null);
			const [busy, setBusy] = react.useState(false);
			const [err, setErr] = react.useState("");
			const run = async () => {
				const q = text.trim();
				if (q === "" || busy) return;
				setBusy(true);
				setErr("");
				try {
					const response = await fetch(`${EXPLAIN_ROUTE}?q=${encodeURIComponent(q)}`,
						{ credentials: "same-origin", cache: "no-store" });
					const body = await response.json();
					if (body?.ok !== true) throw new Error(body?.error ?? `HTTP ${response.status}`);
					setOut(body);
				}
				catch (cause) {
					setErr(String(cause?.message ?? cause));
					setOut(null);
				}
				finally {
					setBusy(false);
				}
			};
			return h("div", { className: "dsa-dry" },
				h("div", { className: "dsa-dryTop" },
					h("span", { className: "dsa-dryPrompt" }, "模拟审批"),
					h("span", { className: "dsa-dryHint" },
						"把要核的动作粘进来，宿主按当前配置走一遍判定链，逐步回它会怎么被处置。不调模型、不执行任何东西。")),
				h("div", { className: "dsa-dryBar" },
					h("span", { className: "dsa-dryInputWrap" },
						h(Input, {
							value: text, placeholder: "粘贴一条命令，或一个路径（按删除试）",
							onChange: event => setText(typeof event === "string" ? event : String(event?.target?.value ?? "")),
						})),
					h(Button, {
						variant: "ghost", size: "sm", disabled: busy || text.trim() === "", onClick: run,
					}, busy ? "模拟中…" : "模拟一下")),
				err === "" ? null : h("div", { className: "dsa-warn" }, `模拟审批失败：${err}`),
				out === null ? null
					: h("div", { className: "dsa-dryOut" },
						h("div", { className: "dsa-dryVerdict" },
							h("span", { className: "dsa-dryVerdictLabel" }, "结论"),
							h("span", null, out.verdict),
							out.asPath === true ? h("span", { className: "dsa-dryAs" }, "（按删除该路径试）") : null),
						h("div", { className: "dsa-dryAs" },
							`按宿主当前配置判定：你的规则共 ${out.ruleTotal ?? 0} 行（命令 ${out.rules?.command ?? 0}／文件 ${out.rules?.file ?? 0}／网络 ${out.rules?.network ?? 0}／工具 ${out.rules?.tool ?? 0}／敏感 ${out.rules?.sensitive ?? 0}）。刚存了行而这个数没动＝保存没落到宿主。`),
						// 模拟跑在宿主进程里，路径类判断按插件所在目录解析；不说清就会被当成「模拟和实际不一样」。
						typeof out.caveat === "string" && out.caveat !== ""
							? h("div", { className: "dsa-dryAs" }, out.caveat) : null,
						h("ol", { className: "dsa-drySteps" },
							...(out.steps ?? []).map(step => h("li", {
								key: step.step, className: `dsa-dryStep ${STATE_TONE[step.state] ?? "t-silent"}`,
							},
								h("span", { className: "dsa-dryStepNo" }, step.step),
								h("span", { className: "dsa-dryStepName" }, step.name),
								h("span", { className: "dsa-dryStepState" }, STATE_LABEL[step.state] ?? step.state),
								h("span", { className: "dsa-dryStepWhy" }, step.why))))),
			);
		}

		function Ladder({ onJump }) {
			return h("div", { className: "dsa-ladder", "aria-label": "判定链" },
				...LADDER.map(item => h("button", {
					key: `${item.step}-${item.name}`,
					type: "button",
					className: "dsa-step",
					title: `${item.name}：${item.who}${item.configurable ? "（可配）" : "（固定）"}`,
					onClick: () => onJump?.(item.card),
				},
					h("span", { className: "dsa-stepNo" }, item.step),
					h("span", { className: "dsa-stepName" }, item.name),
					h("span", { className: item.configurable ? "dsa-stepTag is-on" : "dsa-stepTag" }, item.configurable ? "可配" : "固定"))));
		}

		const REJECTION_LABEL = {
			"not-absolute": "要写绝对路径或 ~ 开头的路径",
			"filesystem-root": "不能是盘根",
			"home-root": "不能是家目录本身",
			"too-broad": "太宽（至少到家目录下一层）",
			"workspace-root": "不能是工作区根本身",
			"credential-or-client-tree": "落在凭据／客户端目录里",
			"credential-material": "像凭据文件",
			"os-critical-tree": "系统关键目录",
			"whole-state-tree": "不能整棵打开 ~/.dsh，只能开子目录",
			"regex-operand": "信任行要写路径，不支持正则",
			blank: "空路径",
		};

		function Control({ field, value, disabled, onChange }) {
			if (field.type === "switch") {
				return h(Switch, { checked: value === true, disabled, label: "", onChange });
			}
			if (field.type === "segmented") {
				return h(SegmentedControl, { id: `frame-${field.key}`, value, options: field.options, label: "", disabled, onChange });
			}
			if (field.type === "rules") {
				return h(RuleDetail, {
					plane: field.plane, rows: value, embedded: true,
					defaults: { single: "ask", file: { read: "ask", write: "ask", delete: "ask" } },
					onDefaults: () => { }, onChange, disabled,
				});
			}
			if (field.type === "list") {
				return h("textarea", {
					className: "dsa-list", value: value.join("\n"), disabled, placeholder: "每行一个",
					onChange: event => onChange(event.target.value.split("\n").map(line => line.trim()).filter(line => line !== "")),
				});
			}
			return h(Input, {
				className: field.type === "number" ? "dsa-number" : "dsa-text",
				type: field.type === "number" ? "number" : "text",
				min: field.min, max: field.max, value, disabled,
				onChange: event => onChange(field.type === "number" ? Number(event.target.value) : event.target.value),
			});
		}

		function FieldRow({ field, value, stored, draft, disabled, onChange }) {
			const plane = field.plane !== undefined ? PLANES[field.plane] : undefined;
			const meta = {
				...field,
				label: field.label ?? plane?.title ?? field.key,
				hint: field.hint ?? plane?.tip,
				placeholder: field.placeholder ?? plane?.placeholder,
			};
			const wide = meta.type === "list" || meta.type === "rules";
			return h("div", { className: "dsa-item dsa-field" + (wide ? " is-wide" : "") + (disabled ? " is-disabled" : "") },
				h("div", { className: "dsa-fieldText" },
					h("span", { className: "dsa-fieldLabel" }, meta.label),
					meta.hint ? h("span", { className: "dsa-fieldHint" }, meta.hint) : null),
				h("div", { className: "dsa-fieldControl" },
					h(Control, { field: meta, value, disabled, onChange })));
		}

		/** * 评审模型＝一对键（reviewerProvider ＋ reviewerModel）合起来的一行选择。
		 * 目录读得到就给下拉挑；读不到由页面退回手填两行，所以这里只管挑。
		 */
		function ModelPickerRow({ state, provider, model, disabled, onPick }) {
			const chosen = `${provider}\u0000${model}`;
			const hint = state.status === "loading" ? "正在读宿主已配置的模型…"
				: state.status === "failed" ? `没读到模型目录（${state.error}），请改用手填的 Provider／Model`
					: state.groups.length === 0 ? "宿主没注册任何可列出的模型，请改用手填的 Provider／Model"
						: state.failures.length > 0
							? `已列出 ${state.groups.length} 个提供方；${state.failures.map(item => item.name).join("／")} 读不到模型`
							: `已列出 ${state.groups.reduce((n, group) => n + group.models.length, 0)} 个模型；选一个＝同时写回 provider 与 model`;
			return h("div", { className: "dsa-item dsa-field" + (disabled ? " is-disabled" : "") },
				h("div", { className: "dsa-fieldText" },
					h("span", { className: "dsa-fieldLabel" }, "评审模型"),
					h("span", { className: "dsa-fieldHint" }, hint)),
				h("div", { className: "dsa-fieldControl" },
					h("select", {
						className: "dsa-filterSelect dsa-modelSelect", value: chosen, disabled: disabled || state.status !== "ready" || state.groups.length === 0,
						onChange: event => {
							const [nextProvider, nextModel] = String(event.target.value).split("\u0000");
							onPick(nextProvider, nextModel);
						},
					},
						state.groups.flatMap(group => [
							h("optgroup", { key: `g-${group.id}`, label: group.name },
								...group.models.map(item => h("option", {
									key: `${group.id}/${item.id}`, value: `${group.id}\u0000${item.id}`,
								}, item.name))),
						]))));
		}

		/** * Managed permission tiers: the host's live catalog, one switch per tier.
		 * Built-in tiers this frame cannot usefully manage stay hidden unless
		 * they were already saved (then the user can switch them off).
		 */
		function PresetPicker({ options, value, disabled, onChange }) {
			const selected = Array.isArray(value) ? value : [];
			const list = Array.isArray(options) && options.length > 0
				? options
				: selected.map(name => ({ name, label: name, description: "" }));
			const UNMANAGED_BUILTINS = new Set(["read-only", "workspace-write", "danger-full-access", "auto"]);
			const shownList = list.filter(option => !UNMANAGED_BUILTINS.has(option.name) || selected.includes(option.name));
			const toggle = (name, on) => onChange(on
				? [...selected.filter(item => item !== name), name]
				: selected.filter(item => item !== name));
			return h("div", { className: "dsa-field is-wide dsa-presetPicker" },
				h("div", { className: "dsa-fieldText" },
					h("span", { className: "dsa-fieldLabel" }, "受管权限档"),
					h("span", { className: "dsa-fieldHint" }, "只接管勾选的权限档；通常只勾「自动审批」。只读／工作区写／完全权限默认不接管。")),
				list.length === 0
					? h("div", { className: "dsa-readonly" }, "宿主没有返回权限目录；保存过的档仍会显示在这里。")
					: shownList.length === 0
						? h("div", { className: "dsa-readonly" }, "没有可接管的权限档；内置只读／工作区写／完全权限默认不接管。")
						: null,
				...shownList.map(option => h("div", { key: option.name, className: "dsa-item dsa-field dsa-presetOption" },
					h("div", { className: "dsa-fieldText" },
						h("span", { className: "dsa-fieldLabel" }, presetLabel(option.name, option.label || option.name))),
					h(Switch, {
						id: `frame-gated-${option.name}`,
						checked: selected.includes(option.name),
						label: "",
						disabled,
						onChange: on => toggle(option.name, on),
					}))));
		}

		function ConfigPage({ view, form }) {
			if (view !== "page") return null;
			const state = form?.state;
			const usable = state?.status === "ready" && state.value !== undefined && state.writable !== false
				&& typeof form.mutate === "function";
			const stored = usable ? state.value : {};
			const [draft, setDraft] = react.useState(() => draftOf(stored));
			const [busy, setBusy] = react.useState(false);
			const [message, setMessage] = react.useState("");
			const [error, setError] = react.useState("");
			// 宿主存的是密文：解开后的那一份只用于比较「有没有真的改动」，
			// 不然每次保存都会把整张敏感表重封一遍。
			const [storedOpen, setStoredOpen] = react.useState(null);
			const signature = JSON.stringify(stored);
			react.useEffect(() => {
				if (busy) return undefined;
				const next = draftOf(JSON.parse(signature));
				setDraft(next);
				if (!hasSealedRows(next.sensitiveRules)) {
					setStoredOpen(null);
					return undefined;
				}
				let alive = true;
				codecSensitiveRows("open", next.sensitiveRules)
					.then(opened => {
						if (!alive) return;
						setStoredOpen(opened);
						// 只换回还没被用户动过的行：密文原样留着、已被改过的明文不覆盖。
						setDraft(current => ({
							...current,
							sensitiveRules: (Array.isArray(current.sensitiveRules) ? current.sensitiveRules : []).map(
								(row, at) => isSealedValue(row?.match) && opened[at] !== undefined
									? { ...row, match: opened[at].match }
									: row),
						}));
					})
					.catch(cause => {
						if (alive) setError(`敏感规则读不出来：${String(cause?.message ?? cause)}`);
					});
				return () => { alive = false; };
			}, [signature, busy]);
			const [filters, setFilters] = react.useState({ range: "7d", decision: "", category: "", q: "", offset: 0,
				// 人工答复是这张页的正事，默认就显示；启动／配置两类是簿记，默认收起。
				hideBoot: true, hideConfig: true, hideHuman: false });
			const [anchor, setAnchor] = react.useState(() => Date.now());
			const [audit, setAudit] = react.useState({
				status: "loading", entries: [], matched: 0, total: 0, segments: 0, chain: null, error: "",
			});
			const [auditTick, setAuditTick] = react.useState(0);
			const [clearing, setClearing] = react.useState(false);
			const [confirmClear, setConfirmClear] = react.useState(false);
			const query = auditQuery(filters, anchor);
			react.useEffect(() => {
				let alive = true;
				setAudit(current => ({ ...current, status: "loading", error: "" }));
				fetch(`${AUDIT_ROUTE}?${query}`, { credentials: "same-origin", cache: "no-store" })
					.then(response => {
						if (!response.ok) throw new Error(`HTTP ${response.status}`);
						return response.json();
					})
					.then(body => {
						if (!alive) return;
						if (body?.ok !== true) throw new Error(body?.error ?? "宿主读审计失败");
						setAudit({
							status: "ready",
							entries: Array.isArray(body.entries) ? body.entries : [],
							matched: Number(body.matched ?? 0),
							total: Number(body.total ?? 0),
							segments: Number(body.segments ?? 0),
							chain: body.chain ?? null,
							error: "",
						});
					})
					.catch(cause => {
						if (alive) setAudit(current => ({ ...current, status: "failed", entries: [], error: String(cause?.message ?? cause) }));
					});
				return () => { alive = false; };
			}, [query, auditTick]);
			const refreshAudit = () => {
				setAnchor(Date.now());
				setAuditTick(tick => tick + 1);
			};
			// 敏感信息表：读一次、动作后再读一次（回写开关与删除都改的是宿主侧那张表）。
			const [secrets, setSecrets] = react.useState({ status: "loading", entries: [], revealed: {}, autoRestore: false, limits: null, error: "" });
			const [secretsTick, setSecretsTick] = react.useState(0);
			const [confirmClearSecrets, setConfirmClearSecrets] = react.useState(false);
			react.useEffect(() => {
				setSecrets(current => ({ ...current, status: "loading", error: "" }));
				fetch(SECRETS_ROUTE, { credentials: "same-origin", cache: "no-store" })
					.then(response => {
						if (!response.ok) throw new Error(`HTTP ${response.status}`);
						return response.json();
					})
					.then(body => {
						if (body?.ok !== true) throw new Error(body?.error ?? "宿主读敏感表失败");
						setSecrets(current => ({
							status: "ready",
							entries: Array.isArray(body.entries) ? body.entries : [],
							revealed: current.revealed,
							autoRestore: body.autoRestore === true,
							limits: body.limits ?? null,
							error: "",
						}));
					})
					.catch(cause => setSecrets(current => ({ ...current, status: "failed", entries: [], error: String(cause?.message ?? cause) })));
			}, [secretsTick]);
			const postSecrets = async payload => {
				try {
					const response = await fetch(SECRETS_ROUTE, {
						method: "POST", credentials: "same-origin", cache: "no-store",
						headers: { "content-type": "application/json" }, body: JSON.stringify(payload),
					});
					const body = await response.json();
					if (body?.ok !== true) throw new Error(body?.error ?? `HTTP ${response.status}`);
					setSecretsTick(tick => tick + 1);
					return body;
				}
				catch (cause) {
					setSecrets(current => ({ ...current, status: "failed", error: String(cause?.message ?? cause) }));
					return false;
				}
			};
			const revealSecret = async token => {
				try {
					const response = await fetch(`${SECRETS_ROUTE}?token=${encodeURIComponent(token)}`,
						{ credentials: "same-origin", cache: "no-store" });
					const body = await response.json();
					if (body?.ok !== true || typeof body.plain !== "string") throw new Error(body?.error ?? "读不到");
					setSecrets(current => ({ ...current, revealed: { ...current.revealed, [token]: body.plain } }));
				}
				catch {
					// 取不到明文就在原处留头 4 字，不弹错误条打断整页。
				}
			};
			const onFilter = patch => setFilters(current => ({ ...current, ...patch, offset: patch.offset === undefined ? 0 : patch.offset }));
			const exportAudit = async format => {
				try {
					setError("");
					const response = await fetch(`${AUDIT_EXPORT_ROUTE}?${auditQuery(filters, anchor)}&format=${format}`,
						{ credentials: "same-origin", cache: "no-store" });
					if (!response.ok) throw new Error(`HTTP ${response.status}`);
					const text = await response.text();
					const type = format === "md" ? "text/markdown" : "application/x-ndjson";
					const href = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
					const link = document.createElement("a");
					link.href = href;
					link.download = `auto-approval-frame-audit-${new Date().toISOString().slice(0, 10)}.${format === "md" ? "md" : "jsonl"}`;
					document.body.appendChild(link);
					link.click();
					link.remove();
					URL.revokeObjectURL(href);
					setMessage(`已导出 ${format === "md" ? "Markdown" : "JSONL"}`);
				}
				catch (cause) {
					setError(String(cause?.message ?? cause));
				}
			};
			const clearAudit = async () => {
				setClearing(true);
				setError("");
				try {
					const response = await fetch(AUDIT_CLEAR_ROUTE, { method: "POST", credentials: "same-origin", cache: "no-store" });
					if (!response.ok) throw new Error(`HTTP ${response.status}`);
					const body = await response.json();
					if (body?.ok !== true) throw new Error(body?.error ?? "清空失败");
					setMessage("审计已清空（保留清空标记）");
					setConfirmClear(false);
					refreshAudit();
				}
				catch (cause) {
					setError(String(cause?.message ?? cause));
				}
				finally {
					setClearing(false);
				}
			};
			const storedCompare = storedOpen === null ? stored : { ...stored, sensitiveRules: storedOpen };
			const ops = usable ? opsFrom(draft, storedCompare) : [];
			const set = (key, value) => setDraft(current => ({ ...current, [key]: value }));
			// 每面一颗「恢复默认」。只改草稿——还没保存时，页尾那颗「撤销」就能整份
			// 退回宿主存的那一份；保存后只是少了这几行覆盖，出厂表自己在 policy 侧补回。
			const resetPlane = plane => set(RULE_KEY_OF[plane], restorePlaneRows(draft[RULE_KEY_OF[plane]]));
			const [frame, setFrame] = react.useState({
				status: "idle", rows: {}, trusted: [], dshOpen: [], rejected: [],
				gatedPresets: [], missingGatedPresets: [], presetOptions: [],
			});
			const [frameTick, setFrameTick] = react.useState(0);
			const [openAdvanced, setOpenAdvanced] = react.useState({});
			const [planeView, setPlaneView] = react.useState(null);
			const [defaults, setDefaults] = react.useState({
				single: "ask", file: { read: "ask", write: "ask", delete: "ask" },
			});
			react.useEffect(() => settingsStylesheet(), []);
			react.useEffect(() => {
				let alive = true;
				setFrame(current => ({ ...current, status: "loading" }));
				fetch(FRAME_ROUTE, { credentials: "same-origin", cache: "no-store" })
					.then(response => {
						if (!response.ok) throw new Error(`HTTP ${response.status}`);
						return response.json();
					})
					.then(body => {
						if (!alive) return;
						if (body?.ok !== true) throw new Error(body?.error ?? "宿主未提供判定链接口");
						setFrame({
							status: "ready",
							gatedPresets: Array.isArray(body.gatedPresets) ? body.gatedPresets : [],
							missingGatedPresets: Array.isArray(body.missingGatedPresets) ? body.missingGatedPresets : [],
							presetOptions: Array.isArray(body.presetOptions) ? body.presetOptions : [],
								rows: body.rows ?? {},
							trusted: Array.isArray(body.trusted) ? body.trusted : [],
							dshOpen: Array.isArray(body.dshOpen) ? body.dshOpen : [],
							rejected: Array.isArray(body.rejected) ? body.rejected : [],
							error: "",
						});
					})
					.catch(cause => {
						if (alive) setFrame(current => ({ ...current, status: "failed", error: String(cause?.message ?? cause) }));
					});
				return () => { alive = false; };
			}, [frameTick]);
			// 模型目录只在选了「指定预设」时读一次（宿主侧读 profile，不走网络）。
			// 注意：这里**不能**返回清理函数——依赖里有 models.status，把状态改成 loading 会立刻重跑本
			// effect 并触发上一次的清理，那个 alive=false 会把在途响应丢掉，页面就永远停在「正在读取」。
			const [models, setModels] = react.useState({ status: "idle", groups: [], failures: [], error: "" });
			react.useEffect(() => {
				if (draft.reviewerSource !== "preset" || models.status !== "idle") return undefined;
				setModels(current => ({ ...current, status: "loading" }));
				fetch(MODELS_ROUTE, { credentials: "same-origin", cache: "no-store" })
					.then(response => {
						if (!response.ok) throw new Error(`HTTP ${response.status}`);
						return response.json();
					})
					.then(body => {
						if (body?.ok !== true) throw new Error(body?.error ?? "宿主未提供模型目录接口");
						setModels({
							status: "ready",
							groups: Array.isArray(body.groups) ? body.groups : [],
							failures: Array.isArray(body.failures) ? body.failures : [],
							note: typeof body.note === "string" ? body.note : "",
							error: "",
						});
					})
					.catch(cause => setModels({ status: "failed", groups: [], failures: [], note: "", error: String(cause?.message ?? cause) }));
			}, [draft.reviewerSource, models.status]);
			const jump = card => {
				const node = document.getElementById(`frame-card-${card}`);
				node?.scrollIntoView?.({ behavior: "smooth", block: "start" });
			};
			const save = async () => {
				setBusy(true);
				setError("");
				setMessage("");
				try {
					const sealedOps = await sealOpsForSave(ops);
					await form.mutate(sealedOps);
					setMessage(`已保存 ${sealedOps.length} 项`);
					setFrameTick(tick => tick + 1);
				}
				catch (cause) {
					setError(String(cause?.message ?? cause));
				}
				finally {
					setBusy(false);
				}
			};
			return h("div", { className: "dsa-page" },
				h("div", { className: "dsa-pageHead" },
					h("div", { className: "dsa-pageTitle" }, "自动审批框架"),
					h("div", { className: "dsa-pageDesc" },
						"本页只配 DSH 的「自动审批」这一档。一次调用依次经过下面几步：前一步没给出结论，才轮到下一步。点一格跳到对应卡片。"),
					h(Ladder, { onJump: jump }),
					h(DryRun)),
				usable ? null : h("div", { className: "dsa-notice" },
					"配置暂不可读（该 profile 未激活本插件）。页面只展示，不接收写入。"),
				...SECTIONS.map(section => {
					// 依赖没满足的字段整行消失（不是灰着留着）：灰留着还是占视线，
					// 而「跟随会话」时那两行手填根本不该被看见。
					const gate = field => field.dependsOn === undefined || draft[field.dependsOn.key] === field.dependsOn.value;
					// 挑模型那一行与手填那两行是同一件事的两种落法，永远只出现一种：
					// 目录读得到（或正在读）⇒ 下拉；读失败或空目录 ⇒ 退回手填 Provider／Model。
					const fallbackShown = models.status === "failed"
						|| (models.status === "ready" && models.groups.length === 0);
					const listed = field => field.type === "modelPicker"
						? fallbackShown !== true
						: field.fallbackOnly !== true || fallbackShown === true;
					const visible = field => field.advanced !== true && field.type !== "rules" && field.head !== true
						&& gate(field) && listed(field);
					const plain = section.fields.filter(visible);
					const advanced = section.fields.filter(field => field.advanced === true && field.type !== "rules");
					const expanded = openAdvanced[section.id] === true;
					const shown = expanded ? section.fields.filter(field => gate(field) && listed(field)) : plain;
					const steps = LADDER.filter(item => item.card === section.id).map(item => item.step);
					const headField = section.fields.find(field => field.head === true);
					const counts = Object.fromEntries(RULE_KEYS.map(item => [item.plane, valueOf({ type: "rules", plane: item.plane }, draft[item.key]).length]));
					const body = section.id === "rules"
						// 安全规则卡只认它那四张表；敏感面与敏感信息的两张视图归敏感保护卡，
						// 否则点开「敏感信息」会在这里拿一张不属于本卡的平面去画明细（meta 直接没有）。
						? (RULE_KEYS.some(item => item.plane === planeView)
							? h(RuleDetail, {
								plane: planeView,
								rows: draft[RULE_KEY_OF[planeView]],
								defaults,
								onDefaults: setDefaults,
								frame,
								disabled: !usable || busy,
								onChange: value => set(RULE_KEY_OF[planeView], value),
								onBack: () => setPlaneView(null),
								onReset: () => resetPlane(planeView),
							})
							: h(RuleSummary, {
								planes: RULE_KEYS.map(item => ({ ...PLANES[item.plane], key: item.key, plane: item.plane })),
								counts,
								onReset: resetPlane,
								presets: Object.fromEntries(RULE_KEYS.map(item => [
									item.plane, (frame.rows?.[item.plane] ?? []).filter(item2 => item2.preset !== "").length,
								])),
								onOpen: setPlaneView,
							}))
						: h("div", { className: "dsa-body" },
							...shown.map((field, index) => {
								const marked = { ...field, __index: index, __count: shown.length };
								if (field.type === "presetPicker")
									return h(PresetPicker, {
										key: field.key,
										options: frame.presetOptions,
										value: draft[field.key],
										disabled: !usable || busy,
										onChange: value => set(field.key, value),
									});
								if (field.type === "modelPicker")
									return h(ModelPickerRow, {
										key: "model-picker",
										state: models,
										provider: draft.reviewerProvider,
										model: draft.reviewerModel,
										disabled: !usable || busy,
										onPick: (provider, model) => {
											// 一次点选写两枚键（两枚都是 volatile，走同一条 mutate 通道）。
											set("reviewerProvider", provider);
											set("reviewerModel", model);
										},
									});
								return h(FieldRow, {
									key: field.key,
									field: marked,
									value: draft[field.key],
									stored,
									draft,
									disabled: !usable || busy,
									onChange: value => set(field.key, value),
								});
							}),
// 目录读不到时把原因写在卡里：此时下拉已退成手填两行，不写就没人知道为什么。
							section.id === "review" && models.status !== "loading"
								&& (models.status === "failed" || models.groups.length === 0)
								? h("div", { className: "dsa-readonly" },
									`没读到宿主配好的模型（${models.error || models.note || "宿主未提供该接口"}），请手填下面两项。`)
								: null,
							section.id === "preset" && Array.isArray(frame.missingGatedPresets) && frame.missingGatedPresets.length > 0
								? h("div", { className: "dsa-notice" },
									`受管权限档 ${frame.missingGatedPresets.join("、")} 不在宿主当前权限表里：本插件不会接管任何会话。把下面这段加进你 profile 的 permission.presets（保留已有档），或把 gatedPresets 改成宿主已有的档，重启后生效。`,
									h("pre", { className: "dsa-noticeCode" },
										`- id: permission\n  config:\n    presets:\n${frame.missingGatedPresets
											.map(name => `      ${name}:\n        sandbox: danger-full-access\n        approval: ask`)
											.join("\n")}`))
								: null,
							// 受管档与调试开关都不在页面上出现：档归插件自己，改它只能走 profile。
							null,
							section.id !== "sensitive" ? null
							: planeView === "sensitive"
								? h(RuleDetail, {
									plane: "sensitive",
									rows: draft.sensitiveRules,
									defaults,
									onDefaults: setDefaults,
									frame,
									embedded: true,
									disabled: !usable || busy,
									onChange: value => set("sensitiveRules", value),
									onBack: () => setPlaneView(null),
									onReset: () => resetPlane("sensitive"),
								})
								: planeView === "secrets"
									? h(SecretVault, {
										key: "secrets-vault",
										secrets,
										onReveal: revealSecret,
										onHide: token => setSecrets(current => {
											const revealed = { ...current.revealed };
											delete revealed[token];
											return { ...current, revealed };
										}),
										onRestore: (token, restore) => postSecrets({ token, restore }),
										onGrant: payload => postSecrets({ grant: true, purpose: "tool-write", ...payload }),
										onRemove: token => postSecrets({ token, remove: true }),
										onClear: async () => {
											await postSecrets({ clear: true });
											setConfirmClearSecrets(false);
										},
										confirmClear: confirmClearSecrets,
										onConfirmClear: setConfirmClearSecrets,
										onBack: () => setPlaneView(null),
									})
									: h(RuleSummary, {
										// 一卡两行，平行同形：**检测规则**（认形状）与**敏感信息**（记占位符）。
										// 它们同属「敏感保护」这一件事的两半，拆成两张卡就看不出是一对。
										planes: [
											{ ...PLANES.sensitive, key: "sensitiveRules", plane: "sensitive" },
											{
												plane: "secrets", key: "secrets", title: "敏感信息",
												desc: "脱敏遮出来的占位符都记在这里，可显示明文、可开关回写、可清空。",
											},
										],
										counts: {
											sensitive: (Array.isArray(frame?.rows?.sensitive) && frame.rows.sensitive.length > 0
												? frame.rows.sensitive.length
												: valueOf({ type: "rules", plane: "sensitive" }, draft.sensitiveRules).length),
											secrets: (secrets.entries ?? []).length,
										},
										onReset: resetPlane,
										presets: { sensitive: (frame?.rows?.sensitive ?? []).filter(item => item.preset !== "").length },
										onOpen: setPlaneView,
									}),
							advanced.length === 0 ? null : h("button", {
								type: "button", className: "dsa-advBtn",
								onClick: () => setOpenAdvanced(current => ({ ...current, [section.id]: !(current[section.id] === true) })),
							}, expanded ? `▲ 收起高级项（${advanced.length} 项）` : `▼ 高级（${advanced.length} 项）`));
					return h("div", {
						key: section.id, id: `frame-card-${section.id}`, className: "dsa-card",
					},
						h("div", { className: "dsa-cardHead" },
							h("span", { className: "dsa-cardBar" }),
							h("span", { className: "dsa-cardTitle" }, section.title),
							steps.length > 0 ? h("span", { className: "dsa-cardBadge" }, `链上第 ${steps.join("、")} 步`) : null,
							// 卡头右侧＝这张卡的总闸，不为它单开一行
							headField === undefined ? null : h("span", { className: "dsa-cardSwitch" },
								h("span", { className: "dsa-cardSwitchLabel", title: headField.hint }, headField.label),
								h(Switch, {
									id: `frame-card-switch-${headField.key}`,
									checked: draft[headField.key] === true, label: "", disabled: !usable || busy,
									onChange: value => set(headField.key, value),
								})),
						),
						h("div", { className: "dsa-cardDesc" }, section.desc),
						body,
						section.id === "audit" ? h(AuditCenter, {
							key: `${section.id}-audit`,
							audit,
							filters,
							onFilter,
							onRefresh: refreshAudit,
							onExport: exportAudit,
							onClear: clearAudit,
							confirmClear,
							onConfirmClear: setConfirmClear,
							clearing,
							// 工具规则表（生效行）用来判按钮是「放行」还是「修改」，并说出它现在的档。
							toolRows: Array.isArray(frame.rows?.tool) ? frame.rows.tool : [],
						}) : null);
				}),
				h("div", { className: "dsa-footer" + (ops.length > 0 ? " is-dirty" : "") },
					error ? h("span", { className: "dsa-error" }, error)
						: message ? h("span", { className: "dsa-ok" }, message)
							: h("span", { className: "dsa-status" },
								ops.length > 0 ? `${ops.length} 项待保存` : "没有改动"),
					h(Button, {
						variant: "ghost", size: "sm", disabled: ops.length === 0 || busy, onClick: () => setDraft(draftOf(stored)),
					}, "撤销"),
					h(Button, {
						variant: "primary", size: "sm", disabled: !usable || busy || ops.length === 0, onClick: save,
					}, busy ? "保存中…" : `保存${ops.length > 0 ? `（${ops.length}）` : ""}`)));
		}

		// ── 审批卡详情区：命令原文 ＋「AI 解读」按钮 ──────────────────────
		// 宿主只留一个详情位（single），这里用更低优先级压住 ui-chat 的渲染。
		// 两条退路：注册失败就不注册；拿不到命令就主动退位——卡片都回到原样。
		let disposeApprovalDetail = null;

		function approvalCommandOf(root) {
			try {
				const args = JSON.parse(root.argsRaw);
				return typeof args?.command === "string" ? args.command : undefined;
			}
			catch {
				return undefined;
			}
		}

		function ApprovalDetail({ callId, useChat }) {
			const command = useChat(snapshot => {
				for (const node of snapshot.nodes.values()) {
					const root = node.kind === "tool-call" ? node.data?.root : undefined;
					if (root !== undefined && root.callId === callId && !("kind" in root) && root.phase === "start")
						return approvalCommandOf(root);
				}
				return undefined;
			});
			const [phase, setPhase] = react.useState("idle");
			const [text, setText] = react.useState("");
			const [error, setError] = react.useState("");
			// 分区内容（出处／目标／评审原话／评审看到）。卡头只有一行且不认换行，
			// 这四段并进去就折成一团，所以它们从路由按 callId 取，在这里换行铺开。
			const [detail, setDetail] = react.useState(null);
			const [detailSettled, setDetailSettled] = react.useState(false);
			react.useEffect(() => {
				if (typeof callId !== "string" || callId === "") {
					setDetailSettled(true);
					return undefined;
				}
				let alive = true;
				(async () => {
					try {
						const response = await fetch(`${CARD_DETAIL_ROUTE}?callId=${encodeURIComponent(callId)}`, {
							credentials: "same-origin",
							cache: "no-store",
						});
						const body = await response.json().catch(() => ({}));
						if (alive && response.ok && body.ok === true) setDetail(body);
					}
					catch {
						// 取不到就保持 null：退回「只有命令原文」的原样，不占位、不报错。
					}
					finally {
						if (alive) setDetailSettled(true);
					}
				})();
				return () => { alive = false; };
			}, [callId]);
			// 命令与分区内容都拿不到 ⇒ 这个位子我们占不住，主动退位，让宿主原有详情回来。
			// 等 detailSettled 再计时：non-bash 工具本来就没有命令，但可能有分区内容。
			react.useEffect(() => {
				if (command !== undefined || detail !== null || !detailSettled) return undefined;
				const timer = setTimeout(() => {
					try {
						disposeApprovalDetail?.();
					}
					catch {
						// 退位失败也不影响审批按钮。
					}
				}, 1500);
				return () => clearTimeout(timer);
			}, [command, detail, detailSettled]);
			const explain = async () => {
				if (phase === "loading" || command === undefined) return;
				setPhase("loading");
				setError("");
				try {
					const response = await fetch(EXPLAIN_COMMAND_ROUTE, {
						method: "POST",
						credentials: "same-origin",
						cache: "no-store",
						headers: { "content-type": "application/json" },
						body: JSON.stringify({ command, callId }),
					});
					const body = await response.json().catch(() => ({}));
					if (!response.ok || body.ok !== true)
						throw new Error(body.error || `HTTP ${response.status}`);
					setText(String(body.text ?? ""));
					setPhase("done");
				}
				catch (failure) {
					setError(String(failure?.message ?? failure).slice(0, 120));
					setPhase("failed");
				}
			};
			if (command === undefined && detail === null) return null;
			const sections = detail === null ? [] : [
				["命中", detail.rule],
				["目标", Array.isArray(detail.targets) && detail.targets.length > 0 ? detail.targets.join("、") : ""],
				["评审原话", detail.quote],
				["证据", detail.seen],
			].filter(([, value]) => typeof value === "string" && value.trim() !== "");
			return h("div", { style: { marginTop: 8, display: "flex", flexDirection: "column", gap: 6 } },
				command !== undefined ? h("pre", {
					style: {
						margin: 0,
						padding: "8px 10px",
						borderRadius: 6,
						background: "rgba(127,127,127,0.10)",
						fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
						fontSize: 12,
						lineHeight: 1.5,
						whiteSpace: "pre-wrap",
						wordBreak: "break-all",
						maxHeight: 180,
						overflow: "auto",
					},
				}, command) : null,
				sections.length > 0 ? h("div", {
					style: {
						display: "grid",
						gridTemplateColumns: "auto 1fr",
						gap: "4px 10px",
						padding: "8px 10px",
						borderRadius: 6,
						background: "rgba(127,127,127,0.06)",
						fontSize: 12,
						lineHeight: 1.6,
					},
				}, sections.flatMap(([label, value]) => [
					h("span", { key: `${label}-k`, style: { opacity: 0.55, whiteSpace: "nowrap" } }, label),
					h("span", { key: `${label}-v`, style: { whiteSpace: "pre-wrap", wordBreak: "break-word" } }, value),
				])) : null,
				h("div", { style: { display: "flex", alignItems: "flex-start", gap: 8, flexWrap: "wrap" } },
					h(Button, { variant: "ghost", size: "sm", disabled: phase === "loading", onClick: explain },
						phase === "loading" ? "解读中…" : "AI 解读"),
					phase === "done" ? h("div", { style: { flex: "1 1 240px", fontSize: 12, lineHeight: 1.6, opacity: 0.9 } }, text) : null,
					phase === "failed" ? h("span", { style: { fontSize: 12, opacity: 0.7 } }, `解读失败：${error}`) : null));
		}

		function apply(ctx) {
			hostCtx = ctx;
			ctx.slots.inject("plugins.row.config", () => ctx.slots.register({
				name: "plugins.row.config",
				key: ROW_CONFIG_KEY,
				locale: LOCALE_NS,
			}, ConfigPage));
			ctx.effect(() => installAutoPermissionIcon(globalThis.document), "dsh-auto-approval-frame: preset label, glyph and risk gate");
			// 审批卡详情区：压住 ui-chat 的默认渲染，换成「原文 ＋ AI 解读」。
			// 优先级必须比默认那条小（宿主按升序取第一条），同优先级会冲突。
			try {
				ctx.slots.inject("conversation.approval.detail", () => {
					try {
						disposeApprovalDetail = ctx.slots.register({
							name: "conversation.approval.detail",
							priority: -1,
						}, ApprovalDetail);
						return disposeApprovalDetail;
					}
					catch {
						// 宿主改了插槽契约：不注册，审批卡保持原样。
						return () => {};
					}
				});
			}
			catch {
				// 老宿主没有这个插槽：什么都不做，设置页照常。
			}
			// 会话头的「审计」标签：只列这个会话的判定记录。默认开，设置页-审计中心可关。
			// 宿主只在插槽变更时刷新 tab 列表（ui-conversation 的 refreshViews 订阅 slots），
			// 所以开关不能只改内容——关掉要真的注销这一条，否则标签还在、点进去是空壳。
			try {
				const form = ctx.configForms?.get?.(LOCALE_NS);
				const tabOn = () => form?.getSnapshot?.()?.value?.auditTab !== false;
				ctx.slots.inject("conversation.view", () => {
					let dispose = null;
					const sync = () => {
						if (tabOn()) {
							if (dispose !== null) return;
							try {
								dispose = ctx.slots.register({
									name: "conversation.view",
									id: PLUGIN_NAME,
									order: 31,
									locale: LOCALE_NS,
									label: () => uiText("审计"),
								}, ConversationAudit);
							}
							catch {
								// 宿主改了会话视图契约：不注册，别处照常。
								dispose = null;
							}
							return;
						}
						if (dispose !== null) {
							const off = dispose;
							dispose = null;
							off();
						}
					};
					const unwatch = typeof form?.subscribe === "function" ? form.subscribe(sync) : () => { };
					sync();
					return () => {
						unwatch();
						if (dispose !== null) {
							const off = dispose;
							dispose = null;
							off();
						}
					};
				});
			}
			catch {
				// 宿主没有 configForms / 没有会话视图插槽：不加这个标签，其余照常。
			}
		}

		exports.apply = apply;
		exports.inject = inject;
		exports.name = name;
		return module.exports;
	},
});
