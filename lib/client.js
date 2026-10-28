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
		const DEFAULTS = {
			enabled: true,
			mode: "auto",
			reviewerSource: "session",
			reviewerProvider: "",
			reviewerModel: "",
			reviewerMaxTokens: 512,
			reviewerTimeoutMs: 20000,
			evidenceBudget: 16000,
			reviewRules: [],
			commandRules: [],
			fileRules: [],
			networkRules: [],
			toolRules: [],
			sensitiveRules: [],
			sensitiveDetect: true,
			autoRestoreSecrets: false,
			fastJudge: true,
			fastJudgeMaxTokens: 256,
			fastJudgeTimeoutMs: 3000,
			retentionDays: 90,
			maxTotalBytes: 536870912,
			maxSegmentBytes: 52428800,
		};

	// 一张表一个平面，行＝{action, match, ops}。四档对每个平面都一样：
	// `release` 是真放行（人拍的板），`ai` ＝这一行不拦、继续判，`ask` ＝问你，
	// `deny` ＝直接拒。遮不遮与档位无关：敏感面命中就遮，档位只管遮完之后怎么处置。
		const ACTION_META = {
			release: { label: "允许", tone: "chipAllow", note: "直接放行：不调模型、不弹面板，这一步就此定掉（结果该遮还是遮）" },
			ai: { label: "AI", tone: "chipAsk", note: "这一行不拦，继续交快判／深评" },
			ask: { label: "人工", tone: "chipAsk", note: "直接弹给你确认，AI 不再判" },
			deny: { label: "拒绝", tone: "chipBlock", note: "直接拒绝，工具收到拒绝原因" },
		};
		// 旧配置里存的档位名往现在这套折：allow 的本义就是「不拦、交 AI 判」，redact 那一档已删
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
		const PLANES = {
			command: {
				title: "命令安全", placeholder: "git push",
				desc: "按优先级控制命令前缀的放行或询问。",
				tip: "按「程序名＋参数前缀」匹配：git push 命中 git push origin main、不命中 git pull；* 占一个参数，整行只写 * 匹配所有命令；re: 开头按正则。",
			},
			file: {
				title: "文件安全", placeholder: "%USERPROFILE%\\.cache\\myapp\\", ops: true,
				desc: "按优先级控制文件路径的读取、写入和删除。",
				tip: "~ ＝家目录；* 只匹配一级、** 匹配任意层级；以 / 或 \\ 结尾＝该目录及其全部内容。",
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
				tip: "内置 7 条形状（私钥／JWT／AWS key／Bearer／服务密钥／凭据赋值／连接串）就在这张表里，改正则、换动作、停用都在行上动。脱敏顶掉的是这一行匹配到的整段，要只遮值就把正则写成只匹配值；带 * 的通配行定位不到具体一段，只能拒绝或允许。",
			},
		};
		// 审计里的 `layer` 字段和页面用同一套名字，跑一次就能对上第几步。
		// 这份表必须和 lib/frame/audit.js 的 LAYER_TEXT 逐字相同——导出件和页面说两套
		// 名字就等于「一个层级两个编号」。回归 client.test 里按字面比对两份表锁住。
		const LAYER_LABEL = {
			floor: "内置行", rules: "你的规则", fact: "事实门",
			fast: "AI 快判", deep: "AI 深评", human: "人工", redact: "结果脱敏",
			lifecycle: "生命周期", config: "配置变更", none: "未判定",
		};
		// 判定链：卡片按这条链排，流程条先告诉用户「哪一步可配、哪一步说了算」。
		// 内置行不再单列一格——它在页面上就是每张规则表置顶那几行标着「内置」的行，
		// 单列一格会让人以为是另一套规则，还会让页面链／台账／模拟审批出现两套编号。
		const LADDER = [
			{ step: "0", name: "是否接管", who: "会话权限档", card: "preset", configurable: true },
			{ step: "1", name: "安全规则", who: "内置行＋你的有序表", card: "rules", configurable: true },
			{ step: "2", name: "事实门", who: "只读·会话内部工具", card: "rules", configurable: false },
			{ step: "3", name: "AI 快判", who: "小模型", card: "review", configurable: true },
			{ step: "4", name: "AI 深评", who: "跟随会话／指定预设", card: "review", configurable: true },
			{ step: "5", name: "人工", who: "宿主审批面板", card: "preset", configurable: false },
			{ step: "6", name: "结果脱敏", who: "检测规则命中→先遮，再按档位问／放／拦", card: "sensitive", configurable: true },
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
				desc: "这一档由 AI 审查后再放行：模型没有结论、或需要强制人工时，仍然回到你手上确认。",
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
				desc: "确定性的先定：自上而下匹配，首条命中即停；拒绝＝直接拒，人工＝弹给你，AI＝这一行不拦、继续判，允许＝直接放行。没命中任何行的调用继续往下走。",
				fields: [
					{ key: "commandRules", type: "rules", plane: "command" },
					{ key: "fileRules", type: "rules", plane: "file" },
					{ key: "networkRules", type: "rules", plane: "network" },
					{ key: "toolRules", type: "rules", plane: "tool" },
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
					{ key: "fastJudge", type: "switch", label: "启用 AI 快判", hint: "单目标的写入／删除先问一次小模型；它只能说放行或升级，升级后走深评" },
					{ key: "reviewRules", type: "list", label: "自定义审查规则", hint: "每行一条，追加给模型的提示词末尾；只能加限制，不能放宽。例：禁止删除 .git 目录" },
					{ key: "reviewerMaxTokens", type: "number", label: "深评输出上限（token）", min: 64, max: 4096, hint: "深评回答很短，512 够用，调大只是多花钱", advanced: true },
					{ key: "reviewerTimeoutMs", type: "number", label: "深评超时（毫秒）", min: 1000, max: 120000, hint: "超过就算评审失败，转人工确认；20000＝20 秒", advanced: true },
					{ key: "evidenceBudget", type: "number", label: "证据预算（字符）", min: 2000, max: 48000, hint: "送给深评的上下文上限；越大越准但越贵", advanced: true },
					{ key: "fastJudgeMaxTokens", type: "number", label: "快判输出上限（token）", min: 64, max: 1024, hint: "快判只回一个 JSON，256 够用", advanced: true },
					{ key: "fastJudgeTimeoutMs", type: "number", label: "快判超时（毫秒）", min: 500, max: 30000, hint: "超时即升级到深评，不拦人", advanced: true },
				],
			},
			{
				id: "sensitive",
				title: "敏感保护",
				desc: "这一卡两件事，平行看：**检测规则**认出内容里的凭据形状，**敏感信息**记着遮出来的占位符。命中就先遮，再按档位处置——默认问你拒绝还是允许。",
				fields: [
					{ key: "sensitiveDetect", type: "switch", head: true, label: "启用检测与处置", hint: "关掉＝整张检测规则表不再表态，工具返回原样进模型上下文" },
					{ key: "autoRestoreSecrets", type: "switch", label: "自动回写占位符", hint: "写文件之后，把文件里**本表铸出的**占位符换回明文。命令参数里的占位符换不了（宿主禁止插件改写参数）" },
					{ key: "sensitiveRules", type: "rules", plane: "sensitive" },
				],
			},
			{
				id: "audit",
				title: "审计中心",
				desc: "每次调用、每条规则命中、每个人工答复和工具最终结果都进哈希链台账（按天分段）；下面每条的「层级」就是它在判定链上的第几步。",
				fields: [
					{ key: "retentionDays", type: "number", label: "保留天数", min: 1, max: 3650, hint: "超过天数的已封存段会被裁剪，并留 retention-pruned 墓碑", advanced: true },
					{ key: "maxTotalBytes", type: "number", label: "总大小上限（字节）", min: 1048576, hint: "超限从最旧的段开始裁；默认 512MB", advanced: true },
					{ key: "maxSegmentBytes", type: "number", label: "单段上限（字节）", min: 1048576, hint: "当天段写到这个大小就换下一个序号；默认 50MB", advanced: true },
				],
			},
		];
		const HOST_ONLY_KEYS = ["gatedPresets", "debug"];
		const HOST_ONLY_LABELS = { gatedPresets: "受管预设", debug: "调试" };
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
			{ value: "allowed", label: "已放行" },
			{ value: "ask", label: "转人工" },
			{ value: "blocked", label: "已拦截" },
			{ value: "approved", label: "已批准" },
			{ value: "rejected", label: "已拒绝" },
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
		function auditQuery(filters, anchor) {
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
			if (filters.decision) params.set("decision", filters.decision);
			if (filters.category) params.set("category", filters.category);
			// Boot rows are the restart bookkeeping, not decisions: hidden unless
			// the operator asks for the lifecycle category explicitly.
			if (filters.hideBoot !== false && !filters.category) params.set("hide", "lifecycle.boot");
			if (filters.q.trim()) params.set("q", filters.q.trim());
			params.set("offset", String(filters.offset || 0));
			params.set("limit", "50");
			return params.toString();
		}

		/**
		 * 敏感信息表：脱敏换来的占位符。
		 * 明文默认不出这行——只给头 4 字与长度，点「显示」才单条取一次（宿主那边记一条
		 * sensitive.revealed，谁看过哪条凭据是可查的）。「回写」是这一条能不能被换回明文。
		 */
		function SecretVault({ secrets, onReveal, onHide, onRestore, onRemove, onClear, confirmClear, onConfirmClear, onBack }) {
			const rows = Array.isArray(secrets.entries) ? secrets.entries : [];
			// 明细页的头和规则表明细同一形制：返回、图标、标题、计数。
			// 「敏感信息」是卡片里的一张明细，不是一张独立页——没有返回键就走不回上一层的摘要。
			const head = react.createElement("div", { className: "dsa-detailHead" },
				onBack === undefined ? null : react.createElement("button", {
					type: "button", className: "dsa-back", onClick: onBack,
				}, "‹ 返回"),
				react.createElement(PlaneIcon, { plane: "secrets" }),
				react.createElement("span", { className: "dsa-detailTitle" }, "敏感信息"),
				react.createElement("span", { className: "dsa-detailCount" },
					`${rows.length} 条 · 明文只在本机映射表，查看会记一笔台账`));
			const wrap = body => react.createElement("div", { className: "dsa-detail is-embedded" }, head, body);
			if (secrets.status === "loading")
				return wrap(react.createElement("div", { className: "dsa-readonly" }, "正在读取敏感信息表…"));
			if (secrets.status === "failed")
				return wrap(react.createElement("div", { className: "dsa-warn" }, `读不到敏感信息表：${secrets.error}`));
			return wrap(react.createElement("div", { className: "dsa-secretList" },
				rows.length === 0
					? react.createElement("div", { className: "dsa-readonly" }, "还没有占位符——脱敏过一次才会有。")
					: rows.map(row => react.createElement("div", {
						key: row.token, className: "dsa-item dsa-secret",
					},
						react.createElement("code", { className: "dsa-secretToken" }, row.token),
						react.createElement("span", { className: "dsa-secretLabel" }, row.label),
						react.createElement("span", { className: "dsa-secretPlain" },
							secrets.revealed[row.token] ?? `${row.head}····（${row.chars} 字）`),
						react.createElement("span", { className: "dsa-secretMeta" },
							`${row.hits} 次 · 出处 ${row.source || "—"}`),
						react.createElement("button", {
							type: "button", className: "dsa-iconBtn",
							title: secrets.revealed[row.token] === undefined ? "显示这一条完整明文（会记一笔台账）" : "收起明文",
							onClick: () => (secrets.revealed[row.token] === undefined
								? onReveal(row.token) : onHide(row.token)),
						}, secrets.revealed[row.token] === undefined ? "显示" : "收起"),
						react.createElement("button", {
							type: "button", className: `dsa-iconBtn ${row.restore ? "" : "is-off"}`,
							title: row.restore ? "这条占位符会在写文件后被换回明文，点它关掉" : "这条不参与自动回写，点它打开",
							onClick: () => onRestore(row.token, !row.restore),
						}, row.restore ? "回写开" : "回写关"),
						react.createElement("button", {
							type: "button", className: "dsa-iconBtn is-danger", title: "删掉这条映射（占位符从此换不回明文）",
							onClick: () => onRemove(row.token),
						}, "✕"))),
				rows.length === 0 ? null : react.createElement("div", { className: "dsa-secretFoot" },
					confirmClear
						? react.createElement(react.Fragment, null,
							react.createElement("span", { className: "dsa-status" }, "清空后所有占位符都换不回明文，确定？"),
							react.createElement(Button, { variant: "primary", size: "sm", onClick: onClear }, "确认清空"),
							react.createElement(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(false) }, "取消"))
						: react.createElement(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(true) }, "清空映射表"))));
		}

		function AuditCenter({ audit, filters, onFilter, onRefresh, onExport, onClear, confirmClear, onConfirmClear, clearing }) {
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

			const tone = entry => {
				if (entry.decision === "allowed" || entry.decision === "approved") return "t-allow";
				if (entry.decision === "blocked" || entry.decision === "rejected" || entry.decision === "failed") return "t-deny";
				if (entry.decision === "ask") return "t-ask";
				return "t-silent";
			};
			const metaOf = entry => [
				entry.rule ? `规则 ${entry.rule}` : "",
				entry.toolName ? `工具 ${entry.toolName}` : "",
				entry.grant ? `权限 ${entry.grant}` : "",
				Array.isArray(entry.reasons) && entry.reasons.length > 0 ? `理由 ${entry.reasons.join("、")}` : "",
				entry.durationMs !== undefined ? `耗时 ${(Number(entry.durationMs) / 1000).toFixed(1)}s` : "",
			].filter(Boolean).join(" · ");
			return react.createElement("div", { className: "dsa-audit" },
				react.createElement("div", { className: "dsa-auditHead" },
					react.createElement("span", { className: "dsa-auditTitle" },
						"判定记录",
						react.createElement("span", { className: "dsa-sectionCount" }, String(total))),
					react.createElement("span", { className: "dsa-auditBtns" },
						react.createElement(Button, { variant: "ghost", size: "sm", onClick: onRefresh, disabled: status === "loading" },
							status === "loading" ? "读取中…" : "刷新"),
						react.createElement(Button, { variant: "ghost", size: "sm", onClick: () => onExport("jsonl") }, "导出 JSONL"),
						react.createElement(Button, { variant: "ghost", size: "sm", onClick: () => onExport("md") }, "导出 Markdown"),
						confirmClear
							? react.createElement(Button, { variant: "ghost", size: "sm", onClick: onClear, disabled: clearing }, clearing ? "清空中…" : "确认清空")
							: react.createElement(Button, { variant: "ghost", size: "sm", onClick: () => onConfirmClear(true) }, "清空"))),
				react.createElement("div", { className: "dsa-auditBar" },
					react.createElement(SegmentedControl, {
						id: "frame-audit-range", value: filters.range, label: "", options: RANGE_OPTIONS,
						onChange: value => onFilter({ range: value }),
					}),
					react.createElement("select", {
						className: "dsa-filterSelect", value: filters.decision,
						onChange: event => onFilter({ decision: event.target.value }),
					}, ...DECISION_OPTIONS.map(item => react.createElement("option", { key: item.value, value: item.value }, item.label))),
					react.createElement("select", {
						className: "dsa-filterSelect", value: filters.category,
						onChange: event => onFilter({ category: event.target.value }),
					}, ...CATEGORY_OPTIONS.map(item => react.createElement("option", { key: item.value, value: item.value }, item.label))),
					react.createElement(Input, {
						style: { width: 220 }, value: filters.q, placeholder: "搜索动作 / 工具 / 规则",
						onChange: event => onFilter({ q: event.target.value }),
					}),
					react.createElement("label", { className: "dsa-toggle", title: "启动/配置等非判定事件不进列表；选「生命周期」分类时仍可见" },
						react.createElement(Switch, {
							id: "frame-audit-hide-boot", checked: filters.hideBoot !== false, label: "",
							onChange: value => onFilter({ hideBoot: value }),
						}),
						react.createElement("span", { className: "dsa-toggleText" }, "隐藏启动记录"))),
				react.createElement("div", { className: "dsa-summaryBand" },
					status === "failed"
						? `读不到审计：${audit?.error || "宿主未提供审计接口"}`
						: `匹配 ${matched} / 共 ${total} 条 · ${audit?.segments ?? 0} 段` +
							(chain ? ` · ${chain.ok === true ? "哈希链校验通过" : `链在第 ${chain.brokenAt ?? "?"} 处断了`}` : "")),
				status === "failed"
					? react.createElement("div", { className: "dsa-emptyList" }, "检查宿主的 audit 路由是否已挂载（connection.fetch），或重启 DSH 后再看。")
					: entries.length === 0
						? react.createElement("div", { className: "dsa-emptyList" }, status === "loading" ? "正在读取…" : "没有符合条件的记录。")
						: react.createElement("div", { className: "dsa-entries" },
							...entries.map(entry => react.createElement("div", {
								key: entry.id ?? `${entry.sequence}-${entry.timestamp}`,
								className: `dsa-item dsa-entry tone-${entry.decision === "allowed" || entry.decision === "approved"
									? "allow" : entry.decision === "blocked" || entry.decision === "rejected" || entry.decision === "failed"
										? "deny" : entry.decision === "ask" ? "ask" : "silent"}`,
							},
								react.createElement("div", { className: "dsa-entryHead" },
									react.createElement("span", { className: "dsa-chip " + tone(entry) }, DECISION_LABEL[entry.decision] ?? entry.decision ?? "-"),
									react.createElement("span", { className: "dsa-entryCategory" }, CATEGORY_LABEL[entry.category] ?? entry.category ?? "-"),
									react.createElement("span", { className: "dsa-entryLayer" }, LAYER_LABEL[entry.layer] ?? entry.layer ?? ""),
									react.createElement("span", { className: "dsa-entryTime" }, when(entry.timestamp))),
								entry.commandPreview ? react.createElement("div", { className: "dsa-entryAction" }, entry.commandPreview) : null,
								metaOf(entry) ? react.createElement("div", { className: "dsa-entryMeta" }, metaOf(entry)) : null,
								entry.message ? react.createElement("div", { className: "dsa-entrySummary" }, entry.message) : null))),
				react.createElement("div", { className: "dsa-pager" },
					react.createElement(Button, { variant: "ghost", size: "sm", disabled: offset <= 0, onClick: () => onFilter({ offset: Math.max(0, offset - 50) }) }, "上一页"),
					react.createElement("span", { className: "dsa-pagerInfo" }, matched === 0 ? "0 条" : `${offset + 1}–${pageEnd} / ${matched} 条`),
					react.createElement(Button, { variant: "ghost", size: "sm", disabled: pageEnd >= matched, onClick: () => onFilter({ offset: offset + 50 }) }, "下一页")));
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
					".dsa-pageHead{display:flex;flex-direction:column;gap:10px}",
					".dsa-pageTitle{font-size:19px;font-weight:650;letter-spacing:-.015em;line-height:1.35;color:var(--dsw-alias-label-primary)}",
					".dsa-pageDesc{font-size:12.5px;line-height:1.75;color:" + mute + ";max-width:66ch}",
					".dsa-card{display:flex;flex-direction:column;gap:12px;padding:16px 18px;border:1px solid " + frame + ";border-radius:16px;background:var(--dsw-alias-bg-layer-1)}",
					".dsa-cardHead{display:flex;align-items:center;gap:var(--r2)}",
					".dsa-cardBar{width:3px;height:15px;border-radius:2px;flex:none;background:var(--dsw-alias-border-brand,#6366f1)}",
					".dsa-cardTitle{font-size:15px;font-weight:650;letter-spacing:-.01em;color:var(--dsw-alias-label-primary)}",
					".dsa-cardBadge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:" + chip + ";color:" + mute + "}",
					".dsa-cardSwitch{display:inline-flex;align-items:center;gap:8px;margin-left:auto}",
					".dsa-cardSwitchLabel{font-size:12px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-cardDesc{font-size:12.5px;line-height:1.75;color:" + mute + ";max-width:66ch}",
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
					".dsa-dryInputWrap{min-width:0;display:block}",
					// 宿主的输入框自带宽度（甚至可能是行内样式），不给 !important 就还是那一小截。
					// 顺手把它加高加大：一行命令七八十个字符，太小根本没法核对粘进来的东西。
					// 顶住宿主输入框的自带宽度（不给 !important 就压不过），但封顶在 460px：
					// 铺满整行太长、42px 太高，两样都被用户打回过。
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
					".dsa-note{margin:2px 0 10px;padding:2px 0 2px 10px;border-left:2px solid " + edge + ";font-size:11.5px;line-height:1.75;color:" + mute + ";max-width:70ch}",
					".dsa-emptyList{padding:14px 16px;border:1px dashed " + edge + ";border-radius:12px;font-size:12px;color:" + mute + "}",
					".dsa-sectionCount{font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;background:" + chip + ";color:var(--dsw-alias-label-secondary)}",
					// 一句话规则行：读序＝语法序（当 X 匹配 Y 时 → 动作）
					".dsa-rules{display:flex;flex-direction:column;gap:8px}",
					// 一行＝一行网格：编号｜句子｜条件｜时｜动作片｜操作。列固定，所以「人工／拒绝」
					// 在五张表里都竖着排齐，预设行也走同一套列（编号列留空）。
					".dsa-sent{align-items:center;grid-template-columns:22px auto minmax(110px,1fr) auto auto auto;gap:8px;display:grid;box-shadow:inset 3px 0 0 var(--dsw-alias-border-l2,rgba(127,127,127,.3))}",
					".dsa-ruleNo{justify-self:center;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:7px;background:" + chip + ";font-size:11.5px;font-weight:700;color:var(--dsw-alias-label-primary)}",
					".dsa-ruleNo.is-blank{background:0 0}",
					".dsa-sent.tone-allow{box-shadow:inset 3px 0 0 var(--dsw-alias-state-success-primary,#2ea043)}",
					".dsa-sent.tone-ask{box-shadow:inset 3px 0 0 var(--dsw-alias-state-warning-primary,#d29922)}",
					".dsa-sent.tone-deny{box-shadow:inset 3px 0 0 var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-sent.tone-release{box-shadow:inset 3px 0 0 var(--dsw-alias-state-success-primary,#2ea043)}",
					".dsa-sent.tone-ai{box-shadow:inset 3px 0 0 " + mute + "}",
					".dsa-groupTitle{font-size:12px;font-weight:650;color:" + mute + ";margin:12px 0 2px}",
					".dsa-sent.is-preset{border-style:dashed;box-shadow:none;background:transparent}",
					".dsa-sentHead{white-space:nowrap;align-items:center;gap:6px;display:inline-flex}",
					".dsa-sentLead{font-size:12.5px;color:var(--dsw-alias-label-secondary)}",
					".dsa-sentNoun{font-size:13px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-sentTag{font-size:10.5px;font-weight:650;padding:2px 7px;border-radius:6px;border:1px dashed var(--dsw-alias-border-l2);color:" + mute + "}",
					".dsa-sentTail{white-space:nowrap;font-size:12.5px;color:var(--dsw-alias-label-secondary)}",
					".dsa-blank{min-width:0;justify-self:stretch;border-bottom:1px dashed var(--dsw-alias-border-l2)}",
					// 内置行的条件列：说明文字，不是可编辑的匹配式——不给输入框那种「能改」的暗示。
					".dsa-sentNote{display:block;min-width:0;padding:4px 0;font-size:11.5px;line-height:1.5;color:" + mute + ";white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
					".dsa-sentOps{justify-content:flex-end;align-items:center;gap:6px;display:inline-flex;flex-wrap:nowrap}",
					".dsa-sentOps .dsa-dot{display:none}",
					".dsa-sentOps .dsa-pill{gap:5px;padding:0 7px 0 8px}",
					".dsa-sentWhy{min-width:0;font-family:var(--dsw-font-markdown-code-block,ui-monospace,monospace);font-size:11.5px;line-height:1.6;color:" + mute + ";white-space:nowrap;overflow:hidden;text-overflow:ellipsis}",
					".dsa-sentBtns{align-items:center;justify-content:flex-end;gap:4px;display:flex;flex:none}",
					// 启用开关：一颗有边框的胶囊按钮，白底、字不换行。别塞进 26×26 的图标钮里。
					".dsa-stateBtn{height:26px;padding:0 10px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);font:inherit;font-size:11.5px;font-weight:600;color:var(--dsw-alias-label-secondary);white-space:nowrap;cursor:pointer;flex:none}",
					".dsa-stateBtn:hover:not(:disabled){background:" + chip + ";color:var(--dsw-alias-label-primary)}",
					".dsa-stateBtn:disabled{opacity:.4;cursor:default}",
					".dsa-stateBtn.is-off{border-style:dashed;color:" + mute + "}",
					".dsa-iconBtn{width:26px;height:26px;border-radius:7px;border:1px solid transparent;background:transparent;cursor:pointer;font-size:12px;color:" + mute + "}",
					".dsa-iconBtn:hover:not(:disabled){background:" + chip + ";color:var(--dsw-alias-label-primary)}",
					".dsa-iconBtn:disabled{opacity:.3;cursor:default}",
					".dsa-iconBtn.is-danger:hover:not(:disabled){color:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-lock{font-size:11px;line-height:1;color:" + mute + "}",
					// 动作片：整片按动作着色
					".dsa-pill{display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 9px 0 10px;border-radius:999px;border:1px solid var(--dsw-alias-border-l2);background:var(--dsw-alias-bg-layer-1);font:inherit;color:inherit}",
					".dsa-pill.is-disabled{opacity:.72}",
					".dsa-pill.is-picker{cursor:pointer;text-align:left}",
					".dsa-pill-op{font-size:11.5px;font-weight:600;color:var(--dsw-alias-label-secondary)}",
					".dsa-dot{width:7px;height:7px;border-radius:999px;flex:none;background:" + mute + "}",
					".dsa-pill.t-allow{background:rgba(46,160,67,.13);border-color:rgba(46,160,67,.42)}",
					".dsa-pill.t-allow .dsa-dot,.dsa-dot.dot-allow{background:var(--dsw-alias-state-success-primary,#2ea043)}",
					
					".dsa-pill.t-ask{background:rgba(210,153,34,.14);border-color:rgba(210,153,34,.45)}",
					".dsa-pill.t-ask .dsa-dot,.dsa-dot.dot-ask{background:var(--dsw-alias-state-warning-primary,#d29922)}",
					
					".dsa-pill.t-deny{background:rgba(248,81,73,.13);border-color:rgba(248,81,73,.42)}",
					".dsa-pill.t-deny .dsa-dot,.dsa-dot.dot-deny{background:var(--dsw-alias-state-error-primary,#f85149)}",
					".dsa-pill.t-ai{background:transparent;border-style:dashed}",
					".dsa-pill.t-ai .dsa-dot,.dsa-dot.dot-ai{background:" + mute + "}",
					".dsa-sent.is-off{opacity:.56}",
					".dsa-iconBtn.is-off{border-style:dashed;color:" + mute + "}",
					".dsa-secretList{display:flex;flex-direction:column;gap:4px;margin-top:6px}",
					".dsa-secret{display:flex;align-items:center;gap:8px;flex-wrap:nowrap}",
					".dsa-secretToken{font-size:11.5px;font-weight:650;color:var(--dsw-alias-label-primary);white-space:nowrap}",
					".dsa-secretLabel{font-size:12px;color:" + mute + ";white-space:nowrap}",
					".dsa-secretPlain{flex:1 1 auto;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;color:var(--dsw-alias-label-primary)}",
					".dsa-secretMeta{font-size:11px;color:" + mute + ";white-space:nowrap}",
					".dsa-secretFoot{display:flex;align-items:center;gap:8px;justify-content:flex-end;margin-top:6px}",
					
					".dsa-pill.t-silent{background:transparent;border-style:dashed}",
					".dsa-pill-text{font-size:12px;font-weight:650;color:var(--dsw-alias-label-primary)}",
					".dsa-pill-caret{font-size:9px;line-height:1;color:" + mute + "}",
					".dsa-pill.is-picker:hover{border-color:" + frame + "}",
					".dsa-pill.is-picker[aria-expanded='true']{border-color:var(--dsw-alias-border-brand,#6366f1)}",
					// 动作片的下拉：浮层贴在片子正下方，宽度不小于片子；分层靠 l3 边框＋实底，不靠投影。
					".dsa-pillCell{position:relative;display:inline-flex}",
					".dsa-menu{position:absolute;top:calc(100% + 4px);right:0;z-index:8;min-width:100%;flex-direction:column;gap:2px;padding:4px;border:1px solid " + frame + ";border-radius:12px;background:var(--dsw-alias-bg-layer-1);display:flex}",
					".dsa-menuItem{align-items:center;gap:8px;width:100%;height:30px;padding:0 10px;border:1px solid transparent;border-radius:9px;background:transparent;cursor:pointer;font:inherit;font-size:12.5px;font-weight:600;color:var(--dsw-alias-label-primary);white-space:nowrap;text-align:left;display:flex}",
					".dsa-menuItem:hover{border-color:" + edge + ";background:var(--dsa-row)}",
					".dsa-menuItem.is-current{border-color:" + frame + ";background:var(--dsa-row)}",
					".dsa-menuCheck{margin-left:auto;font-size:11px;line-height:1}",
					".dsa-warn{margin-top:10px;padding:10px 12px;border-radius:10px;font-size:11.5px;line-height:1.7;color:var(--dsw-alias-state-warning-primary,#d29922);background:rgba(210,153,34,.1)}",
					// 审计中心（同一套字阶，判定记录是卡内小节，不是第二张卡）
					".dsa-audit{display:flex;flex-direction:column;gap:10px}",
					".dsa-auditHead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:14px}",
					".dsa-auditTitle{display:flex;align-items:center;gap:8px;font-size:11px;font-weight:700;letter-spacing:.06em;color:" + mute + "}",
					".dsa-auditBtns{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}",
					".dsa-auditBar{display:flex;align-items:center;gap:10px;flex-wrap:wrap}",
					".dsa-filterSelect{height:32px;padding:0 10px;border-radius:8px;font-size:12.5px;color:var(--dsw-alias-label-primary);background:" + fill + ";border:1px solid " + edge + "}",
					// 模型那一栏要撑满控件列，不然选项是宿主给的长名字，窄一条看着就像没填。
					".dsa-modelSelect{width:100%;min-width:250px;max-width:340px}",
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
					".dsa-pager{display:flex;align-items:center;justify-content:flex-end;gap:10px;padding-top:2px}",
					".dsa-pagerInfo{font-size:12px;color:" + mute + "}",
			].join("");
		}

		function settingsStylesheet() {
			const doc = globalThis.document;
			if (doc == null)
				return () => { };
			for (const existing of doc.querySelectorAll("style[data-plugin]")) {
				if (existing.getAttribute("data-plugin-css") === "dsh-auto-approval-frame/settings") existing.remove();
			}
			const style = doc.createElement("style");
			style.setAttribute("data-plugin", "dsh-auto-approval-frame");
			style.setAttribute("data-plugin-css", "dsh-auto-approval-frame/settings");
			style.textContent = settingsCss();
			doc.head?.appendChild(style);
			return () => style.remove();
		}

		function draftOf(value) {
			const draft = {};
			for (const field of FIELDS) {
				const raw = value?.[field.key];
				const fallback = DEFAULTS[field.key];
				if (field.type === "list" || field.type === "rules") draft[field.key] = Array.isArray(raw) ? [...raw] : (Array.isArray(fallback) ? [...fallback] : []);
				else if (field.type === "number") draft[field.key] = Number.isFinite(raw) ? raw : fallback;
				else if (field.type === "switch") draft[field.key] = raw === true;
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
					// 检测规则的两枚随行字段：preset＝它盖住哪条内置形状；enabled=false＝这行不表态。
					preset: String(source?.preset ?? ""),
					label: String(source?.label ?? ""),
					enabled: source?.enabled !== false,
				};
			const folded = ACTION_META[FOLD_ACTION[source?.action] ?? source?.action] !== undefined
				? (FOLD_ACTION[source?.action] ?? source.action) : "";
			const legacyOps = Array.isArray(source?.ops) ? source.ops : [];
			const covers = op => folded !== "" && (legacyOps.length === 0 || legacyOps.includes("all") || legacyOps.includes(op));
			const opAction = op => (ACTION_META[FOLD_ACTION[source?.[op]] ?? source?.[op]] !== undefined
				? (FOLD_ACTION[source?.[op]] ?? source[op]) : covers(op) ? folded : "");
			const ops = { read: opAction("read"), write: opAction("write"), delete: opAction("delete") };
			// 内置行的档位是**一条**（事实层只认这一条），不是读／写／删三格：
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
				// 内置行没有匹配式（命中由事实层给出），所以它**不能**被「空条件」这道闸丢掉，
				// 否则改一次档位就把整排内置行从配置里抹掉了。
				if (row.preset !== "") {
					const kept = {
						id: `builtin-${row.preset}`,
						preset: row.preset,
						label: row.label,
						enabled: row.enabled !== false,
						action: row.action,
					};
					// 检测规则的内容就是这一段正则：内置行同样可改，所以必须随行存回去。
					if (field.plane === "sensitive" && row.match !== "") kept.match = row.match;
					rows.push(kept);
					continue;
				}
				const match = row.match.trim();
				if (match === "" || blankRow(field.plane, row)) continue;
				if (field.plane === "file") {
					rows.push({ match, read: row.read, write: row.write, delete: row.delete });
					continue;
				}
				const out = { action: row.action, match };
				// 只有检测规则这张表带这三枚随行字段；其余平面写出去的形状一个字节都不变。
				// `id` 与宿主内置行同名（`builtin-<形状>`），台账里指认的是同一条。
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
				const same = field.type === "list" || field.type === "rules"
					? JSON.stringify(next) === JSON.stringify(base ?? [])
					: next === base;
				if (same) continue;
				ops.push({ op: "set", path: [field.key], value: next });
			}
			return ops;
		}

		// 四个平面同一套档位，没有第五档：命中就遮是敏感那一层自己在做的事，不是选项。
		const ACTION_DOT = { release: "dot-release", ai: "dot-ai", ask: "dot-ask", deny: "dot-deny" };
		const ACTION_CHOICES = [
			{ value: "deny", label: "拒绝" },
			{ value: "ask", label: "人工" },
			{ value: "ai", label: "AI" },
			{ value: "release", label: "允许" },
		];
		const choicesFor = () => ACTION_CHOICES;
		const OP_CHOICES = [
			{ value: "", label: "不表态" },
			...ACTION_CHOICES,
		];

		/**
		 * 一颗动作片 ＋ 它自己的下拉菜单。
		 * 不用原生 <select>（系统弹层比片子窄一圈、字也更小），也不再摊成一行按钮：
		 * 点片子就在片子正下方弹出一个浮层菜单，宽度不小于片子，选项按动作着色、当前项打勾。
		 */
		function ActionPill({ label, value, choices, disabled, title, open, onToggle, onPick }) {
		const tone = ACTION_DOT[value] ? value : "silent";
		const shown = (choices.find(item => item.value === (value ?? "")) ?? { label: "不表态" }).label;
		const inner = [
			label === null || label === undefined ? null : react.createElement("span", { key: "l", className: "dsa-pill-op" }, label),
			react.createElement("span", { key: "d", className: "dsa-dot dot-" + tone }),
			react.createElement("span", { key: "t", className: "dsa-pill-text" }, shown),
		];
		if (disabled === true || onPick === undefined)
			return react.createElement("span", { className: "dsa-pillCell" },
				react.createElement("span", { className: "dsa-pill t-" + tone + " is-disabled", title }, ...inner));
		return react.createElement("span", { className: "dsa-pillCell" },
			react.createElement("button", {
				type: "button", className: "dsa-pill t-" + tone + " is-picker", title,
				"aria-haspopup": "listbox", "aria-expanded": open === true, onClick: onToggle,
			}, ...inner, react.createElement("span", { className: "dsa-pill-caret", "aria-hidden": "true" }, open === true ? "▴" : "▾")),
			open === true ? react.createElement("span", { className: "dsa-menu", role: "listbox" },
				...choices.map(item => {
					const itemTone = ACTION_DOT[item.value] ? item.value : "silent";
					const current = item.value === (value ?? "");
					return react.createElement("button", {
						key: item.value || "silent", type: "button", role: "option", "aria-selected": current,
						className: "dsa-menuItem t-" + itemTone + (current ? " is-current" : ""),
						onClick: () => onPick(item.value),
					}, react.createElement("span", { className: "dsa-dot dot-" + itemTone }), item.label,
						current ? react.createElement("span", { className: "dsa-menuCheck" }, "✓") : null);
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
			return react.createElement("span", {
				className: "dsa-tile", "aria-hidden": "true",
				dangerouslySetInnerHTML: {
					__html: `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`,
				},
			});
		}

		/** 摘要列表：一行一个平面，点进去才是编辑页（不四表平铺）。 */
		function RuleSummary({ planes, counts, presets, onOpen }) {
			return react.createElement("div", { className: "dsa-summary" },
				...planes.map(plane => react.createElement("button", {
					key: plane.key,
					type: "button",
					className: "dsa-item dsa-summaryRow",
					onClick: () => onOpen(plane.plane),
				},
					react.createElement(PlaneIcon, { plane: plane.plane }),
					react.createElement("span", { className: "dsa-summaryText" },
						react.createElement("span", { className: "dsa-summaryTitle" }, plane.title),
						react.createElement("span", { className: "dsa-summaryDesc" }, plane.desc)),
					react.createElement("span", {
						className: "dsa-summaryCount" + (counts[plane.plane] > 0 ? " is-set" : ""),
					}, counts[plane.plane] > 0 ? `${counts[plane.plane]} 条` : "未设置"),
					// 没有内置项的概念就不画这枚片（敏感信息表是账，不是规则表）。
					presets[plane.plane] === undefined ? null : react.createElement("span", { className: "dsa-summaryPreset", title: "这张表里标着「内置」的行数：默认就在，能换档位、能停用" },
						`内置 ${presets[plane.plane] ?? 0}`),
					react.createElement("span", { className: "dsa-chevron" }, "›"))));
		}

		/** 明细页：表头 → 工具条（一行）→ 说明 → 自定义行 → 内置行（同表同形制，可改可停用），全部同一套列。 */
		function RuleDetail({ plane, rows, defaults, onDefaults, onChange, frame, onBack, embedded, disabled }) {
			const meta = PLANES[plane];
			const [pending, setPending] = react.useState("");
			// 展开的动作选择器：一屏只开一个，键＝「行:操作」或「defaults:操作」。
			const [open, setOpen] = react.useState("");
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
			// 检测规则这一张表＝「内置形状＋用户自己的行」。内置形状不是页面上另画的一排只读行：
			// 它们和用户的行同表同形制，改内容／换动作／停用都写回同一份 sensitiveRules
			// （`preset` 标出它盖住哪条内置）。读侧用宿主 `frame.rows`（同一份生效表），
			// 页面不再自己拼第二份内置清单。
			// 草稿是唯一的编辑真相：用户行＋已物化的内置行都取自草稿；
			// 宿主 `frame.rows` 只用来补出**还没被碰过**的内置行（内置清单只有一份，住在宿主）。
			const hostRows = Array.isArray(frame?.rows?.[plane]) ? frame.rows[plane] : [];
			const ownPresets = new Set(draftRows.filter(row => row.preset !== "").map(row => row.preset));
			const hostOnly = hostRows
				.filter(row => row.preset !== "" && !ownPresets.has(row.preset))
				.map(row => rowOf(row, plane));
			const list = [...draftRows, ...hostOnly];
			// 只写草稿：宿主那几条没被碰过的内置行留在宿主默认值里，
			// 不然点一下任何行都会把整排内置行抄进配置文件。
			const write = next => onChange(next);
			const patch = (index, changes) => {
				if (index < draftRows.length) {
					write(draftRaw.map((raw, at) => (at === index ? { ...draftRows[at], ...changes } : raw)));
					return;
				}
				const hostRow = hostOnly[index - draftRows.length];
				if (hostRow === undefined) return;
				write([...draftRaw, { ...hostRow, ...changes }]);
			};
			const ownIndexes = [];
			draftRaw.forEach((raw, at) => { if (rowOf(raw, plane).preset === "") ownIndexes.push(at); });
			const move = (index, delta) => {
				const pos = ownIndexes.indexOf(index);
				const target = pos < 0 ? undefined : ownIndexes[pos + delta];
				if (target === undefined) return;
				const next = [...draftRaw];
				[next[index], next[target]] = [next[target], next[index]];
				write(next);
			};
			const remove = index => {
				if (index >= draftRows.length || draftRows[index].preset !== "") return;
				write(draftRaw.filter((_, at) => at !== index));
			};
			const add = () => {
				const match = pending.trim();
				if (match === "") return;
				const row = plane === "file" ? { match, ...defaults.file } : { match, action: defaults.single };
				write([{ ...row }, ...draftRaw]);
				setPending("");
			};
			// 内置行的条件列：命令／文件／网络／工具面是说明文字（命中由事实层给），
			// 敏感面是真正可改的匹配式。覆盖行只带档位与开关，缺失的内容从宿主那同一行借回来。
			const noteOf = row => {
				if (row.preset === "") return row.match;
				if (row.match !== "") return row.match;
				const host = hostRows.find(item => item.preset === row.preset);
				return String(host?.match ?? "");
			};
			// 内置行只有一档（事实层给的理由不分读／写／删），所以文件面的内置行也只画一颗片。
			const opsOf = row => (plane === "file" && row.preset === "" ? ["read", "write", "delete"] : ["action"]);
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
			const pillFor = (row, op, index) => react.createElement(ActionPill, {
				key: op,
				label: op === "action" ? null : OP_LABEL[op],
				value: op === "action" ? row.action : row[op],
				choices: op === "action" ? choicesFor(plane) : OP_CHOICES,
				title: op === "action" ? (ACTION_META[row.action]?.note ?? "") : "不表态＝这一行不管这个操作",
				open: open === pillKey(index, op),
				onToggle: () => toggle(pillKey(index, op)),
				onPick: picked => choose(index, op, picked),
				disabled,
			});

			// 检测规则取的是**最严的一档**，不看先后，所以上下移没意义——按钮整排撤掉，
			// 免得让人以为排前面就优先。内置行同理：命中由事实层给，位置不参与判定，只能改档位／停用。
			// 启用开关是一颗**真按钮**（有边框、不换行）：上一版它是 26×26 的图标按钮里塞四个字，
			// 窄列里「启用中」直接竖着排成三行，还挨着 ✕，看着像布局坏了。
			const stepButtons = (row, index) => {
				const preset = row.preset !== "";
				const canToggle = plane === "sensitive" || preset;
				return react.createElement("span", { className: "dsa-sentBtns" },
					canToggle ? react.createElement("button", {
						type: "button", disabled,
						className: `dsa-stateBtn ${row.enabled === false ? "is-off" : ""}`,
						title: row.enabled === false
							? "这一条现在不算数，点它启用"
							: (plane === "sensitive" ? "让这一条先不表态（内置形状不能删，只能关）" : "让这一条不再拉高（内置行不能删，只能关）"),
						onClick: () => patch(index, { enabled: row.enabled === false }),
					}, row.enabled === false ? "已停用" : "启用中") : null,
					preset ? null : react.createElement("button", {
						type: "button", className: "dsa-iconBtn", title: "上移（更先命中）", disabled: disabled || index === ownIndexes[0],
						onClick: () => move(index, -1),
					}, "↑"),
					preset ? null : react.createElement("button", {
						type: "button", className: "dsa-iconBtn", title: "下移", disabled: disabled || index === ownIndexes[ownIndexes.length - 1],
						onClick: () => move(index, 1),
					}, "↓"),
					// 内置行没有「删」这个动作，就别画一颗灰着的 ✕——它只会看起来像坏了。
					preset ? null : react.createElement("button", {
						type: "button", className: "dsa-iconBtn is-danger",
						title: "删除这一行",
						disabled,
						onClick: () => remove(index),
					}, "✕"));
			};
			// 一句话规则行：读序＝语法序——「当 命令 匹配 X → 拒绝」。
			// 表格要靠列对齐才读得懂，句子不用；条件还能就地改，不必删了重加。
			// 行首编号＝命中优先级，是这张表唯一真正要紧的信息，得第一眼看见。
			const sentence = (row, index) => react.createElement("div", {
				key: index, className: `dsa-item dsa-sent tone-${rowTone(row)}${row.enabled === false ? " is-off" : ""}`,
			},
				react.createElement("b", { className: "dsa-ruleNo", title: `第 ${index + 1} 条：自上而下匹配，命中的第一条生效` }, index + 1),
				react.createElement("span", { className: "dsa-sentHead" },
					// 内置形状也走这一句形制，只在名字前面加一枚「内置」片——
					// 它们是表里的行，不是表外另一排只读说明。
					row.preset !== ""
						? react.createElement("span", { className: "dsa-sentTag" }, "内置") : null,
					react.createElement("span", { className: "dsa-sentLead" }, "当"),
					// 内置行的主语就是它自己的名字（「凭据文件名」），用户行的主语是平面名。
					react.createElement("b", { className: "dsa-sentNoun" }, row.label !== "" ? row.label : SENT_NOUN[plane]),
					// 内置行的条件列是说明文字，前面不再挂动词（「当 提权执行 匹配 sudo…」是假句子）。
					row.preset !== "" && plane !== "sensitive"
						? null
						: react.createElement("span", { className: "dsa-sentLead" }, plane === "sensitive" ? "命中" : "匹配")),
				react.createElement("span", { className: "dsa-blank" },
					plane === "sensitive" || row.preset === ""
						? react.createElement(Input, {
							value: noteOf(row), placeholder: meta.placeholder, disabled,
							onChange: event => patch(index, {
								match: typeof event === "string" ? event : String(event?.target?.value ?? ""),
							}),
						})
						// 内置行的条件是事实层给的说明，不是匹配式：改了字也改不了命中范围，
						// 所以这里只把它读出来，能改的是右边的档位和启用开关。
						: react.createElement("span", { className: "dsa-sentNote", title: "这串是说明：命中由事实层判定，能改的是档位和启用开关" },
							noteOf(row) === "" ? "—" : noteOf(row))),
				// 只留一个箭头：上一版这里写「时 →」/「时：」，是「当…时」句式的残尾，单看毫无意义。
				react.createElement("span", { className: "dsa-sentTail" }, "→"),
				react.createElement("span", { className: "dsa-sentOps" }, ...opsOf(row).map(op => pillFor(row, op, index))),
				stepButtons(row, index));
			const head = react.createElement("div", { className: "dsa-detailHead" },
				onBack === undefined ? null : react.createElement("button", {
					type: "button", className: "dsa-back", onClick: onBack,
				}, "‹ 返回"),
				react.createElement(PlaneIcon, { plane }),
				react.createElement("span", { className: "dsa-detailTitle" }, meta.title),
				react.createElement("span", { className: "dsa-detailCount" },
					plane === "sensitive"
						? `${list.length} 条 · 内置形状也在这一张表里，可改可停用；命中取最严的一档，不看先后`
						: `${list.length} 条 · 自上而下匹配，命中第一条后停止`));
			// 工具条合成一行：条件输入框（这页的主角，占满剩余宽度）→ 新行的默认动作 → 添加。
			// 上一版把「添加」「新规则默认」拆成两行细颗粒，和正文一样重，看不出哪句是给你动手的。
			const defaultKeys = plane === "file" ? ["read", "write", "delete"] : ["single"];
			const defaultPill = (key, label, value) => react.createElement(ActionPill, {
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

			const tool = react.createElement("div", { className: "dsa-item dsa-tool" },
				react.createElement("span", { className: "dsa-addWrap" },
					react.createElement(Input, {
						value: pending, placeholder: `新增一行：例如 ${meta.placeholder}`,
						onChange: event => setPending(typeof event === "string" ? event : String(event?.target?.value ?? "")),
					})),
				react.createElement("span", { className: "dsa-toolDefaults" },
					react.createElement("span", { className: "dsa-defaultsLabel" }, "新规则默认"),
					...(plane === "file"
						? defaultKeys.map(op => defaultPill(op, OP_LABEL[op], defaults.file[op]))
						: [defaultPill("single", null, defaults.single)])),
				react.createElement(Button, {
					variant: "ghost", size: "sm", disabled: disabled === true || pending.trim() === "", onClick: add,
				}, "＋ 添加"));
			// 一张明细页两块：**自定义**（你加的行，自上而下命中即停）与**内置**（判定链会拉高的
			// 那些理由）。两块同形制、同列，也**同样可改**——换档位、停用都在行上动，
			// 不再有一排带 🔒 的只读预设行（那是「另一套规则」的错觉来源）。
			const pairs = list.map((row, index) => [row, index]);
			const own = pairs.filter(([row]) => row.preset === "");
			const floor = pairs.filter(([row]) => row.preset !== "");
			const body = react.createElement("div", { className: "dsa-rules" },
				react.createElement("div", { key: "own", className: "dsa-groupTitle" },
					plane === "sensitive"
						? `自定义（${own.length}）· 命中取最严的一档，不看先后`
						: `自定义（${own.length}）· 自上而下匹配，命中第一条后停止`),
				...own.map(([row, index]) => sentence(row, index)),
				own.length === 0 ? react.createElement("div", { key: "empty", className: "dsa-emptyList" },
					"还没有自己的规则") : null,
				floor.length === 0 ? null : react.createElement("div", { key: "floor", className: "dsa-groupTitle" },
					plane === "sensitive"
						? `内置（${floor.length}）· 全部可改：改内容、换档位、停用都在这里`
						: `内置（${floor.length}）· 全部可改：换档位、停用都在这里，停用＝这一条不再拉高`),
				...floor.map(([row, index]) => sentence(row, index)));
			const warn = rejected.length === 0 ? null : react.createElement("div", { className: "dsa-warn" },
				`这些路径没被当成信任根：${rejected.map(item => `${item.dir}（${REJECTION_LABEL[item.reason] ?? item.reason}）`).join("；")}`);
			// 一行介绍就够：顺序语义已经在表头那条计数里，这里只讲匹配语法。
			const note = react.createElement("div", { className: "dsa-note" }, meta.tip);
			return react.createElement("div", { className: "dsa-detail" + (embedded ? " is-embedded" : "") },
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

		/**
		 * 试算：粘一条命令，看它在哪一步被定掉。
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
			return react.createElement("div", { className: "dsa-dry" },
				react.createElement("div", { className: "dsa-dryTop" },
					react.createElement("span", { className: "dsa-dryPrompt" }, "模拟审批"),
					react.createElement("span", { className: "dsa-dryHint" },
						"把要核的动作粘进来，宿主按当前配置走一遍判定链，逐步回它会怎么被处置。不调模型、不执行任何东西。")),
				react.createElement("div", { className: "dsa-dryBar" },
					react.createElement("span", { className: "dsa-dryInputWrap" },
						react.createElement(Input, {
							value: text, placeholder: "粘贴一条命令，或一个路径（按删除试）",
							onChange: event => setText(typeof event === "string" ? event : String(event?.target?.value ?? "")),
						})),
					react.createElement(Button, {
						variant: "ghost", size: "sm", disabled: busy || text.trim() === "", onClick: run,
					}, busy ? "模拟中…" : "模拟一下")),
				err === "" ? null : react.createElement("div", { className: "dsa-warn" }, `模拟审批失败：${err}`),
				out === null ? null
					: react.createElement("div", { className: "dsa-dryOut" },
						react.createElement("div", { className: "dsa-dryVerdict" },
							react.createElement("span", { className: "dsa-dryVerdictLabel" }, "结论"),
							react.createElement("span", null, out.verdict),
							out.asPath === true ? react.createElement("span", { className: "dsa-dryAs" }, "（按删除该路径试）") : null),
						react.createElement("div", { className: "dsa-dryAs" },
							`按宿主当前配置判定：你的规则共 ${out.ruleTotal ?? 0} 行（命令 ${out.rules?.command ?? 0}／文件 ${out.rules?.file ?? 0}／网络 ${out.rules?.network ?? 0}／工具 ${out.rules?.tool ?? 0}／敏感 ${out.rules?.sensitive ?? 0}）。刚存了行而这个数没动＝保存没落到宿主。`),
						// 模拟跑在宿主进程里，路径类判断按插件所在目录解析；不说清就会被当成「模拟和实际不一样」。
						typeof out.caveat === "string" && out.caveat !== ""
							? react.createElement("div", { className: "dsa-dryAs" }, out.caveat) : null,
						react.createElement("ol", { className: "dsa-drySteps" },
							...(out.steps ?? []).map(step => react.createElement("li", {
								key: step.step, className: `dsa-dryStep ${STATE_TONE[step.state] ?? "t-silent"}`,
							},
								react.createElement("span", { className: "dsa-dryStepNo" }, step.step),
								react.createElement("span", { className: "dsa-dryStepName" }, step.name),
								react.createElement("span", { className: "dsa-dryStepState" }, STATE_LABEL[step.state] ?? step.state),
								react.createElement("span", { className: "dsa-dryStepWhy" }, step.why))))),
			);
		}

		function Ladder({ onJump }) {
			return react.createElement("div", { className: "dsa-ladder", "aria-label": "判定链" },
				...LADDER.map(item => react.createElement("button", {
					key: `${item.step}-${item.name}`,
					type: "button",
					className: "dsa-step",
					title: `${item.name}：${item.who}${item.configurable ? "（可配）" : "（固定）"}`,
					onClick: () => onJump?.(item.card),
				},
					react.createElement("span", { className: "dsa-stepNo" }, item.step),
					react.createElement("span", { className: "dsa-stepName" }, item.name),
					react.createElement("span", { className: item.configurable ? "dsa-stepTag is-on" : "dsa-stepTag" }, item.configurable ? "可配" : "固定"))));
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
				return react.createElement(Switch, { checked: value === true, disabled, label: "", onChange });
			}
			if (field.type === "segmented") {
				return react.createElement(SegmentedControl, { id: `frame-${field.key}`, value, options: field.options, label: "", disabled, onChange });
			}
			if (field.type === "rules") {
				return react.createElement(RuleDetail, {
					plane: field.plane, rows: value, embedded: true,
					defaults: { single: "ask", file: { read: "ask", write: "ask", delete: "ask" } },
					onDefaults: () => { }, onChange, disabled,
				});
			}
			if (field.type === "list") {
				return react.createElement("textarea", {
					className: "dsa-list", value: value.join("\n"), disabled, placeholder: "每行一个",
					onChange: event => onChange(event.target.value.split("\n").map(line => line.trim()).filter(line => line !== "")),
				});
			}
			return react.createElement(Input, {
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
			return react.createElement("div", { className: "dsa-item dsa-field" + (wide ? " is-wide" : "") + (disabled ? " is-disabled" : "") },
				react.createElement("div", { className: "dsa-fieldText" },
					react.createElement("span", { className: "dsa-fieldLabel" }, meta.label),
					meta.hint ? react.createElement("span", { className: "dsa-fieldHint" }, meta.hint) : null),
				react.createElement("div", { className: "dsa-fieldControl" },
					react.createElement(Control, { field: meta, value, disabled, onChange })));
		}

		/**
		 * 评审模型＝一对键（reviewerProvider ＋ reviewerModel）合起来的一行选择。
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
			return react.createElement("div", { className: "dsa-item dsa-field" + (disabled ? " is-disabled" : "") },
				react.createElement("div", { className: "dsa-fieldText" },
					react.createElement("span", { className: "dsa-fieldLabel" }, "评审模型"),
					react.createElement("span", { className: "dsa-fieldHint" }, hint)),
				react.createElement("div", { className: "dsa-fieldControl" },
					react.createElement("select", {
						className: "dsa-filterSelect dsa-modelSelect", value: chosen, disabled: disabled || state.status !== "ready" || state.groups.length === 0,
						onChange: event => {
							const [nextProvider, nextModel] = String(event.target.value).split("\u0000");
							onPick(nextProvider, nextModel);
						},
					},
						state.groups.flatMap(group => [
							react.createElement("optgroup", { key: `g-${group.id}`, label: group.name },
								...group.models.map(item => react.createElement("option", {
									key: `${group.id}/${item.id}`, value: `${group.id}\u0000${item.id}`,
								}, item.name))),
						]))));
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
			const signature = JSON.stringify(stored);
			react.useEffect(() => {
				if (!busy) setDraft(draftOf(JSON.parse(signature)));
			}, [signature, busy]);
			const [filters, setFilters] = react.useState({ range: "7d", decision: "", category: "", q: "", offset: 0, hideBoot: true });
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
					return true;
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
			const ops = usable ? opsFrom(draft, stored) : [];
			const set = (key, value) => setDraft(current => ({ ...current, [key]: value }));
			const [frame, setFrame] = react.useState({ status: "idle", rows: {}, trusted: [], dshOpen: [], rejected: [] });
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
					await form.mutate(ops);
					setMessage(`已保存 ${ops.length} 项`);
					setFrameTick(tick => tick + 1);
				}
				catch (cause) {
					setError(String(cause?.message ?? cause));
				}
				finally {
					setBusy(false);
				}
			};
			return react.createElement("div", { className: "dsa-page" },
				react.createElement("div", { className: "dsa-pageHead" },
					react.createElement("div", { className: "dsa-pageTitle" }, "自动审批框架"),
					react.createElement("div", { className: "dsa-pageDesc" },
						"本页只配 DSH 的「自动审批」这一档。一次调用依次经过下面几步：前一步没给出结论，才轮到下一步。点一格跳到对应卡片。"),
					react.createElement(Ladder, { onJump: jump }),
					react.createElement(DryRun)),
				usable ? null : react.createElement("div", { className: "dsa-notice" },
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
							? react.createElement(RuleDetail, {
								plane: planeView,
								rows: draft[RULE_KEY_OF[planeView]],
								defaults,
								onDefaults: setDefaults,
								frame,
								disabled: !usable || busy,
								onChange: value => set(RULE_KEY_OF[planeView], value),
								onBack: () => setPlaneView(null),
							})
							: react.createElement(RuleSummary, {
								planes: RULE_KEYS.map(item => ({ ...PLANES[item.plane], key: item.key, plane: item.plane })),
								counts,
								presets: Object.fromEntries(RULE_KEYS.map(item => [
									item.plane, (frame.rows?.[item.plane] ?? []).filter(item2 => item2.preset !== "").length,
								])),
								onOpen: setPlaneView,
							}))
						: react.createElement("div", { className: "dsa-body" },
							...shown.map((field, index) => {
								const marked = { ...field, __index: index, __count: shown.length };
								if (field.type === "modelPicker")
									return react.createElement(ModelPickerRow, {
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
								return react.createElement(FieldRow, {
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
								? react.createElement("div", { className: "dsa-readonly" },
									`没读到宿主配好的模型（${models.error || models.note || "宿主未提供该接口"}），请手填下面两项。`)
								: null,
							section.id === "preset" && Array.isArray(frame.missingGatedPresets) && frame.missingGatedPresets.length > 0
								? react.createElement("div", { className: "dsa-notice" },
									`受管权限档 ${frame.missingGatedPresets.join("、")} 不在宿主当前权限表里：本插件不会接管任何会话。把下面这段加进你 profile 的 permission.presets（保留已有档），或把 gatedPresets 改成宿主已有的档，重启后生效。`,
									react.createElement("pre", { className: "dsa-noticeCode" },
										`- id: permission\n  config:\n    presets:\n${frame.missingGatedPresets
											.map(name => `      ${name}:\n        sandbox: danger-full-access\n        approval: ask`)
											.join("\n")}`))
								: null,
							section.id === "preset" ? react.createElement("div", { className: "dsa-readonly" },
								`只读（走 profile 补丁改）：${HOST_ONLY_KEYS
									.map(key => `${HOST_ONLY_LABELS[key] ?? key}＝${JSON.stringify(frame[key] ?? stored[key] ?? state?.value?.[key] ?? null)}`)
									.join("　")}；会话里的档位名由本插件显示为「自动审批」`) : null,
							section.id !== "sensitive" ? null
							: planeView === "sensitive"
								? react.createElement(RuleDetail, {
									plane: "sensitive",
									rows: draft.sensitiveRules,
									defaults,
									onDefaults: setDefaults,
									frame,
									embedded: true,
									disabled: !usable || busy,
									onChange: value => set("sensitiveRules", value),
									onBack: () => setPlaneView(null),
								})
								: planeView === "secrets"
									? react.createElement(SecretVault, {
										key: "secrets-vault",
										secrets,
										onReveal: revealSecret,
										onHide: token => setSecrets(current => {
											const revealed = { ...current.revealed };
											delete revealed[token];
											return { ...current, revealed };
										}),
										onRestore: (token, restore) => postSecrets({ token, restore }),
										onRemove: token => postSecrets({ token, remove: true }),
										onClear: async () => {
											await postSecrets({ clear: true });
											setConfirmClearSecrets(false);
										},
										confirmClear: confirmClearSecrets,
										onConfirmClear: setConfirmClearSecrets,
										onBack: () => setPlaneView(null),
									})
									: react.createElement(RuleSummary, {
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
										presets: { sensitive: (frame?.rows?.sensitive ?? []).filter(item => item.preset !== "").length },
										onOpen: setPlaneView,
									}),
							advanced.length === 0 ? null : react.createElement("button", {
								type: "button", className: "dsa-advBtn",
								onClick: () => setOpenAdvanced(current => ({ ...current, [section.id]: !(current[section.id] === true) })),
							}, expanded ? `▲ 收起高级项（${advanced.length} 项）` : `▼ 高级（${advanced.length} 项）`));
					return react.createElement("div", {
						key: section.id, id: `frame-card-${section.id}`, className: "dsa-card",
					},
						react.createElement("div", { className: "dsa-cardHead" },
							react.createElement("span", { className: "dsa-cardBar" }),
							react.createElement("span", { className: "dsa-cardTitle" }, section.title),
							steps.length > 0 ? react.createElement("span", { className: "dsa-cardBadge" }, `链上第 ${steps.join("／")} 步`) : null,
							// 卡头右侧＝这张卡的总闸，不为它单开一行
							headField === undefined ? null : react.createElement("span", { className: "dsa-cardSwitch" },
								react.createElement("span", { className: "dsa-cardSwitchLabel", title: headField.hint }, headField.label),
								react.createElement(Switch, {
									id: `frame-card-switch-${headField.key}`,
									checked: draft[headField.key] === true, label: "", disabled: !usable || busy,
									onChange: value => set(headField.key, value),
								})),
						),
						react.createElement("div", { className: "dsa-cardDesc" }, section.desc),
						body,
						section.id === "audit" ? react.createElement(AuditCenter, {
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
						}) : null);
				}),
				react.createElement("div", { className: "dsa-footer" + (ops.length > 0 ? " is-dirty" : "") },
					error ? react.createElement("span", { className: "dsa-error" }, error)
						: message ? react.createElement("span", { className: "dsa-ok" }, message)
							: react.createElement("span", { className: "dsa-status" },
								ops.length > 0 ? `${ops.length} 项待保存` : "没有改动"),
					react.createElement(Button, {
						variant: "ghost", size: "sm", disabled: ops.length === 0 || busy, onClick: () => setDraft(draftOf(stored)),
					}, "撤销"),
					react.createElement(Button, {
						variant: "primary", size: "sm", disabled: !usable || busy || ops.length === 0, onClick: save,
					}, busy ? "保存中…" : `保存${ops.length > 0 ? `（${ops.length}）` : ""}`)));
		}

		function apply(ctx) {
			ctx.slots.inject("plugins.row.config", () => ctx.slots.register({
				name: "plugins.row.config",
				key: ROW_CONFIG_KEY,
				locale: LOCALE_NS,
			}, ConfigPage));
			ctx.effect(() => installAutoPermissionIcon(globalThis.document), "dsh-auto-approval-frame: preset label, glyph and risk gate");
		}

		exports.apply = apply;
		exports.inject = inject;
		exports.name = name;
		return module.exports;
	},
});
