// 宿主原生工具效果表（人工审阅，75 条＝tool-catalog.js 的全部模型可见名字）。
//
// 为什么要这张表：工具面旧形只登记了少数名字，其余都落 `unclassified-tool`，连
// `read_image` 这种纯读也被当成“认不出操作类型”。表把每个原生工具的效果显式写下来：
//   read     = 把本机/远端内容取回，可按 paths/urls 落在文件面/网络面；
//   write    = 写文件，paths 是落点，body 是送出去的内容；
//   delete   = 删文件；
//   internal = 不碰文件、不出网，只改会话/宿主状态（release 的「会话内部工具」）；
//   other    = 危险、语义随参数变、或读的是共享/敏感面——**不**登记成适配器，交 AI 判。
//
// 未列进 `TOOL_ADAPTERS` 的 other 仍会走“认不出操作类型”那一行；这不是漏，而是明确
// 不把危险工具自动放行。宿主新增工具时，重跑 gen-tool-catalog.mjs 并补这里；漏一条
// `test/unit/tool-catalog.test.mjs` 会红，不会静默当成安全工具。
//
// 路径/正文/URL 键名以 catalog 的 JSON Schema 为准；`path`/`notebook_path`/`cwd`/
// `replacement`/`query`/`args` 是旧调用面的别名，保留以不破坏既有客户端。
export const TOOL_EFFECTS = {
    // ── 读：只取回内容 ─────────────────────────────────────────────────────
    read: { op: 'read', paths: ['file_path', 'path', 'notebook_path'] },
    // 原生读图：把 file_path 指向的图片读进上下文，不写文件、不出网。不在册会落
    // `unclassified-tool`，每次调用都被当成“认不出操作类型”交模型。
    read_image: { op: 'read', paths: ['file_path', 'path'] },
    glob: { op: 'read', paths: ['path', 'cwd'] },
    grep: { op: 'read', paths: ['path'] },
    // 取网页／搜网页都是取回本地，没有载荷离开本机。旧形没登记 ⇒ 参数里的网址被当成
    // 目的地，方向缺省按 remote 算，一次公开页面的 GET 被读成「往外发东西」。
    web_fetch: { op: 'read', urls: ['url'] },
    // `query` 是旧形，catalog 现在叫 `queries`；两个都收，别让搜索词里的域名漏网。
    web_search: { op: 'read', urls: ['query', 'queries'] },

    // ── 写：落盘/改文件 ────────────────────────────────────────────────────
    write: { op: 'write', paths: ['file_path', 'path'], body: ['content'] },
    edit: { op: 'write', paths: ['file_path', 'path'], body: ['new_string', 'replacement'] },

    // ── 内部：不碰文件、不出网，只动会话/宿主状态 ─────────────────────────
    ask_user_question: { op: 'internal', body: ['questions'] },
    get_goal: { op: 'internal' },
    // job_output 只读后台任务输出；job_kill 经归属隔离取消执行者自己起的 job，
    // 两者都不碰用户文件、不出网。边界如实记：读出的内容直接进上下文，结果侧敏感扫描仍在。
    job_kill: { op: 'internal' },
    job_list: { op: 'internal' },
    job_output: { op: 'internal' },
    list_agents: { op: 'internal' },
    list_subagent_models: { op: 'internal' },
    schedule_list: { op: 'internal' },
    schedule_view: { op: 'internal' },
    // 技能调用只把本机技能文档装进上下文；不写文件、不出网。登记成 read 会因无路径可举证
    // 落 unproven-read 白过 AI，所以归 internal。
    skill: { op: 'internal', body: ['args'] },
    team_task_get: { op: 'internal' },
    team_task_list: { op: 'internal' },
    terminal_list: { op: 'internal' },
    todo_write: { op: 'internal' },
    wait_agent: { op: 'internal' },

    // ── other：不登记适配器，交 AI；理由逐条写清 ──────────────────────────
    apply_patch: { op: 'other', why: '补丁正文里的路径要先解析，不能按普通参数读' },
    bash: { op: 'other', why: 'shell 工具由命令面拆段判，不走工具适配器' },
    cordis_inspect_list: { op: 'other', why: '运行时内省，可能暴露宿主/插件配置' },
    cordis_inspect_query: { op: 'other', why: '运行时内省，可能暴露宿主/插件配置' },
    create_goal: { op: 'other', why: '目标状态属于人管，先过 AI' },
    create_worktree: { op: 'other', why: '建分支/检出会改仓库与工作目录' },
    exit_plan_mode: { op: 'other', why: '计划审批是人的决定，先过 AI' },
    interrupt_agent: { op: 'other', why: '改别的代理的执行状态，不是本会话内部' },
    list_mcp_resource_templates: { op: 'other', why: 'MCP 资源语义由服务定，可能远程' },
    list_mcp_resources: { op: 'other', why: 'MCP 资源语义由服务定，可能远程' },
    load_workspace_dependencies: { op: 'other', why: '加载依赖会执行包/构建脚本' },
    lsp: { op: 'other', why: '语言服务器会读文件并起子进程' },
    office_convert: { op: 'other', why: '读写 Office 输入并落临时转换文件' },
    office_recalculate: { op: 'other', why: '重算并写出 Office 结果' },
    office_render: { op: 'other', why: '渲染输入文件，输出图片附件' },
    plugin_manager: { op: 'other', why: '安装/启用插件会执行构建脚本' },
    plugin_market: { op: 'other', why: '市场索引/远程数据，不是本地文件读' },
    present: { op: 'other', why: 'files 是嵌套对象，路径不能按顶层键取' },
    propose_action: { op: 'other', why: '会给用户递动作卡，先过 AI' },
    pwsh: { op: 'other', why: 'shell 工具由命令面拆段判，不走工具适配器' },
    ralph: { op: 'other', why: '固定工作流会派生执行轮次' },
    read_mcp_resource: { op: 'other', why: 'MCP 资源可能是远端/敏感数据' },
    run_code: { op: 'other', why: '执行程序，效果由代码决定' },
    schedule_create: { op: 'other', why: '写宿主计划，未来会自动执行' },
    schedule_edit: { op: 'other', why: '改宿主计划，未来会自动执行' },
    send_message: { op: 'other', why: '给别的代理发消息，可能触发动作' },
    session_event_read: { op: 'other', why: '会话历史可能含敏感内容' },
    session_event_search: { op: 'other', why: '会话历史可能含敏感内容' },
    session_event_trace: { op: 'other', why: '会话历史可能含敏感内容' },
    session_search: { op: 'other', why: '会话历史可能含敏感内容' },
    session_trace: { op: 'other', why: '会话历史可能含敏感内容' },
    stagehand_act: { op: 'other', why: '浏览器自动化，可能读写远端页面' },
    stagehand_extract: { op: 'other', why: '浏览器取数，可能访问远端页面' },
    stagehand_navigate: { op: 'other', why: '浏览器导航，明确出网' },
    stagehand_observe: { op: 'other', why: '浏览器取数，可能访问远端页面' },
    stagehand_screenshot: { op: 'other', why: '浏览器取图，可能访问远端页面' },
    stagehand_tabs: { op: 'other', why: '浏览器标签页控制，可能访问远端页面' },
    str_replace_editor: { op: 'other', why: '同一工具含 view/create/edit，效果随 command 变' },
    subagent: { op: 'other', why: '派生代理可执行任意后续工具' },
    subagent_oar: { op: 'other', why: '派生外部代理可执行任意后续动作' },
    team_task_create: { op: 'other', why: '写共享任务板，会派生别人的动作' },
    team_task_update: { op: 'other', why: '改共享任务板，会派生别人的动作' },
    terminal_close: { op: 'other', why: '关终端会中止正在跑的命令' },
    terminal_open: { op: 'other', why: '开终端后可执行任意命令' },
    terminal_read: { op: 'other', why: '终端输出可能含敏感内容' },
    terminal_send: { op: 'other', why: '往终端送文本等于执行命令' },
    terminal_signal: { op: 'other', why: '给终端进程发信号，效果随信号变' },
    update_goal: { op: 'other', why: '目标状态属于人管，先过 AI' },
    user_terminal_list: { op: 'other', why: '用户终端面，先过 AI' },
    user_terminal_read: { op: 'other', why: '用户终端输出可能含敏感内容' },
    workflow: { op: 'other', why: '工作流脚本会派生执行' },
    working_directory: { op: 'other', why: '改会话工作目录会影响后续相对路径' },
};
