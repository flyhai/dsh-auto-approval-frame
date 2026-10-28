// Renders the client bundle against a small fake DOM so the settings page and the
// session-UI decoration (label, glyph, risk gate) are verified offline instead of
// on the operator's next restart.
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { LAYER_TEXT } from '../lib/frame/audit.js';
import { ACTION_WORDS, RULE_PLANES, effectiveRows } from '../lib/frame/policy.js';

// ── fake DOM ────────────────────────────────────────────────────────────────
const parseSelector = (selector) => String(selector).split(',').map(part => {
    const out = { tag: null, classes: [], attrs: [] };
    for (const token of part.trim().matchAll(/(^[a-zA-Z][\w-]*)|(\.([\w-]+))|\[(?:([\w-]+)(?:([~^]?=)"([^"]*)")?)?\]/g)) {
        if (token[1]) out.tag = token[1].toLowerCase();
        else if (token[3]) out.classes.push(token[3]);
        else if (token[4]) out.attrs.push({ name: token[4], op: token[5] ?? null, value: token[6] ?? null });
    }
    return out;
});
const matchPart = (node, part) => {
    if (node.nodeType !== 1) return false;
    if (part.tag != null && node.tagName.toLowerCase() !== part.tag) return false;
    for (const className of part.classes) if (!node.classes.has(className)) return false;
    for (const attr of part.attrs) {
        if (!node.hasAttribute(attr.name)) return false;
        if (attr.op === null) continue;
        const value = node.getAttribute(attr.name);
        if (attr.op === '=' && value !== attr.value) return false;
        if (attr.op === '^=' && !value.startsWith(attr.value)) return false;
    }
    return true;
};
class FakeNode {
    constructor(tag, attrs = {}) {
        this.nodeType = 1;
        this.tagName = String(tag).toUpperCase();
        this.attributes = new Map(Object.entries(attrs).map(([key, value]) => [key, String(value)]));
        this.childNodes = [];
        this.parent = null;
        this.handlers = new Map();
        this.classes = new Set(String(attrs.class ?? '').split(/\s+/).filter(Boolean));
        this.rawHtml = '';
    }
    get children() { return this.childNodes.filter(node => node.nodeType === 1); }
    get firstChild() { return this.childNodes[0] ?? null; }
    get parentElement() { return this.parent != null && this.parent.nodeType === 1 ? this.parent : null; }
    get firstElementChild() { return this.children[0] ?? null; }
    get isConnected() { let node = this; while (node.parent != null) node = node.parent; return node === document.body || node === document.head; }
    get classList() { return { contains: name => this.classes.has(name) }; }
    get className() { return [...this.classes].join(' '); }
    set className(value) {
        this.classes = new Set(String(value).split(/\s+/).filter(Boolean));
        this.attributes.set('class', String(value));
    }
    get textContent() {
        const own = this.childNodes.filter(node => node.nodeType === 3).map(node => node.data).join('');
        return own !== '' || this.children.length === 0 ? own : this.children.map(child => child.textContent).join('');
    }
    set textContent(value) { this.childNodes = [{ nodeType: 3, data: String(value), parent: this }]; }
    get innerHTML() { return this.rawHtml; }
    set innerHTML(value) {
        this.rawHtml = String(value);
        // Enough structure for the code under test: an <svg> in the markup is a real child.
        this.childNodes = /<svg[\s>]/.test(this.rawHtml) ? [new FakeNode('svg')] : [];
    }
    append(...nodes) { nodes.forEach(node => this.appendChild(node)); }
    appendChild(node) { node.parent = this; this.childNodes.push(node); return node; }
    insertBefore(node, reference) {
        node.parent = this;
        const index = reference == null ? -1 : this.childNodes.indexOf(reference);
        if (index < 0) this.childNodes.push(node);
        else this.childNodes.splice(index, 0, node);
        return node;
    }
    replaceChild(next, previous) {
        const index = this.childNodes.indexOf(previous);
        if (index < 0) throw new Error('replaceChild: 节点不在父节点下');
        next.parent = this;
        this.childNodes[index] = next;
        return previous;
    }
    remove() {
        if (this.parent == null) return;
        this.parent.childNodes = this.parent.childNodes.filter(node => node !== this);
        this.parent = null;
    }
    getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
    setAttribute(name, value) {
        this.attributes.set(name, String(value));
        if (name === 'class') this.classes = new Set(String(value).split(/\s+/).filter(Boolean));
    }
    removeAttribute(name) { this.attributes.delete(name); }
    hasAttribute(name) { return this.attributes.has(name); }
    get dataset() {
        const self = this;
        const dash = key => String(key).replace(/[A-Z]/g, mark => `-${mark.toLowerCase()}`);
        return new Proxy({}, {
            get: (_, key) => self.getAttribute(`data-${dash(key)}`),
            set: (_, key, value) => { self.setAttribute(`data-${dash(key)}`, value); return true; },
        });
    }
    matches(selector) { return parseSelector(selector).some(part => matchPart(this, part)); }
    closest(selector) {
        for (let node = this; node != null; node = node.parent) if (node.nodeType === 1 && node.matches(selector)) return node;
        return null;
    }
    descendants() {
        const out = [];
        const walk = (node) => { for (const child of node.childNodes) if (child.nodeType === 1) { out.push(child); walk(child); } };
        walk(this);
        return out;
    }
    querySelectorAll(selector) { return this.descendants().filter(node => node.matches(selector)); }
    querySelector(selector) { return this.querySelectorAll(selector)[0] ?? null; }
    addEventListener(type, handler) {
        if (!this.handlers.has(type)) this.handlers.set(type, []);
        this.handlers.get(type).push(handler);
    }
    removeEventListener(type, handler) { this.handlers.set(type, (this.handlers.get(type) ?? []).filter(item => item !== handler)); }
    click() { dispatchClick(this); }
    dispatchChange(checked) {
        this.checked = checked;
        for (const handler of this.handlers.get('change') ?? []) handler({ target: this });
    }
}
const docListeners = [];
const document = {
    documentElement: { lang: 'zh-CN' },
    head: new FakeNode('head'),
    body: new FakeNode('body'),
    defaultView: { navigator: { language: 'zh-CN' } },
    createElement: tag => new FakeNode(tag),
    addEventListener: (type, handler, capture) => docListeners.push({ type, handler, capture: capture === true }),
    removeEventListener: (type, handler) => {
        const index = docListeners.findIndex(entry => entry.type === type && entry.handler === handler);
        if (index >= 0) docListeners.splice(index, 1);
    },
};
function dispatchClick(target) {
    let stopped = false;
    const event = {
        target,
        preventDefault() { },
        stopPropagation() { stopped = true; },
        stopImmediatePropagation() { stopped = true; },
    };
    for (const entry of docListeners.filter(item => item.type === 'click' && item.capture)) {
        entry.handler(event);
        if (stopped) return;
    }
    for (let node = target; node != null; node = node.parent) {
        for (const handler of node.handlers?.get('click') ?? []) handler(event);
        if (stopped) return;
    }
}

// ── fake React ──────────────────────────────────────────────────────────────
// 每个组件实例要有自己的 hook 槽位：页面里嵌了子组件（规则明细、审计中心），
// 共用一条 hooks 数组会让子组件读到父组件第 0 号状态（一个对象），
// 于是 useState('') 拿到对象、`.trim()` 当场炸。按「父路径/组件名#序号」分槽。
let hooks = [];
let cursor = 0;
const hookStore = new Map();
let pathStack = [];
let siblingCounters = new Map();
const reactEffects = [];
const react = {
    createElement(type, props, ...children) {
        const flat = children.flat(Infinity).filter(child => child !== null && child !== undefined && child !== false);
        if (typeof type !== 'function')
            return { type, props: props ?? {}, children: flat };
        if (pathStack.length === 0) siblingCounters = new Map();
        const parent = pathStack.join('/');
        const name = type.name || 'anon';
        const counterKey = `${parent}|${name}`;
        const nth = (siblingCounters.get(counterKey) ?? 0) + 1;
        siblingCounters.set(counterKey, nth);
        const path = `${parent}/${name}#${nth}`;
        const outerHooks = hooks;
        const outerCursor = cursor;
        if (!hookStore.has(path)) hookStore.set(path, []);
        hooks = hookStore.get(path);
        cursor = 0;
        pathStack.push(path);
        try {
            return type({ ...props, children: flat });
        }
        finally {
            pathStack.pop();
            hooks = outerHooks;
            cursor = outerCursor;
        }
    },
    useState(initial) {
        const store = hooks;
        const index = cursor++;
        if (store.length <= index) store[index] = typeof initial === 'function' ? initial() : initial;
        // setter 必须绑住自己组件实例的那条数组：`hooks` 是模块级变量，
        // 渲染结束时它指向最后渲染的子组件，点击时才写就会写别人的槽位。
        return [store[index], next => { store[index] = typeof next === 'function' ? next(store[index]) : next; }];
    },
    // effect 也要按实例槽位记 deps 与清理函数：React 在依赖变化时会**先跑上一次的清理**再重跑。
    // 少了这一步，「effect 自己改状态 → 重跑 → 清理把在途请求丢掉」这类 bug 在这里根本测不出来
    // （模型下拉永远停在「正在读取」就是这么漏过去的）。
    useEffect(effect, deps) {
        const store = hooks;
        const index = cursor++;
        const slot = store[index] ?? (store[index] = { deps: undefined, cleanup: null, ran: false });
        const changed = slot.ran !== true || deps === undefined
            || deps.some((value, at) => value !== slot.deps?.[at]);
        if (changed === true) reactEffects.push({ slot, effect, deps });
    },
};
const resetHooks = () => { hooks = []; cursor = 0; hookStore.clear(); pathStack = []; siblingCounters = new Map(); };
// 跑完一轮 effect：先按 React 的语义清掉上一轮的清理函数，再执行新的一轮。
const flushEffects = () => {
    for (const item of reactEffects.splice(0)) {
        if (typeof item === 'function') { item(); continue; }
        const { slot, effect, deps } = item;
        if (typeof slot.cleanup === 'function') slot.cleanup();
        slot.ran = true;
        slot.deps = deps;
        slot.cleanup = effect() ?? null;
    }
};
const textOf = node => {
    if (node == null || node === false) return '';
    if (typeof node === 'string' || typeof node === 'number') return String(node);
    if (Array.isArray(node)) return node.map(textOf).join(' ');
    if (typeof node === 'object' && 'props' in node) {
        const props = node.props ?? {};
        const nested = props.children === undefined ? [] : (Array.isArray(props.children) ? props.children : [props.children]);
        return `${(node.children ?? []).map(textOf).join(' ')} ${nested.map(textOf).join(' ')} ${props.label ?? ''} ${(props.options ?? []).map(item => item.label).join(' ')} ${props.value ?? ''}`;
    }
    return '';
};
const walkTree = (node, visit) => {
    if (node == null || typeof node !== 'object') return;
    if (Array.isArray(node)) return node.forEach(item => walkTree(item, visit));
    visit(node);
    walkTree(node.children, visit);
};
const findIn = (node, predicate) => { const out = []; walkTree(node, item => { if (predicate(item)) out.push(item); }); return out; };

// The code under test reaches for globalThis.document / globalThis.MutationObserver
// exactly as it would in the browser, so the stubs go on the global object.
document.querySelectorAll = selector => [document.head, document.body].flatMap(node => node.querySelectorAll(selector));
document.querySelector = selector => document.querySelectorAll(selector)[0] ?? null;
globalThis.document = document;
const observers = [];
const frames = [];
globalThis.MutationObserver = class {
    constructor(callback) { this.callback = callback; }
    observe(target) { observers.push({ target, callback: this.callback }); }
    disconnect() { this.dead = true; }
};
globalThis.requestAnimationFrame = callback => frames.push(callback);
const windowScope = { __ModuleLoader__: { load: definition => { windowScope.definition = definition; } } };
const clientSource = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'lib', 'client.js'), 'utf8');
new Function('window', 'document', 'MutationObserver', 'requestAnimationFrame', 'navigator',
    clientSource)(
    windowScope, document, globalThis.MutationObserver, globalThis.requestAnimationFrame, globalThis.navigator,
);
const loadedIds = [];
const loader = id => {
    loadedIds.push(id);
    if (id === 'react') return react;
    if (id === '@deepseek-ai/dsh-client-ui-primitives') return {
        Switch: props => ({ type: 'Switch', props, children: [] }),
        SegmentedControl: props => ({ type: 'SegmentedControl', props, children: [] }),
        Input: props => ({ type: 'Input', props, children: [] }),
        Button: props => ({ type: 'Button', props, children: [] }),
    };
    throw new Error(`客户端半请求了预期外模块：${id}`);
};
const bundle = windowScope.definition.factory(loader);
assert.equal(windowScope.definition.id, 'dsh-auto-approval-frame');
assert.deepEqual(loadedIds, ['react', '@deepseek-ai/dsh-client-ui-primitives'], '客户端半只该依赖 react 与宿主原语');
assert.deepEqual(bundle.inject, ['slots', 'locale', 'configForms']);
console.log('OK 客户端半形状：包络 id、模块依赖、服务需求全部符合契约');

const registered = [];
const ctxEffects = [];
bundle.apply({
    slots: { inject: (slot, build) => registered.push({ slot, contribution: build() }), register: (meta, component) => ({ meta, component }) },
    effect: (fn, label) => ctxEffects.push({ fn, label }),
});
assert.equal(registered[0].slot, 'plugins.row.config');
assert.equal(registered[0].contribution.meta.key, 'dsh-auto-approval-frame#auto-approval-frame', '行 key 必须等于宿主 rowConfigKey(bundle,rowId)');
assert.equal(registered[0].contribution.meta.locale, 'dsh-auto-approval-frame');

// 设置列表里「自动审批框架」那一行的图标由宿主从包元数据读：package.json 的 `icon`
// 必须是包内的 SVG/PNG/JPEG/WebP（≤256 KiB）。少了这一行，那一行就是空图标位。
{
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    assert.ok(typeof pkg.icon === 'string' && pkg.icon !== '', 'package.json 要声明 icon（否则插件行没有图标）');
    const iconPath = join(dirname(pkgPath), pkg.icon);
    assert.ok(existsSync(iconPath), `icon 文件要在包内且存在：${pkg.icon}`);
    assert.ok(readFileSync(iconPath, 'utf8').trimStart().startsWith('<svg'), 'icon 要是 SVG');
}
console.log('OK 插件行图标：package.json 的 icon 在包内可读');

// ── 会话权限面装饰（按本机跑通的判据逐条锁住）────────────────────────────
const ctxEffect = ctxEffects[0];
assert.match(ctxEffect.label, /preset label, glyph and risk gate/);
const dispose = ctxEffect.fn();
assert.ok(observers.length > 0, '必须挂 MutationObserver，否则面板重渲染后文案与图标失联');
const flush = () => { observers.forEach(entry => entry.callback([])); frames.splice(0, frames.length).forEach(run => run()); };
const row = (text, glyph = 'none') => {
    const button = new FakeNode('button', { role: 'menuitem' });
    if (glyph === 'span') {                       // 宿主给内置档位画的图标在 per-row span 里
        const wrap = new FakeNode('span');
        wrap.appendChild(new FakeNode('svg'));
        button.appendChild(wrap);
    }
    if (glyph === 'tick') button.appendChild(new FakeNode('svg'));  // 选中行的对勾：裸 svg 子节点
    const span = new FakeNode('span');
    span.textContent = text;
    button.appendChild(span);
    return button;
};
const buildMenu = (glyph) => {
    const menu = new FakeNode('div', { role: 'menu' });
    menu.append(row('仅可查看', glyph), row('工作区内修改', glyph), row('完全权限', glyph), row('Auto approval', glyph));
    document.body.appendChild(menu);
    return menu;
};

// 1) 宿主画了图标 ⇒ 本档补一个，并把文案换成中文
const glyphed = buildMenu('span');
flush();
const autoRow = glyphed.children[3];
const labelOf = (row) => row.children.find(child => child.tagName === 'SPAN' && child.querySelector('svg') == null);
assert.equal(labelOf(autoRow).textContent, '自动审批', '中文界面里预设名必须换成中文');
assert.ok(autoRow.querySelector('.dsa-frameAutoIcon') !== null, '宿主给其他档位画了图标，本档必须由插件补齐');
assert.equal(autoRow.children[0].classList.contains('dsa-frameAutoIcon'), true, '图标插在行首，不追加到末尾');
assert.equal(glyphed.children[0].querySelector('.dsa-frameAutoIcon'), null, '其他档位不由本插件加图标');
// 幂等：重复扫描不得叠图标
const glyphsAfter = document.body.querySelectorAll('.dsa-frameAutoIcon').length;
flush(); flush();
assert.equal(document.body.querySelectorAll('.dsa-frameAutoIcon').length, glyphsAfter, '重复扫描必须幂等，不叠图标');

// 2) 纯文本档位列表 ⇒ 不加孤立图标，只换文案（宿主走 kind='option' 分支）
const plain = buildMenu('none');
flush();
const plainAuto = plain.children[3];
assert.equal(labelOf(plainAuto).textContent, '自动审批', '但文案仍要本地化');
assert.equal(plainAuto.querySelector('.dsa-frameAutoIcon'), null, '宿主没画图标时不得塞孤立图标');

// 3) 折叠态触发器：只有文本节点时，绝不新建/替换 React 持有的节点（上一版就是这里把会话点卡死的）
const trigger = new FakeNode('button', { 'aria-label': '访问模式 Auto approval' });
trigger.textContent = 'Auto approval';
const textChildrenBefore = trigger.childNodes.filter(node => node.nodeType === 3).length;
document.body.appendChild(trigger);
flush();
assert.equal(trigger.childNodes.filter(node => node.nodeType === 3).length, textChildrenBefore,
    '触发器的文本节点必须原样保留：替换 React 持有的文本会让宿主重渲染抛错');
assert.equal(trigger.getAttribute('aria-label'), '访问模式 自动审批', '折叠态 aria 同步语言');
assert.equal(trigger.getAttribute('data-frame-original-aria'), '访问模式 Auto approval', '原文必须留档，语言切换时才能正确还原');
assert.ok(trigger.children.some(child => child.classList?.contains('dsa-frameAutoIcon')), '折叠态触发器也要补图标');

// 4) 语言双向：切英文后文案与 aria 都回英文
document.documentElement.lang = 'en-US';
flush();
assert.equal(labelOf(autoRow).textContent, 'Auto approval', '英文界面必须换回英文，不是硬写中文');
assert.equal(trigger.getAttribute('aria-label'), '访问模式 Auto approval', 'aria 也跟着语言回退');
document.documentElement.lang = 'zh-CN';
flush();
assert.equal(labelOf(autoRow).textContent, '自动审批', '语言切回时二次改写生效');

// 5) listbox（设置里的权限下拉）：只改标签，不画图标
const listboxHost = new FakeNode('div', { role: 'listbox', 'aria-label': '/permission 匹配项' });
const option = new FakeNode('div', { role: 'option' });
const optionLabel = new FakeNode('span');
optionLabel.textContent = 'Auto approval';
option.appendChild(optionLabel);
listboxHost.appendChild(option);
document.body.appendChild(listboxHost);
flush();
assert.equal(optionLabel.textContent, '自动审批', '设置里的权限下拉也要本地化');
assert.equal(option.querySelector('.dsa-frameAutoIcon'), null, 'listbox 项只改文案、不画图标');

// 6) 节点离开后回收标记与图标
glyphed.remove(); plain.remove(); trigger.remove(); listboxHost.remove();
flush();
assert.equal(document.body.querySelectorAll('.dsa-frameAutoIcon').length, 0, '节点离开后不留残图标');
assert.equal(document.body.querySelectorAll('[data-frame-icon]').length, 0, '标记也要回收');
console.log('OK 会话权限面：文案与图标按本机判据补齐、幂等、语言双向、离开即回收');

// ── 点击必须原样交回宿主（插件不得劫持权限菜单）─────────────────────
{
    const menu = new FakeNode('div', { role: 'menu' });
    const hostCalls = [];
    const autoItem = row('Auto approval', 'span');
    autoItem.addEventListener('click', () => hostCalls.push('host'));
    menu.append(row('仅可查看', 'span'), row('工作区内修改', 'span'), row('完全权限', 'span'), autoItem);
    document.body.appendChild(menu);
    flush();
    menu.children[3].click();
    assert.deepEqual(hostCalls, ['host'], '点击「自动审批」必须直达宿主：劫持点击就是上一版「切不了」的成因');
    assert.equal(document.body.querySelector('[data-frame-risk]'), null, '不得再插确认窗');
    menu.remove();
    flush();
    console.log('OK 点击不被劫持：切档直达宿主（上一版失效成因的回归锁）');
}

// 装饰层与设置页互不影响
assert.equal(registered[0].contribution.meta.key, 'dsh-auto-approval-frame#auto-approval-frame');

const ConfigPage = registered[0].contribution.component;
const renderPage = props => react.createElement(ConfigPage, props);
// 判定链读侧（宿主路由）的替身：内置保护、生效的信任行、被拒的允许行。
const FRAME_BODY = {
    ok: true,
    mode: 'auto',
    debug: false,
    gatedPresets: ['auto-approval'],
    missingGatedPresets: [],
    // 内置行由宿主那一处生成（effectiveRows）：测试用同一个函数，不另抄一份清单。
    rows: Object.fromEntries(RULE_PLANES.map(plane => [plane, effectiveRows({
        fileRules: [{ match: 'c:/ws/frame-client/trash', read: 'allow', write: 'allow', delete: 'allow' }],
    }, plane).map(row => ({
        id: row.id, preset: row.preset ?? '', label: row.label ?? '', match: row.match,
        action: row.action, read: row.read ?? '', write: row.write ?? '', delete: row.delete ?? '',
        enabled: row.enabled !== false,
    })),
    ])),
    trusted: [{ match: 'c:/ws/trash', read: 'allow', write: 'allow', delete: 'allow' }],
    dshOpen: [{ match: 'c:/ws/.dsh/skills', read: 'allow', write: '', delete: '' }],
    rejected: [{ dir: 'c:/ws/.dsh', reason: 'whole-state-tree' }],
};

const emptyAudit = { ok: true, matched: 0, total: 0, segments: 0, entries: [], chain: null };
// 宿主模型目录（GET /api/auto-approval-frame/models）的替身：两组提供方＋一条读取失败。
const MODELS_BODY = {
    ok: true,
    groups: [
        { id: 'nodeb4603', name: '本机 vLLM', models: [{ id: 'qwen3.8-27b', name: 'Qwen3.8 27B' }, { id: 'ds-reasoner', name: 'DS Reasoner' }] },
        { id: 'deepseek', name: 'DeepSeek', models: [{ id: 'deepseek-chat', name: 'DeepSeek Chat' }] },
    ],
    failures: [{ id: 'ollama', name: 'Ollama', message: 'connection refused' }],
};
globalThis.fetch = async url => ({
    ok: true,
    json: async () => (String(url).includes('/audit?') ? emptyAudit
        : String(url).includes('/models') ? MODELS_BODY : FRAME_BODY),
});
const stored = {
    enabled: true, mode: 'auto', reviewerSource: 'preset', reviewerProvider: 'nodeb4603', reviewerModel: 'qwen3.8-27b',
    reviewerMaxTokens: 1024, reviewerTimeoutMs: 20000, evidenceBudget: 16000,
    reviewRules: ['拒绝查看或删除 ~/.ssh 及任何凭据文件'],
    commandRules: ['deny rm -rf'],
    fileRules: [
        { match: 'C:/ws/trash', read: 'allow', write: 'allow', delete: 'allow' },
        { match: 'C:/ws/.dsh/skills', read: 'allow', write: '', delete: '' },
        { match: '**/.git/**', read: '', write: '', delete: 'deny' },
    ],
    networkRules: [], toolRules: [], sensitiveRules: [{ action: 'ask', match: 'password=' }],
    sensitiveDetect: true, fastJudge: true, fastJudgeMaxTokens: 256, fastJudgeTimeoutMs: 3000,
    retentionDays: 90, maxTotalBytes: 536870912, maxSegmentBytes: 52428800,
    gatedPresets: ['auto-approval'], debug: false,
};
let mutated = null;
const form = { state: { status: 'ready', value: stored, writable: true }, mutate: async ops => { mutated = ops; } };
assert.equal(renderPage({ view: 'card', form }), null, '只在 page 视图渲染');
resetHooks();
const tree = renderPage({ view: 'page', form });
const rendered = textOf(tree);
for (const label of ['自动审批', '接管与模式', '审批模式', '仅风险提示', '跟随会话', '指定预设', '安全规则',
    '命令安全', '文件安全', '网络安全', '工具规则', 'AI 审查', '自定义审查规则', '敏感保护', '检测规则', '敏感信息',
    '审计中心', '是否接管', '链上第', '保存', '撤销']) {
    assert.ok(rendered.includes(label), `设置页缺少中文文案：${label}`);
}
const leaked = rendered.match(/\b(enabled|reviewerSource|reviewerProvider|reviewerModel|reviewerMaxTokens|reviewerTimeoutMs|evidenceBudget|trustedDirs|dshOpen|neverAutoExtra|reviewRules|commandRules|fileRules|networkRules|toolRules|sensitiveRules|sensitiveDetect|fastJudge|fastJudgeMaxTokens|fastJudgeTimeoutMs|retentionDays|maxTotalBytes|maxSegmentBytes|gatedPresets)\b/g);
assert.equal(leaked, null, `设置页不该把 schema 键名当标签：${leaked?.join(',')}`);
assert.ok(rendered.includes('只读（走 profile 补丁改）'), 'host-only 键必须标明只读');
assert.ok(!rendered.includes('允许自动删除的目录'), '信任范围不再是独立字段，只能作为文件规则行出现');
// 链上不再单列「代码下界」：它在这版里就是每张表置顶的内置行，多一格只会让人以为有两套规则、还出现两套编号。
assert.ok(!rendered.includes('代码下界'), '判定链与卡片文案里都不该再出现「代码下界」这一格');
// 层级名字全站一套：页面这张表必须和导出件用的 LAYER_TEXT 逐字相同。两份分别住在
// webview 和 node 侧、运行时没法共享，所以按字面比锁住——否则页面上叫「内置行」、
// 导出的台账里叫别的名字，跑一次对不上一次。
{
    const literal = clientSource.match(/const LAYER_LABEL = \{([\s\S]*?)\};/);
    assert.ok(literal, '页面里要有 LAYER_LABEL 这张层级表');
    const pairs = Object.fromEntries([...literal[1].matchAll(/(\w+):\s*"([^"]+)"/g)].map(([, key, value]) => [key, value]));
    assert.deepEqual(pairs, LAYER_TEXT, '页面层级名与台账层级名分叉了');
    assert.ok(!clientSource.includes('代码下界'), '旧名字「代码下界」不得残留在页面源码里');
}
// 档位词表两侧同义：宿主认得的写法（含中文），页面也必须折到同一档——
// 否则手写的行在页面上显示成另一档，再保存一次就把原意改掉了。
{
    const literal = clientSource.match(/const FOLD_ACTION = \{([\s\S]*?)\};/);
    assert.ok(literal, '页面里要有 FOLD_ACTION 这张档位同义词表');
    const pairs = Object.fromEntries([...literal[1].matchAll(/([^\s:,]+):\s*"([^"]+)"/g)].map(([, key, value]) => [key, value]));
    for (const [canonical, words] of Object.entries(ACTION_WORDS)) {
        for (const word of words) {
            const folded = pairs[word] ?? word;
            assert.equal(folded, canonical,
                `宿主认得的档位词「${word}」在页面上折成「${folded}」，应为「${canonical}」`);
        }
    }
}
const stepTitles = findIn(tree, node => node.type === 'button' && String(node.props?.className ?? '') === 'dsa-step').map(node => String(node.props.title ?? ''));
assert.equal(stepTitles.length, 7, '链上七格：0 接管／1 安全规则／2 事实门／3 快判／4 深评／5 人工／6 脱敏');
assert.ok(stepTitles.some(t => t.startsWith('安全规则：') && t.includes('内置行＋你的有序表')), stepTitles.join(' | '));
assert.ok(!stepTitles.some(t => t.includes('代码下界')), stepTitles.join(' | '));

assert.equal(findIn(tree, node => node.type === 'textarea').length, 1,
    '只剩「自定义审查规则」用整块文本；范围／开口类字段必须已经并掉');
// 安全规则卡默认只给摘要列表，四张表不平铺（上一版就是四表叠一起，密到看不清）。
// 检测规则也走同一形制，但它留在「敏感保护」卡里——它是结果侧的脱敏，不是拦截规则。
const has = name => node => String(node.props?.className ?? '').split(' ').includes(name);
const rulesCard = findIn(tree, node => node.props?.id === 'frame-card-rules')[0];
const sensitiveCard = findIn(tree, node => node.props?.id === 'frame-card-sensitive')[0];
const summaryRows = findIn(tree, has('dsa-summaryRow'));
assert.equal(findIn(rulesCard, has('dsa-summaryRow')).length, 4, '安全规则卡四行摘要：命令／文件／网络／工具');
assert.equal(findIn(sensitiveCard, has('dsa-summaryRow')).length, 2, '敏感保护卡里两行平行：检测规则＋敏感信息');
assert.equal(summaryRows.length, 6, '摘要→明细共六张表：命令／文件／网络／工具／检测规则／敏感信息');
// 六行都得有图标：「敏感信息」此前渲染成空图标位（PlaneIcon 没有 secrets 条目）。
assert.equal(summaryRows.every(row => findIn(row, has('dsa-tile')).length === 1), true,
    `每行摘要都要有图标：${summaryRows.map(row => textOf(row).trim().split(/\s+/)[0]).join(',')}`);
assert.ok(!textOf(rulesCard).includes('检测规则'), '检测规则不搬进「安全规则」');
assert.ok(!textOf(tree).includes('C:/ws/trash'), '列表态不得把规则表铺开');
assert.ok(!textOf(tree).includes('‹ 返回'), '默认不在明细页');
// 判定链读侧要跑 effect 才有数据（内置保护、生效信任行、被拒行）。
flushEffects();
await new Promise(resolve => setTimeout(resolve, 0));
summaryRows[1].props.onClick();
const detail = renderPage({ view: 'page', form });
const detailText = textOf(detail);
assert.ok(detailText.includes('‹ 返回'), '明细页要能回列表');
assert.ok(detailText.includes('新规则默认'), '明细页要有新增行的默认动作');
assert.ok(detailText.includes('命中第一条后停止'), '明细页要写清顺序语义');
assert.ok(detailText.includes('凭据与客户端目录'), '内置保护要作为预设行出现在文件明细里');
assert.ok(!detailText.includes('预设 · 代码下界'), '预设不再是单独一段，只能作为同表里的行');
// 内置行**可改可停用**了，就没有「不可越过」这把锁：锁在，就等于页面上又出现一套规则。
assert.ok(!detailText.includes('🔒'), '不再给内置行画 🔒——它已是可以换档、可以停用的一行');
assert.ok(detailText.includes('内置（'), '内置行单独成块并计数，与「自定义」平行');
assert.ok(detailText.includes('自定义（'), '用户加的行归「自定义」块');
assert.ok(detailText.includes('整棵打开 ~/.dsh'), '被拒的允许行要说明为什么没生效');
// 明细页只铺开被点开的那一张表：命令表的行不该出现在文件表里
assert.ok(!detailText.includes('当 命令 匹配 rm -rf'), '文件明细不得把别的表也铺开');
const isPill = node => String(node.props?.className ?? '').split(' ').includes('dsa-pill');
const isStrip = node => String(node.props?.className ?? '').split(' ').includes('dsa-menu');
const pills = findIn(detail, isPill);
assert.ok(pills.length >= 8, `动作片太少：${pills.length}`);
const detailArea = findIn(detail, node => String(node.props?.className ?? '').split(' ').includes('dsa-detail'))[0];
assert.ok(detailArea, '点开一张表要有明细容器');
assert.equal(findIn(detailArea, node => node.type === 'select').length, 0,
    '动作片不再嵌原生 select：系统弹出层比片子窄一圈、字也更小，点开就风格断档');
assert.ok(pills.filter(pill => String(pill.props.className).includes('is-picker'))
    .every(pill => (pill.children ?? []).some(child => textOf(child).trim() === '▾')), '可改的动作片都要有展开指示');
assert.ok(findIn(detail, node => String(node.props?.className ?? '').split(' ').includes('is-preset'))
    .every(row => findIn(row, node => String(node.props.className ?? '').includes('is-picker')).length === 0),
    '预设行的动作片是只读的，不该能点开');
// 点开规则行第一颗片（文件面＝读取）：同尺寸的选项排紧跟在这行下面
const firstRow = findIn(detail, node => String(node.props?.className ?? '').split(' ').includes('dsa-sent')
    && !String(node.props.className).includes('is-preset'))[0];
const rowPill = findIn(firstRow, node => isPill(node) && String(node.props.className).includes('is-picker'))[0];
rowPill.props.onClick();
const opened = renderPage({ view: 'page', form });
const strips = findIn(opened, isStrip);
assert.equal(strips.length, 1, '一屏只开一个选项排');
const opts = findIn(strips[0], node => String(node.props?.className ?? '').split(' ').includes('dsa-menuItem'));
assert.deepEqual(opts.map(node => textOf(node).replace(/\s+/g, ' ').trim()),
    ['不表态', '拒绝', '人工', 'AI ✓', '允许'], '五档齐全（不表态＋四档），旧 allow 显示成 AI 且当前值打勾');
// 选完即收起，并写回那颗片
opts[2].props.onClick();
const chosen = renderPage({ view: 'page', form });
assert.equal(findIn(chosen, isStrip).length, 0, '选完就收起');
const backRow = findIn(chosen, node => String(node.props?.className ?? '').split(' ').includes('dsa-sent')
    && !String(node.props.className).includes('is-preset'))[0];
assert.ok(textOf(findIn(backRow, node => String(node.props.className ?? '').includes('is-picker'))[0]).includes('人工'),
    '选完的值要写回那颗片');
// 「新规则默认」用同一个控件，选项＝四档（默认动作不该有「不表态」）
const defaultPill = findIn(renderPage({ view: 'page', form }), node => isPill(node)
    && String(node.props.className ?? '').includes('is-picker')
    && String(node.props.title ?? '') === '新增行的默认动作')[0];
defaultPill.props.onClick();
const defaultsOpen = renderPage({ view: 'page', form });
const defaultOpts = findIn(findIn(defaultsOpen, isStrip)[0], node => String(node.props?.className ?? '').split(' ').includes('dsa-menuItem'));
assert.deepEqual(defaultOpts.map(node => textOf(node).replace(/\s+/g, ' ').trim()), ['拒绝', '人工 ✓', 'AI', '允许'],
    '默认动作＝四档（没有「不表态」这一说），且当前项打勾');
assert.equal(findIn(defaultsOpen, node => String(node.props?.className ?? '').split(' ').includes('dsa-opts')).length, 0,
    '不许再有摊开的按钮排——那玩意儿不是下拉框');
// 高级项默认折叠，展开后必须齐备——否则等于把配置面砍没了。
assert.ok(!detailText.includes('证据预算'), '高级项默认折叠');
for (const node of findIn(renderPage({ view: 'page', form }), item => item.type === 'button' && textOf(item).includes('高级（')))
    node.props.onClick();
const expandedText = textOf(renderPage({ view: 'page', form }));
for (const label of ['证据预算', '深评输出上限（token）', '快判超时（毫秒）', '保留天数', '总大小上限（字节）', '单段上限（字节）'])
    assert.ok(expandedText.includes(label), `展开高级后缺字段：${label}`);
assert.ok(findIn(renderPage({ view: 'page', form }), node => node.type === 'button' && textOf(node).includes('收起高级项')).length >= 2,
    '每张有高级项的卡都要能收回去');
console.log('OK 设置页：五段按链排、安全规则两级（摘要→明细）、动作片含不表态与四档、内置保护读回、高级可展开');

// 一套视觉要铺满整页：别的卡也得是卡片，不能只有规则区改了。
{
    resetHooks();
    const all = renderPage({ view: 'page', form });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    const page = renderPage({ view: 'page', form });
    const classed = name => findIn(page, node => String(node.props?.className ?? '').split(' ').includes(name)).length;
    assert.ok(classed('dsa-card') >= 5, '五张卡都要走同一套卡片样式');
    // 目录可用时「Provider＋Model」两行手填被一行模型下拉取代 ⇒ 行数比旧版少两行是对的，
    // 判据改成：每张有字段的卡里，每个字段都是同一套行容器。
    const cardFields = id => {
        const card = findIn(page, node => node.props?.id === id)[0];
        const rows = findIn(card, node => String(node.props?.className ?? '').split(' ').includes('dsa-field'));
        return [rows.length, findIn(card, node => String(node.props?.className ?? '').includes('dsa-fieldLabel')).length];
    };
    for (const id of ['frame-card-preset', 'frame-card-review']) {
        const [rows, labels] = cardFields(id);
        assert.ok(rows >= 1 && rows === labels, `${id}：每个字段都要是一条 dsa-field 行，且带标签（行 ${rows}／标签 ${labels}）`);
    }
    assert.ok(classed('dsa-field') >= 5, '整页至少五条统一字段行（模型下拉把两行手填合成一行）');
    assert.equal(classed('dsa-page'), 1, '页面骨架同用一套类');
    assert.ok(classed('dsa-tile') >= 6, '六行摘要行行要有图标（不是首字缩略，敏感信息也不例外）');
    // 计数与判定同源：从宿主那份 effectiveRows 现算，不写死数字（写死＝改清单就红一次无辜的测试）。
    const floorCount = effectiveRows({}, 'file').filter(row => row.preset !== '').length;
    assert.ok(floorCount >= 8, `内置行清单要有足够条目：${floorCount}`);
    assert.ok(textOf(page).includes(`内置 ${floorCount}`),
        `摘要行要标出该表的内置行数（与行内「内置」标签同名）：${textOf(page).slice(0, 200)}`);
    assert.ok(findIn(sensitiveCard, has('dsa-summaryRow')).some(node => textOf(node).includes('检测规则')),
        '检测规则的摘要行长在敏感保护卡里');
    assert.ok(textOf(page).includes('未设置'), '没有行的平面标「未设置」，不留空白');
    // 命令表也要看得见下界，不能只有文件表有预设
    findIn(renderPage({ view: 'page', form }), node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[0].props.onClick();
    const commandText = textOf(renderPage({ view: 'page', form }));
    assert.ok(commandText.includes('提权执行') && commandText.includes('不可逆销毁'), '命令表底部要列出内置预设行');
    assert.ok(findIn(renderPage({ view: 'page', form }), node => String(node.props?.className ?? '').split(' ').includes('is-presetSet')).length === 0,
        '预设行不得另起一个容器，必须与用户行同表同列');
    // 视觉四处硬要求：卡→行→控件三档边框逐级变浅；行底只比卡底深一点点（深浅主题各一档）；
    // 分层不靠投影；规则行走固定列网格，动作片竖着排齐。
    const css = document.querySelectorAll('style').map(node => node.textContent).join('');
    assert.ok(/\.dsa-card\{[^}]*border:1px solid var\(--dsw-alias-border-l3/.test(css), '卡框用最深一档 l3');
    assert.ok(/\.dsa-item\{[^}]*border:1px solid var\(--dsw-alias-border-l2/.test(css), '行框 l2：比卡浅一档、比控件深一档');
    assert.ok(/\.dsa-item\{[^}]*background:var\(--dsa-row\)/.test(css)
        && /\.dsa-page\{[^}]*--dsa-row:rgba\(0,0,0,\.[0-3]/.test(css)
        && /body\[data-ds-dark-theme\] \.dsa-page\{--dsa-row:rgba\(255,255,255,/.test(css),
        '行底要走「比卡底浅一点」的自定档，且深浅主题各一档（bg-layer 在浅色下全是 #fff，bg-module-platform 又太深）');
    assert.equal(/box-shadow: *0 /.test(css), false, `不许用投影分层：${(css.match(/[^"]*box-shadow: *0 [^"]*/) ?? []).join(' | ')}`);
    assert.ok(/\.dsa-sent\{[^}]*display:grid/.test(css) && /\.dsa-sent\{[^}]*grid-template-columns:22px auto minmax\(110px,1fr\) auto auto auto/.test(css)
        && /\.dsa-sentOps\{[^}]*flex-wrap:nowrap/.test(css),
        '规则行必须是固定六列网格——询问／拦截才排得齐，五张表同一把尺');
    assert.ok(/\.dsa-sentOps\{[^}]*justify-content:flex-end/.test(css), '动作片靠列右端对齐');
    assert.ok(/\.dsa-menu\{[^}]*position:absolute/.test(css) && /\.dsa-menu\{[^}]*min-width:100%/.test(css)
        && /\.dsa-menu\{[^}]*border:1px solid var\(--dsw-alias-border-l3/.test(css),
        '动作下拉必须是贴在片子下方的浮层（不小于片子宽、l3 边框），不是摊在行里的一排按钮');
    assert.equal(/\.dsa-opts\{/.test(css), false, '摊开的按钮排样式必须已经删干净');
    assert.ok(/\.dsa-dryInputWrap input\{[^}]*width:100%!important/.test(css)
        && /\.dsa-dryInputWrap input\{[^}]*max-width:4\d\dpx/.test(css)
        && /\.dsa-dryInputWrap input\{[^}]*min-height:3\dpx/.test(css),
        '输入框要宽到能读完一条命令（!important 顶住宿主自带宽度），但必须封顶在 ~460px 并只有一行高——铺满整行太长、42px 太高');
    assert.ok(/\.dsa-dryStep:nth-child\(odd\)\{background:var\(--dsa-row\)/.test(css),
        '模拟结果的斑马条走同一档浅底，不用 bg-layer-2（深主题下那档明显偏深）');
    assert.ok(/\.dsa-footer\{[^}]*\}/.test(css) && !/\.dsa-footer\{[^}]*position:sticky/.test(css), '干净态保存条不悬浮');
    assert.ok(/\.dsa-footer\.is-dirty\{[^}]*position:sticky/.test(css), '只有待保存时才升格成粘底悬浮条');
    assert.ok(/\.dsa-footer\{[^}]*justify-content:flex-end/.test(css), '按钮靠右：主操作落最右');
    // 干净态不带 is-dirty，改一笔才带上——悬浮条不该一直压在页面上。
    const footerOf = node => findIn(node, item => String(item.props?.className ?? '').split(' ').includes('dsa-footer'))[0];
    const cleanRender = renderPage({ view: 'page', form });
    assert.equal(footerOf(cleanRender).props.className, 'dsa-footer', '未改动时就是页尾一行');
    findIn(cleanRender, item => item.type === 'SegmentedControl' && item.props.id === 'frame-mode')[0].props.onChange('advise');
    const dirty = renderPage({ view: 'page', form });
    assert.ok(footerOf(dirty).props.className.includes('is-dirty'), '改一笔就升格成粘底悬浮条');
    const footChildren = (footerOf(dirty).children ?? []).filter(Boolean);
    assert.ok(footChildren[0].type !== 'Button' && textOf(footChildren[1]).trim() === '撤销' && textOf(footChildren[2]).includes('保存'),
        `页脚顺序＝说明在左、撤销、保存落最右：${footChildren.map(node => textOf(node).trim()).join(' / ')}`);
    console.log('OK 全站一套容器：卡 l3／行 l2／控件 l1＋有色行底、无投影、预设与用户行同表、保存条按需悬浮且按钮靠右');

// 试算器：粘一条命令，页面按当前配置逐步回它在每一关的落点（不调模型）。
{
    const asked = [];
    const baseFetch = globalThis.fetch;
    globalThis.fetch = async url => {
        const text = String(url);
        if (text.includes('/explain')) {
            asked.push(decodeURIComponent(text));
            return { ok: true, json: async () => ({ ok: true, verdict: '第 1 步 安全规则：直接拦截，工具收到拒绝', asPath: false, ruleTotal: 5, rules: { command: 1, file: 4, network: 0, tool: 0, sensitive: 0 }, steps: [
                { step: '1', name: '安全规则', state: 'deny', why: '你的行命中：deny rm -rf' },
                { step: '2', name: '事实门', state: 'n/a', why: '前面已定，不再往下走' },
            ], cwd: 'C:/host', caveat: '按目录 C:/host 判定；若该会话的工作目录不同，路径相关的落点可能不一样。' }) };
        }
        return baseFetch(url);
    };
    resetHooks();
    renderPage({ view: 'page', form });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    let dry = renderPage({ view: 'page', form });
    const blank = findIn(dry, node => node.type === 'Input' && String(node.props.placeholder ?? '').includes('粘贴一条命令'))[0];
    assert.ok(blank, '页面顶部要有试算输入框');
    assert.ok(!textOf(dry).includes('看它走哪一步'), '按钮文案已改成「模拟一下」（用户定名）');
    assert.ok(textOf(dry).includes('模拟审批') && !textOf(dry).includes('模拟执行') && !textOf(dry).includes('AI 打算执行'),
        '入口叫「模拟审批」（用户两次定名）——旧文案看着像在说 AI 要干什么，看不懂');
    assert.ok(findIn(dry, node => String(node.props?.className ?? '').split(' ').includes('dsa-dryTop')).length === 1
        && findIn(dry, node => String(node.props?.className ?? '').split(' ').includes('dsa-dryBar')).length === 1,
        '标题＋说明占一行，输入框独占一行');
    assert.equal(findIn(dry, node => node.type === 'Button' && textOf(node).includes('模拟一下'))[0].props.variant, 'ghost',
        '这个按钮不用主色实底（填充太深），只当普通动作');
    assert.equal(findIn(dry, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.variant, 'primary',
        '全页唯一的主色实底留给保存');
    assert.equal(findIn(dry, node => node.type === 'Button' && textOf(node).includes('模拟一下'))[0].props.disabled, true,
        '空输入不许试算');
    blank.props.onChange({ target: { value: 'rm -rf build' } });
    dry = renderPage({ view: 'page', form });
    await findIn(dry, node => node.type === 'Button' && textOf(node).includes('模拟一下'))[0].props.onClick();
    const dryText = textOf(renderPage({ view: 'page', form }));
    assert.equal(asked.length, 1, `试算要问宿主：${asked.join(',')}`);
    assert.ok(asked[0].includes('q=rm -rf build'), '把原文交给解释器');
    assert.ok(dryText.includes('第 1 步 安全规则：直接拦截'), '结论要用人话写在最前');
    assert.ok(dryText.includes('拦截') && dryText.includes('不再走'), '每一步给出落点与状态');
    // 自证行：把宿主当前生效的规则数摆出来——用户存了行而这里没动，就是写入没落到宿主。
    assert.ok(dryText.includes('你的规则共 5 行') && dryText.includes('命令 1') && dryText.includes('文件 4'), dryText.slice(0, 400));
    // 模拟跑在宿主进程里，工作目录和会话不一定相同——这句限定必须显示出来，
    // 否则跨目录的会话就会把「模拟和实际不一样」当成判定链的 bug。
    assert.ok(dryText.includes('若该会话的工作目录不同'), dryText.slice(-300));
    globalThis.fetch = baseFetch;
    console.log('OK 试算器：一条命令走一遍判定链，逐步回落点');
}

// 敏感保护：开关长在卡头（不为它单开一行），检测规则照命令安全做成两级——摘要行→明细表。
{
    resetHooks();
    renderPage({ view: 'page', form });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    const page = renderPage({ view: 'page', form });

    const headSwitch = findIn(page, node => node.type === 'Switch' && node.props.id === 'frame-card-switch-sensitiveDetect');
    assert.equal(headSwitch.length, 1, '敏感总闸画在卡头右侧');
    assert.equal(findIn(page, node => node.type === 'Switch' && node.props.id === 'frame-card-switch-enabled').length, 1,
        '「启用本插件」同样走卡头，卡内不再为开关留一行');
    const fieldLabels = findIn(page, node => String(node.props?.className ?? '').includes('dsa-fieldLabel')).map(textOf);
    assert.ok(!fieldLabels.some(label => label.includes('启用检测与脱敏') || label.includes('启用本插件')),
        `开关不该再占一条独立字段行：${fieldLabels.join(' | ')}`);
    assert.ok(!textOf(page).includes('password='), '默认是摘要态，敏感表不平铺');
    // 一句话规则行：读序＝语法序（进任意一张表看自己的行）
    findIn(page, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[0].props.onClick();
    const toolPage = renderPage({ view: 'page', form });
    const sentence = findIn(toolPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-sent'))[0];
    assert.ok(sentence !== undefined, '规则行要渲染成句子');
    const cells = (sentence.children ?? []).map(child => textOf(child).replace(/\s+/g, ' ').trim());
    assert.deepEqual(cells.slice(0, 2), ['1', '当 命令 匹配'], `一行的列序不对（编号｜句子）：${cells.join(' | ')}`);
    assert.equal(cells[3], '时 →', '句子尾缀单独一列，动作片才能整体靠右排齐');
    assert.ok((sentence.children ?? []).filter(Boolean).length === 6, `规则行必须凑满六列：${cells.join(' | ')}`);
    assert.ok(textOf(sentence).includes('rm -rf'), '条件列就是这一格的值');
    // 内置行与用户行**同列同形制**（「只读预设行」这一类已经取消）：六列、也编号，只是名字前挂一枚「内置」片。
    const floorRow = findIn(toolPage, node => String(node.props?.className ?? '').includes('dsa-sent')
        && findIn(node, item => String(item.props?.className ?? '').includes('dsa-sentTag')).length > 0)[0];
    assert.ok(floorRow !== undefined, '内置行要带「内置」片');
    const floorCells = (floorRow.children ?? []).map(child => textOf(child).replace(/\s+/g, ' ').trim());
    assert.equal(floorCells.length, 6, `内置行必须与用户行同列数：${floorCells.join(' | ')}`);
    assert.ok(/^\d+$/.test(floorCells[0]), `内置行也编号（它也在这张表里）：${floorCells[0]}`);
    assert.ok(floorCells[1].startsWith('内置'), `第二列＝来源片＋名称：${floorCells[1]}`);
    assert.ok(textOf(sentence).includes('时 →'), '句子要有「时 →」收尾');
    // 文件面用「时：」并把读/写/删嵌进同一句，未表态的列显式写「不表态」
    findIn(toolPage, node => node.props?.className === 'dsa-back')[0].props.onClick();
    const listPage = renderPage({ view: 'page', form });
    findIn(listPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[1].props.onClick();
    const filePage = renderPage({ view: 'page', form });
    const fileWords = textOf(filePage);
    assert.ok(fileWords.includes('时：'), '文件句子里要有「时：」接三个操作');
    assert.ok(fileWords.includes('不表态'), '未表态的操作列要显式写「不表态」');
    assert.ok(!fileWords.includes('我的规则'), '不再单独开「我的规则」段标题');
    // 敏感表真的能编辑并保存（漏声明字段时 draft 里根本没有它，改了也存不下去）
    let sensOps = null;
    const sensForm = { state: { status: 'ready', value: stored, writable: true }, mutate: async ops => { sensOps = ops; } };
    resetHooks();
    renderPage({ view: 'page', form: sensForm });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    let sensPage = renderPage({ view: 'page', form: sensForm });
    findIn(sensPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[4].props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    const sensText = textOf(sensPage);
    // 内置形状现在是表里的行（私钥／JWT／AWS key／Bearer／服务密钥／凭据赋值／连接串），
    // 不再是表底一排只读预设说明。
    for (const name of ['私钥', 'JWT', 'AWS AccessKey', '凭据赋值', '连接串'])
        assert.ok(sensText.includes(name), `检测规则表里要有内置形状行「${name}」`);
    assert.ok(sensText.includes('‹ 返回'), '敏感明细要照命令安全那样能回列表');
    const sensInput = findIn(sensPage, node => node.type === 'Input' && node.props.value === 'password=')[0];
    assert.ok(sensInput, '检测规则表要在敏感保护卡里，形制照命令安全');
    // 就地改条件（不用删了重加）
    sensInput.props.onChange({ target: { value: 'ghp_' } });
    sensPage = renderPage({ view: 'page', form: sensForm });
    // 工具条新增：一行内既有输入框也有「＋ 添加」，新行插到顶部
    const toolInput = findIn(sensPage, node => node.type === 'Input' && String(node.props.placeholder ?? '').includes('新增一行'))[0];
    assert.ok(toolInput, '明细页顶部要有新增行的输入框');
    toolInput.props.onChange('token=');
    sensPage = renderPage({ view: 'page', form: sensForm });
    await findIn(sensPage, node => node.type === 'Button' && textOf(node).includes('＋ 添加'))[0].props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    await findIn(sensPage, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.onClick();
    const savedSensitive = sensOps?.find(op => op.path[0] === 'sensitiveRules')?.value ?? [];
    assert.deepEqual(savedSensitive.filter(row => !row.preset),
        [{ action: 'ask', match: 'token=' }, { action: 'ask', match: 'ghp_' }],
        '敏感表要能存回配置（就地改＋新增都算）');
    // 没碰过的内置行不跟着别的行的编辑一起抄进配置：默认值留在宿主，改谁才写谁。
    assert.equal(savedSensitive.filter(row => row.preset).length, 0,
        '没碰过的内置行不该被顺手物化进配置');

    // 碰一条内置行＝只写这一条（档位写回带 preset 的行），其余仍在宿主默认值里。
    const builtinRow = () => findIn(sensPage, node => String(node.props?.className ?? '').includes('dsa-sent')
        && textOf(node).includes('私钥'))[0];
    assert.ok(builtinRow() !== undefined, '内置形状行要是可操作的行');
    findIn(builtinRow(), isPill)[0].props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    const menu = findIn(builtinRow(), node => String(node.props?.className ?? '').split(' ').includes('dsa-menu'))[0];
    assert.ok(menu !== undefined, '内置行的动作片也要能点开');
    findIn(menu, node => String(node.props?.className ?? '').split(' ').includes('dsa-menuItem'))
        .find(node => textOf(node).trim().startsWith('拒绝')).props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    await findIn(sensPage, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.onClick();
    const touched = (sensOps?.find(op => op.path[0] === 'sensitiveRules')?.value ?? []).filter(row => row.preset);
    assert.deepEqual(touched.map(row => `${row.preset}:${row.action}:${row.enabled}`), ['private-key:deny:true'],
        '改内置行只写回被改的那一条（带 preset，其余留在宿主默认）');

    // 检测规则的内容可改：内置行的正则写回同一条（preset 覆盖行），不是只存档位。
    const patternInput = findIn(builtinRow(), node => node.type === 'Input'
        && String(node.props?.value ?? '').includes('PRIVATE KEY'))[0];
    assert.ok(patternInput, '内置形状的条件列是可改的正则输入框');
    patternInput.props.onChange({ target: { value: 're:-----BEGIN MY KEY-----' } });
    sensPage = renderPage({ view: 'page', form: sensForm });
    await findIn(sensPage, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.onClick();
    const edited = (sensOps?.find(op => op.path[0] === 'sensitiveRules')?.value ?? [])
        .filter(row => row.preset === 'private-key')[0];
    assert.equal(edited?.match, 're:-----BEGIN MY KEY-----', '内置行的正则改了就存回去，不是只存档位');
    const noCell = node => String(node.props?.className ?? '').split(' ').includes('dsa-ruleNo');
    const rowNos = findIn(sensPage, node => noCell(node) && !String(node.props.className).includes('is-blank')).map(node => textOf(node).trim());
    assert.deepEqual(rowNos.slice(0, 2), ['1', '2'], '行首编号＝命中优先级，自定义块在前');
    assert.equal(rowNos.length, 9, '自定义 2 行＋内置 7 行都编号：内置不是表外另一排');
    assert.ok(textOf(sensPage).includes('内置（7）'), '内置行单独成组并计数');
    assert.ok(textOf(sensPage).includes('自定义（2）'), '用户行归「自定义」组');
    // 「留空编号列」这种占位行已经没有了：内置行就是表里的行，动作片自然与用户行同列。
    assert.equal(findIn(sensPage, node => noCell(node) && String(node.props.className).includes('is-blank')).length, 0,
        '不再有留空编号的占位行');
    assert.equal(findIn(sensPage, node => String(node.props?.className ?? '').includes('is-preset')).length, 0,
        '不再有「只读预设行」这一类');
    assert.equal(findIn(sensPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-detail')).length, 1,
        '点开敏感表时安全规则卡仍停在摘要，不能两张卡各画一份明细');
    // 「敏感信息」也是一张可进可出的明细：点进去要有返回键，返回后回到两行摘要。
    // 此前它没有头部、没有返回键——点进去就出不来。
    const backButtons = page => findIn(page, node => node.type === 'button' && textOf(node).trim() === '‹ 返回');
    const summaryCount = page => findIn(page, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow')).length;
    backButtons(sensPage)[0].props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    assert.equal(summaryCount(sensPage), 6, '检测规则明细返回后回到敏感保护卡的两行摘要');
    findIn(sensPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[5].props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    assert.ok(textOf(sensPage).includes('敏感信息'), '敏感信息明细页要有标题');
    assert.ok(textOf(sensPage).includes('明文只在本机映射表'), '明细页头要写清明文只在本机、查看会记账');
    const vaultBack = backButtons(sensPage)[0];
    assert.ok(vaultBack !== undefined, '敏感信息明细必须有「‹ 返回」');
    vaultBack.props.onClick();
    sensPage = renderPage({ view: 'page', form: sensForm });
    assert.equal(summaryCount(sensPage), 6, '敏感信息返回后回到两行摘要');
    // 空表那行只报状态，别把卡头已经说过的规则再念一遍（一句事实只留一处）。
    const emptyForm = { state: { status: 'ready', value: { ...stored, commandRules: [] }, writable: true }, mutate: async () => { } };
    resetHooks();
    renderPage({ view: 'page', form: emptyForm });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    let emptyPage = renderPage({ view: 'page', form: emptyForm });
    findIn(emptyPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'))[0].props.onClick();
    emptyPage = renderPage({ view: 'page', form: emptyForm });
    const emptyRow = findIn(emptyPage, node => String(node.props?.className ?? '').split(' ').includes('dsa-emptyList'))[0];
    assert.equal(textOf(emptyRow).replace(/\s+/g, ' ').trim(), '还没有自己的规则',
        '空表行只报状态；「未命中＝不表态、继续往下判」卡头已经说过，不该再念一遍');
    const rulesCardText = textOf(findIn(emptyPage, node => node.props?.id === 'frame-card-rules')[0]);
    assert.equal((rulesCardText.match(/继续往下/g) ?? []).length, 1, '同一张卡里这句解释只许出现一次');
    console.log('OK 检测规则留在敏感保护卡（摘要→明细）、总闸在卡头、内置检测作为预设行、能存回配置');
}

}

resetHooks();
const controls = [];
walkTree(renderPage({ view: 'page', form }), node => { if (['SegmentedControl', 'Switch', 'Input', 'Button'].includes(node.type)) controls.push(node); });
for (const node of controls.filter(item => item.type === 'SegmentedControl')) {
    assert.ok(typeof node.props.id === 'string' && node.props.id.startsWith('frame-'), 'SegmentedControl 缺 id 会被宿主拒绝');
    assert.ok(node.props.options.every(option => typeof option.label === 'string'), '分段控件每项都要有文案');
}
assert.ok(controls.every(node => node.type !== 'Input' || node.props.disabled !== true),
    '来源＝指定预设时手填项（若出现）必须可编辑');
// 指定预设 ⇒ 给一行「评审模型」下拉（列宿主已配好的模型，点一次写回两枚键）；
// 跟随会话 ⇒ 这几行整行消失，不是灰着留在那儿占视线。
{
    let modelOps = null;
    const presetForm = { state: { status: 'ready', value: stored, writable: true }, mutate: async ops => { modelOps = ops; } };
    resetHooks();
    reactEffects.splice(0);
    renderPage({ view: 'page', form: presetForm });
    flushEffects();
    // 关键一步：请求还在路上时先来一轮「重渲染＋重跑 effect」（status 从 idle 变 loading 就是会这样）。
    // 旧写法在这里返回的清理函数会把在途响应丢掉，页面永远停在「正在读取」——现在必须仍然落到 ready。
    renderPage({ view: 'page', form: presetForm });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    let page = renderPage({ view: 'page', form: presetForm });
    const card = findIn(page, node => node.props?.id === 'frame-card-review')[0];
    const picker = findIn(card, node => node.type === 'select' && String(node.props.className ?? '').includes('dsa-modelSelect'))[0];
    assert.ok(picker, '「指定预设」要给一行模型选择器，不是让人手敲 provider／model 字符串');
    assert.deepEqual(findIn(picker, node => node.type === 'optgroup').map(node => node.props.label),
        ['本机 vLLM', 'DeepSeek'], '按提供方分组，列宿主已注册好的模型');
    assert.ok(textOf(card).includes('Ollama 读不到模型'), '某个提供方读不到要写出来，不能悄悄少一组');
    assert.equal(findIn(card, node => node.type === 'Input').length, 0, '目录可用时不该再出现手填 Provider／Model 两行');
    picker.props.onChange({ target: { value: 'deepseek\u0000deepseek-chat' } });
    page = renderPage({ view: 'page', form: presetForm });
    await findIn(page, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.onClick();
    assert.deepEqual((modelOps ?? []).filter(op => op.path[0].startsWith('reviewer')).map(op => `${op.path[0]}=${op.value}`),
        ['reviewerProvider=deepseek', 'reviewerModel=deepseek-chat'], '一次点选写回两枚键');
    // 目录读失败 ⇒ 退回手填两行（这是真会发生的边界：提供方没配、或宿主没给这个路由）
    const brokenFetch = globalThis.fetch;
    globalThis.fetch = async url => (String(url).includes('/models') ? { ok: false, status: 500, json: async () => ({ ok: false, error: 'no route' }) } : brokenFetch(url));
    resetHooks();
    reactEffects.splice(0);
    renderPage({ view: 'page', form: presetForm });
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    const fallbackPage = renderPage({ view: 'page', form: presetForm });
    const fallbackCard = findIn(fallbackPage, node => node.props?.id === 'frame-card-review')[0];
    assert.equal(findIn(fallbackCard, node => node.type === 'select' && String(node.props.className ?? '').includes('dsa-modelSelect')).length, 0, '读不到目录就别摆一个空下拉');
    assert.ok(findIn(fallbackCard, node => node.type === 'Input').length >= 2, '读不到目录 ⇒ 退回手填 Provider／Model');
    globalThis.fetch = brokenFetch;
}
resetHooks();
const sessionForm = { state: { status: 'ready', value: { ...stored, reviewerSource: 'session' }, writable: true }, mutate: async () => { } };
{
    const sessionCard = findIn(renderPage({ view: 'page', form: sessionForm }), node => node.props?.id === 'frame-card-review')[0];
    const sessionText = textOf(sessionCard);
    assert.ok(!sessionText.includes('Provider') && !sessionText.includes('Model') && !sessionText.includes('评审模型'),
        '跟随会话 ⇒ 评审目标的三行全部消失（灰着留着也算没做对）');
    assert.equal(findIn(sessionCard, node => node.type === 'Input').length, 0, '跟随会话时不该有 provider/model 输入框');
    assert.equal(findIn(sessionCard, node => node.type === 'select').length, 0, '跟随会话时不该有模型下拉');
    assert.ok(sessionText.includes('启用 AI 快判'), '同卡其余字段照常显示，不是整卡被藏起来');
}
// One mounted page: hooks must persist across re-renders, exactly like React.
resetHooks();
const page = () => renderPage({ view: 'page', form });
const saveButton = () => findIn(page(), node => node.type === 'Button' && textOf(node).includes('保存'))[0];
assert.equal(saveButton().props.disabled, true, '无改动时保存必须禁用，避免空写');
const modeNode = findIn(page(), node => node.type === 'SegmentedControl' && node.props.id === 'frame-mode')[0];
modeNode.props.onChange('advise');
const saveAfter = saveButton();
assert.notEqual(saveAfter.props.disabled, true, '有改动后保存必须可点');
await saveAfter.props.onClick();
assert.deepEqual(mutated, [{ op: 'set', path: ['mode'], value: 'advise' }], '一次改动一条 op，且只点名 volatile 键');
resetHooks();
assert.equal(saveButton().props.disabled, true, '写回后 draft 与 stored 一致，保存重新禁用');
console.log('OK 控件契约与保存路径：id/文案齐备、依赖字段禁用、空改动禁保存、写出一条 volatile op');

// 规则表：摘要→明细两级；新增、改动作、调序、删除都写成结构化行，半截行不落盘
{
    let ruleOps = null;
    const ruleForm = {
        state: { status: 'ready', value: { ...stored, commandRules: [{ action: 'deny', match: 'rm -rf' }] }, writable: true },
        mutate: async ops => { ruleOps = ops; },
    };
    const summaryRows = tree => findIn(tree, node => String(node.props?.className ?? '').split(' ').includes('dsa-summaryRow'));
    const pills = tree => findIn(tree, node => String(node.props?.className ?? '').split(' ').includes('dsa-pill'));
    const norm = node => textOf(node).replace(/\s+/g, ' ').trim();
    // 新交互：点动作片 ⇒ 行下方展开同尺寸选项排 ⇒ 点一项即写回并收起。
    const pickAction = async (tree, page, locate, value) => {
        const pill = locate(tree);
        assert.ok(pill !== undefined, '找不到要改的动作片');
        pill.props.onClick();
        const strip = findIn(page(), node => String(node.props?.className ?? '').split(' ').includes('dsa-menu'))[0];
        assert.ok(strip !== undefined, '点开后要展开选项排');
        const option = findIn(strip, node => String(node.props?.className ?? '').split(' ').includes('dsa-menuItem'))
            .find(node => norm(node).startsWith(value));
        assert.ok(option !== undefined, `选项排里没有「${value}」`);
        option.props.onClick();
        return page();
    };
    const save = async tree => {
        await findIn(tree, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.onClick();
    };
    const rulePage = () => renderPage({ view: 'page', form: ruleForm });

    resetHooks();
    summaryRows(rulePage())[0].props.onClick();
    let tree = rulePage();
    const addInput = findIn(tree, node => node.type === 'Input' && String(node.props.placeholder ?? '').includes('git push'))[0];
    assert.ok(addInput, '明细页要有条件输入框（带示例 placeholder）');
    assert.equal(findIn(tree, node => node.type === 'Button' && textOf(node).includes('＋ 添加'))[0].props.disabled, true,
        '空条件时「＋ 添加」必须禁用，半截行进不了表');
    addInput.props.onChange({ target: { value: 'git push --force' } });
    tree = rulePage();
    findIn(tree, node => node.type === 'Button' && textOf(node).includes('＋ 添加'))[0].props.onClick();
    tree = rulePage();
    await save(tree);
    assert.deepEqual(ruleOps, [{
        op: 'set', path: ['commandRules'],
        value: [{ action: 'ask', match: 'git push --force' }, { action: 'deny', match: 'rm -rf' }],
    }], '新行用「新规则默认」那一档，并插到顶部');

    resetHooks();
    summaryRows(rulePage())[0].props.onClick();
    tree = rulePage();
    const rowPill = pills(tree)[1];
    assert.ok(rowPill !== undefined && textOf(rowPill).includes('拒绝'), '行内动作片要显示当前档位（拒绝）');
    tree = await pickAction(tree, rulePage, page => pills(page)[1], '允许');
    await save(tree);
    assert.deepEqual(ruleOps, [{ op: 'set', path: ['commandRules'], value: [{ action: 'release', match: 'rm -rf' }] }],
        '改成「允许」保存为 release 行（语义＝直接放行，不调模型、不弹面板）');

    resetHooks();
    summaryRows(rulePage())[0].props.onClick();
    tree = rulePage();
    findIn(tree, node => node.type === 'button' && textOf(node).trim() === '✕')[0].props.onClick();
    tree = rulePage();
    await save(tree);
    assert.deepEqual(ruleOps, [{ op: 'set', path: ['commandRules'], value: [] }], '删除行后保存空表');

    // 文件行：一行一个路径，读／写／删各自表态。
    let fileOps = null;
    const fileForm = {
        state: { status: 'ready', value: { ...stored, fileRules: [{ match: 'D:/logs', read: 'allow', write: '', delete: '' }] }, writable: true },
        mutate: async ops => { fileOps = ops; },
    };
    const filePage = () => renderPage({ view: 'page', form: fileForm });
    resetHooks();
    summaryRows(filePage())[1].props.onClick();
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    let fileTree = filePage();
    assert.ok(textOf(fileTree).includes('D:/logs'), '文件明细要列出自己的行');
    assert.ok(textOf(fileTree).includes('凭据与客户端目录'), '预设行排在同一张表底部');
    // 只数自己那一行上的片：工具条里「新规则默认」那三颗 title 不一样；内置行同表同形制，
    // 也有自己的片，所以按「哪一行装着 D:/logs」整行取，别按全表下标猜。
    const ownRow = tree => findIn(tree, node => String(node.props?.className ?? '').includes('dsa-sent')
        && findIn(node, child => child.type === 'Input' && child.props?.value === 'D:/logs').length > 0)[0];
    const opsOfRow = tree => pills(ownRow(tree)).map(node => norm(node));
    const labelled = opsOfRow(fileTree).filter(text => ['读取', '写入', '删除'].some(op => text.startsWith(op)) && text.includes('▾'));
    assert.deepEqual(labelled, ['读取 AI ▾', '写入 不表态 ▾', '删除 不表态 ▾'],
        `文件行要有读／写／删三颗片、各显当前档位（旧 allow 折成 AI），实得 ${labelled.join(' | ')}`);
    fileTree = await pickAction(fileTree, filePage, tree => pills(ownRow(tree)).find(node => norm(node).startsWith('写入')), '允许');
    await save(fileTree);
    assert.deepEqual(fileOps, [{
        op: 'set', path: ['fileRules'],
        value: [{ match: 'D:/logs', read: 'ai', write: 'release', delete: '' }],
    }], '同一行里读（旧 allow 折成 AI）、写＝允许（release）、删＝不表态要按原样存回');
    console.log('OK 规则表：两级导航、新增插顶、四档动作、按操作表态、删除与半截行都正确');
}

resetHooks();
const readonly = renderPage({ view: 'page', form: { state: { status: 'ready', value: stored, writable: false } } });
assert.ok(textOf(readonly).includes('不接收写入'), '只读态必须明说');
assert.equal(findIn(readonly, node => node.type === 'Button' && textOf(node).includes('保存'))[0].props.disabled, true, '只读态不得可保存');
resetHooks();
assert.ok(textOf(renderPage({ view: 'page', form: { state: { status: 'loading' } } })).includes('不接收写入'), '未就绪态同样禁止保存');
resetHooks();
assert.ok(textOf(renderPage({ view: 'page', form: {} })).includes('不接收写入'), '宿主没交表单时同样禁止保存');
console.log('OK 不可写／未就绪／无表单：页面明说并禁用保存，绝不静默丢弃编辑');

// 审计中心：从宿主审计路由取数并渲染（webview 读不了盘，数据由宿主递过来）
{
    const fetched = [];
    globalThis.fetch = async url => {
        const text = String(url);
        if (text.includes('/audit?')) fetched.push(text);
        return {
            ok: true,
            json: async () => (text.includes('/audit?')
                ? {
                    ok: true,
                    matched: 3,
                    total: 8,
                    segments: 1,
                    entries: [
                        { id: 'e9', sequence: 9, timestamp: Date.UTC(2026, 9, 27, 1, 6, 0), decision: 'allowed', category: 'tool', layer: 'fast', toolName: 'bash', commandPreview: 'rm -f junk0.txt', message: '垃圾桶里的可弃空文件', rule: 'deny rm -rf' },
                        { id: 'e8', sequence: 8, timestamp: Date.UTC(2026, 9, 27, 1, 5, 0), decision: 'ask', category: 'approval', layer: 'human', message: '人工答复：rejected' },
                        { id: 'e7', sequence: 7, timestamp: Date.UTC(2026, 9, 27, 1, 4, 0), decision: 'info', category: 'sensitive', layer: 'redact', toolName: 'read', message: '结果已脱敏：Bearer' },
                    ],
                    chain: { ok: true, lines: 8 },
                }
                : FRAME_BODY),
        };
    };
    resetHooks();
    reactEffects.splice(0);
    const livePage = () => renderPage({ view: 'page', form });
    let liveTree = livePage();
    assert.ok(textOf(liveTree).includes('正在读取'), '首帧显示读取中');
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    liveTree = livePage();
    assert.equal(fetched.length, 1, '首屏只发一次查询');
    assert.ok(fetched[0].startsWith('/api/auto-approval-frame/audit?'), `只请求宿主审计路由：${fetched[0]}`);
    assert.ok(fetched[0].includes('limit=50'));
    assert.ok(fetched[0].includes('hide=lifecycle.boot'), '默认隐藏启动记录');
    const text = textOf(liveTree);
    assert.ok(text.includes('审计中心'), text);
    assert.ok(text.includes('隐藏启动记录'), '筛选行要有开关');
    assert.ok(text.includes('匹配 3 / 共 8 条'), '渲染匹配数与总数');
    assert.ok(text.includes('链校验通过'), '渲染链校验状态');
    assert.ok(text.includes('已放行'), '渲染判定结果');
    assert.ok(text.includes('rm -f junk0.txt'), '渲染动作原文');
    assert.ok(text.includes('AI 快判'), '条目头部要按判定链的名字标层级');
    assert.ok(text.includes('结果已脱敏：Bearer') && text.includes('结果脱敏'), '脱敏记录的层级要对上链上第 6 步');
    assert.ok(findIn(liveTree, node => node.props?.className === 'dsa-entryLayer').length > 0, '层级要单独成片，不混在元信息串里');
    assert.ok(text.includes('规则 deny rm -rf'), '渲染命中的规则');
    assert.ok(text.includes('转人工'), '渲染第二类结果');
    assert.ok(text.includes('人工答复：rejected'), '渲染第二类结果的原话');
    assert.ok(text.includes('1–3 / 3 条'), '渲染分页信息');
    const bootSwitch = findIn(liveTree, node => node.type === 'Switch' && node.props.id === 'frame-audit-hide-boot')[0];
    assert.equal(bootSwitch.props.checked, true, '开关默认打开');
    bootSwitch.props.onChange(false);
    reactEffects.splice(0);
    livePage();
    flushEffects();
    await new Promise(resolve => setTimeout(resolve, 0));
    assert.equal(fetched.length, 2, '关掉开关后重新取数');
    assert.equal(fetched[1].includes('hide='), false, '关掉后不再隐藏启动记录');
}
console.log('OK 审计中心：同源取宿主审计并按筛选渲染条目');

// 受管档不在宿主权限表：卡片里必须出现可复制的 profile 片段。
FRAME_BODY.missingGatedPresets = ['auto-approval'];
resetHooks();
renderPage({ view: 'page', form });
flushEffects();
await new Promise(resolve => setTimeout(resolve, 0));
const missingPage = renderPage({ view: 'page', form });
const missingText = textOf(missingPage);
assert.ok(missingText.includes('受管权限档 auto-approval 不在宿主当前权限表里'), '缺失受管档要红字提示');
assert.ok(missingText.includes('- id: permission'), '提示里要给可复制的 profile 片段');
FRAME_BODY.missingGatedPresets = [];
console.log('OK 受管权限档缺失：设置页红字＋可复制片段');

console.log('\nALL CLIENT CASES PASS');
