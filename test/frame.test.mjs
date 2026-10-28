// Offline regression for the frame. Usage: node test/frame.test.mjs <fixture-dir>
// The fixture is a throwaway git repo outside the workspace; nothing here
// touches a live profile or a real document.
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync, symlinkSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { homedir } from 'node:os';
import assert from 'node:assert/strict';
import { normalizePath, isWithin, canonicalizeMsys } from '../lib/frame/paths.js';
import { splitSegments, tokenize } from '../lib/frame/parse.js';
import { collectFacts } from '../lib/frame/facts.js';
import { grantFor, isSensitiveBasename, neverReasonFor } from '../lib/frame/grant.js';
import { missingGatedPresets, resolveRoots, trustRejection, userIntents } from '../lib/frame/gate.js';
import { projectEvidence, BLOCK_BUDGETS } from '../lib/frame/evidence.js';
import { parseVerdict, mayRelease, buildSystemPrompt } from '../lib/frame/verdict.js';
import { createAuditStore, chainHash, bodyTextOf, renderEntry } from '../lib/frame/audit.js';
import { FLOOR_ROWS, RULE_PLANES, effectiveRows, evaluatePolicies, floorActions, networkTargets, parseRules, scanSensitive, sensitiveRows, trustRules } from '../lib/frame/policy.js';
import { createSecretVault } from '../lib/frame/vault.js';
import { createPendingStore } from '../lib/frame/pending.js';
import { redactSecrets } from '../lib/frame/sanitize.js';

const root = resolve(process.argv[2] ?? join(homedir(), 'Documents/ai/垃圾桶/frame-fixture'));
const ws = join(root, 'ws');
const trash = join(root, 'trash');
rmSync(root, { recursive: true, force: true });
mkdirSync(ws, { recursive: true });
mkdirSync(trash, { recursive: true });
const git = (...args) => execFileSync('git', ['-C', ws, ...args], { encoding: 'utf8', windowsHide: true });
git('init', '-q');
git('config', 'user.name', 'frame');
git('config', 'user.email', 'frame@example.invalid');
const write = (path, text = '') => writeFileSync(join(ws, path), text);
write('.gitignore', 'ignored.txt\n');
write('tracked-empty.txt');
write('tracked-dirty.txt', 'x');
git('add', '.');
git('commit', '-qm', 'baseline');
write('junk0a.txt');
write('junk0b.txt');
write('content.txt', 'hello');
write('ignored.txt');
write('.env', 'TOKEN=shhh');
mkdirSync(join(ws, 'sub'), { recursive: true });
write(join('sub', 'nested0.txt'));
mkdirSync(join(ws, 'emptydir'), { recursive: true });
write('l5.txt', 'log line');
writeFileSync(join(trash, 'l8.txt'), 'log line');
writeFileSync(join(trash, 'l10.txt'), '');
for (let index = 1; index <= 21; index += 1) write(`batch${index}.txt`);
let symlinkSupported = true;
try {
    symlinkSync(join(ws, 'junk0a.txt'), join(ws, 'link.txt'));
}
catch {
    symlinkSupported = false;
}

const allowRow = (match, ops = ['all']) => ({ action: 'allow', match, ops });
const config = { mode: 'auto', fileRules: [allowRow(trash)] };
const roots = resolveRoots(ws, config);
assert.equal(roots.workspace, normalizePath(ws, ws));
assert.equal(roots.trusted.length, 1, 'the trash dir must be accepted as a trusted root');
assert.deepEqual(roots.rejectedTrusted, [], 'fixture roots must not be rejected');
const run = (command) => {
    const facts = collectFacts({ toolName: 'bash', args: { command }, roots });
    return { facts, grant: grantFor(facts, roots) };
};
const state = (label, command, expected, ...reasonParts) => {
    const { grant } = run(command);
    assert.equal(grant.state, expected, `${label}: state ${grant.state} != ${expected} (${grant.reasons.join(', ')})`);
    for (const part of reasonParts)
        assert.ok(grant.reasons.some(reason => reason.includes(part)), `${label}: missing reason ${part} in ${grant.reasons.join(', ')}`);
    console.log(`OK ${label} :: ${grant.state} :: ${grant.reasons.join(', ') || '-'}`);
};

// ── paths ───────────────────────────────────────────────────────────────────
assert.equal(canonicalizeMsys('/c/Users/x'), process.platform === 'win32' ? 'C:\\Users\\x' : '/c/Users/x');
assert.ok(isWithin(ws, join(ws, 'sub', 'a.txt')));
assert.ok(!isWithin(ws, join(root, 'other')));
console.log('OK paths: containment + msys drive spelling');

// ── parse plane ─────────────────────────────────────────────────────────────
assert.deepEqual(tokenize('rm -f "two words"'), ['rm', '-f', 'two words']);
const compound = splitSegments('rm -f a b\necho exit=$?\nls a 2>/dev/null || echo gone');
assert.equal(compound.length >= 3, true);
assert.equal(compound[0].program, 'rm');
assert.equal(compound[0].words.filter(word => word.kind === 'operand').length, 2);
assert.equal(splitSegments('echo $(whoami) x')[0].opaque, true);
assert.equal(splitSegments('rm *.txt')[0].opaque, true, 'unquoted glob must be opaque');
assert.equal(splitSegments('cat a > out')[0].redirects.length, 1);
// Windows 绝对路径里的反斜杠是分隔符，不是 POSIX 转义：以前被吃掉后
// `rm -f C:\ws\a.txt` 变成 `C:wsa.txt`，再按工作区解析成一个假的内层路径，
// rootHit／git 状态全都错位——规则和信任范围都会被它骗。
assert.deepEqual(tokenize('rm -f C:\\ws\\a.txt'), ['rm', '-f', 'C:\\ws\\a.txt']);
assert.deepEqual(tokenize('cat \\\\server\\share\\f.txt'), ['cat', '\\\\server\\share\\f.txt']);
assert.deepEqual(tokenize('rm -f a\\ b'), ['rm', '-f', 'a b'], '普通的空格转义仍按 POSIX');
const winFacts = collectFacts({ toolName: 'bash', args: { command: `rm -f ${join(ws, 'junk0a.txt')}` }, roots });
assert.equal(winFacts.targets[0].path, normalizePath(join(ws, 'junk0a.txt'), ws),
    'Windows 绝对路径操作数要解析到真实文件');
assert.equal(winFacts.targets[0].rootHit, 'workspace');
assert.equal(winFacts.targets[0].gitState, 'untracked');
console.log('OK parse: quotes, compound segments, substitution, glob, redirect');

// ── L0: 只读命令必须走得到快路 ─────────────────────────────────────────────
// 真机台账实证：每条 `cd … && grep -rn 'a|b' … | head -20` 都被送去评审。
// 成因是 cd / awk 这类程序落进 segmentOpClass 的默认 exec 分支，只要混进一个
// 非读段，「所有段都是读」的快路判据就整条失效。
{
    const { facts } = run(`cd "${ws}" && grep -rn "file\\|path\\|dir" . | head -20`);
    assert.deepEqual(facts.segments.map(segment => segment.opClass), ['read', 'read', 'read'],
        'cd / grep / head 都必须是读');
    assert.equal(facts.opaque, false, 'grep 的正则不是未解析路径，不该整条标 opaque');
}
{
    const { facts } = run(`grep -rn "a|b" "${ws}" | awk '{print $1}'`);
    assert.deepEqual(facts.segments.map(segment => segment.opClass), ['read', 'read'],
        'awk 是流过滤器，管道右侧不写盘');
}
// 模式操作数不是路径候选：把它当路径读，曾把 `file|path|dir|...` 这种正则片段
// 同时写进台账和评审模型看到的证据块。
{
    const { facts } = run('grep -rn "file\\|path\\|dir" .');
    assert.equal(facts.targets.some(target => String(target.input ?? '').includes('\\|')), false,
        '正则片段不得出现在 targets 里');
    assert.ok(facts.targets.every(target => target.dynamic !== true || target.opClass !== 'read'),
        '读段的动态操作数不再进 targets');
}
// 原地改写仍然是写，不管 flag 怎么拼。
{
    const { facts } = run(`sed -i.bak 's/a/b/' "${join(ws, 'content.txt')}"`);
    assert.deepEqual(facts.segments.map(segment => segment.opClass), ['write'], 'sed -i 必须是写');
}
console.log('OK 只读快路：cd/awk 归读，模式操作数不再冒充路径，sed -i 仍是写');

// 会话内部工具（compress 等）只编辑会话、没有对外副作用；它曾被当成
// unclassified-tool 送去深评并转人工，属于误报。
{
    const facts = collectFacts({ toolName: 'compress', args: { content: [{ startId: 'm00001', endId: 'm00008' }] }, roots });
    assert.equal(facts.segments[0].opClass, 'internal');
    const grant = grantFor(facts, roots);
    assert.equal(grant.state, 'auto', grant.reasons.join(', '));
    assert.equal(grant.reasons.includes('unclassified-tool'), false);
}
console.log('OK 会话内部工具：compress 归 internal，不再触发未分类工具');

// ── L0/L1: the deletion shapes ──────────────────────────────────────────────
state('three zero-byte untracked files', 'rm junk0a.txt junk0b.txt sub/nested0.txt', 'auto');
state('rm -f zero-byte', 'rm -f junk0a.txt', 'auto');
state('rm -- separator', 'rm -- junk0a.txt', 'auto');
state('rm -fv combined', 'rm -fv junk0a.txt', 'auto');
state('msys absolute inside workspace', `rm -f /${ws[0].toLowerCase()}/${ws.slice(3).replaceAll('\\', '/')}/junk0a.txt`, 'auto');
state('quoted windows absolute', `rm -f "${ws}\\junk0a.txt"`, 'auto');
state('bash escapes leave a mangled absent name', `rm -f ${ws}\\junk0a.txt`, 'auto');
state('spaced filename', `rm -f "${join(ws, 'sub', 'nested0.txt')}"`, 'auto');
state('compound rm + echo stays auto', 'rm -f junk0a.txt\necho exit=$?', 'auto');
state('compound rm + verify ls', `rm -f "${ws}\\junk0a.txt"\nls "${ws}\\junk0a.txt" 2>/dev/null || echo gone`, 'auto');
state('trash file with content (trusted root)', `rm -f "${join(trash, 'l8.txt')}"`, 'auto');
state('trash zero-byte', `rm -f "${join(trash, 'l10.txt')}"`, 'auto');
state('tracked file delete stays releasable', 'rm tracked-dirty.txt', 'auto');
assert.equal(run('rm tracked-dirty.txt').facts.targets[0].gitState, 'tracked');
assert.equal(run('rm content.txt').facts.targets[0].gitState, 'untracked');
assert.equal(run('rm ignored.txt').facts.targets[0].gitState, 'ignored');
console.log('OK git state carried per target: tracked / untracked / ignored distinguished');
state('ignored zero-byte', 'rm ignored.txt', 'auto');
state('untracked file with content is not releasable', 'rm content.txt', 'confirm', 'unrecoverable-content');
// 真机事故：同一批文件删第二次（已不存在）不该再要人工确认一次"删空气"
writeFileSync(join(ws, 'gone.txt'), '');
state('already-absent delete is a no-op', 'rm -f gone.txt', 'auto');
{
    const { grant } = run('rm -f gone.txt');
    assert.equal(grant.reasons.includes('delete-of-non-file'), false, grant.reasons.join(', '));
}
state('absent inside trusted dir stays releasable', `rm -f "${join(trash, 'never-existed.log')}"`, 'auto');
writeFileSync(join(ws, 'gone.txt'), 'x');
writeFileSync(join(ws, 'sub', 'nested0.txt'), 'now it has content');
state('real directory delete still asks', 'rmdir emptydir', 'confirm', 'delete-of-non-file');
writeFileSync(join(ws, 'sub', 'nested0.txt'), '');
state('empty flag delete is unknown-operand-free', 'rm -i junk0a.txt', 'confirm', 'unrecognized-delete-flag');
state('files0-from reads a hidden list', 'rm --files0-from list.txt', 'confirm', 'unrecognized-delete-flag');
state('recursive delete never auto-releases', 'rm -rf emptydir', 'confirm', 'recursive-delete');
state('rmdir of a directory', 'rmdir emptydir', 'confirm', 'delete-of-non-file');
state('glob operand is unresolvable', 'rm batch*.txt', 'confirm', 'unresolvable-operand');
state('command substitution is opaque', 'rm -f $(printf junk0a.txt)', 'confirm', 'opaque-command');
state('batch above the limit', `rm ${Array.from({ length: 21 }, (_, index) => `batch${index + 1}.txt`).join(' ')}`, 'confirm', 'batch-too-large');
state('shred is elevated', 'shred junk0a.txt', 'confirm', 'elevated-operation:destroy');
state('dd is elevated', 'dd if=/dev/zero of=disk.img', 'confirm', 'elevated-operation:destroy');
state('chmod is elevated', 'chmod 777 junk0a.txt', 'confirm', 'elevated-operation:privilege');
state('git push --force is elevated', 'git push --force', 'confirm', 'history-rewrite');
state('outside every trusted root', `rm -f "${join(homedir(), 'Desktop', 'x.txt')}"`, 'confirm', 'path-outside-trusted-roots');
state('cd then delete outside', 'cd /c/Windows/System32\nrm -f hosts', 'never', 'os-critical-tree');
if (symlinkSupported)
    state('symlink operand', 'rm -f link.txt', 'confirm', 'symlink-operand');

// ── L1: the never floor (the three paths that leaked in the old frame) ──────
const neverCases = [
    [`${homedir()}\\.ssh\\id_ed25519`, 'credential-or-client-tree'],
    [`${homedir()}\\.dsh\\.credentials.yaml`, 'credential-or-client-tree'],
    [`${homedir()}\\AppData\\Roaming\\gcloud\\credentials.json`, 'credential-or-client-tree'],
    [`${homedir()}\\.dsh\\auto-approval-llm\\audit.jsonl`, 'credential-or-client-tree'],
    [`${ws}\\.env`, 'credential-material'],
    [`${ws}\\.git\\config`, 'credential-or-client-tree'],
    ['C:\\', 'filesystem-root'],
    [homedir(), 'home-root'],
    [ws, 'workspace-root'],
    ['C:\\Windows\\System32\\config', 'os-critical-tree'],
];
for (const [path, expected] of neverCases) {
    const target = { path: normalizePath(path, ws, roots.home), opClass: 'delete' };
    const reason = neverReasonFor(target, roots);
    assert.equal(reason, expected, `${path}: never reason ${reason} != ${expected}`);
}
console.log(`OK never floor: ${neverCases.length} paths pinned to a human`);
assert.equal(neverReasonFor({ path: normalizePath(join(ws, 'junk0a.txt'), ws), opClass: 'delete' }, roots), undefined);
assert.equal(isSensitiveBasename('.env.example'), false);
assert.equal(isSensitiveBasename('.env.local'), true);
assert.equal(isSensitiveBasename('id_ed25519'), true);
assert.equal(isSensitiveBasename('notes.md'), false);
console.log('OK credential basename matcher incl. .env.example exemption');

// ── L1 exception: an opened DSH_HOME subtree is an `allow` row, not a key ────
const skillsOpen = join(roots.dshHome, 'skills');
const openedRoots = resolveRoots(ws, {
    fileRules: [allowRow(skillsOpen), allowRow(roots.dshHome), allowRow(join(roots.dshHome, 'sessions', '.ssh'))],
});
assert.equal(openedRoots.dshOpen.length, 1, 'only a subtree of the state tree may be opened');
assert.equal(openedRoots.rejectedTrusted.map(item => item.reason).sort().join(','), 'credential-or-client-tree,whole-state-tree');
const openedTarget = (path, opClass = 'delete') => neverReasonFor({ path: normalizePath(path, ws, roots.home), opClass }, openedRoots);
assert.equal(openedTarget(join(skillsOpen, 'docgov.md')), undefined, 'an opened subtree is not harness state');
assert.equal(openedTarget(join(skillsOpen, '.env')), 'credential-material');
assert.equal(openedTarget(join(roots.dshHome, 'sessions', 'a.jsonl')), 'credential-or-client-tree');
assert.equal(neverReasonFor({ path: normalizePath(join(roots.dshHome, 'auto-approval-frame', 'decisions.jsonl'), ws, roots.home), opClass: 'delete' }, roots), 'credential-or-client-tree');
// An opening row scoped to one operation must not excuse the others.
const readScoped = resolveRoots(ws, { fileRules: [allowRow(skillsOpen, ['read'])] });
assert.equal(neverReasonFor({ path: normalizePath(join(skillsOpen, 'docgov.md'), ws, roots.home), opClass: 'delete' }, readScoped),
    'credential-or-client-tree', '只开「读取」的行打不开 `.dsh`，删除仍必人工');
assert.equal(neverReasonFor({ path: normalizePath(join(skillsOpen, 'docgov.md'), ws, roots.home), opClass: 'read' }, readScoped),
    undefined, '该开的读操作仍然放行');
console.log('OK DSH_HOME opening: subtree only, per-operation, credential rules still absolute');

// ── L1 guard: what an `allow` row may declare as a trust root ────────────────
const guard = [
    [homedir(), 'home-root'],
    [join(homedir(), 'Documents'), 'too-broad'],
    ['relative/dir', 'not-absolute'],
    ['C:\\', 'filesystem-root'],
    [join(homedir(), '.ssh'), 'credential-or-client-tree'],
    [join(homedir(), '.dsh'), 'whole-state-tree'],
    [ws, 'workspace-root'],
];
for (const [dir, expected] of guard)
    assert.equal(trustRejection(dir, roots), expected, `${dir}: ${trustRejection(dir, roots)} != ${expected}`);
assert.equal(trustRejection(trash, roots), undefined);
assert.equal(trustRejection('re:^c:/x', roots), 'regex-operand', 'a trust row must name a path, not a regex');
console.log(`OK trusted-root guard: ${guard.length} rejections + 1 acceptance`);
assert.equal(resolveRoots(ws, { fileRules: [allowRow(homedir()), allowRow(trash)] }).trusted.length, 1);
console.log('OK resolveRoots drops the rejected row and reports it');

// ── managed permission tier existence ───────────────────────────────────────
const catalog = { optionOf: name => { if (name !== 'auto-approval') throw new Error('unknown'); return { name }; } };
assert.deepEqual(missingGatedPresets(catalog, ['auto-approval', 'custom-tier']), ['custom-tier'],
    '宿主目录里没有的受管档必须报出来');
assert.deepEqual(missingGatedPresets(catalog, ['auto-approval']), []);
assert.deepEqual(missingGatedPresets(undefined, ['auto-approval']), [],
    '读不到权限目录时不猜缺失（交给启动/页面其它判据）');
console.log('OK 受管权限档：宿主目录缺档要报出来，服务缺失不猜');

// ── L2 verdict contract ─────────────────────────────────────────────────────
const allow = '{"status":"reviewed","decision":"allow","reasonCode":"no_material_risk","summary":"disposable"}';
assert.equal(parseVerdict(allow).decision, 'allow');
assert.equal(parseVerdict(`Here you go:\n\`\`\`json\n${allow}\n\`\`\``).decision, 'allow');
const contradicted = parseVerdict('{"status":"reviewed","decision":"allow","reasonCode":"data_egress","summary":"x"}');
assert.equal(contradicted.decision, 'block');
assert.equal(contradicted.invariantRepaired, 'allow-requires-no-material-risk');
assert.equal(parseVerdict('{"status":"reviewed","decision":"block","reasonCode":"no_material_risk"}').status, 'unable');
assert.equal(parseVerdict('').unableReason, 'schema_invalid');
assert.equal(parseVerdict('I cannot decide').unableReason, 'schema_invalid');
assert.equal(parseVerdict('{"status":"reviewed","decision":"allow","reasonCode":"no_material_risk","summary":"he said ""delete"" them"}').summary, 'he said "delete" them');
assert.equal(parseVerdict('{"status":"unable","unableReason":"whatever"}').unableReason, 'reviewer_unable');
assert.equal(parseVerdict('{"status":"unable","unableReason":"timeout"}').unableReason, 'timeout');
// 小模型常把裁决本身写进 status（{"status":"block","decision":"block",...}）。
// 严格形状检查会整条丢掉，操作员为一个语义正确的答案付了钱却读不到。
{
    const repaired = parseVerdict('{"status":"block","decision":"block","reasonCode":"unauthorized_by_user","summary":"x"}');
    assert.equal(repaired.status, 'reviewed');
    assert.equal(repaired.decision, 'block');
    assert.equal(repaired.reasonCode, 'unauthorized_by_user');
}
{
    const denied = parseVerdict('{"status":"deny","decision":"block","reasonCode":"other","summary":"y"}');
    assert.equal(denied.status, 'reviewed');
    assert.equal(denied.decision, 'block');
}
// 别名只在 decision 自身合法时生效：不许靠 status 发明裁决。
assert.equal(parseVerdict('{"status":"block","reasonCode":"other"}').status, 'unable');
assert.equal(parseVerdict('{"status":"allow","decision":"maybe","reasonCode":"other"}').status, 'unable');
console.log('OK verdict: strict parse, fence + doubled-quote repair, status 别名归一, allow⇔no_material_risk');
const reviewed = { status: 'reviewed', decision: 'allow', reasonCode: 'no_material_risk' };
assert.equal(mayRelease(reviewed, { state: 'auto' }, 'auto'), true);
assert.equal(mayRelease(reviewed, { state: 'auto' }, 'advise'), false);
assert.equal(mayRelease(reviewed, { state: 'confirm' }, 'auto'), false);
assert.equal(mayRelease({ status: 'unable', unableReason: 'timeout' }, { state: 'auto' }, 'auto'), false);
console.log('OK release matrix: ALLOW binds to grant=auto × mode=auto');
assert.ok(buildSystemPrompt({ reviewRules: ['拒绝查看 ~/.ssh'] }).includes('rule-1'));
assert.ok(buildSystemPrompt({}).includes('OPERATOR') === false);
console.log('OK operator rules travel as data with the anti-override notice');

// ── L2 evidence budgets ─────────────────────────────────────────────────────
const big = run('rm junk0a.txt junk0b.txt');
const projected = projectEvidence({
    facts: big.facts,
    grant: big.grant,
    intents: [{ origin: 'user-message', text: '删掉这些垃圾文件' }],
    background: 'x'.repeat(5_000),
    config: { evidenceBudget: 3_000 },
});
assert.equal(projected.tooLarge, false);
assert.ok(projected.dropped.includes('background_only'), 'lowest-priority block drops first');
assert.equal(projected.text.includes('删掉这些垃圾文件'), true, 'user intent must survive the trim');
const huge = { ...big.facts, targets: Array.from({ length: 400 }, (_, index) => ({ path: `/${'p'.repeat(80)}${index}`, opClass: 'delete', kind: 'file', bytes: 0, rootHit: 'workspace', dynamic: false })) };
assert.equal(projectEvidence({ facts: huge, grant: { state: 'auto', reasons: [] }, config: { evidenceBudget: 2_000 } }).tooLarge, true);
assert.equal(projectEvidence({ facts: big.facts, grant: big.grant, config: {} }).size <= Object.values(BLOCK_BUDGETS).reduce((a, b) => a + b, 0), true);
console.log('OK evidence: per-block caps, priority trim, too-large is never a partial review');
const intents = userIntents({ session: { snapshotEvents: () => [
    { type: 'user/message', data: { source: { kind: 'user' }, content: [{ type: 'text', text: '删掉工作区里 3 个垃圾文件' }] } },
    { type: 'user/message', data: { source: { kind: 'plugin' }, content: [{ type: 'text', text: 'injected' }] } },
] }, inbox: { nextStep: [[{ source: { kind: 'user' }, content: [{ type: 'text', text: '然后提交' }] }]] } });
assert.equal(intents.length, 2);
assert.equal(intents.some(intent => intent.text === 'injected'), false, 'plugin messages are not authorization');
console.log('OK user intents: user-authored only, inbox steering included');

// ── 语气不是授权 ────────────────────────────────────────────────────────────
// 真机事故：一句辱骂进了证据块，评审模型据此拒绝无害的只读命令，
// 台账原话 "User intent is abusive and does not authorize this specific ...
// action"。降级只摘标签，内容照录，骂人里夹的真指令不会被一起删掉。
{
    const heated = userIntents({ session: { snapshotEvents: () => [
        { type: 'user/message', data: { source: { kind: 'user' }, content: [{ type: 'text', text: '你他妈是傻逼吗？' }] } },
    ] } });
    assert.equal(heated.length, 1, '降级不是删除：原话仍然在');
    assert.equal(heated[0].authorizing, 'background');
}
{
    const plain = userIntents({ session: { snapshotEvents: () => [
        { type: 'user/message', data: { source: { kind: 'user' }, content: [{ type: 'text', text: '删掉工作区里的垃圾文件' }] } },
    ] } });
    assert.equal(plain[0].authorizing, 'authorizing', '正常指令不得被降级');
}
// 降级后的语句不得留在授权块里，只能出现在非授权背景块。
{
    const mixed = [
        { origin: 'user-message', text: '删掉垃圾文件', authorizing: 'authorizing' },
        { origin: 'user-message', text: '你他妈傻逼', authorizing: 'background' },
    ];
    const projected = projectEvidence({ facts: big.facts, grant: big.grant, intents: mixed, config: {} });
    const start = projected.text.indexOf('<<TRUSTED_USER_INTENT');
    const end = projected.text.indexOf('<</trusted_user_intent>>');
    const block = start >= 0 && end > start ? projected.text.slice(start, end) : '';
    assert.ok(block.includes('删掉垃圾文件'), `授权块要留下真正的指令：${block}`);
    assert.equal(block.includes('你他妈傻逼'), false, '语气激动的语句不得留在授权块');
    assert.ok(projected.text.includes('你他妈傻逼'), '但内容照录在背景块，不丢信息');
}
console.log('OK 意图证据：辱骂句降级为背景，内容保留、授权标签摘除');

// ── 配置面单一性：服务端名单 ≡ 卡片字段 ≡ 补丁声明 ─────────────────────────
// 卡片写入点名非 volatile 键会被配置面整批拒绝，所以这三份名单必须逐键相等。
{
    const { readFileSync: read } = await import('node:fs');
    const server = read(new URL('../lib/index.js', import.meta.url), 'utf8');
    const client = read(new URL('../lib/client.js', import.meta.url), 'utf8');
    const patch = read(new URL('../cordis.patch.yml', import.meta.url), 'utf8');
    const list = (source, name) => {
        const matched = new RegExp(`const ${name} = \\[([\\s\\S]*?)\\];`).exec(source);
        return matched === null ? [] : [...matched[1].matchAll(/["']([\w]+)["']/g)].map(item => item[1]);
    };
    const editable = list(server, 'EDITABLE_KEYS');
    const hostOnly = list(server, 'HOST_ONLY_KEYS');
    const cardFields = [...client.matchAll(/\bkey: "([\w]+)", type:/g)].map(item => item[1]);
    const cardReadonly = list(client, 'HOST_ONLY_KEYS');
    const insertBlock = patch.slice(patch.indexOf('- insert:'));
    const declared = [...insertBlock.matchAll(/^ {8}([\w]+):/gm)].map(item => item[1]);
    assert.deepEqual([...editable, ...hostOnly].sort(), declared.slice().sort(), 'server lists must cover the shipped patch config exactly');
    assert.deepEqual(cardFields.sort(), editable.sort(), 'the card must expose exactly the volatile keys');
    assert.deepEqual(cardReadonly.sort(), hostOnly.sort(), 'the card must name the host-owned keys it refuses to write');
    assert.equal(editable.filter(key => hostOnly.includes(key)).length, 0, 'a key cannot be both card-owned and host-owned');
    console.log(`OK config surface: ${declared.length} 键＝${editable.length} 可写＋${hostOnly.length} 补丁only，三份名单一致`);
}

// ── L4 audit store: day segments, manifest sha256, chain, retention, clear ──
const readFileSync = (await import('node:fs')).readFileSync;
const { createHash } = await import('node:crypto');
const auditDir = join(root, 'audit');
const clock = { now: Date.UTC(2026, 9, 27, 9, 0, 0) };
const audit = createAuditStore({ dir: auditDir, now: () => clock.now, maxSegmentBytes: 600 });
assert.equal(audit.append({ category: 'lifecycle', eventType: 'lifecycle.boot', decision: 'info', layer: 'lifecycle', message: '启动' }).ok, true);
for (let index = 0; index < 4; index += 1)
    assert.equal(audit.append({ category: 'tool', eventType: 'tool.allowed', decision: 'allowed', layer: 'fast', toolName: 'bash', commandPreview: `rm -f junk${index}.txt`, message: `ok ${index}` }).ok, true);
const segmentFiles = () => readdirSync(auditDir).filter(name => /^\d{4}-\d{2}-\d{2}(?:\.\d+)?\.jsonl$/.test(name));
assert.ok(segmentFiles().length >= 2, `单段上限必须真的切段：${segmentFiles().join(', ')}`);
const verified = audit.verify();
assert.equal(verified.ok, true, JSON.stringify(verified.issues));
assert.equal(verified.lines, 5);
assert.equal(verified.segments, segmentFiles().length);
const manifestRows = () => readFileSync(join(auditDir, 'manifest.jsonl'), 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
const closedRows = manifestRows().filter(row => row.event === 'segment-closed');
assert.ok(closedRows.length >= 1, '封段必须写 manifest');
assert.equal(closedRows[0].entryCount > 0, true);
const closedSha = createHash('sha256').update(readFileSync(join(auditDir, closedRows[0].segment))).digest('hex');
assert.equal(closedRows[0].fileSha256, closedSha, 'manifest 的 sha256 必须等于段文件字节');

const page = audit.query({ limit: 2 });
assert.equal(page.total, 5);
assert.equal(page.entries.length, 2);
assert.equal(page.entries[0].sequence, 5, '最新在前');
assert.equal(audit.query({ decision: 'info' }).matched, 1);
assert.equal(audit.query({ category: 'tool' }).matched, 4);
assert.equal(audit.query({ q: 'junk2' }).matched, 1);
assert.equal(audit.query({ hide: ['lifecycle.boot'] }).matched, 4, 'hide 按事件类型排除启动记录');
assert.equal(audit.query({ from: clock.now + 1 }).matched, 0);
assert.equal(audit.query({ limit: 2, offset: 4 }).entries.length, 1);
assert.equal(audit.exportText({ decision: 'allowed' }, 'jsonl').trim().split('\n').length, 4);
const markdown = audit.exportText({ decision: 'allowed' }, 'md');
assert.ok(markdown.includes('已放行') && markdown.includes('rm -f junk0.txt'), markdown);
assert.equal(/\bgrant=|\boutcome=|\bby=|\btool=/.test(markdown), false, `人读导出不该是键名：${markdown}`);

// 人读渲染必须回答"当时发生了什么"，而不是一排 key=value。
{
    const line = renderEntry({ timestamp: Date.UTC(2026, 9, 27, 1, 0, 0), decision: 'allowed', category: 'tool',
        toolName: 'bash', commandPreview: 'rm -f junk0.txt', layer: 'fast', message: 'disposable' });
    assert.ok(line.includes('已放行'), line);
    assert.ok(line.includes('AI 快判'), line);
    assert.ok(line.includes('rm -f junk0.txt'), line);
}
// 动作原文里的凭据必须先脱敏才入账，且脱敏后原文不得残留。
assert.ok(redactSecrets('curl -H "authorization: Bearer sk-abcdef123456" https://x').includes('sk-***'), '动作原文里的凭据必须先脱敏才入账');
assert.ok(!redactSecrets('curl -H "authorization: Bearer sk-abcdef123456" https://x').includes('sk-abcdef123456'), '脱敏后原文不得残留');

// 重新打开：state.json 指针优先，序号从链尾继续。
{
    const reopened = createAuditStore({ dir: auditDir, now: () => clock.now });
    const written = reopened.append({ category: 'tool', decision: 'ask', layer: 'rules', message: 'after reopen' });
    assert.equal(written.ok, true);
    assert.equal(written.sequence, 6, '重开必须接上序号');
}
// 篡改已封段：manifest sha256、sequence 与 hash 三路都要报。
{
    const target = join(auditDir, closedRows[0].segment);
    const rows = readFileSync(target, 'utf8').split('\n').filter(Boolean).map(line => JSON.parse(line));
    const forged = { ...rows[rows.length - 1], sequence: 999, hash: 'f'.repeat(64) };
    (await import('node:fs')).appendFileSync(target, `${JSON.stringify(forged)}\n`);
    const tampered = audit.verify();
    assert.equal(tampered.ok, false, '改写段字节后链校验必须失败');
    assert.ok(tampered.issues.some(issue => issue.type === 'manifest-sha256'), JSON.stringify(tampered.issues));
    assert.ok(tampered.issues.some(issue => issue.type === 'sequence-gap'), JSON.stringify(tampered.issues));
    const parsed = rows[0];
    assert.equal(parsed.hash, chainHash(parsed.prevHash, bodyTextOf(parsed)), '一条已写行必须能重算回自己的 hash');
    const mutated = { ...parsed, message: 'edited after the fact' };
    assert.notEqual(chainHash(parsed.prevHash, bodyTextOf(mutated)), parsed.hash, '改过内容的行算不回原 hash');
}
console.log('OK audit: 分段/摘要/manifest sha256/查询/导出/篡改检测/重开续号');

// ── retention: 超龄段整段裁剪，留墓碑，链仍可校验 ──────────────────────────
{
    const dir = join(root, 'audit-retention');
    const retentionClock = { now: Date.UTC(2026, 0, 1, 12) };
    const store = createAuditStore({ dir, now: () => retentionClock.now, maxSegmentBytes: 300, retentionDays: 30 });
    store.append({ category: 'tool', decision: 'allowed', layer: 'fact', message: 'old day' });
    retentionClock.now = Date.UTC(2026, 0, 20, 12);
    store.append({ category: 'tool', decision: 'allowed', layer: 'fact', message: 'kept day' });
    retentionClock.now = Date.UTC(2026, 1, 15, 12);
    store.prune();
    const kept = readdirSync(dir).filter(name => /^\d{4}-\d{2}-\d{2}(?:\.\d+)?\.jsonl$/.test(name));
    assert.deepEqual(kept, ['2026-01-20.jsonl'], '超龄段必须裁掉，新段保留');
    const tombstones = readFileSync(join(dir, 'manifest.jsonl'), 'utf8').split('\n').filter(Boolean)
        .map(line => JSON.parse(line)).filter(row => row.event === 'retention-pruned');
    assert.equal(tombstones.length, 1, '裁剪必须留墓碑');
    assert.equal(tombstones[0].segment, '2026-01-01.jsonl');
    assert.equal(store.verify().ok, true, JSON.stringify(store.verify().issues));
}
console.log('OK retention: 整段裁剪 + 墓碑，链校验跨墓碑仍成立');

// ── clear: 段全删、manifest 只留清空标记、链从创世重启 ─────────────────────
{
    const dir = join(root, 'audit-clear');
    const store = createAuditStore({ dir });
    store.append({ category: 'tool', decision: 'blocked', layer: 'rules', message: 'before clear' });
    store.clear();
    const after = store.query({ limit: 10 });
    assert.equal(after.total, 1, '清空后只留一条清空事件');
    assert.equal(after.entries[0].eventType, 'audit.clear');
    assert.equal(after.entries[0].sequence, 1, '链从创世重启');
    assert.equal(store.verify().ok, true, JSON.stringify(store.verify().issues));
    const cleared = readFileSync(join(dir, 'manifest.jsonl'), 'utf8').split('\n').filter(Boolean)
        .map(line => JSON.parse(line)).filter(row => row.event === 'audit-cleared');
    assert.equal(cleared.length, 1);
    assert.equal(cleared[0].clearedEntries, 1);
}
console.log('OK clear: 段删除 + 清空标记 + 序号归零，校验仍通过');

// ── migration: 旧单文件台账整块导入并原样留存 ──────────────────────────────
{
    const dir = join(root, 'audit-legacy');
    const store = createAuditStore({ dir });
    const legacyPath = join(root, 'legacy-decisions.jsonl');
    const rows = [
        { at: Date.UTC(2026, 9, 26, 1), event: 'boot', sequence: 1, summary: 'boot' },
        { at: Date.UTC(2026, 9, 26, 2), event: 'decision', sequence: 2, toolName: 'bash', grant: 'auto', outcome: 'allowed-once', decidedBy: 'ai', action: 'rm -f x.txt', summary: 'ok', reasons: [] },
        { at: Date.UTC(2026, 9, 26, 3), event: 'human-answer', sequence: 3, toolName: 'bash', outcome: 'approved', summary: 'approve' },
        { at: Date.UTC(2026, 9, 26, 4), event: 'other', sequence: 4 },
    ];
    writeFileSync(legacyPath, `${rows.map(row => JSON.stringify(row)).join('\n')}\n`);
    const migration = store.migrateLegacy(legacyPath);
    assert.equal(migration.ok, true, migration.reason);
    assert.equal(migration.imported, 3, '只导入已知形状的行');
    assert.equal((await import('node:fs')).existsSync(legacyPath), false, '旧文件必须移走而不是复制');
    assert.equal(readdirSync(join(dir, 'legacy')).length, 1, '旧文件原样留在 legacy/ 作证据');
    const migrated = store.query({ limit: 10 }).entries;
    assert.equal(migrated.some(entry => entry.eventType === 'lifecycle.migrate'), true);
    // 生命周期行不许冒充「内置行」：层级名要和它做的事对上，否则台账里的「内置行」一大片，
    // 真正被内置行拦下的动作反而找不出来。
    assert.equal(migrated.filter(entry => entry.category === 'lifecycle').every(entry => entry.layer === 'lifecycle'), true,
        JSON.stringify(migrated.filter(entry => entry.category === 'lifecycle')));
    assert.equal(migrated.some(entry => entry.eventType === 'approval.answer' && entry.decision === 'approved'), true);
    assert.equal(migrated.some(entry => entry.eventType === 'tool.allowed' && entry.commandPreview === 'rm -f x.txt'), true);
    assert.equal(store.verify().ok, true, JSON.stringify(store.verify().issues));
}
console.log('OK migration: 旧台账逐行映射、原文件移入 legacy/、SHA 记入链');

// ── L1 rule tables: ordered rows, allow is not a release, strictest plane wins ─
{
    const rows = parseRules(['deny rm -rf', { action: 'ask', match: 'curl' }, '# comment', 'nonsense',
        { action: 'allow', match: 'git push' }], 'command');
    assert.equal(rows.length, 3, '旧字符串行与新结构化行同源解析');
    const segs = command => collectFacts({ toolName: 'bash', args: { command }, roots }).segments;
    assert.deepEqual(segs('git push origin main').map(segment => segment.words), [['push', 'origin', 'main']],
        '段必须带上有序参数串，命令规则靠前缀匹配');

    const deny = evaluatePolicies({
        toolName: 'bash', command: 'rm -rf build', segments: segs('rm -rf build'),
        config: { commandRules: ['deny rm -rf'] },
    });
    assert.deepEqual([deny.decision, deny.plane], ['deny', 'command']);

    const ordered = evaluatePolicies({
        toolName: 'bash', command: 'git push origin main', segments: segs('git push origin main'),
        config: { commandRules: [{ action: 'allow', match: 'git push' }, { action: 'deny', match: 'git' }] },
    });
    assert.equal(ordered.decision, 'ai', '平面内首条命中即停；旧的 allow 折进 AI（本层不拦、继续判）');
    const orderedNext = evaluatePolicies({
        toolName: 'bash', command: 'git status', segments: segs('git status'),
        config: { commandRules: [{ action: 'allow', match: 'git push' }, { action: 'deny', match: 'git' }] },
    });
    assert.equal(orderedNext.decision, 'deny', '首条不命中才轮到下一条');

    const ask = evaluatePolicies({
        toolName: 'bash', command: 'curl https://x.example', segments: segs('curl https://x.example'),
        config: { networkRules: ['deny *.ru', 'ask *.example'] },
    });
    assert.equal(ask.decision, 'ask');
    const denyWins = evaluatePolicies({
        toolName: 'mcp:github', command: 'ls', segments: segs('ls'),
        config: { toolRules: ['ask mcp:*'], commandRules: ['deny ls'] },
    });
    assert.equal(denyWins.decision, 'deny', 'deny 跨平面优先于 ask');
    const allowLoses = evaluatePolicies({
        toolName: 'bash', command: 'rm -f a', segments: segs('rm -f a'),
        config: { fileRules: [{ action: 'allow', match: 'C:/ws', ops: ['all'] }], commandRules: ['deny rm'] },
    });
    assert.equal(allowLoses.decision, 'deny', '一条 allow 不能撤销另一平面的 deny');

    const glob = evaluatePolicies({
        toolName: 'bash', command: 'rm -f a', segments: segs('rm -f a'), targets: [{ path: 'C:/ws/.git/config', opClass: 'delete' }],
        config: { fileRules: ['deny **/.git/**'] },
    });
    assert.equal(glob.decision, 'deny');
    const opScoped = evaluatePolicies({
        toolName: 'bash', command: 'cat c:/ws/.git/config', segments: segs('cat c:/ws/.git/config'),
        targets: [{ path: 'C:/ws/.git/', opClass: 'read' }],
        config: { fileRules: [{ action: 'deny', match: 'C:/ws/.git/', ops: ['delete'] }] },
    });
    assert.equal(opScoped.decision, 'pass', '只写「删除」的行管不到读取');
    // 一行一路径，读／写／删各自表态。
    const perOp = fileRules => ({ fileRules });
    const oneRow = [perOp([{ match: 'D:/logs', read: 'allow', write: '', delete: 'deny' }])];
    const fileEval = (opClass, rows) => evaluatePolicies({
        toolName: 'bash', command: 'x', segments: [], targets: [{ path: 'D:/logs/a.txt', opClass }], config: rows,
    });
    assert.equal(fileEval('delete', oneRow[0]).decision, 'deny', '同一行的删除列拦截生效');
    assert.equal(fileEval('read', oneRow[0]).decision, 'ai', '同一行的读列「允许」＝旧的 allow＝交 AI 复核');
    assert.equal(fileEval('write', oneRow[0]).decision, 'pass', '写列留空＝这一行不表态');
    // 沉默不算命中，所以后面那行还能管同一个操作。
    const fallthrough = {
        fileRules: [
            { match: 'D:/logs', read: '', write: '', delete: 'deny' },
            { match: 'D:/logs', read: 'allow', write: '', delete: '' },
        ],
    };
    assert.equal(fileEval('read', fallthrough).decision, 'ai', '前一行不表态时后一行仍然生效');
    assert.equal(fileEval('delete', fallthrough).decision, 'deny', '首条表态的行仍然优先');
    // 内置项全部成表里的行（旧的那份「预设描述清单」删了——两份内置清单＝迟早对不上）。
    const byPlane = plane => FLOOR_ROWS.filter(row => row.plane === plane).length;
    assert.ok(byPlane('file') >= 8 && byPlane('command') >= 5 && byPlane('tool') >= 1,
        `三个面都要有内置行：${JSON.stringify(byPlane)}`);
    assert.equal(FLOOR_ROWS.every(row => row.action === 'ask'), true, '内置行默认全是人工＝今天的行为，不预设放行');
    assert.equal(effectiveRows({}, 'file').filter(row => row.preset !== '').length, byPlane('file'),
        '空配置时生效表里的内置行数就是清单数（页面计数与判定同源）');
    const override = [{ preset: 'credential-material', action: 'release' }];
    const merged = effectiveRows({ fileRules: override }, 'file');
    assert.equal(merged.filter(row => row.preset !== '').length, byPlane('file'), '覆盖行不新增行，只换档');
    assert.equal(merged.find(row => row.preset === 'credential-material').action, 'release',
        '内置行可以改成允许（危险名单后议，现在不设特例）');
    assert.equal(floorActions({ fileRules: override }).get('credential-material'), 'release',
        '档位表把这一条交给 grant 处理');

    const silent = evaluatePolicies({ toolName: 'bash', command: 'ls', segments: segs('ls'), config: {} });
    assert.equal(silent.decision, 'pass', '没有命中任何行＝不表态');
    const sensitive = evaluatePolicies({
        toolName: 'bash', command: 'echo password=hunter2hunter2', segments: segs('echo password=hunter2hunter2'), config: {},
    });
    assert.equal(sensitive.decision, 'ask', '内置敏感检测只要求人工');
    assert.deepEqual(sensitive.sensitiveHits, ['credential-assign'], '内置形状现在就是表里的行，台账指认用它的形状名');
    const detectorOff = evaluatePolicies({
        toolName: 'bash', command: 'echo password=hunter2hunter2', segments: segs('echo password=hunter2hunter2'),
        config: { sensitiveDetect: false },
    });
    assert.equal(detectorOff.decision, 'pass');
    // 停用的行在**每个**平面都不算数（不只敏感面）：否则点了「已停用」，命令照样被它拦。
    const disabled = evaluatePolicies({
        toolName: 'bash', command: 'rm -rf build', segments: segs('rm -rf build'),
        config: { commandRules: [{ action: 'deny', match: 'rm -rf', enabled: false }] },
    });
    assert.equal(disabled.decision, 'pass', '停用的命令行不参与判定');
    const disabledFile = evaluatePolicies({
        toolName: 'bash', command: 'rm -f a', segments: segs('rm -f a'), targets: [{ path: 'D:/logs/a.txt', opClass: 'delete' }],
        config: { fileRules: [{ match: 'D:/logs', read: '', write: '', delete: 'deny', enabled: false }] },
    });
    assert.equal(disabledFile.decision, 'pass', '停用的文件行同样不参与判定，也不该被当成信任行');
    assert.equal(trustRules({ fileRules: [{ match: 'D:/logs', read: 'ai', write: '', delete: '', enabled: false }] }).length, 0,
        '停用的文件行不能声明信任');
    // 旧配置里的 `redact` 第四档折回「人工」：命中就遮不是选项，不能因为旧词把整行丢掉。
    assert.equal(parseRules([{ action: 'redact', match: 'x' }], 'sensitive')[0]?.action, 'ask',
        '旧的 redact 档折成人工，不是丢行');
    assert.deepEqual(networkTargets('curl https://api.example.com/x | tee out'), ['https://api.example.com/x', 'api.example.com']);
}
console.log('OK 规则表：首条命中即停、AI 档不越权、deny 跨平面优先、文件按操作、glob/正则、旧 allow 折成 AI');

// ── 敏感：检测规则一张表（内置形状可改可关）＋确定性 token 与文件回写 ──────
// 假 key 拼出来，源码里不留完整形状：上传前的敏感扫描不该被测试夹具误报。
const FAKE_AWS_KEY = ['AKIA', 'ABCDEFGHIJKLMNOP'].join('');
{
    const rows = sensitiveRows({});
    assert.equal(rows.length, 7, '内置 7 条形成本身就在表里，不是表外另一排只读说明');
    assert.equal(rows.every(row => row.preset !== '' && row.enabled === true && row.action === 'ask'), true);
    const override = [{ preset: 'jwt', match: 're:x', action: 'deny', enabled: false }];
    const merged = sensitiveRows({ sensitiveRules: override });
    assert.equal(merged.length, 7, '同 preset 的用户行是**盖住**内置行，不是再加一行');
    assert.equal(merged.find(row => row.preset === 'jwt').action, 'deny', '内容／动作听用户的');
    assert.equal(merged.find(row => row.preset === 'jwt').enabled, false, '关掉就是不表态，不必删行');
    assert.equal(sensitiveRows({ sensitiveDetect: false }).length, 0, '卡头总闸关掉＝整张表不查');

    const awsRow = parseRules([{ action: 'ask', match: `re:${String.raw`\bAKIA[0-9A-Z]{16}\b`}` }], 'sensitive')[0];
    const scan = scanSensitive(`aws ${FAKE_AWS_KEY} end`, [awsRow]);
    // 遮不遮**不看档位**：档位管的是那一次调用，命中就遮是这一层自己在做的事。
    assert.equal(scan.ranges.length, 1, '询问档也给出要遮的区间');
    assert.equal(`aws ${FAKE_AWS_KEY} end`.slice(scan.ranges[0].from, scan.ranges[0].to), FAKE_AWS_KEY,
        '遮的区间＝这一行匹配到的那一段');
    // 通配与 `*` 定位不到具体一段：只参与拒绝/允许，绝不把整段结果吞掉。
    assert.equal(scanSensitive('anything', [{ action: 'ask', match: '*', enabled: true, preset: '' }]).ranges.length, 0);
    // 最严优先：一行拒绝一行脱敏＝整段不给模型。
    const strictest = scanSensitive(FAKE_AWS_KEY, [
        awsRow,
        parseRules([{ action: 'deny', match: `re:${String.raw`AKIA\w+`}` }], 'sensitive')[0],
    ]);
    assert.equal(strictest.action, 'deny', '跨行取最严');
}
{
    const vault = createSecretVault({ dir: join(root, 'vault') });
    const token = vault.register(FAKE_AWS_KEY, { detector: 'aws-key', label: 'AWS AccessKey' });
    assert.equal(vault.register(FAKE_AWS_KEY, { detector: 'aws-key' }), token,
        '同一明文永远同一 token——回写与再脱敏才对得上');
    assert.ok(vault.register('other-secret-value', { detector: 'credential-assign' }) !== token, '不同明文不同 token');
    assert.equal(vault.restoreText(`x ${token} y`).text, `x ${FAKE_AWS_KEY} y`, '回写换回原文');
    assert.equal(vault.containsToken(`x ${token}`).length, 1);
    assert.equal(vault.containsToken('x [[SEC-000000000000]]').length, 0, '不是这张表铸的 token 一概不碰');
    const listed = vault.list();
    assert.equal(listed.length, 2);
    assert.equal(listed.every(item => item.plain === undefined), true, '列表默认不出明文，只出头 4 字与长度');
    assert.equal(vault.plainOf(token), FAKE_AWS_KEY, '单条取明文才给（并刷新 TTL 使用时间）');
    vault.setRestore(token, false);
    assert.equal(vault.restoreText(`x ${token}`).text, `x ${token}`, '这一条的回写开关关了就不动它');
    const reopened = createSecretVault({ dir: join(root, 'vault') });
    assert.equal(reopened.size(), 2, '重开还是同一张表');
    assert.equal(reopened.plainOf(token), FAKE_AWS_KEY, 'pepper 与表同目录，重启后 token 仍然认得');
    assert.equal(reopened.clear(), 2);
    assert.equal(reopened.plainOf(token), undefined, '清空后占位符换不回明文');
}
console.log('OK 敏感：检测规则一张表（内置可改可关、取最严）＋确定性 token、列表不出明文、回写与清空');

// ── L1→L2 handoff store ─────────────────────────────────────────────────────
const store = createPendingStore();
store.put('call-1', { actionHash: 'aaa', sessionId: 's1', grant: 'confirm' });
assert.equal(store.take('call-1', 'aaa').grant, 'confirm');
store.put('call-2', { actionHash: 'bbb', sessionId: 's1' });
assert.equal(store.take('call-2', 'zzz'), undefined, 'a drifted action cannot inherit a verdict');
store.put('call-3', { actionHash: 'ccc', sessionId: 's2' });
store.dropSession('s2');
assert.equal(store.size(), 0);
store.put('call-4', { actionHash: 'ddd', sessionId: 's3' });
store.sweep(Date.now() + 10 * 60 * 1000);
assert.equal(store.size(), 0, 'TTL sweep clears a stale ask');
console.log('OK pending: read-once, actionHash binding, session drop, TTL');

// ── profile 模型目录：只认结构，不走网络、不猜 YAML ─────────────────────────
const { profileProviders, readModelGroups } = await import('../lib/frame/profile.js');
const declared = profileProviders([
    '- id: llm-pi-ai',
    '  config:',
    '    providers:',
    '      prod:',
    '        displayName: "生产网关"',
    '        models:',
    '          - id: a-70b',
    '            name: A 70B',
    '            input:',
    '              - text',
    '          - id: b-32b',
    '        compat:',
    '          x: 1',
    '      bare:',
    '        displayName: 裸提供方',
    '',
].join('\n'));
assert.deepEqual(declared.map(item => [item.id, item.name, item.models.map(model => `${model.id}/${model.name}`)]),
    [['prod', '生产网关', ['a-70b/A 70B', 'b-32b/b-32b']], ['bare', '裸提供方', []]],
    '提供方名取 displayName；模型缺 name 时回落到 id；input 列表不能被当成模型');
const fixtureHome = join(root, 'profile-home');
mkdirSync(join(fixtureHome, 'profiles', 'desktop'), { recursive: true });
writeFileSync(join(fixtureHome, 'profiles', 'desktop', 'cordis.yml'), '- id: other\n  config:\n    unrelated: 1\n');
writeFileSync(join(fixtureHome, 'profiles', 'desktop', 'cordis.patch.yml'), [
    '    providers:',
    '      prod:',
    '        displayName: 生产网关',
    '        models:',
    '          - id: a-70b',
    '            name: A 70B',
    '',
].join('\n'));
const merged = readModelGroups(fixtureHome);
assert.deepEqual(merged.groups.map(group => group.id), ['prod'], '只留真有模型的提供方');
assert.equal(merged.note, '');
const emptyHome = join(root, 'empty-home');
mkdirSync(join(emptyHome, 'profiles', 'desktop'), { recursive: true });
const nothing = readModelGroups(emptyHome);
assert.deepEqual(nothing.groups, [], 'profile 里没声明模型时返回空，让页面退回手填而不是卡住');
assert.ok(nothing.note.includes('没有声明'), `读不到要说清原因：${nothing.note}`);
assert.ok(readModelGroups(join(root, 'no-such-dir')).note.includes('读不到 profile 目录'), '目录都不存在时同样给得出原因');
console.log('OK profile 模型目录：按结构读 displayName／models，缺项回落、空目录给原因');

console.log(`\nALL FRAME CASES PASS (fixture ${root})`);
rmSync(root, { recursive: true, force: true });
