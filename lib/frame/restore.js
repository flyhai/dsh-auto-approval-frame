// 把 token 换回明文的**唯一**落点：文件层。
//
// 为什么不是执行前：宿主契约明写「Input rewriting is excluded because arguments are
// already logged and presented」——参数改不得，所以模型用 token 写出的那份文件，
// 只能在它写完之后由我们把里面的 token 换回明文。也因此两条边界要说死：
//  · 只覆盖**落到文件里**的 token；命令参数里的（`--token [[SEC-…]]`）执行时不会变明文；
//  · 只换**这张表铸出来**的 token，别的方括号文本一概不碰。
// 写回是「读→换→原子重写」，且跳过凭据／系统关键树：往 `~/.ssh` 里回填明文不是修正。
import { lstatSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { collectFacts } from './facts.js';
import { neverReasonFor } from './grant.js';

const MAX_FILE_BYTES = 4 * 1024 * 1024;

/**
 * @returns rows 每个目标一条：`{path, tokens}` 真的回写了什么，或 `{path, skipped}` 为什么没动。
 */
export function restoreVaultedWrites({ toolName, args, roots, vault, probe }) {
    const facts = collectFacts({ toolName, args, roots, probe });
    const out = [];
    for (const target of facts.targets) {
        if (target.opClass !== 'write' || target.dynamic === true || typeof target.path !== 'string')
            continue;
        const never = neverReasonFor(target, roots);
        if (never !== undefined) {
            out.push({ path: target.path, tokens: [], skipped: `不回填到${never}` });
            continue;
        }
        let text;
        try {
            // 读→换→原子重写会把链接本身换掉：目标是符号链接时不碰，链接指向哪儿不确定。
            if (lstatSync(target.path).isSymbolicLink()) {
                out.push({ path: target.path, tokens: [], skipped: '目标是符号链接，重写会把链接换成普通文件' });
                continue;
            }
            if (statSync(target.path).size > MAX_FILE_BYTES) {
                out.push({ path: target.path, tokens: [], skipped: '文件超过 4 MB' });
                continue;
            }
            text = readFileSync(target.path, 'utf8');
        }
        catch {
            // 读不到＝不是文本／已不在／无权限：不去猜，也不碰它。
            out.push({ path: target.path, tokens: [], skipped: '读不出文本内容' });
            continue;
        }
        const found = vault.containsToken(text);
        if (found.length === 0)
            continue;
        const restored = vault.restoreText(text);
        if (restored.restored.length === 0) {
            out.push({ path: target.path, tokens: [], skipped: '这几条的回写开关是关的' });
            continue;
        }
        const tmp = `${target.path}.dsa-${process.pid}.tmp`;
        try {
            writeFileSync(tmp, restored.text);
            renameSync(tmp, target.path);
        }
        catch (error) {
            out.push({ path: target.path, tokens: [], skipped: `写回失败：${String(error?.message ?? error)}` });
            continue;
        }
        out.push({ path: target.path, tokens: restored.restored });
    }
    return out;
}
