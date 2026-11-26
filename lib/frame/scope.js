// 任务资源范围（B01／ 判据 2）：把「读得到」与「允许读」拆成两件事。
// 本模块只回答一个问题——这个读目标是否落在**本任务声明的资源域**里；它不拍板、
// 不查权限、不改任何候选理由。放不放仍由规则表里那一行说话（proven-read 的谓词用它）。
import { isWithin } from './paths.js';

/** * 技能说明是这个任务的合理依据（报告 §7.2：「当前选用技能的说明读⇒仍直放」）。
 * 装了哪些技能由用户决定，所以「家目录下的 skills 子树」整段算任务资源；
 * 其它项目的业务／架构／面板／配置档案不因为「是文本」就自动算进来。
 */
export function isSkillDoc(path, home) {
    if (typeof path !== 'string' || path === '')
        return false;
    if (!isWithin(home, path, home))
        return false;
    return path.replaceAll('\\', '/').toLowerCase().split('/').includes('skills');
}

/** * 单个目标落在哪：'task'（本项目／信任根／宿主开口／技能说明）或 'external'。
 * 只用事实层已经算好的 `rootHit`——它是按**会话声明的信任边界**算的，
 * 这里再自己解一遍规则会把同一件事写成两份。
 */
export function scopeOfTarget(target, roots) {
    if (target === undefined || target === null)
        return 'external';
    const hit = target.rootHit;
    if (hit === 'workspace' || hit === 'trusted' || hit === 'dsh-open')
        return 'task';
    return isSkillDoc(target.path ?? target.input, roots?.home) ? 'task' : 'external';
}

/** * 一次调用的读面范围：'task'＝全部读目标都在任务资源域内；'external'＝至少一个在外面；
 * 'none'＝这次调用没有读目标（不构成范围判断，由「读面为空」那条自己说话）。
 */
export function scopeOfTargets(targets, roots) {
    const reads = (targets ?? []).filter(target =>
        target !== undefined && target !== null && target.dynamic !== true && target.opClass === 'read');
    if (reads.length === 0)
        return 'none';
    return reads.every(target => scopeOfTarget(target, roots) === 'task') ? 'task' : 'external';
}
