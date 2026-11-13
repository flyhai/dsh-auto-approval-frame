// 数值型设置的唯一所有者：出厂值、下限、上限各写一遍，别处只从这里取。
//
// 直接读这张表的三处：`lib/index.js` 的 Config schema、`frame/review.js`＋`frame/evidence.js`
// 的兜底、`frame/audit.js` 的建柜参数。这处的病就是过去各写各的——深评上限 schema 写 2048、
// 评审代码的兜底写 512，一份不含该键的 config 就能把 verdict（依据＋理由）截半（审查第 5 点）。
//
// 另外两处 require 不到本档，只能留字面量，由 test/unit/config-defaults.test.mjs 逐键对拍：
// `lib/client.js`（浏览器半边，宿主 __ModuleLoader__ 只让它 require 宿主包）和
// `cordis.patch.yml`（随包出厂层，宿主在跑 JS 之前读它，写死多少就是多少，会盖掉这里的 def；
// 0.6.11 及以前那一格写着 512，就是同一个病的另一半）。
export const NUMERIC_SETTINGS = {
    reviewerMaxTokens: { def: 2048, min: 64, max: 4_096 },
    reviewerTimeoutMs: { def: 20_000, min: 1_000, max: 120_000 },
    evidenceBudget: { def: 16_000, min: 2_000, max: 48_000 },
    fastJudgeMaxTokens: { def: 256, min: 64, max: 1_024 },
    fastJudgeTimeoutMs: { def: 3_000, min: 500, max: 30_000 },
    // 解释调用的输出上限。0.6.11 以前它只以 `config.explainMaxTokens` 的字面量活在评审代码里，
    // 既没进 schema 也没进设置页——登记进来是为了让「谁改这个数字」有一条明路（审查第 6 点）。
    explainMaxTokens: { def: 2_048, min: 1_024, max: 2_048 },
    retentionDays: { def: 90, min: 1, max: 3_650 },
    // 两枚字节帽只有下限：上限由台账自己的分段／剪枝逻辑管，不在配置面封顶。
    maxTotalBytes: { def: 512 * 1024 * 1024, min: 1024 * 1024 },
    maxSegmentBytes: { def: 50 * 1024 * 1024, min: 1024 * 1024 },
};

/** 出厂值。 */
export const numericDefault = key => NUMERIC_SETTINGS[key].def;

/** 缺键、非数、NaN ⇒ 出厂值；其余夹进 [min, max]（没写 max 就不封顶）。与 schema 同一把尺。 */
export function numericValue(key, value) {
    const { def, min, max } = NUMERIC_SETTINGS[key];
    const raw = typeof value === 'number' && Number.isFinite(value) ? value : def;
    const floored = Math.max(raw, min);
    return max === undefined ? floored : Math.min(floored, max);
}

/**
 * 只兜出厂值＋下限，不夹上限。
 * 证据预算这一处历史上就不封顶（集成测试靠把 `evidenceBudget` 写到 400_000 来放大块预算），
 * 在这里顺手夹成 48_000 会改掉取证形状，不属于收默认值这件事。
 */
export function numericFloor(key, value) {
    const { def, min } = NUMERIC_SETTINGS[key];
    const raw = typeof value === 'number' && Number.isFinite(value) ? value : def;
    return Math.max(raw, min);
}
