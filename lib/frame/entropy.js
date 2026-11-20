// 高熵令牌：不依赖 `key=value` 上下文、也没有已知厂商前缀的裸随机串。
//
// 纯函数、无 IO。结果侧（`policy.js` 的 `matchRanges`）与台账侧（`sanitize.js` 的
// `redactSecrets`）都调这里——同一套判定、同一个区间，不存在第二份实现。
// 口径是「宁可漏，不误报」：形状先过硬门槛，再算熵；任何一条不过都不判。

export const ENTROPY_PRESET = 'high-entropy';
export const ENTROPY_LABEL = '高熵令牌';

const SEGMENT = /[A-Za-z0-9+/=_-]+/g;
const HEX_ONLY = /^[0-9a-fA-F]+$/;
const INTEGRITY = /^sha(?:1|256|384|512)-/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const BOUNDARY_BEFORE_OR_AFTER = new Set(['.', ':', '\\', '~', '%']);
const BAD_LEAD = new Set(['/', '-', '_', '=']);

export const ENTROPY_MIN_LENGTH = 32;
export const ENTROPY_MAX_LENGTH = 512;
export const ENTROPY_THRESHOLD = 4.3;

/** 按字符频率算 bit/字符（Shannon）。 */
export function shannonEntropy(text) {
    const value = String(text ?? '');
    if (value === '')
        return 0;
    const counts = new Map();
    for (const ch of value)
        counts.set(ch, (counts.get(ch) ?? 0) + 1);
    let bits = 0;
    for (const count of counts.values()) {
        const p = count / value.length;
        bits -= p * Math.log2(p);
    }
    return bits;
}

/** 一段文本里的高熵令牌区间（`{from,to}`，区间＝令牌本体，不含两侧空格／引号）。 */
export function highEntropyRanges(text) {
    const source = String(text ?? '');
    if (source === '')
        return [];
    const out = [];
    const segment = new RegExp(SEGMENT.source, 'g');
    let found;
    while ((found = segment.exec(source)) !== null) {
        const value = found[0];
        // 1. 整词＋长度：>512 的段整段跳过，不切块（2MB 资产不能被切成几千段令牌）。
        if (value.length < ENTROPY_MIN_LENGTH || value.length > ENTROPY_MAX_LENGTH)
            continue;
        const from = found.index;
        const to = from + value.length;
        // 2. 边界：紧邻的 `.` `:` `\` `~` `%`、段首的 `/ - _ =`、段内 `//` 都出局。
        if (BOUNDARY_BEFORE_OR_AFTER.has(source[from - 1]) || BOUNDARY_BEFORE_OR_AFTER.has(source[to]))
            continue;
        if (BAD_LEAD.has(value[0]) || value.includes('//'))
            continue;
        // 3. 形态：大写、小写、数字各至少一个。
        if (!/[A-Z]/.test(value) || !/[a-z]/.test(value) || !/[0-9]/.test(value))
            continue;
        // 4. 纯 hex：md5／sha／git 提交号整类出局。
        if (HEX_ONLY.test(value))
            continue;
        // 5. 完整性串：package-lock 的 `integrity`。
        if (INTEGRITY.test(value))
            continue;
        // 6. data URI 的载荷。
        if (source.slice(Math.max(0, from - 16), from).includes('base64,'))
            continue;
        // 7. 熵门槛。
        if (shannonEntropy(value) < ENTROPY_THRESHOLD)
            continue;
        // 8. UUID 防回归（第 3 条已挡，显式列出）。
        if (UUID.test(value))
            continue;
        out.push({ from, to });
    }
    return out;
}
