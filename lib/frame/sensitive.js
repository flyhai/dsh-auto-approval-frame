// 敏感形状的来源表与 token 的回收形状。
//
// 这里**不做规则匹配**：形状表被 `policy.js` 铺成「检测规则」里的预设行，命中与
// 动作都在那张表上判（一条实现、一个所有者）。本文件只留两件纯事：形状本身，以及
// 认得我们自己铸出的 token。
//
// token 必须确定性（同一明文永远同一串）：模型把 token 写进配置文件、我们在文件层
// 换回明文之后，模型回读该文件时同一段明文会再次脱成**同一个** token。用随机串的话
// 每一轮都生成新串——映射越积越多，回写与再脱敏互相对不上。

/** * 预设形状：`source` 就是页面上可以改的那段正则文本（`re:` 行）。
 * 匹配范围＝「这一行命中要遮住的那一段」，所以 `credential-assign` 连键名一起吞——
 * 键名本身也泄露意图；只想遮值就把正则写成只匹配值。
 */
export const DETECTOR_SHAPES = [
    { id: 'private-key', label: '私钥', source: String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]*PRIVATE KEY-----` },
    { id: 'jwt', label: 'JWT', source: String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,}\b` },
    { id: 'aws-key', label: 'AWS AccessKey', source: String.raw`\bAKIA[0-9A-Z]{16}\b` },
    { id: 'bearer', label: 'Bearer 令牌', source: String.raw`\bBearer\s+[A-Za-z0-9._~+/-]{8,}` },
    // 前缀族补齐——仍只有这一条（同一 id、同一匹配区间），不新增内置行。
    // 门槛：GitHub 8／GitLab 20／npm 30／Slack 8／Google 固定 35／Stripe restricted 20／
    // 1Password 服务账号 26／SendGrid 三段式 22+43。裸词与过短尾串一律不中（见 57-gap.md）。
    { id: 'api-key', label: '服务密钥', source: String.raw`\b(?:sk[-_][A-Za-z0-9_-]{8,}|gh[pousr]_[A-Za-z0-9_-]{8,}|github_pat[-_][A-Za-z0-9_-]{8,}|glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9_-]{30,}|xox[baprs][-_][A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{35}|rk_live_[0-9A-Za-z]{20,}|ops_[A-Za-z0-9]{26,}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b` },
    // 键名后允许一枚闭合引号：JSON／YAML 里是 `"password":"值"`，原写法要求键名后面直接跟冒号，
    // 于是最普通的一条 JSON 凭据形状根本不匹配（F07）。
    // 第一组留住「键名＋分隔符」：台账侧按组回填 `键名=***`（页面看得出遮了什么），
    // 结果侧仍按整段命中区间铸 token——匹配范围与旧版逐字相同。
    // 键名部分扩成「任意段拼前缀」——`aws_secret_access_key=`、`AWS_SECRET_ACCESS_KEY=`、
    // `client_secret:`、`DB_PASSWORD=` 这类复合键名此前全部漏遮（结果侧与台账侧同漏：`\b`
    // 卡在词首，`secret`／`password` 前面是下划线就够不着）。两条仍然共用同一条正则与同一个
    // 匹配区间；台账侧按第一组回填键名，结果侧整段铸 token。
    // 值这一半要求「像值」：要么带引号的字面量，要么含数字的裸值；纯标识符、点链、调用一律不算。
    // 老写法取 `[^\s"']{6,}`，于是 `password = prompt(`、`password: password`、
    // `PASSWORD: CREDUI_FLAGS_…`、`password: password.to_string()` 这些**代码**全被当成凭据遮掉，
    // 模型拿到的是占位符、看不到自己在读写什么。凭据判定的成本是「看不清」，宁可漏掉纯字母裸值
    // （那类通常也走引号形），也不能把标识符当秘密。
    { id: 'credential-assign', label: '凭据赋值', keyed: true, keep: 1, source: String.raw`\b((?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|token|api[_-]?key|(?:secret|private|access|client|auth|account|master|encryption|signing|session)[_-]?key)["']?\s*[:=]\s*)(?:["'][^"'\s]{6,}["']|(?![A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)(?=[^\s"']*\d)[^\s"'(){}\[\],;]{6,})` },
    { id: 'connection-string', label: '连接串', source: String.raw`\b[a-z][a-z0-9+.-]*:\/\/[^/\s?#]+:[^/\s?#]+@` },
    // 真存在的姓名／邮箱这一格定死要按敏感。
    // 邮箱按常用文法（本地段＋域名段，顶级域至少两字母）；身份证号只认 18 位现行证，
    // 且要求中间那段是「世纪＋月＋日」——纯 18 位数字（订单号、时间戳串）不遮。15 位旧证不覆盖。
    { id: 'email', label: '邮箱', source: String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b` },
    { id: 'cn-id-card', label: '身份证号', source: String.raw`\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b` },
];

// 保留域不是邮箱：MHTML 的合成 origin 与 RFC 保留 TLD 都不该占掉一条邮箱遮罩。
const RESERVED_EMAIL_DOMAIN = /^(?:mhtml\.blink|localhost)$/i;
const RESERVED_EMAIL_TLD = /^(?:invalid|test|localhost|example|local)$/i;
export function isReservedEmail(value) {
    const text = String(value ?? '');
    const at = text.lastIndexOf('@');
    if (at === -1)
        return false;
    const domain = text.slice(at + 1).trim().replace(/[)\]}>.,;:!?]+$/, '').toLowerCase();
    if (domain === '')
        return false;
    if (RESERVED_EMAIL_DOMAIN.test(domain))
        return true;
    return RESERVED_EMAIL_TLD.test(domain.split('.').pop() ?? '');
}

// 设备 CLI 的凭据位：`password [simple|cipher|irreversible-cipher|hash] <值>`。
// 返回**值的区间**，关键字和限定词留在原地；`<占位符>`／已铸 token 不算值。
const DEVICE_CREDENTIAL = /\b(password|passwd)\s+(irreversible-cipher|simple|cipher|hash)\s+("[^"\r\n]*"|'[^'\r\n]*'|(?![<\[])[^\s"']+)/gi;
const DEVICE_KEYWORD = /\b(password|passwd)\s+(irreversible-cipher|simple|cipher|hash)\b/gi;
const CREDENTIAL_KEY = /\b(?:password|passwd|pwd|secret|token|api[_-]?key|(?:secret|private|access|client|auth|account|master|encryption|signing|session)[_-]?key)\b(?=\s*["']?\s*[:=])/gi;

function deviceCredentialParts(text) {
    const source = String(text ?? '');
    const values = [];
    const keywords = [];
    if (source === '')
        return { values, keywords };
    for (const match of source.matchAll(DEVICE_CREDENTIAL)) {
        keywords.push({ from: match.index, to: match.index + match[1].length });
        const at = match.index + match[0].indexOf(match[2], match[1].length);
        keywords.push({ from: at, to: at + match[2].length });
        const token = match[3] ?? '';
        const value = token.replace(/^["']|["']$/g, '');
        if (value === '' || /^[=:]/.test(value) || /^<.*>$/.test(value)
            || /^\[\[SEC-/.test(value) || /^(?:irreversible-cipher|simple|cipher|hash)$/i.test(value))
            continue;
        const from = match.index + match[0].length - token.length;
        values.push({ from, to: match.index + match[0].length });
    }
    return { values, keywords };
}

export function deviceCredentialRanges(text) {
    return deviceCredentialParts(text).values;
}

/** 命令里“关键字/键名”的位置：已登记明文落在这些位置时不遮（值才遮）。 */
export function keywordRanges(text) {
    const source = String(text ?? '');
    const out = deviceCredentialParts(source).keywords.slice();
    if (source === '')
        return out;
    for (const match of source.matchAll(CREDENTIAL_KEY))
        out.push({ from: match.index, to: match.index + match[0].length });
    for (const match of source.matchAll(DEVICE_KEYWORD)) {
        // 已经由上面按完整文法收过的关键字不重复；这里只补 `<占位符>` 等没匹配到值的情况。
        if (!out.some(range => range.from === match.index && range.to === match.index + match[1].length))
            out.push({ from: match.index, to: match.index + match[1].length });
        const at = match.index + match[0].indexOf(match[2], match[1].length);
        if (!out.some(range => range.from === at && range.to === at + match[2].length))
            out.push({ from: at, to: at + match[2].length });
    }
    return out;
}

// `[[SEC-<12 hex>]]`：12 位＝48 bit，碰撞概率可忽略；方括号成对出现，回收时一眼定位。
// token 的语法**只有这一处定义**（`vault.js` 造它、认它、换回明文都 import 本常量），
// 别处再写一遍正则字面量＝第二个所有者，将来改长度一定漏改一处。
export const TOKEN_PATTERN = /\[\[SEC-[0-9a-f]{12}\]\]/g;

// 占位符不是秘密：配置模板里 `access_key_secret = "[$Access_Key_Secret]"` 与
// 真值 `access_key_secret = "Abc123Xyz789"` 在文本上一个形状——键名像凭据、等号、
// 值不短且无空格。正则层分不出来，只能在命中之后再看一眼值本身。
// 判定一律**整段**：每个分支都要求括号／引号把整段包住，不做部分匹配——否则真值
// 前后各加一枚括号就能过（这个口子是形态豁免的固有代价，尽量收窄而不是否认）。
const PLACEHOLDER_WORDS = /^(?:changeme|change[_-]?me|placeholder|your[_-]?(?:token|key|secret|password|api[_-]?key)|redacted|dummy|todo|fixme|none|null|undefined|example|sample)$/i;

/** 像随机串（大小写＋数字混排且够长）：这种包在括号里也不当占位符。 */
function looksRandom(text) {
    if (text.length < 16)
        return false;
    return /[A-Z]/.test(text) && /[a-z]/.test(text) && /[0-9]/.test(text);
}

/** 这段值是不是「请在此填写」的写法。调用方答是，就把这条命中从区间里剔掉。 */
export function isPlaceholderValue(value) {
    let text = String(value ?? '').trim().replace(/^["']|["']$/g, '').trim();
    if (text === '')
        return false;
    // 已铸成 token：盘上本来就该是它，回写时换回明文。
    TOKEN_PATTERN.lastIndex = 0;
    if (TOKEN_PATTERN.test(text)) {
        TOKEN_PATTERN.lastIndex = 0;
        return true;
    }
    // 整段星号／x，或值里出现四个以上连续 X：`xxx`、`AKIA` 后接十六个 X 这类模板占位。
    if (/^\*{3,}$/.test(text) || /^[xX]{3,}$/.test(text) || /[Xx]{4,}/.test(text))
        return true;
    if (/^\$\{[^}]{1,60}\}$/.test(text) || /^\{\{[^}]{1,60}\}\}$/.test(text) || /^%[A-Za-z0-9_]{1,40}%$/.test(text))
        return true;
    if (/^<[^<>]{1,60}>$/.test(text) || /^\[[^[\]]{1,40}\]$/.test(text))
        return looksRandom(text.slice(1, -1)) === false;
    return PLACEHOLDER_WORDS.test(text);
}

