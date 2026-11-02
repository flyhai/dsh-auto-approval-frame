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
    { id: 'credential-assign', label: '凭据赋值', keyed: true, keep: 1, source: String.raw`\b((?:[A-Za-z0-9]+[_-])*(?:password|passwd|pwd|secret|token|api[_-]?key|(?:secret|private|access|client|auth|account|master|encryption|signing|session)[_-]?key)["']?\s*[:=]\s*["']?)([^\s"']{6,})` },
    { id: 'connection-string', label: '连接串', source: String.raw`\b[a-z][a-z0-9+.-]*:\/\/[^/\s?#]+:[^/\s?#]+@` },
    // （用户 11-02 令「检测规则 增加邮箱 身份证号 检测」）：真存在的姓名／邮箱这一格定死要按敏感。
    // 邮箱按常用文法（本地段＋域名段，顶级域至少两字母）；身份证号只认 18 位现行证，
    // 且要求中间那段是「世纪＋月＋日」——纯 18 位数字（订单号、时间戳串）不遮。15 位旧证不覆盖。
    { id: 'email', label: '邮箱', source: String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b` },
    { id: 'cn-id-card', label: '身份证号', source: String.raw`\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b` },
];

// `[[SEC-<12 hex>]]`：12 位＝48 bit，碰撞概率可忽略；方括号成对出现，回收时一眼定位。
// token 的语法**只有这一处定义**（`vault.js` 造它、认它、换回明文都 import 本常量），
// 别处再写一遍正则字面量＝第二个所有者，将来改长度一定漏改一处。
export const TOKEN_PATTERN = /\[\[SEC-[0-9a-f]{12}\]\]/g;

