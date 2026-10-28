// 敏感形状的来源表与 token 的回收形状。
//
// 这里**不做规则匹配**：形状表被 `policy.js` 铺成「检测规则」里的内置行，命中与
// 动作都在那张表上判（一条实现、一个所有者）。本文件只留两件纯事：形状本身，以及
// 认得我们自己铸出的 token。
//
// token 必须确定性（同一明文永远同一串）：模型把 token 写进配置文件、我们在文件层
// 换回明文之后，模型回读该文件时同一段明文会再次脱成**同一个** token。用随机串的话
// 每一轮都生成新串——映射越积越多，回写与再脱敏互相对不上。

/**
 * 内置形状：`source` 就是页面上可以改的那段正则文本（`re:` 行）。
 * 匹配范围＝「这一行命中要遮住的那一段」，所以 `credential-assign` 连键名一起吞——
 * 键名本身也泄露意图；只想遮值就把正则写成只匹配值。
 */
export const DETECTOR_SHAPES = [
    { id: 'private-key', label: '私钥', source: String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,8192}?-----END [A-Z ]*PRIVATE KEY-----` },
    { id: 'jwt', label: 'JWT', source: String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{20,}\b` },
    { id: 'aws-key', label: 'AWS AccessKey', source: String.raw`\bAKIA[0-9A-Z]{16}\b` },
    { id: 'bearer', label: 'Bearer 令牌', source: String.raw`\bBearer\s+[A-Za-z0-9._~+/-]{8,}` },
    { id: 'api-key', label: '服务密钥', source: String.raw`\b(?:sk|ghp|github_pat|xox[baprs])[-_][A-Za-z0-9_-]{8,}\b` },
    { id: 'credential-assign', label: '凭据赋值', source: String.raw`\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*["']?[^\s"']{6,}` },
    { id: 'connection-string', label: '连接串', source: String.raw`\b[a-z][a-z0-9+.-]*:\/\/[^/\s?#]+:[^/\s?#]+@` },
];

// `[[SEC-<12 hex>]]`：12 位＝48 bit，碰撞概率可忽略；方括号成对出现，回收时一眼定位。
// token 的语法**只有这一处定义**（`vault.js` 造它、认它、换回明文都 import 本常量），
// 别处再写一遍正则字面量＝第二个所有者，将来改长度一定漏改一处。
export const TOKEN_PATTERN = /\[\[SEC-[0-9a-f]{12}\]\]/g;

