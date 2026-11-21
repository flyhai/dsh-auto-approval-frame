// 盘上密文的固定钥匙：敏感规则的条件值、敏感信息映射表都用它封。
//
// 钥匙编码在源码里且**只增不改**：每条有大写编号，信封头上带着编号。
// 以后真要换钥匙，只能**新增**一条编号、旧的永远留着——旧文件靠旧编号解出来，
// 再按当前编号重新封回去。直接改旧的字节段＝已经落盘的数据全部变成打不开的密文，
// 这有测试盯着（`test/unit/secretbox.test.mjs` 钉死钥匙指纹与一条历史密文）。
//
// 它不以明文常量出现——下面是与掩码异或过的字节，运行时拼回种子再派生钥匙。
// 这把钥匙只解决一件事：文件落到盘上是密文，干活时顺手读到也看不见内容。
// 它不构成对拿到代码者的保密——肯把这段代码跑一遍的人总能还原，这不是本设计的防线。
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const SEALED_PREFIX = 'enc:v1:';

const DOMAIN = 'dsh-auto-approval-frame/at-rest/v1';

// 🔒 只增不改：新钥匙追加一条，id 递增；旧条目的 body/mask 一个字节都不许动。
const MATERIAL = [
    {
        id: 1,
        body: [80, 80, 167, 58, 140, 200, 189, 66, 109, 85, 39, 224, 9, 68, 214, 247,
            248, 214, 162, 162, 19, 163, 122, 213, 241, 152, 247, 247, 22, 32, 115, 192],
        mask: [213, 104, 73, 175, 100, 190, 196, 243, 39, 235, 232, 241, 182, 161, 72, 159],
    },
];

const derive = ({ id, body, mask }) => {
    const seed = Buffer.from(body.map((byte, index) => byte ^ mask[index % mask.length]));
    return createHash('sha256').update(`${DOMAIN}#key-${id}`).update(seed).digest();
};

const KEYS = new Map(MATERIAL.map(item => [item.id, derive(item)]));
export const CURRENT_KEY_ID = MATERIAL[MATERIAL.length - 1].id;
const AAD = Buffer.from(DOMAIN, 'utf8');

export function isSealed(value) {
    return typeof value === 'string' && value.startsWith(SEALED_PREFIX);
}

/** 测试用：某把钥匙的指纹（不是钥匙本身），改动了那一班的 BODY/MASK 就会变。 */
export function keyFingerprint(keyId = CURRENT_KEY_ID) {
    const key = KEYS.get(keyId);
    if (key === undefined)
        throw new Error(`没有编号 ${keyId} 的钥匙`);
    return createHash('sha256').update(key).digest('hex').slice(0, 16);
}

/** 测试用：认得的钥匙编号。 */
export function keyIds() {
    return [...KEYS.keys()];
}

/** AES-256-GCM：编号(1)｜iv(12)｜tag(16)｜密文，整段 base64 后加前缀。 */
export function sealText(plain, keyId = CURRENT_KEY_ID) {
    const key = KEYS.get(keyId);
    if (key === undefined)
        throw new Error(`没有编号 ${keyId} 的钥匙`);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(AAD);
    const body = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
    const head = Buffer.from([keyId]);
    return `${SEALED_PREFIX}${Buffer.concat([head, iv, cipher.getAuthTag(), body]).toString('base64')}`;
}

/** 解开并交回用了哪把钥匙；解不开就抛——调用方据此标停用，绝不回退成明文。 */
export function openSealed(sealed) {
    if (!isSealed(sealed))
        throw new Error('不是密文');
    const raw = Buffer.from(sealed.slice(SEALED_PREFIX.length), 'base64');
    if (raw.length < 29)
        throw new Error('密文太短');
    const keyId = raw[0];
    const key = KEYS.get(keyId);
    if (key === undefined)
        throw new Error(`这把钥匙不认得（编号 ${keyId}）`);
    const decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(1, 13));
    decipher.setAAD(AAD);
    decipher.setAuthTag(raw.subarray(13, 29));
    return {
        text: Buffer.concat([decipher.update(raw.subarray(29)), decipher.final()]).toString('utf8'),
        keyId,
    };
}

export function openText(sealed) {
    return openSealed(sealed).text;
}
