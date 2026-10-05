# jwt

终端里的 JWT 小工具：解码查看、签名校验、生成测试 token。纯 Python 标准库，零依赖，离线运行。

## 安装

```bash
cd jwt
python3 -m jwt --help
```

## 用法

```bash
# 解码（只看内容，不校验签名）
python3 -m jwt decode <token>

# JSON 输出
python3 -m jwt decode <token> --json

# 校验签名（HS256/HS384/HS512）
python3 -m jwt verify <token> --secret mykey

# 生成测试 token（仅供测试）
python3 -m jwt create --payload '{"sub":"123","exp":1893456000}' --secret mykey
```

### decode 输出示例

```
===== JWT 解码（未校验签名，仅供查看）=====

算法 alg：HS256

【header】
{
  "alg": "HS256",
  "typ": "JWT"
}

【payload】
{
  "sub": "123",
  "name": "王芳",
  "exp": 1893456000
}

【状态】
  ✅ 未过期（exp=2030-01-01 00:00:00 CST）
```

## ⚠️ 安全说明（必读）

- **解码 ≠ 信任**：`decode` 只做 base64url 解码，任何人都能伪造一个"看起来合法"的 payload。真正重要的是签名。
- `verify` 只支持 **HS256 / HS384 / HS512**（对称密钥）。RSA / ECDSA（RS256/ES256 等）需要 `cryptography` 第三方库，本工具为保持零依赖不支持——遇到这类 token 会明确报错，而不是静默跳过校验。
- `create` 生成的 token **仅供本地测试**，不要用测试密钥签发生产 token。
- 密钥请通过 `--secret` 传入，不要写进 shell 历史敏感的位置；用完即焚。

## 已知局限

- 不支持 JWE（加密 JWT），只处理 JWS（签名 JWT）。
- 不做 JWKS / 公钥分发，只做"拿着密钥验签名"这一件事。
- `exp`/`iat`/`nbf` 按本机时钟判断，时钟不准会导致误判。

## License

MIT © 2026 ljiang9
