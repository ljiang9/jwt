#!/usr/bin/env python3
"""jwt —— 终端里的 JWT 解码/校验小工具。

解码不等于信任：decode 只解析载荷，不校验签名；
要确认 token 可信，必须用 verify + 正确的密钥。
"""
import argparse
import base64
import binascii
import hashlib
import hmac
import json
import sys
import time
from datetime import datetime, timezone

VERSION = "0.1.0"

HS_ALGS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def err(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def b64url_decode(seg):
    """解码 base64url 段，失败抛 ValueError。"""
    pad = "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg + pad)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"base64url 解码失败：{e}")


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def split_token(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"token 格式错误：应为 header.payload.signature 三段，实际 {len(parts)} 段")
    return parts


def decode_seg(seg, name):
    try:
        raw = b64url_decode(seg)
    except ValueError as e:
        raise ValueError(f"{name} 段{e}")
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"{name} 段不是合法 JSON：{e}")


def human_ts(ts):
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc).astimezone()
        return dt.strftime("%Y-%m-%d %H:%M:%S %Z")
    except (ValueError, OSError, OverflowError):
        return "（无法解析）"


def analyze_payload(payload, now):
    """返回 payload 的状态标注列表。"""
    notes = []
    if not isinstance(payload, dict):
        return ["payload 不是 JSON 对象，无法分析时间字段"]
    exp = payload.get("exp")
    if exp is not None:
        try:
            if int(exp) < now:
                notes.append(f"⚠️ 已过期（exp={human_ts(exp)}）")
            else:
                notes.append(f"✅ 未过期（exp={human_ts(exp)}）")
        except (ValueError, TypeError):
            notes.append("exp 字段不是合法时间戳")
    else:
        notes.append("无 exp 字段（永不过期，请确认是否符合预期）")
    iat = payload.get("iat")
    if iat is not None:
        notes.append(f"签发时间 iat={human_ts(iat)}")
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            if int(nbf) > now:
                notes.append(f"⚠️ 尚未生效（nbf={human_ts(nbf)}）")
        except (ValueError, TypeError):
            pass
    return notes


def cmd_decode(args):
    try:
        h_b64, p_b64, _sig = split_token(args.token)
        header = decode_seg(h_b64, "header")
        payload = decode_seg(p_b64, "payload")
    except ValueError as e:
        err(str(e))
    alg = header.get("alg", "（缺失）") if isinstance(header, dict) else "（header 非对象）"
    now = int(time.time())
    if args.json:
        print(json.dumps({"header": header, "payload": payload, "alg": alg,
                          "notes": analyze_payload(payload, now)},
                         ensure_ascii=False, indent=2))
        return
    print("===== JWT 解码（未校验签名，仅供查看）=====")
    print(f"\n算法 alg：{alg}")
    print("\n【header】")
    print(json.dumps(header, ensure_ascii=False, indent=2))
    print("\n【payload】")
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    print("\n【状态】")
    for n in analyze_payload(payload, now):
        print(f"  {n}")
    print("\n⚠️ 注意：解码 ≠ 信任。如需确认 token 可信，请用 verify 校验签名。")


def verify_token(token, secret):
    """返回 (ok: bool, alg: str)。签名不对/算法不支持抛 ValueError。"""
    h_b64, p_b64, sig_b64 = split_token(token)
    header = decode_seg(h_b64, "header")
    alg = header.get("alg") if isinstance(header, dict) else None
    if alg not in HS_ALGS:
        raise ValueError(f"不支持的算法：{alg}（仅支持 HS256/HS384/HS512；RSA/ECDSA 需要 cryptography 库）")
    try:
        sig = b64url_decode(sig_b64)
    except ValueError as e:
        raise ValueError(f"signature 段{e}")
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, HS_ALGS[alg]).digest()
    return hmac.compare_digest(expected, sig), alg


def cmd_verify(args):
    try:
        ok, alg = verify_token(args.token, args.secret)
    except ValueError as e:
        err(str(e))
    if args.json:
        print(json.dumps({"verified": ok, "alg": alg}, ensure_ascii=False, indent=2))
    else:
        print(f"算法：{alg}")
        print("✅ 签名有效" if ok else "❌ 签名无效（密钥错误或 token 被篡改）")
    sys.exit(0 if ok else 1)


def cmd_create(args):
    try:
        payload = json.loads(args.payload)
    except json.JSONDecodeError as e:
        err(f"payload 不是合法 JSON：{e}")
    if not isinstance(payload, dict):
        err("payload 必须是 JSON 对象")
    header = {"alg": "HS256", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode())
    sig = hmac.new(args.secret.encode("utf-8"), f"{h_b64}.{p_b64}".encode("ascii"),
                   hashlib.sha256).digest()
    token = f"{h_b64}.{p_b64}.{b64url_encode(sig)}"
    if args.json:
        print(json.dumps({"token": token}, ensure_ascii=False))
    else:
        print(token)
        print("\n⚠️ 仅供本地测试使用，不要用测试密钥签发生产 token。")


def build_parser():
    p = argparse.ArgumentParser(prog="jwt", description="终端 JWT 工具：解码 / 校验 / 生成（纯标准库）")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="解码 token（不校验签名）")
    d.add_argument("token", help="JWT 字符串")
    d.add_argument("--json", action="store_true", help="JSON 输出")
    d.set_defaults(func=cmd_decode)

    v = sub.add_parser("verify", help="用密钥校验 HS256/384/512 签名")
    v.add_argument("token", help="JWT 字符串")
    v.add_argument("--secret", required=True, help="签名密钥")
    v.add_argument("--json", action="store_true", help="JSON 输出")
    v.set_defaults(func=cmd_verify)

    c = sub.add_parser("create", help="生成测试用 token（HS256，仅供测试）")
    c.add_argument("--payload", required=True, help='JSON 对象，如 \'{"sub":"123"}\'')
    c.add_argument("--secret", required=True, help="签名密钥")
    c.add_argument("--json", action="store_true", help="JSON 输出")
    c.set_defaults(func=cmd_create)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
