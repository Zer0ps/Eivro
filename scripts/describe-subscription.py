#!/usr/bin/env python3
"""Manual subscription diagnostics. Responses stay in memory; output omits credentials."""
import base64
from collections import Counter
import getpass
import gzip
import io
import json
import re
import resource
import subprocess
import sys
from urllib.parse import parse_qsl, urlsplit
import zipfile

LIMIT = 2 * 1024 * 1024
ENUM_FIELDS = {"protocol", "type", "network", "security", "mode", "flow", "encryption", "headerType", "fp", "packetEncoding"}
SAFE_ENUMS = set("vless vmess trojan shadowsocks hysteria2 socks http freedom blackhole dns loopback direct block selector urltest tcp raw ws grpc xhttp httpupgrade kcp tls reality none gun multi guna auto stream-up stream-one packet-up xtls-rprx-vision chrome firefox safari edge randomized xudp packetaddr".split())
NUMBER_FIELDS = {"concurrency", "xudpConcurrency", "alterId", "aid", "port", "server_port"}


def key_name(key):
    return key if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9-]{0,60}", key) else "<key>"


def value_shape(key, value):
    if value is None or isinstance(value, bool):
        return value
    if key in NUMBER_FIELDS:
        try:
            number = int(value)
            if -(2**31) <= number < 2**31:
                return number
        except (TypeError, ValueError):
            pass
    if isinstance(value, str):
        if not value:
            return ""
        if key in ENUM_FIELDS and value in SAFE_ENUMS:
            return value
        if key in {"mux", "allowInsecure", "insecure"} and value in {"true", "false", "0", "1"}:
            return value
        if key in {"spx", "spiderX", "path"} and value == "/":
            return "/"
        return f"<string:{len(value)}>"
    return f"<{type(value).__name__}>"


def describe(data, depth=0, budget=None):
    budget = [0, 0] if budget is None else budget
    if depth > 3 or len(data) > LIMIT:
        raise ValueError("Payload limit")
    if data.startswith(b"\x1f\x8b"):
        body = gzip.GzipFile(fileobj=io.BytesIO(data)).read(LIMIT + 1)
        budget[0] += len(body)
        if budget[0] > LIMIT:
            raise ValueError("Expanded payload limit")
        return {"gzip": describe(body, depth + 1, budget)}
    if data.startswith(b"PK"):
        out = []
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if len(archive.infolist()) > 32:
                raise ValueError("Archive entry limit")
            for entry in archive.infolist():
                if entry.is_dir():
                    continue
                budget[1] += 1
                if budget[1] > 32 or entry.file_size > LIMIT:
                    raise ValueError("Archive limit")
                with archive.open(entry) as file:
                    body = file.read(LIMIT + 1)
                budget[0] += len(body)
                if budget[0] > LIMIT:
                    raise ValueError("Expanded payload limit")
                out.append(describe(body, depth + 1, budget))
        return {"zip": out}
    text = data.decode("utf-8-sig").strip()
    if text.startswith("<"):
        return {"format": "HTML, not a subscription"}
    if text.startswith(("[", "{")):
        counts = Counter()

        def walk(value, path="$", level=0):
            if level > 24:
                raise ValueError("JSON nesting limit")
            if isinstance(value, dict):
                shape = {key_name(k): value_shape(k, v) for k, v in value.items() if not isinstance(v, (dict, list))}
                containers = {key_name(k): type(v).__name__ for k, v in value.items() if isinstance(v, (dict, list))}
                counts[(path, json.dumps({**shape, **containers}, sort_keys=True))] += 1
                for k, v in value.items():
                    if isinstance(v, (dict, list)):
                        walk(v, path + "." + key_name(k), level + 1)
            elif isinstance(value, list):
                for v in value:
                    walk(v, path + "[]", level + 1)

        walk(json.loads(text))
        return {"format": "JSON", "shapes": [{"path": p, "count": n, "fields": json.loads(s)} for (p, s), n in counts.items()]}
    if "://" not in text:
        compact = "".join(text.split())
        decoded = base64.b64decode(compact + "=" * (-len(compact) % 4), altchars=b"-_", validate=True)
        return {"base64": describe(decoded, depth + 1, budget)}
    counts = Counter()
    for line in text.splitlines():
        if not line.strip():
            continue
        link = urlsplit(line.strip())
        if link.scheme == "vmess":
            body = line.strip()[8:]
            nested = describe(base64.b64decode(body + "=" * (-len(body) % 4)), depth + 1, budget)
            counts[json.dumps({"vmess": nested}, sort_keys=True)] += 1
            continue
        params = [[key_name(k), value_shape(k, v)] for k, v in parse_qsl(link.query, keep_blank_values=True)]
        counts[json.dumps({"scheme": value_shape("protocol", link.scheme), "params": sorted(params)}, sort_keys=True)] += 1
    return {"format": "links", "shapes": [{"count": n, **json.loads(s)} for s, n in counts.items()]}


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = getpass.getpass("HTTPS-ссылка подписки (ввод скрыт): ").strip()
    url = urlsplit(source)
    if url.scheme != "https" or url.username or url.password or any(ord(c) < 32 for c in source):
        raise ValueError("HTTPS URL required")
    config = "url = " + json.dumps(source) + "\n"
    result = subprocess.run(
        ["curl", "--silent", "--fail", "--noproxy", "*", "--location", "--max-redirs", "3", "--connect-timeout", "10", "--max-time", "25", "--max-filesize", str(LIMIT), "--proto", "=https", "--proto-redir", "=https", "--user-agent", "Eivro/0.2.0", "--header", "Accept-Encoding: identity", "--config", "-"],
        input=config.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    )
    if result.returncode:
        print("Загрузка не удалась; код curl:", result.returncode)
        return 1
    print(json.dumps(describe(result.stdout), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, OSError, EOFError, subprocess.TimeoutExpired, zipfile.BadZipFile):
        print("Не удалось получить или разобрать ответ. Ключи и тело ответа не выводились.")
        sys.exit(1)
