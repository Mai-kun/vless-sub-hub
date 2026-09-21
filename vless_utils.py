#!/usr/bin/env python3
"""
Общие утилиты для работы с VLESS-ключами: парсинг, проверка, кэширование DNS.
"""

import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import hashlib
import logging
import sys
from functools import lru_cache
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import unquote

# Настроим stdout на UTF-8 для Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
logging.basicConfig(level=logging.INFO, format="%(message)s")


def parse_vless_key(key: str) -> Optional[Dict[str, Any]]:
    """
    Полный парсер VLESS-ключа.
    Возвращает словарь с полями:
    - uuid, host, port
    - params: dict query-параметров (security, sni, type, fp, pbk, sid, path, host, serviceName)
    - remark: строка после # (дешифрованная)
    - raw: оригинальный ключ
    - hash: уникальный хэш для дедупликации (uuid@host:port:type:sni)
    """
    if not key.startswith("vless://"):
        return None

    try:
        # Разделяем схему, uuid+hostport+query, фрагмент
        without_scheme = key[len("vless://"):]
        hash_pos = without_scheme.find("#")
        fragment = unquote(without_scheme[hash_pos + 1:]) if hash_pos != -1 else ""
        before_fragment = without_scheme[:hash_pos] if hash_pos != -1 else without_scheme

        # Разделяем uuid@host:port?query
        at_pos = before_fragment.rfind("@")
        if at_pos == -1:
            return None

        uuid = before_fragment[:at_pos]
        after_at = before_fragment[at_pos + 1:]

        # Разделяем host:port и query
        query_pos = after_at.find("?")
        if query_pos == -1:
            host_port = after_at
            query_str = ""
        else:
            host_port = after_at[:query_pos]
            query_str = after_at[query_pos + 1:]

        # Парсим host:port
        if ":" not in host_port:
            return None
        host, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
        host = host.strip("[]")

        # Парсим query-параметры
        params = {}
        if query_str:
            for pair in query_str.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = unquote(v)

        # Извлекаем тип транспорта (по умолчанию tcp)
        transport = params.get("type", "tcp")
        sni = params.get("sni", host)  # SNI по умолчанию = host

        # Хэш для дедупликации
        hash_str = f"{uuid}@{host}:{port}:{transport}:{sni}"
        key_hash = hashlib.md5(hash_str.encode()).hexdigest()[:12]

        return {
            "raw": key,
            "uuid": uuid,
            "host": host,
            "port": port,
            "params": params,
            "remark": fragment,
            "hash": key_hash,
        }
    except Exception as e:
        logging.debug(f"Ошибка парсинга ключа {key[:50]}: {e}")
        return None


@lru_cache(maxsize=256)
def parse_host_port(key: str) -> Optional[Tuple[str, int]]:
    """
    Извлекает хост и порт из VLESS-ключа (совместимость со старым кодом).
    Возвращает (host, port) или None при ошибке.
    """
    parsed = parse_vless_key(key)
    if parsed:
        return parsed["host"], parsed["port"]
    return None


@lru_cache(maxsize=512)
def getaddrinfo_cached(host: str, port: int):
    """
    Кэшированная версия socket.getaddrinfo.
    """
    return socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)


def test_key_tcp(
    key: str,
    timeout: float = 3.0,
    max_latency_ms: float = 2000
) -> Optional[Dict[str, Any]]:
    """
    Проверяет доступность сервера через TCP.
    Возвращает словарь с результатом или None если недоступен.
    """
    parsed = parse_vless_key(key)
    if not parsed:
        return None

    host, port = parsed["host"], parsed["port"]
    params = parsed["params"]

    try:
        infos = getaddrinfo_cached(host, port)
    except socket.gaierror:
        return None

    best = None
    for (family, socktype, proto, canonname, sockaddr) in infos:
        start = time.time()
        sock = None
        try:
            sock = socket.socket(family, socktype)
            sock.settimeout(timeout)
            result = sock.connect_ex(sockaddr)
            elapsed = round((time.time() - start) * 1000, 1)

            if result == 0 and elapsed <= max_latency_ms:
                security = (params.get("security") or "").lower()
                sni = params.get("sni") or host  # если sni="" или None, используем host

                # TLS handshake только для security == "tls";
                # для security == "reality" достаточно успешного TCP-коннекта (result == 0)
                if security == "tls":
                    rem_timeout = max(timeout - (time.time() - start), 0.5)
                    tls_ok = test_tls_handshake(sock, sni, rem_timeout)
                    if not tls_ok:
                        continue

                if best is None or elapsed < best["latency_ms"]:
                    best = {
                        "key": key,
                        "host": host,
                        "port": port,
                        "latency_ms": elapsed,
                        "family": family,
                        "security": security,
                    }
        except (socket.timeout, OSError, ssl.SSLError):
            continue
        finally:
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

    return best


def test_tls_handshake(
    sock: socket.socket,
    sni: str,
    timeout: float = 2.0
) -> bool:
    """Выполняет TLS handshake, устойчив к сбоям."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        server_name = sni if sni else None
        ssl_sock = context.wrap_socket(
            sock,
            server_hostname=server_name,
            do_handshake_on_connect=False
        )
        ssl_sock.settimeout(timeout)
        ssl_sock.do_handshake()
        ssl_sock.close()
        return True
    except Exception:
        return False


def parse_country_from_key(key: str) -> Optional[Tuple[str, str]]:
    """
    Извлекает название страны и флаг из фрагмента ключа.
    Возвращает (country_name, flag_emoji) или (None, None).
    """
    if '#' not in key:
        return None, None

    try:
        fragment = unquote(key.split('#', 1)[1])
        # Ищем название страны (начинается с заглавной, может содержать пробелы, дефисы)
        match = re.search(
            r'([A-Z][A-Za-zÀ-ž](?:[A-Za-zÀ-ž\s\-]*[A-Za-zÀ-ž])?)(?:\s*[,|])',
            fragment
        )
        if not match:
            return None, None

        country = match.group(1).strip()
        flag = fragment[:match.start()].strip()
        return country, flag
    except Exception:
        return None, None


# Транспорты, не поддерживаемые NekoBox (sing-box): "unknown transport type: xhttp"
UNSUPPORTED_TRANSPORTS = {"xhttp", "splithttp"}


BAD_DOMAINS = (
    "09vpn.com",
    "myfilecdn.com",
    "serverslocal.ru",
    "banovano.space",
    "biznes.lol",
)


def validate_key(key: str) -> bool:
    """Проверяет, что VLESS-ключ совместим с NekoBox и не заблокирован."""
    parsed = parse_vless_key(key)
    if not parsed:
        return False

    transport = (parsed["params"].get("type") or "tcp").lower()
    if transport in UNSUPPORTED_TRANSPORTS:
        return False

    security = (parsed["params"].get("security") or "none").lower()
    if security not in ("tls", "reality"):
        return False

    host = parsed.get("host", "").lower()
    if any(domain in host for domain in BAD_DOMAINS):
        return False

    return True


def deduplicate_keys(keys: List[str]) -> List[str]:
    """
    Удаляет дубликаты ключей на основе хэша (uuid@host:port:type:sni).
    Сохраняет первый встреченный вариант.
    """
    seen = {}
    result = []
    for key in keys:
        parsed = parse_vless_key(key)
        if not parsed:
            continue
        key_hash = parsed["hash"]
        if key_hash not in seen:
            seen[key_hash] = True
            result.append(key)
    logging.info(f"Дедупликация: {len(keys)} -> {len(result)} уникальных ключей")
    return result


PROBE_URL = "http://www.gstatic.com/generate_204"
XRAY_START_TIMEOUT = 3.0
_port_lock = threading.Lock()
_next_local_port = 20000


def find_xray_bin() -> Optional[str]:
    """Ищет бинарник Xray: XRAY_BIN, PATH, либо ./xray(.exe)."""
    env_bin = os.environ.get("XRAY_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin
    for name in ("xray", "xray.exe"):
        found = shutil.which(name)
        if found:
            return found
        local = os.path.abspath(name)
        if os.path.isfile(local) and os.access(local, os.X_OK):
            return local
    return None


def _allocate_local_port() -> int:
    global _next_local_port
    with _port_lock:
        port = 20000 + (_next_local_port % 40000)
        _next_local_port += 1
        return port


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").lower() in ("1", "true", "yes")


def build_xray_config(parsed: Dict[str, Any], local_port: int) -> Dict[str, Any]:
    """Собирает клиентский JSON-конфиг Xray для одного VLESS-ключа."""
    params = parsed["params"]
    network = (params.get("type") or "tcp").lower()
    if network == "h2":
        network = "http"
    elif network == "splithttp":
        network = "xhttp"

    security = (params.get("security") or "none").lower()
    if security not in ("tls", "reality"):
        security = "none"

    sni = params.get("sni") or params.get("host") or parsed["host"]
    fingerprint = params.get("fp") or "chrome"
    path = params.get("path") or "/"
    host_header = params.get("host") or sni

    stream: Dict[str, Any] = {
        "network": network,
        "security": security,
    }

    if security == "reality":
        stream["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "publicKey": params.get("pbk") or "",
            "shortId": params.get("sid") or "",
            "spiderX": params.get("spx") or "/",
        }
    elif security == "tls":
        tls_settings: Dict[str, Any] = {
            "serverName": sni,
            "fingerprint": fingerprint,
            "allowInsecure": _truthy(params.get("allowInsecure")),
        }
        alpn = params.get("alpn")
        if alpn:
            tls_settings["alpn"] = [part.strip() for part in alpn.split(",") if part.strip()]
        stream["tlsSettings"] = tls_settings

    if network == "ws":
        stream["wsSettings"] = {
            "path": path,
            "host": host_header,
        }
    elif network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName") or params.get("servicename") or "",
            "multiMode": (params.get("mode") or "").lower() == "multi",
        }
    elif network == "xhttp":
        xhttp: Dict[str, Any] = {
            "path": path,
            "host": host_header,
        }
        if params.get("mode"):
            xhttp["mode"] = params["mode"]
        extra_raw = params.get("extra")
        if extra_raw:
            try:
                extra = json.loads(extra_raw)
                if isinstance(extra, dict):
                    xhttp["extra"] = extra
            except json.JSONDecodeError:
                pass
        stream["xhttpSettings"] = xhttp
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {
            "path": path,
            "host": host_header,
        }
    elif network == "http":
        stream["httpSettings"] = {
            "path": path,
            "host": [host_header],
        }
    elif network == "tcp" and (params.get("headerType") or "none") == "http":
        stream["tcpSettings"] = {
            "header": {
                "type": "http",
                "request": {
                    "path": [path] if path else ["/"],
                    "headers": {
                        "Host": [host_header],
                    },
                },
            }
        }

    user: Dict[str, Any] = {
        "id": parsed["uuid"],
        "encryption": params.get("encryption") or "none",
    }
    flow = params.get("flow")
    if flow and network == "tcp" and security in ("tls", "reality"):
        user["flow"] = flow

    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "tag": "http-in",
                "listen": "127.0.0.1",
                "port": local_port,
                "protocol": "http",
                "settings": {"allowTransparent": False},
            }
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": parsed["host"],
                            "port": parsed["port"],
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": stream,
            }
        ],
    }


def _wait_port(port: int, timeout: float = XRAY_START_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.15):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _stop_process(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2)
    except Exception:
        pass


def test_key_xray(
    key: str,
    timeout: float = 2.5,
    xray_bin: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Поднимает headless Xray и проверяет ключ реальным HTTP-запросом
    на http://cp.cloudflare.com/generate_204. Успех только при HTTP 204.
    """
    parsed = parse_vless_key(key)
    if not parsed:
        return None

    params = parsed["params"]
    if (params.get("security") or "").lower() == "reality" and not params.get("pbk"):
        return None

    binary = xray_bin or find_xray_bin()
    if not binary:
        logging.error("Xray binary not found. Set XRAY_BIN or put xray on PATH.")
        return None

    local_port = _allocate_local_port()
    config = build_xray_config(parsed, local_port)
    config_path = None
    proc = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            prefix="xray-probe-",
            delete=False,
            encoding="utf-8",
        ) as handle:
            json.dump(config, handle)
            config_path = handle.name

        proc = subprocess.Popen(
            [binary, "run", "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not _wait_port(local_port):
            return None
        if proc.poll() is not None:
            return None

        try:
            import requests

            proxy = f"http://127.0.0.1:{local_port}"
            start = time.time()
            resp = requests.get(
                PROBE_URL,
                proxies={"http": proxy, "https": proxy},
                timeout=timeout,
                allow_redirects=True,
            )
            elapsed = round((time.time() - start) * 1000, 1)
        except requests.RequestException:
            return None

        if resp.status_code not in (200, 204):
            return None

        return {
            "key": key,
            "host": parsed["host"],
            "port": parsed["port"],
            "latency_ms": elapsed,
            "family": socket.AF_INET,
            "security": params.get("security", ""),
        }
    except Exception as exc:
        logging.debug(f"Xray probe failed for {parsed['host']}:{parsed['port']}: {exc}")
        return None
    finally:
        _stop_process(proc)
        if config_path:
            try:
                os.unlink(config_path)
            except OSError:
                pass


if __name__ == "__main__":
    # Тесты
    test_keys = [
        "vless://uuid@host:443?security=tls&sni=example.com#🇺🇸 United States",
        "vless://uuid@[::1]:80#Test",
        "invalid",
    ]

    for k in test_keys:
        print(f"{k[:50]:50} | valid: {validate_key(k)} | host_port: {parse_host_port(k)}")