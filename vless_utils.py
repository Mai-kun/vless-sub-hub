#!/usr/bin/env python3
"""
Общие утилиты для работы с VLESS-ключами: парсинг, проверка, кэширование DNS.
"""

import re
import socket
import ssl
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
                security = params.get("security", "")
                sni = params.get("sni") or host  # если sni="" или None, используем host

                if security in ("tls", "reality"):
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


def validate_key(key: str) -> bool:
    """
    Проверяет базовую валидность VLESS-ключа.
    """
    return parse_vless_key(key) is not None


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


if __name__ == "__main__":
    # Тесты
    test_keys = [
        "vless://uuid@host:443?security=tls&sni=example.com#🇺🇸 United States",
        "vless://uuid@[::1]:80#Test",
        "invalid",
    ]

    for k in test_keys:
        print(f"{k[:50]:50} | valid: {validate_key(k)} | host_port: {parse_host_port(k)}")