#!/usr/bin/env python3
"""
Тестирование новых функций vless_utils.
"""

import vless_utils

test_keys = [
    # Стандартный ключ с TLS
    "vless://abc123-4567-89ab-cdef-0123456789ab@example.com:443?security=tls&sni=vpn.example.com&fp=chrome#🇺🇸 США | VPN",
    # Reality
    "vless://def456-7890-1234-5678-901234567890@[2001:db8::1]:8443?security=reality&sni=google.com&pbk=xxx&sid=yyy#🇩🇪 Германия | Reality",
    # WS + path
    "vless://uuid@server.net:80?type=ws&path=/vless&host=proxy.net#🇫🇷 Франция | WS",
    # Без параметров
    "vless://uuid@1.2.3.4:8080#Simple",
    # Невалидные
    "invalid",
    "vless://bad@host",  # нет порта
]

for key in test_keys:
    parsed = vless_utils.parse_vless_key(key)
    print(f"{key[:60]:60} | valid: {parsed is not None}")
    if parsed:
        print(f"  uuid: {parsed['uuid'][:20]}... host: {parsed['host']}:{parsed['port']}")
        print(f"  params: {list(parsed['params'].keys())}")
        print(f"  remark: {parsed['remark'].encode('utf-8', errors='replace')}")
        print(f"  hash: {parsed['hash']}")
        print()

# Тест дедупликации
dup_keys = [
    "vless://same@host:443?security=tls&sni=example.com#Test1",
    "vless://same@host:443?security=tls&sni=example.com#Test2",  # дубль
    "vless://other@host:443?security=tls&sni=example.com#Different",
]
unique = vless_utils.deduplicate_keys(dup_keys)
print(f"Дедупликация: {len(dup_keys)} -> {len(unique)}")