#!/usr/bin/env python3
"""
Генерация подписок для VPN-клиентов.
"""

import base64
import os
import json
import logging
import urllib.parse
from typing import Dict, Any, List
from vless_utils import parse_vless_key, parse_country_from_key

SUBSCRIPTIONS_DIR = "docs/sub"

# Таблица соответствия ISO-кодов флагам
FLAG_TO_CODE = {
    "🇺🇸": "US", "🇷🇺": "RU", "🇩🇪": "DE", "🇫🇮": "FI", "🇸🇪": "SE",
    "🇳🇱": "NL", "🇵🇱": "PL", "🇪🇪": "EE", "🇱🇻": "LV", "🇱🇹": "LT",
    "🇫🇷": "FR", "🇬🇧": "GB", "🇸🇬": "SG", "🇮🇹": "IT", "🇪🇸": "ES",
    "🇯🇵": "JP", "🇨🇿": "CZ", "🇺🇦": "UA", "🇹🇷": "TR", "🇨🇭": "CH",
    "🇦🇱": "AL", "🇦🇺": "AU", "🇧🇬": "BG", "🇭🇰": "HK", "🇮🇳": "IN", "🇳🇴": "NO"
}

def format_key_name(key: str, latency_ms: float = None, custom_cat: str = None) -> str:
    """Форматирует ключ с новым хэштегом для читаемости в клиенте."""
    parsed = parse_vless_key(key)
    if not parsed:
        return key

    raw = parsed["raw"]
    # Отрезаем старый хэштег
    base_url = raw.split("#")[0]
    remark = parsed.get("remark", "")

    # Определяем код страны
    country_code = ""
    for emoji, code in FLAG_TO_CODE.items():
        if emoji in remark:
            country_code = code
            break
    if not country_code:
        c_name, _ = parse_country_from_key(key)
        country_code = c_name[:2].upper() if c_name else "UN"

    # Тип транспорта
    security = parsed["params"].get("security", "")
    proto_type = parsed["params"].get("type", "tcp")
    transport = "reality" if security == "reality" else proto_type

    # Пинг
    latency_str = f"{int(latency_ms)}ms" if latency_ms else ""

    parts = [f"[{country_code}]"]
    if custom_cat:
        parts.append(custom_cat)
    if latency_str:
        parts.append(latency_str)
    parts.append(transport)

    new_remark = urllib.parse.quote(" | ".join(parts))
    return f"{base_url}#{new_remark}"

def generate_subscriptions(results: Dict[str, Any]) -> None:
    os.makedirs(SUBSCRIPTIONS_DIR, exist_ok=True)
    all_keys = []
    categories = {}

    def extract_keys(data_dict, cat_prefix=""):
        res = []
        if not data_dict or not data_dict.get("top10"):
            return res
        for entry in data_dict["top10"]:
            k = entry["key"]
            ms = entry.get("latency_ms")
            res.append(format_key_name(k, latency_ms=ms, custom_cat=cat_prefix.upper()))
        return res

    # 1. VPN категории
    for country in ["baltics", "finland", "germany", "sweden", "netherlands", "poland"]:
        if country in results:
            keys = extract_keys(results[country], cat_prefix=country)
            categories[f"vpn_{country}"] = keys
            all_keys.extend(keys)

    # 2. Other countries
    if "other_countries" in results:
        for name, data in results["other_countries"].items():
            slug = name.lower().replace(" ", "_")
            keys = extract_keys(data, cat_prefix=name[:3])
            categories[f"other_{slug}"] = keys
            all_keys.extend(keys)

    # 3. Белые списки
    for mode in ["w_baltics", "w_finland", "w_germany", "w_sweden", "w_netherlands", "w_poland", "w_other", "russia"]:
        if mode in results:
            keys = extract_keys(results[mode], cat_prefix="WL")
            categories[mode] = keys
            all_keys.extend(keys)

    # Дедупликация
    seen = set()
    unique_keys = []
    for k in all_keys:
        parsed = parse_vless_key(k)
        if parsed and parsed["hash"] not in seen:
            seen.add(parsed["hash"])
            unique_keys.append(k)

    # Сохранение all
    with open(os.path.join(SUBSCRIPTIONS_DIR, "all_raw.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(unique_keys))
    with open(os.path.join(SUBSCRIPTIONS_DIR, "all.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(unique_keys).encode()).decode())

    # Сохранение категорий (сохраняем даже пустые файлы, чтобы не было 404)
    for cat_name, cat_keys in categories.items():
        content_raw = "\n".join(cat_keys)
        content_b64 = base64.b64encode(content_raw.encode()).decode() if content_raw else ""
        with open(os.path.join(SUBSCRIPTIONS_DIR, f"{cat_name}.txt"), "w", encoding="utf-8") as f:
            f.write(content_b64)
        with open(os.path.join(SUBSCRIPTIONS_DIR, f"{cat_name}_raw.txt"), "w", encoding="utf-8") as f:
            f.write(content_raw)

    logging.info(f"Подписки успешно сформированы в {SUBSCRIPTIONS_DIR}/")
