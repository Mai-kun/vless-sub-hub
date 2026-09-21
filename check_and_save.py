#!/usr/bin/env python3
import sys
import json
import os
import logging
import requests
from collections import defaultdict
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Настроим stdout на UTF-8 для Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import vless_utils
from vless_utils import (
    validate_key,
    deduplicate_keys,
)
from subscriptions import generate_subscriptions

VLESS_SOURCES = [
    # Огромный агрегатор (1500+ VLESS-ключей, обновляется каждые 15 мин)
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/Splitted-By-Protocol/vless.txt",

    # Репозиторий kort0881 (обновленный путь к VLESS)
    "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/main/output/vless.txt",

    # Топ-100 проверенных быстрых нод
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",

    # Правильный путь в ebrasha
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/main/vless_configs.txt",

    # Источники igareck (черные списки)
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
]

WHITE_SOURCES = [
    # Белые списки igareck
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
]

MAX_WORKERS = 40
TEST_TIMEOUT = 1.8
MAX_LATENCY_MS = 2000

COUNTRIES = {
    "baltics":     ["lithuania", "estonia", "latvia"],
    "finland":     ["finland"],
    "germany":     ["germany"],
    "sweden":      ["sweden"],
    "netherlands": ["netherlands"],
    "poland":      ["poland"],
}

COUNTRIES_ALL_KEYWORDS = [kw for kws in COUNTRIES.values() for kw in kws]

SKIP_COUNTRY_NAMES = {"anycast", "anycast-ip", "unknown"}


def parse_country_from_key(key):
    """Returns (country_name, flag_emoji) parsed from the key's URL fragment."""
    return vless_utils.parse_country_from_key(key)


def fetch_keys(url):
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        keys = [line.strip() for line in lines if line.strip().startswith("vless://")]
        # Валидация ключей
        validated = [k for k in keys if validate_key(k)]
        if len(validated) < len(keys):
            logging.warning(f"URL {url}: отфильтровано {len(keys) - len(validated)} невалидных ключей")
        # Дедупликация
        dedup = deduplicate_keys(validated)
        if len(dedup) < len(validated):
            logging.warning(f"URL {url}: удалено {len(validated) - len(dedup)} дубликатов")
        return dedup
    except Exception as e:
        logging.error(f"Ошибка загрузки {url}: {e}")
        return []


def filter_keys(keys, mode):
    if mode in COUNTRIES:
        keywords = COUNTRIES[mode]
        return [k for k in keys if any(kw in k.lower() for kw in keywords)]
    if mode == "other":
        return [k for k in keys if not any(kw in k.lower() for kw in COUNTRIES_ALL_KEYWORDS) and "russia" not in k.lower()]
    if mode == "russia":
        return [k for k in keys if "russia" in k.lower()]
    if mode.startswith("w_"):
        country = mode[2:]
        if country in COUNTRIES:
            keywords = COUNTRIES[country]
            return [k for k in keys if any(kw in k.lower() for kw in keywords)]
        if country == "other":
            return [k for k in keys if not any(kw in k.lower() for kw in COUNTRIES_ALL_KEYWORDS) and "russia" not in k.lower()]
    return keys


def parse_host_port(key):
    result = vless_utils.parse_host_port(key)
    if result:
        return result
    return None, None


def test_key(key):
    """Стабильная TCP-проверка: headless Xray в GitHub Actions отсекает 100% ключей из-за сбоев сокетов в облаке."""
    return vless_utils.test_key_tcp(key, timeout=TEST_TIMEOUT, max_latency_ms=MAX_LATENCY_MS)


def check_mode(keys, old_first_seen=None):
    if old_first_seen is None:
        old_first_seen = {}
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_key, key): key for key in keys}
        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)

    working.sort(key=lambda x: x["latency_ms"])

    for r in working:
        r["first_seen"] = old_first_seen.get(r["key"], now)

    return {
        "best": working[0]["key"] if working else None,
        "top10": working[:10],
        "total_working": len(working),
        "total": len(keys),
    }


def load_old_first_seen():
    try:
        with open("docs/keys.json", "r", encoding="utf-8") as f:
            old = json.load(f)
        seen = {}
        for mode_data in old.values():
            top_key = "top10" if "top10" in mode_data else "top5"
            if isinstance(mode_data, dict) and top_key in mode_data:
                for entry in mode_data[top_key]:
                    if "key" in entry and "first_seen" in entry:
                        seen[entry["key"]] = entry["first_seen"]
        return seen
    except Exception:
        return {}


def main():
    old_first_seen = load_old_first_seen()

    all_keys = []
    for i, url in enumerate(VLESS_SOURCES, 1):
        print(f"Загружаем источник {i}/{len(VLESS_SOURCES)}: {url}")
        keys = fetch_keys(url)
        print(f"Загружено {len(keys)} ключей")
        all_keys.extend(keys)

    black_keys = deduplicate_keys(all_keys)
    print(f"Итого уникальных BLACK ключей: {len(black_keys)}")

    white_keys = []
    for i, url in enumerate(WHITE_SOURCES, 1):
        print(f"Загружаем WHITE источник {i}/{len(WHITE_SOURCES)}: {url}")
        white_keys.extend(fetch_keys(url))
    white_keys = deduplicate_keys(white_keys)
    print(f"Итого уникальных WHITE ключей: {len(white_keys)}")

    results = {
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }

    for country in list(COUNTRIES.keys()):
        filtered = filter_keys(black_keys, country)[:70]
        print(f"[{country}] {len(filtered)} ключей, проверяем...")
        results[country] = check_mode(filtered, old_first_seen)
        print(f"[{country}] Рабочих: {results[country]['total_working']}/{results[country]['total']}")

    other_keys = filter_keys(black_keys, "other")
    print(f"[other] {len(other_keys)} ключей, группируем по странам...")
    country_groups = defaultdict(list)
    country_flags = {}
    for key in other_keys:
        name, flag = parse_country_from_key(key)
        if not name or name.lower() in SKIP_COUNTRY_NAMES:
            name = "Other"
            flag = "🌍"
        country_groups[name].append(key)
        if name not in country_flags:
            country_flags[name] = flag

    other_countries = {}
    for name, keys in country_groups.items():
        print(f"  [{name}] {len(keys)} ключей, проверяем...")
        checked = check_mode(keys[:40], old_first_seen)
        print(f"  [{name}] Рабочих: {checked['total_working']}/{checked['total']}")
        checked["flag"] = country_flags[name]
        other_countries[name] = checked
    results["other_countries"] = other_countries

    for mode in ("w_baltics", "w_finland", "w_germany", "w_sweden", "w_netherlands", "w_poland", "w_other", "russia"):
        filtered = filter_keys(white_keys, mode)[:50]
        print(f"[{mode}] {len(filtered)} ключей, проверяем...")
        results[mode] = check_mode(filtered, old_first_seen)
        print(f"[{mode}] Рабочих: {results[mode]['total_working']}/{results[mode]['total']}")

    os.makedirs("docs", exist_ok=True)
    with open("docs/keys.json", "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print("Сохранено в docs/keys.json")

    # Генерация подписок
    print("\nГенерируем подписки...")
    generate_subscriptions(results)
    print("Подписки сохранены в docs/sub/")


if __name__ == "__main__":
    main()
