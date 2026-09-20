#!/usr/bin/env python3
import sys
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import vless_utils

GITHUB_RAW_URL = "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt"
MAX_WORKERS = 15
TEST_TIMEOUT = 3.0
MAX_LATENCY_MS = 2000

logging.basicConfig(level=logging.INFO, format="%(message)s")

def fetch_keys(url):
    logging.info("📥 Загружаем ключи из GitHub...")
    try:
        resp = requests.get(url, timeout=20)
        resp.raise_for_status()
        lines = resp.text.strip().splitlines()
        keys = [line.strip() for line in lines if line.strip().startswith("vless://")]
        validated = [k for k in keys if vless_utils.validate_key(k)]
        dedup = vless_utils.deduplicate_keys(validated)
        logging.info(f"✅ Найдено {len(dedup)} уникальных VLESS-ключей\n")
        return dedup
    except Exception as e:
        logging.error(f"❌ Ошибка загрузки: {e}")
        sys.exit(1)

def main():
    keys = fetch_keys(GITHUB_RAW_URL)
    print(f"🔍 Тестируем {len(keys)} ключей...\n")

    working = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(vless_utils.test_key_tcp, key, TEST_TIMEOUT, MAX_LATENCY_MS): key for key in keys}
        done = 0
        for future in as_completed(futures):
            done += 1
            res = future.result()
            if res:
                working.append(res)
                print(f"[{done}/{len(keys)}] ✅ {res['host']}:{res['port']} — {res['latency_ms']} мс")
            else:
                print(f"[{done}/{len(keys)}] ❌ недоступен")

    working.sort(key=lambda x: x["latency_ms"])
    print("\n" + "="*55)
    print(f"📊 ИТОГ: рабочих {len(working)} из {len(keys)}")
    print("="*55)

    if working:
        print("\n🏆 ТОП-5 самых быстрых:")
        for i, r in enumerate(working[:5], 1):
            print(f"  {i}. {r['host']}:{r['port']} — {r['latency_ms']} мс")
        with open("working_keys.txt", "w", encoding="utf-8") as f:
            for r in working:
                f.write(r["key"] + "\n")
        print("\n💾 Сохранено в working_keys.txt")
        print(f"\n⚡ ЛУЧШИЙ КЛЮЧ:\n{working[0]['key']}\n")

if __name__ == "__main__":
    main()