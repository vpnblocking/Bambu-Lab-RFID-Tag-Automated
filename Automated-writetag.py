# -*- coding: utf-8 -*-

"""
Bambu Lab RFID Writer (Stable Absolute Path Edition)

Features:
- Absolute paths (safe to run from anywhere)
- GitHub cache (24h TTL)
- Resume last spool selection
- Tag support: Gen4 FUID, Gen4 UFUID, Gen1a (cwipe + cload)
- Back navigation (no dead ends)
- SHA256 preview of dump/key
- JSON + TXT logs
"""

import os
import sys
import json
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime

from lib import get_proxmark3_location, run_command


# =============================
# PATH SETUP (Absolute Paths)
# =============================

BASE_DIR = Path(__file__).resolve().parent

DOWNLOAD_DIR = BASE_DIR / "downloads"
CACHE_DIR = BASE_DIR / "cache"
LOG_DIR = BASE_DIR / "logs"

for d in (DOWNLOAD_DIR, CACHE_DIR, LOG_DIR):
    d.mkdir(exist_ok=True)

pm3Command = BASE_DIR / "bin" / "pm3"
pm3Location = None


# =============================
# CONFIG
# =============================

GITHUB_API = "https://api.github.com/repos/queengooborg/Bambu-Lab-RFID-Library/contents"
CACHE_TTL = 60 * 60 * 24
LAST_USED_FILE = CACHE_DIR / "last_used.json"


# =============================
# UTILITIES
# =============================

def color(text, code="0"):
    return f"\033[{code}m{text}\033[0m"


def safe_request(url, retries=3, delay=1):
    """Reliable GitHub fetch."""
    for i in range(retries):
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            return r
        except:
            print(color(f"⚠ Network error ({i+1}/{retries}), retrying...", "33"))
            time.sleep(delay)
    raise RuntimeError("❌ GitHub unreachable.")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================
# CACHE HANDLING
# =============================

def get_cache_file(path=""):
    return CACHE_DIR / (f"{path.replace('/', '_')}.json" if path else "root.json")


def load_last_used():
    if LAST_USED_FILE.exists():
        return json.loads(LAST_USED_FILE.read_text()).get("last")
    return None


def save_last_used(path):
    LAST_USED_FILE.write_text(json.dumps({"last": path}))


def clear_cache():
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
    print(color("🧹 Cache cleared.\n", "32"))


def github_list(path="", force=False):
    cache_file = get_cache_file(path)

    if cache_file.exists() and not force:
        data = json.loads(cache_file.read_text())
        if time.time() - data["timestamp"] < CACHE_TTL:
            return data["data"]

    data = safe_request(f"{GITHUB_API}/{path}" if path else GITHUB_API).json()
    cache_file.write_text(json.dumps({"timestamp": time.time(), "data": data}))
    return data


# =============================
# MENU SYSTEM
# =============================

def choose(options, message, allow_back=False):
    while True:
        print(f"\n{message}:")
        for idx, item in enumerate(options, 1):
            print(f"{idx}) {item['name']}")

        print("\n--- Options ---")
        if allow_back:
            print("B) Back")
        print("R) Refresh")
        print("C) Clear Cache")
        print("Q) Quit")

        choice = input("> ").strip().lower()

        if choice == "q":
            sys.exit(0)
        if choice == "c":
            clear_cache()
            return "__REFRESH__"
        if choice == "r":
            return "__REFRESH__"
        if allow_back and choice == "b":
            return "__BACK__"
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1]

        print(color("❌ Invalid option.", "31"))


# =============================
# FILE SELECTION
# =============================

def detect_dump_files(path):
    files = github_list(path)
    dump = next((f for f in files if f["name"].lower().endswith("dump.bin")), None)
    key = next((f for f in files if f["name"].lower().endswith("key.bin")), None)

    if not dump or not key:
        raise RuntimeError("Missing dump.bin/key.bin")

    return dump, key


def download_file(url, outpath):
    print(f"\n📥 Downloading {outpath.name}...")
    outpath.write_bytes(safe_request(url).content)
    print(color("✔ Downloaded.", "32"))
    return outpath


def fetch_dump_interactive():
    print("\n📦 Loading materials...")

    while True:
        materials = [d for d in github_list() if d["type"] == "dir"]
        choice = choose(materials, "Select material type", allow_back=False)
        if choice != "__REFRESH__":
            break

    current = choice["path"]
    stack = [current]

    while True:
        items = github_list(current)
        subdirs = [d for d in items if d["type"] == "dir"]

        if subdirs:
            choice = choose(subdirs, "Select variant", allow_back=True)

            if choice == "__REFRESH__":
                continue
            if choice == "__BACK__":
                if len(stack) > 1:
                    stack.pop()
                    current = stack[-1]
                    continue
                return fetch_dump_interactive()

            current = choice["path"]
            stack.append(current)
            continue

        try:
            dump, key = detect_dump_files(current)
        except:
            print(color("❌ No valid files here.", "31"))
            stack.pop()
            current = stack[-1]
            continue

        print(color(f"\n✔ Dump found in: {current}", "32"))
        confirm = input("Use this dump? (y/N/B): ").lower()

        if confirm == "y":
            dump_path = download_file(dump["download_url"], DOWNLOAD_DIR / dump["name"])
            key_path = download_file(key["download_url"], DOWNLOAD_DIR / key["name"])
            save_last_used(current)
            return str(dump_path), str(key_path), dump["name"]

        if confirm == "b":
            stack.pop()
            current = stack[-1]
            continue

        return fetch_dump_interactive()


# =============================
# TAG ACTIONS
# =============================

def getTagType():
    output = run_command([str(pm3Command), "-d", "1", "-c", "hf mf info"]).lower()

    if "gen 1a" in output:
        return "Gen 1a"
    if "ufuid" in output:
        return "Gen 4 UFUID"
    if "fuid" in output:
        return "Gen 4 FUID"

    raise RuntimeError("Unsupported tag.")


def writeTagGen1a(dumpfile):
    print(color("\n🧹 Wiping tag...", "33"))
    run_command([str(pm3Command), "-c", "hf mf cwipe"])

    print(color("\n💾 Writing...", "32"))
    run_command([str(pm3Command), "-c", f'hf mf cload -f "{dumpfile}"'])

    print(color("\n✔ Gen1a write complete.\n", "32"))


def writeTag(tagdump, keydump, tagtype):

    if tagtype == "Gen 1a":
        return writeTagGen1a(tagdump)

    if tagtype == "Gen 4 FUID":
        run_command([str(pm3Command), "-c", f'hf mf restore --force -f "{tagdump}" -k "{keydump}"'])
        return

    if tagtype == "Gen 4 UFUID":
        run_command([
            str(pm3Command), "-c",
            f'hf mf cload -f "{tagdump}"; hf 14a raw -a -k -b 7 40; hf 14a raw -k 43; '
            f'hf 14a raw -k -c e100; hf 14a raw -c 85000000000000000000000000000008'
        ])
        return

    raise RuntimeError("Invalid tag type handler.")


# =============================
# LOGGING
# =============================

def write_log(tagtype, dumpname, keyname, sha_dump, sha_key):
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    file = LOG_DIR / f"{timestamp}-write-log.txt"

    file.write_text(
        f"Bambu RFID Write Log\n"
        f"---------------------\n"
        f"Timestamp: {timestamp}\n"
        f"Tag Type: {tagtype}\n\n"
        f"Dump: {dumpname}\nSHA256: {sha_dump}\n"
        f"Key:  {keyname}\nSHA256: {sha_key}\n"
    )

    print(color(f"\n📝 Log saved: {file}", "34"))


# =============================
# MAIN
# =============================

def main():
    global pm3Location

    print(color("\n======= Bambu RFID Writer =======", "36"))

    pm3Location = get_proxmark3_location()
    if not pm3Location:
        print(color("❌ Proxmark not detected.", "31"))
        return

    last = load_last_used()

    if last and input(f"📌 Use last spool ({last})? (y/N): ").lower() == "y":
        dump, key = detect_dump_files(last)
        dump_path = download_file(dump["download_url"], DOWNLOAD_DIR / dump["name"])
        key_path = download_file(key["download_url"], DOWNLOAD_DIR / key["name"])
        dumpname = dump["name"]
    else:
        dump_path, key_path, dumpname = fetch_dump_interactive()

    input("\n📌 Place tag and press ENTER...")

    while True:
        try:
            tagtype = getTagType()
            print(color(f"✔ Detected: {tagtype}", "32"))
            break
        except:
            print(color("❌ No valid tag detected.", "31"))
            if input("Retry? (y/N): ").lower() != "y":
                return

    dump_sha = sha256_file(dump_path)
    key_sha = sha256_file(key_path)

    print(color("\n📄 File Integrity:", "36"))
    print(f"Dump SHA256: {dump_sha}")
    print(f"Key  SHA256: {key_sha}")

    if input("\nProceed? (y/N): ").lower() != "y":
        print(color("\n❌ Cancelled.", "31"))
        return

    writeTag(dump_path, key_path, tagtype)
    write_log(tagtype, dumpname, Path(key_path).name, dump_sha, key_sha)

    print(color("\n🎉 Done — Tag programmed successfully.\n", "32"))


if __name__ == "__main__":
    main()
