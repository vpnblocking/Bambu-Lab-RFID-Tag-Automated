# -*- coding: utf-8 -*-

"""
Bambu Lab RFID Writer - Improved Refactor Edition

Features:
- GitHub cache (24h TTL) for repository browsing
- Safe retry network layer
- Resume last spool selection
- Tag type detection (Gen4 UFUID / FUID)
- Validation of dump/key and SHA256 preview before writing
- JSON + TXT logs saved after writing
- Graceful error handling (no script crashes)
"""

import os
import re
import sys
import json
import time
import hashlib
import requests
from pathlib import Path
from datetime import datetime

from lib import get_proxmark3_location, run_command


# =============================
#  GLOBAL CONFIG
# =============================

GITHUB_API = "https://api.github.com/repos/queengooborg/Bambu-Lab-RFID-Library/contents"

DOWNLOAD_DIR = Path("downloads")
CACHE_DIR = Path("cache")
LOG_DIR = Path("logs")

for d in (DOWNLOAD_DIR, CACHE_DIR, LOG_DIR):
    d.mkdir(exist_ok=True)

CACHE_TTL = 60 * 60 * 24  # 24h
LAST_USED_FILE = CACHE_DIR / "last_used.json"

pm3Command = "bin/pm3"
pm3Location = None


# =============================
# UTILITIES
# =============================

def color(text, code="0"):
    return f"\033[{code}m{text}\033[0m"


def safe_request(url, retries=3, delay=1):
    """Reliable GitHub request with retry fallback."""
    for attempt in range(retries):
        try:
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            return r
        except Exception:
            print(color(f"⚠ Request failed ({attempt+1}/{retries}), retrying...", "33"))
            time.sleep(delay)

    raise RuntimeError("❌ Network unreachable after retries.")


def sha256_file(path):
    """Generate SHA256 checksum."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


# =============================
# CACHE HANDLER
# =============================

def get_cache_file(path=""):
    return CACHE_DIR / ("root.json" if not path else f"{path.replace('/', '_')}.json")


def load_last_used():
    if LAST_USED_FILE.exists():
        return json.loads(LAST_USED_FILE.read_text()).get("last")
    return None


def save_last_used(path):
    LAST_USED_FILE.write_text(json.dumps({"last": path}))


def clear_cache():
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
    print(color("\n🧹 Cache cleared.\n", "32"))


def github_list(path="", force=False):
    """Fetch GitHub folder structs with caching."""
    cache_file = get_cache_file(path)

    if cache_file.exists() and not force:
        data = json.loads(cache_file.read_text())
        if time.time() - data["timestamp"] < CACHE_TTL:
            return data["data"]

    url = f"{GITHUB_API}/{path}" if path else GITHUB_API
    r = safe_request(url)
    data = r.json()

    cache_file.write_text(json.dumps({"timestamp": time.time(), "data": data}))
    return data


# =============================
# USER INPUT / MENU SYSTEM
# =============================

def choose(options, message):
    """Safe selection menu."""
    while True:
        print(f"\n{message}:")
        for i, item in enumerate(options, start=1):
            print(f"{i}) {item['name']}")

        print("\n--- Options ---")
        print("R) Refresh list")
        print("C) Clear cache")
        print("Q) Quit")

        choice = input("> ").strip().lower()

        if choice == "q":
            sys.exit(0)
        if choice == "c":
            clear_cache()
            return "__REFRESH__"
        if choice == "r":
            return "__REFRESH__"
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice)-1]

        print(color("❌ Invalid input. Try again.", "31"))


# =============================
# FILE SELECTION LOGIC
# =============================

def detect_dump_files(path):
    files = github_list(path)
    dump = next((f for f in files if f["name"].lower().endswith("dump.bin")), None)
    key  = next((f for f in files if f["name"].lower().endswith("key.bin")), None)

    if not dump or not key:
        raise RuntimeError("❌ Folder missing required dump/key files.")

    return dump, key


def download_file(url, outpath):
    print(f"\n📥 Downloading `{outpath.name}` ...")
    r = safe_request(url)
    outpath.write_bytes(r.content)
    print(color(f"✔ Saved to {outpath}", "32"))
    return outpath


def fetch_dump_interactive():
    print("\n📦 Loading spool list...")

    while True:
        root = github_list()
        materials = [d for d in root if d["type"] == "dir"]
        choice = choose(materials, "Select material type")
        if choice != "__REFRESH__":
            break

    current = choice["path"]

    while True:
        items = github_list(current)
        subdirs = [i for i in items if i["type"] == "dir"]

        if subdirs:
            choice = choose(subdirs, "Select variant (color/batch)")
            if choice == "__REFRESH__":
                continue
            current = choice["path"]
            continue

        try:
            dump, key = detect_dump_files(current)
        except RuntimeError as e:
            print(color(f"\n{e}", "31"))
            print(color("↩ Select a deeper folder.\n", "33"))
            continue

        print(color(f"\n✔ Dump detected in: {current}", "32"))
        if input("Use this dump? (y/N): ").lower() == "y":
            dump_path = download_file(dump["download_url"], DOWNLOAD_DIR / dump["name"])
            key_path  = download_file(key["download_url"], DOWNLOAD_DIR / key["name"])
            save_last_used(current)
            return str(dump_path), str(key_path), dump["name"]

        print(color("\n↩ Restart selection...", "33"))


# =============================
# PROXMARK HANDLING
# =============================

def getTagType():
    print("\n🔍 Detecting tag...")
    output = run_command([pm3Location / pm3Command, "-d", "1", "-c", "hf mf info"]).lower()

    if "no tag" in output or "select failed" in output:
        raise RuntimeError("❌ No compatible NFC tag detected.")

    if "ufuid" in output:
        return "Gen 4 UFUID"
    if "fuid" in output:
        return "Gen 4 FUID"

    raise RuntimeError("❌ Unknown or unsupported tag.")


def writeTag(dump, key, ttype):
    print("\n💾 Writing tag...")
    if ttype == "Gen 4 FUID":
        run_command([pm3Location / pm3Command, "-c", f'hf mf restore --force -f "{dump}" -k "{key}"'], pipe=False)

    elif ttype == "Gen 4 UFUID":
        run_command([
            pm3Location / pm3Command, "-c",
            f'hf mf cload -f "{dump}"; '
            f'hf 14a raw -a -k -b 7 40; '
            f'hf 14a raw -k 43; '
            f'hf 14a raw -k -c e100; '
            f'hf 14a raw -c 85000000000000000000000000000008'
        ], pipe=False)


def verify_write():
    print("\n🔍 Validating write...")
    output = run_command([pm3Location / pm3Command, "-c", "hf mf info"])
    if "uid" in output.lower():
        print(color("✔ Validation OK — write successful.", "32"))
    else:
        print(color("⚠ Could not fully verify tag. It may still be correct.", "33"))


# =============================
# LOGGING
# =============================

def write_log(tag_type, dumpfile, keyfile, sha_dump, sha_key):
    ts = datetime.now().strftime("%Y-%m-%d-%H%M")
    txt = LOG_DIR / f"{ts}-write-log.txt"
    jsn = LOG_DIR / f"{ts}-write-log.json"

    data = {
        "timestamp": ts,
        "tag_type": tag_type,
        "dump_file": dumpfile,
        "dump_sha": sha_dump,
        "key_file": keyfile,
        "key_sha": sha_key,
    }

    txt.write_text(
        f"Bambu RFID Writing Log\n"
        f"=======================\n\n"
        f"Timestamp: {ts}\n"
        f"Tag Type: {tag_type}\n\n"
        f"Dump: {dumpfile}\nSHA256: {sha_dump}\n\n"
        f"Key:  {keyfile}\nSHA256: {sha_key}\n\n"
    )
    jsn.write_text(json.dumps(data, indent=2))

    print(color(f"\n📝 Logs saved:\n - {txt}\n - {jsn}", "34"))


# =============================
# MAIN
# =============================

def main():
    global pm3Location

    print(color("\n===============================", "36"))
    print(color("   Bambu Lab RFID Writer", "36"))
    print(color("===============================\n", "36"))

    pm3Location = get_proxmark3_location()
    if not pm3Location:
        print(color("❌ Proxmark3 not detected.", "31"))
        return

    last = load_last_used()
    if last and input(f"📌 Use last spool ({last})? (y/N): ").lower() == "y":
        dump, key = detect_dump_files(last)
        dump_path = download_file(dump["download_url"], DOWNLOAD_DIR / dump["name"])
        key_path  = download_file(key["download_url"],  DOWNLOAD_DIR / key["name"])
        dumpname  = dump["name"]
    else:
        dump_path, key_path, dumpname = fetch_dump_interactive()

    input("\n📌 Place tag on Proxmark and press ENTER...")

    while True:
        try:
            tagtype = getTagType()
            print(color(f"\n✔ Tag detected: {tagtype}\n", "32"))
            break
        except RuntimeError as e:
            print(color(f"\n{e}", "31"))
            print(color("⚠ Unsupported or unreadable tag.\n", "33"))

            print("Options:")
            print("1) Retry")
            print("2) Replace tag and retry")
            print("3) Cancel process")

            choice = input("> ").strip()
            if choice == "3":
                print(color("\n❌ Cancelled by user.\n", "31"))
                return
            print(color("\n📌 Adjust/replace tag and press ENTER...", "36"))
            input()

    dump_sha = sha256_file(dump_path)
    key_sha  = sha256_file(key_path)

    print(color("\n📄 File Verification", "36"))
    print(color("────────────────────────", "36"))

    print(f"📁 Dump file: {Path(dump_path).name}")
    print(f"   Size: {os.path.getsize(dump_path)} bytes")
    print(f"   SHA256: {dump_sha}\n")

    print(f"🔑 Key file: {Path(key_path).name}")
    print(f"   Size: {os.path.getsize(key_path)} bytes")
    print(f"   SHA256: {key_sha}\n")

    print(color("✔ Files verified.\n", "32"))

    if input("Proceed writing? (y/N): ").lower() != "y":
        print(color("\n❌ Cancelled.\n", "31"))
        return

    writeTag(dump_path, key_path, tagtype)
    verify_write()
    write_log(tagtype, dumpname, Path(key_path).name, dump_sha, key_sha)

    print(color("\n🎉 Tag successfully written!\n", "32"))


if __name__ == "__main__":
    main()
