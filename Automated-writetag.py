# -*- coding: utf-8 -*-

"""
Bambu Lab RFID Tag Writer - Interactive Edition (English + Cache Version)

Features:
- Interactive GitHub spool selection from https://github.com/queengooborg/Bambu-Lab-RFID-Library
- Local cache system to avoid GitHub rate limits
- Cache auto-expiration (24h TTL)
- Option to refresh folder cache or clear all cache
- Tag type detection (Gen4 FUID/UFUID)
- SHA256 verification and write logs
- Automatic dump.bin/key.bin detection

Requirements:
- Python 3.8+
- pip install requests
- Proxmark3 connected
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
#  CONFIGURATION
# =============================

GITHUB_API = "https://api.github.com/repos/queengooborg/Bambu-Lab-RFID-Library/contents"
DOWNLOAD_DIR = Path("downloads")
CACHE_DIR = Path("cache")
LOG_DIR = Path("logs")

for d in (DOWNLOAD_DIR, CACHE_DIR, LOG_DIR):
    d.mkdir(exist_ok=True)

CACHE_TTL = 60 * 60 * 24  # 24 hours

pm3Command = "bin/pm3"
pm3Location = None



# =============================
#  CACHE UTILITIES
# =============================

def get_cache_file(path):
    """Map GitHub path to safe cache file name."""
    if not path:
        return CACHE_DIR / "root.json"
    return CACHE_DIR / f"{path.replace('/', '_')}.json"


def clear_cache():
    """Remove all cache files."""
    for f in CACHE_DIR.glob("*.json"):
        f.unlink()
    print("\n🧹 Cache cleared.\n")


def github_list(path="", force_refresh=False):
    """Fetch GitHub folder listing with caching."""

    cache_file = get_cache_file(path)

    # Load from cache if fresh and not forced
    if cache_file.exists() and not force_refresh:
        with open(cache_file, "r") as f:
            cached = json.load(f)

        if time.time() - cached["timestamp"] < CACHE_TTL:
            return cached["data"]

    # Fetch from GitHub
    url = f"{GITHUB_API}/{path}" if path else GITHUB_API
    r = requests.get(url)

    # If rate limited, fallback to cache if exists
    if r.status_code == 403 and cache_file.exists():
        print("⚠ GitHub API limit reached — using cached data.")
        with open(cache_file, "r") as f:
            cached = json.load(f)
        return cached["data"]

    r.raise_for_status()
    data = r.json()

    # Save cache
    with open(cache_file, "w") as f:
        json.dump({"timestamp": time.time(), "data": data}, f)

    return data



# =============================
#  FILE AND HASH UTILITIES
# =============================

def sha256_file(path):
    """Generate SHA256 checksum."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def choose(options, message):
    """Selection menu with additional cache controls."""
    print(f"\n{message}:")
    for i, item in enumerate(options, start=1):
        print(f"{i}) {item['name']}")

    print("\n--- Options ---")
    print("R) Refresh this list (force GitHub fetch)")
    print("C) Clear all cache")
    print("Q) Quit")

    choice = input("> ").strip().lower()

    if choice == "r":
        print("\n🔄 Refreshing data...")
        refreshed = github_list(options[0].get("path", ""), force_refresh=True)
        # Can't directly rerun menu here cleanly — so return None to restart caller logic.
        return "__REFRESH__"

    if choice == "c":
        clear_cache()
        return "__REFRESH__"

    if choice == "q":
        sys.exit(0)

    return options[int(choice)-1]



# =============================
#  GITHUB FILE PARSER
# =============================

def detect_dump_files(path):
    """Detect dump.bin + key.bin inside final folder."""
    contents = github_list(path)

    dump = None
    key = None

    for f in contents:
        name = f["name"].lower()
        if name.endswith("dump.bin"):
            dump = f
        elif name.endswith("key.bin"):
            key = f

    if not dump:
        raise RuntimeError("❌ No *.dump.bin found.")
    if not key:
        raise RuntimeError("❌ No *.key.bin found.")

    return dump, key


def download_file(url, filename):
    """Download a file"""
    print(f"\n📥 Downloading `{filename.name}` ...")
    r = requests.get(url)
    r.raise_for_status()

    filename.parent.mkdir(parents=True, exist_ok=True)
    with open(filename, "wb") as f:
        f.write(r.content)

    print(f"✔ Saved to: {filename}")
    return filename



# =============================
#  INTERACTIVE NAVIGATION
# =============================

def select_variant(base_path):
    """Material → variant selection"""
    while True:
        dirs = [d for d in github_list(base_path) if d["type"] == "dir"]
        result = choose(dirs, "Select a material family / variant")
        if result == "__REFRESH__":
            continue
        return result


def navigate_to_dump(material_folder):
    """Navigate deeper until reaching final folder with dump.bin/key.bin."""

    current = select_variant(material_folder["path"])
    current_path = current["path"]

    while True:
        contents = github_list(current_path)
        dirs = [d for d in contents if d["type"] == "dir"]

        if dirs:
            print(f"\n📂 Current path: {current_path}")
            result = choose(dirs, "Select subfolder (color → batch → ID):")

            if result == "__REFRESH__":
                continue

            current_path = result["path"]
            continue

        # Final folder → detect dump+key
        try:
            dump, key = detect_dump_files(current_path)
        except RuntimeError as e:
            print(f"\n{e}")
            print("↩ Returning to previous level...")
            return navigate_to_dump(material_folder)

        print(f"\n✔ Valid dump detected at: {current_path}")
        if input("Use this dump? (y/N): ").lower() == "y":
            return current_path, dump, key

        print("\n↩ Restarting selection...")
        return navigate_to_dump(material_folder)



def fetch_dump_interactive():
    print("\n📦 Fetching materials list...")

    while True:
        root = github_list()
        materials = [d for d in root if d["type"] == "dir"]
        result = choose(materials, "Select material:")

        if result == "__REFRESH__":
            continue

        chosen = result
        break

    path, dump, key = navigate_to_dump(chosen)

    dump_path = download_file(dump["download_url"], DOWNLOAD_DIR / dump["name"])
    key_path  = download_file(key["download_url"], DOWNLOAD_DIR / key["name"])

    return str(dump_path), str(key_path), dump["name"]



# =============================
#  PROXMARK HANDLER
# =============================

def getTagType():
    print("\n🔍 Detecting tag type...")

    output = run_command([pm3Location / pm3Command, "-d", "1", "-c", "hf mf info"])
    output = output.replace("\r\n", "\n").replace("\r", "\n")

    if "iso14443a card select failed" in output.lower():
        raise RuntimeError("❌ No compatible NFC tag detected.")

    cap_re = r"(?:\[\+\]\s*Magic capabilities\.*\s*([()\w\d /-]+)\n+)"
    match = re.search(
        rf"\[=\]\s*--- Magic Tag Information\n+(\[=\]\s*<n/a>\n+|{cap_re}+)",
        output
    )

    if not match:
        raise RuntimeError("❌ Unable to read tag memory format.")

    if "<n/a>" in match.group(1):
        raise RuntimeError("❌ Unsupported or already locked tag.")

    capabilities = re.findall(cap_re, output)

    if "Gen 4 GDM / USCUID ( Gen4 Magic Wakeup )" in capabilities:
        return "Gen 4 FUID"
    if "Gen 4 GDM / USCUID ( ZUID Gen1 Magic Wakeup )" in capabilities:
        return "Gen 4 UFUID"

    raise RuntimeError("❌ Unsupported tag type (must be Gen4 FUID or UFUID).")



def writeTag(tagdump, keydump, tagtype):
    print("\n💾 Writing tag now...")

    if tagtype == "Gen 4 FUID":
        run_command([pm3Location / pm3Command,
                     "-c", f'hf mf restore --force -f "{tagdump}" -k "{keydump}"'], pipe=False)
        return

    if tagtype == "Gen 4 UFUID":
        run_command([
            pm3Location / pm3Command, "-c",
            f'hf mf cload -f "{tagdump}"; '
            f'hf 14a raw -a -k -b 7 40; '
            f'hf 14a raw -k 43; '
            f'hf 14a raw -k -c e100; '
            f'hf 14a raw -c 85000000000000000000000000000008'
        ], pipe=False)



# =============================
#  LOGGING
# =============================

def write_log(tag_type, dump_file, key_file, dump_sha, key_sha):
    timestamp = datetime.now().strftime("%Y-%m-%d-%H%M")
    log_file = LOG_DIR / f"{timestamp}-write-log.txt"

    with open(log_file, "w") as f:
        f.write("Bambu RFID Writer Log\n")
        f.write("=====================\n\n")
        f.write(f"Timestamp: {timestamp}\n")
        f.write(f"Tag type: {tag_type}\n\n")
        f.write(f"Dump file: {dump_file}\nSHA256: {dump_sha}\n\n")
        f.write(f"Key file: {key_file}\nSHA256: {key_sha}\n\n")

    print(f"\n📝 Log saved: {log_file}")



# =============================
#  MAIN PROGRAM
# =============================

def main():
    global pm3Location

    print("\n===================================================")
    print("🧪 Bambu Lab RFID Writer (with Cache System)")
    print("===================================================")

    pm3Location = get_proxmark3_location()
    if not pm3Location:
        print("❌ Proxmark3 not detected.")
        return

    tagdump, keydump, dumpname = fetch_dump_interactive()

    print("\n📌 Place the Proxmark3 on the tag and press ENTER...")
    input()

    tagtype = getTagType()

    # ===== HASH CHECK =====
    dump_sha = sha256_file(tagdump)
    key_sha = sha256_file(keydump)

    print("\n📄 File Verification:")
    print(f"Dump: {tagdump}  ({os.path.getsize(tagdump)} bytes)")
    print(f" SHA256 → {dump_sha}\n")

    print(f"Key:  {keydump}  ({os.path.getsize(keydump)} bytes)")
    print(f" SHA256 → {key_sha}\n")

    if input("Proceed? (y/N): ").lower() != "y":
        print("❌ Cancelled.")
        return

    # ==== WRITE ====
    writeTag(tagdump, keydump, tagtype)

    # ==== LOG ====
    write_log(tagtype, dumpname, Path(keydump).name, dump_sha, key_sha)

    print("\n🎉 Tag successfully written!\n")



if __name__ == "__main__":
    main()
