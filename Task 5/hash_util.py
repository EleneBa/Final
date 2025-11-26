# hash_util.py
import hashlib
import json
import os
import sys
from typing import Dict


HASHES_JSON = "hashes.json"


def compute_hashes(file_path: str) -> Dict[str, str]:
    """
    Compute SHA-256, SHA-1, and MD5 hashes for a given file.
    Returns a dict like:
        {"sha256": "...", "sha1": "...", "md5": "..."}
    """
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()

    # Read file in binary mode in chunks
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "md5": md5.hexdigest(),
    }


def save_baseline(file_path: str, hashes: Dict[str, str]) -> None:
    """
    Save baseline hashes to hashes.json.
    """
    data = {
        "reference_file": os.path.basename(file_path),
        "hashes": hashes,
    }
    with open(HASHES_JSON, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    print(f"[INFO] Baseline hashes saved to {HASHES_JSON} for file: {file_path}")


def load_baseline() -> Dict:
    """
    Load baseline hashes from hashes.json.
    """
    with open(HASHES_JSON, "r", encoding="utf-8") as f:
        return json.load(f)


def compare_hashes(baseline: Dict[str, str], current: Dict[str, str]) -> bool:
    """
    Compare two hash dictionaries. Return True if all match.
    """
    all_match = True
    for algo in ["sha256", "sha1", "md5"]:
        base_val = baseline[algo]
        curr_val = current[algo]
        status = "MATCH" if base_val == curr_val else "MISMATCH"
        print(f"{algo.upper()}:")
        print(f"    baseline: {base_val}")
        print(f"    current : {curr_val}")
        print(f"    -> {status}")
        if base_val != curr_val:
            all_match = False
    return all_match


def main():
    if len(sys.argv) != 2:
        print("Usage: py hash_util.py <file_path>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.isfile(file_path):
        print(f"[ERROR] File not found: {file_path}")
        sys.exit(1)

    print(f"[INFO] Computing hashes for {file_path}...")
    current_hashes = compute_hashes(file_path)

    # Case 1: no baseline yet -> create it
    if not os.path.exists(HASHES_JSON):
        print("[INFO] No hashes.json found. Creating baseline from this file.")
        save_baseline(file_path, current_hashes)
        print("[RESULT] Baseline created. Integrity status: N/A (first run)")
        return

    # Case 2: baseline exists -> compare
    print(f"[INFO] Loading baseline from {HASHES_JSON}...")
    baseline_data = load_baseline()
    baseline_hashes = baseline_data["hashes"]
    reference_file = baseline_data["reference_file"]

    print(f"[INFO] Baseline reference file: {reference_file}")
    print("[INFO] Comparing current hashes to baseline...")

    all_match = compare_hashes(baseline_hashes, current_hashes)

    if all_match:
        print("\n[RESULT] INTEGRITY CHECK: PASS (file has NOT been modified)")
    else:
        print("\n[RESULT] INTEGRITY CHECK: FAIL (file HAS been modified!)")


if __name__ == "__main__":
    main()
