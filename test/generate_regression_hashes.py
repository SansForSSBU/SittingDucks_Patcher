import unittest
import subprocess
import os
import json
import hashlib
import base64
from itertools import product

def get_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.file_digest(f, "md5").digest()

def run_patcher(ver, instaload=False, speedfix=False, newgameplus=False):
    args = ["python3", "patcher.py", f"test/game_exes/{ver}/overlay.exe", "test/tmp/overlay.exe"]
    if instaload: args.append("--instaload")
    if speedfix: args.append("--speedfix")
    if newgameplus: args.append("--newgameplus")
    subprocess.run(args)

def generate_regression_hashes(game_ver):
    # TODO: Once all game versions have been gathered, use a for loop to try all.
    permutations = list(product([False, True], repeat=3))
    hashes = {}
    for perm in permutations:
        run_patcher(game_ver, instaload=perm[0], speedfix=perm[1], newgameplus=perm[2])
        hashes[str(perm)] = base64.b64encode(get_hash("test/tmp/overlay.exe")).decode("utf-8")

    return hashes

if __name__ == "__main__":
    game_ver = "EU"
    hashes = generate_regression_hashes(game_ver)
    with open(f"test/hashes/{game_ver}.json", "w") as f:
        json.dump(hashes, f, indent=4)