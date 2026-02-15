import base64
import json
import subprocess
from itertools import product

from utils import get_hash


def run_patcher(game_ver, instaload=False, speedfix=False, newgameplus=False):
    overlay = "overlay.exe" if game_ver in ["EU", "US04", "US05"] else "OVERLAY.exe"
    args = [
        "python3",
        "patcher.py",
        f"test/game_exes/{game_ver}/{overlay}",
        "test/tmp/overlay.exe",
    ]
    if instaload:
        args.append("--instaload")
    if speedfix:
        args.append("--speedfix")
    if newgameplus:
        args.append("--newgameplus")
    subprocess.run(args)


def generate_regression_hashes(game_ver):
    permutations = list(product([False, True], repeat=3))
    hashes = {}
    for perm in permutations:
        run_patcher(game_ver, instaload=perm[0], speedfix=perm[1], newgameplus=perm[2])
        hashes[str(perm)] = base64.b64encode(get_hash("test/tmp/overlay.exe")).decode(
            "utf-8"
        )

    return hashes


game_vers = ["EU", "PO", "RU", "US04", "US05"]
if __name__ == "__main__":
    for game_ver in game_vers:
        hashes = generate_regression_hashes(game_ver)
        with open(f"test/hashes/{game_ver}.json", "w") as f:
            json.dump(hashes, f, indent=4)
