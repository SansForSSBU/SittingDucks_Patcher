import unittest
import subprocess
import os
import patcher
import json
import hashlib
import base64
from itertools import product

def run_patcher(ver, instaload=False, speedfix=False, newgameplus=False):
    args = ["python3", "patcher.py", f"test/game_exes/{ver}/overlay.exe", "test/tmp/overlay.exe"]
    if instaload: args.append("--instaload")
    if speedfix: args.append("--speedfix")
    if newgameplus: args.append("--newgameplus")
    subprocess.run(args)

class TestPatcher(unittest.TestCase):
    def test_output_file_hashes(self):
        # TODO: Once all game versions have been gathered, use a for loop to try all.
        game_ver = "EU"
        permutations = list(product([False, True], repeat=3))
        hashes = {}
        for perm in permutations:
            run_patcher(game_ver, instaload=perm[0], speedfix=perm[1], newgameplus=perm[2])
            hashes[str(perm)] = base64.b64encode(patcher.get_hash("test/tmp/overlay.exe")).decode("utf-8")
        
        print(hashes)
        with open(f"test/hashes/{game_ver}.json", "w") as f:
            json.dump(hashes, f, indent=4)



if __name__ == "__main__":
    unittest.main()