import unittest
import subprocess
import os
import patcher
import json
import hashlib
import base64
from itertools import product
import generate_regression_hashes

def run_patcher(ver, instaload=False, speedfix=False, newgameplus=False):
    args = ["python3", "patcher.py", f"test/game_exes/{ver}/overlay.exe", "test/tmp/overlay.exe"]
    if instaload: args.append("--instaload")
    if speedfix: args.append("--speedfix")
    if newgameplus: args.append("--newgameplus")
    subprocess.run(args)

def test_regression_hashes():
    game_ver = "EU"
    with open(f"test/hashes/{game_ver}.json") as f:
        verification_hashes = json.load(f)
    hashes = generate_regression_hashes.generate_regression_hashes(game_ver)
    for k in verification_hashes:
        assert hashes[k] == verification_hashes[k]