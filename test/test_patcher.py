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
    def test_regression_hashes(self):