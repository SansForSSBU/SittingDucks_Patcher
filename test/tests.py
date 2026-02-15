import unittest
import subprocess
import os
import patcher

def test_patcher(ver, instaload=False, speedfix=False, newgameplus=False):
    args = ["python3", "patcher.py", f"test/game_exes/{ver}/overlay.exe", "test/tmp/overlay.exe"]
    if instaload: args.append("--instaload")
    if speedfix: args.append("--speedfix")
    if newgameplus: args.append("--newgameplus")
    subprocess.run(args)

class TestPatcher(unittest.TestCase):
    def test_output_file_hashes(self):
        test_patcher("EU", instaload=True)



if __name__ == "__main__":
    unittest.main()