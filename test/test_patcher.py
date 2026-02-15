import json

import generate_regression_hashes


def test_regression_hashes():
    game_vers = ["EU", "PO", "RU", "US04", "US05"]
    for game_ver in game_vers:
        with open(f"test/hashes/{game_ver}.json") as f:
            verification_hashes = json.load(f)
        hashes = generate_regression_hashes.generate_regression_hashes(game_ver)
        for k in verification_hashes:
            assert hashes[k] == verification_hashes[k]
