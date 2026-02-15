import hashlib


def get_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.file_digest(f, "md5").digest()