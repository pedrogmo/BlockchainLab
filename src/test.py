import hashlib
import struct

def mine_nonce(email: str, github_url: str, difficulty: int) -> int:
    """Brute-force search for a valid nonce."""
    nonce = 0
    email_utf8 = email.encode("utf-8")
    github_url_utf8 = github_url.encode("utf-8")

    while True:
        nonce_bytes = struct.pack(">Q", nonce)
        data = email_utf8 + b"\n" + github_url_utf8 + b"\n" + nonce_bytes
        hash_bytes = hashlib.sha256(data).digest()

        zero_bytes = difficulty // 8
        remaining_zeros = difficulty % 8

        failed = False
        i = 0
        while i < zero_bytes:
            if hash_bytes[i] != 0:
                failed = True
                break
            i += 1

        if failed:
            nonce += 1
            continue

        if hash_bytes[i] < (1 << (8 - remaining_zeros)):
            return nonce

        # if hash_bytes[0] == 0 and hash_bytes[1] == 0 and hash_bytes[2] == 0 and hash_bytes[3] < 16:
        #     return nonce

        nonce += 1

email = "pgomesmoreira@tudelft.nl"
github = "https://github.com/pedrogmo/BlockchainLab"

nonce = mine_nonce(email, github, 28)
print(nonce)

email_utf8 = email.encode("utf-8")
github_url_utf8 = github.encode("utf-8")
nonce_bytes = struct.pack(">Q", nonce)
data = email_utf8 + b"\n" + github_url_utf8 + b"\n" + nonce_bytes
hash_bytes = hashlib.sha256(data).digest()

print(hash_bytes.hex())