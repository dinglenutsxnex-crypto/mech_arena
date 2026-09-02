MODE = "decrypt"

KEY = "08050674cc9ab867197f0cad55a770ca"
IV  = "653e0715236e0f734f1ebf64228b322d"

from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

BASE = Path(__file__).parent
INPUT_DIR = Path("/storage/emulated/0/archive.bytes")
OUTPUT_DIR   = Path("/storage/emulated/0/decrypted_archives")
REPACKED_DIR = Path("/storage/emulated/0/repacked_archives")

def dec_data(d, k, i):
    c = Cipher(algorithms.AES(k), modes.CBC(i), default_backend()).decryptor()
    plain = c.update(d) + c.finalize()
    pad = plain[-1]
    return plain[:-pad] if 1 <= pad <= 16 else plain

def enc_data(d, k, i):
    padder = padding.PKCS7(128).padder()
    p = padder.update(d) + padder.finalize()
    enc = Cipher(algorithms.AES(k), modes.CBC(i), default_backend()).encryptor()
    return enc.update(p) + enc.finalize()

k = bytes.fromhex(KEY)
i = bytes.fromhex(IV)

if MODE == "decrypt":
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for f in INPUT_DIR.rglob('*.enc'):
        rel = f.relative_to(INPUT_DIR)
        outpath = OUTPUT_DIR / rel.with_suffix('.zip')
        outpath.parent.mkdir(parents=True, exist_ok=True)
        outpath.write_bytes(dec_data(f.read_bytes(), k, i))
        print(f"{rel} -> {outpath.name}")
    print("DONE")

elif MODE == "encrypt":
    REPACKED_DIR.mkdir(parents=True, exist_ok=True)
    for zp in OUTPUT_DIR.rglob('*.zip'):
        rel = zp.relative_to(OUTPUT_DIR)
        ep = REPACKED_DIR / rel.with_suffix('.enc')
        ep.parent.mkdir(parents=True, exist_ok=True)
        ep.write_bytes(enc_data(zp.read_bytes(), k, i))
        print(f"{rel} -> {ep.name}")
    print("DONE")

else:
    print("Set MODE to 'decrypt' or 'encrypt'")
