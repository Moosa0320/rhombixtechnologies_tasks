from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"
INPUT_FILE = "message.txt"
OUTPUT_FILE = "encrypted_file.bin"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as kf:
        key = kf.read()
    print(f"Loaded existing key from {KEY_FILE}")
else:
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as kf:
        kf.write(key)
    print(f"Generated new key and saved to {KEY_FILE}")


cipher = Fernet(key)

with open(INPUT_FILE, "rb") as f:
    plaintext = f.read()

ciphertext = cipher.encrypt(plaintext)


with open(OUTPUT_FILE, "wb") as out:
    out.write(ciphertext)
print(f"Encrypted {INPUT_FILE} -> {OUTPUT_FILE}")



