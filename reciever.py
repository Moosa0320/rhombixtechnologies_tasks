from cryptography.fernet import Fernet
import os

from sender import cipher, ciphertext

KEY_FILE = "secret.key"
INPUT_FILE = "encrypted_file.bin"
OUTPUT_FILE = "decrypted_message.txt"


if not os.path.exists(KEY_FILE):
    print("Key File Missing! You need secret key from Sender!")
    exit()

with open(KEY_FILE, "rb") as kf:
    key = kf.read()
cipher = Fernet(key)


with open(INPUT_FILE, "rb") as f:
    ciphertext = f.read()

try:
    plaintext = cipher.decrypt(ciphertext)
except:
    print("Decryption Failed! Wrong Key or corrupted File!")
    exit()

with open(OUTPUT_FILE, "wb") as out:
    out.write(plaintext)

print(f"Decrypted {INPUT_FILE} -> {OUTPUT_FILE}")