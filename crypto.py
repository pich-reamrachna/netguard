import os
from cryptography.fernet import Fernet
from colors import green, yellow

KEY_FILE = os.getenv("KEY_FILE", "netguard.key")
LOG_FILE = os.getenv("LOG_FILE", "netguard_log.enc")

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    print(green(f"[+] New encryption key generated and saved to '{KEY_FILE}'"))
    return key

def encrypt_and_save(log_entries, key):
    fernet = Fernet(key)
    existing = ""
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "rb") as f:
                existing = fernet.decrypt(f.read()).decode()
        except Exception:
            existing = ""

    combined = (existing.strip() + "\n\n" + "\n".join(log_entries)).strip()
    with open(LOG_FILE, "wb") as f:
        f.write(fernet.encrypt(combined.encode()))
    print(green(f"[+] Session appended and saved to '{LOG_FILE}'"))

def decrypt_and_show(key):
    if not os.path.exists(LOG_FILE):
        print(yellow("[-] No log file found. Run a monitoring session first."))
        return
    fernet = Fernet(key)
    with open(LOG_FILE, "rb") as f:
        decrypted = fernet.decrypt(f.read()).decode()
    print("\n" + "="*55)
    print("         DECRYPTED LOG FILE CONTENTS")
    print("="*55)
    print(decrypted)
    print("="*55 + "\n")
