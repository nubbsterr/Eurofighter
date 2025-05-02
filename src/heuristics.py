import base64
import re

# decode base64 ciphertext,  returns decoded ASCII string
def decodeBase64(ciphertext):
    try:
        plaintext = base64.b64decode(ciphertext, validate=True).decode("utf-8")
        print(f"[+] Eurofighter successfully decoded {ciphertext} to {plaintext}")
        return plaintext
    except Exception as err:
        print(f"[!] {ciphertext} is not a base64 string and could not be decoded!")
        print(f"[!] {err}")
        return ""

# use regex to determine if string is b64 or not
def isBase64(ciphertext):
    if (re.match(r"[A-Za-z0-9+/=]", ciphertext)): # basically is a base64 string with no spaces, only a bunch of alpha characters and numbers
        print(f"[+] Eurofighter has potentially found a base64 string: {ciphertext}")
    try:
        base64.b64decode(ciphertext, validate=True) # raises error if not base64, duh
        return True
    except Exception:
        return False
