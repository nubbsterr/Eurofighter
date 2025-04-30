import hashlib 
import requests
import re
import sys

# return hex SHA256 signature of .exe/.dll file
def genSHA256(filepath):
    with open(filepath, "rb") as file: # open in read and binary mode, to pass binary data to hashlib, not text
        digest = hashlib.file_digest(file, "sha256") # that shrimple
    return digest.hexdigest()

# manually add a signature to db if not already in w/ specified file OR signature
def manualAdd(usrinput):
    isSHA256 = re.compile(r"^[a-fA-F0-9]{64}$").match(usrinput) # match usrinput to potential SHA256 digest; 64 characters of hexadecimal output; a-f, A-F, 0-9
    if (re.search(r"\.exe$", usrinput)) or (re.search(r"\.dll$", usrinput)): 
        print(f"[+] Eurofighter has deduced that the input is a filepath: {usrinput}")
        with open("signatures.txt", "a+") as db:
            content = db.read()
            digest = genSHA256(usrinput)
            if digest not in content:
                db.write(f"{digest}\n")
                print(f"[+] Eurofighter successfully added a signature to db: {digest}")
            else:
                print(f"[!] Eurofighter was served a duplicate entry and could not include it: {digest}")
    elif isSHA256:
        print(f"[+] Eurofighter has deduced that the input is a SHA256 hash: {usrinput}")
        with open("signatures.txt", "a+") as db:
            content = db.read()
            if usrinput not in content:
                db.write(f"{usrinput}\n")
                print(f"[+] Eurofighter successfully added a signature to db: {usrinput}")
            else:
                print(f"[!] Eurofighter was served a duplicate entry and coult not include it: {usrinput}")
    else:
        print(f"[x] Eurofighter could not deduce your input: {usrinput}")
        sys.exit(1)
        
def getSignatures():
    url = "https://bazaar.abuse.ch/api/v1/get_recent/?limit=100" # query for latest 100 signatures
    httpheaders = { "Auth-Key": "AUTH_KEY_HERE" }
    try:
        response = requests.get(url, httpheaders)
        response.raise_for_status()
        if response.status_code == 200: # nesting horror
            print(f"[+] A status code of 200 (OK) was returned from MalwareBazaar.")
            jsonresponse = response.json()
            for element in jsonresponse["data"]: # check if the file is an exe or dll b4 adding to db
                if (element["file_type"] == "exe") or (element["file_type"] == "dll"):
                    with open("signatures.txt", "a+") as db:
                        content = db.read()
                        if element["sha256_hash"] not in content:
                            db.write(f"{element["sha256_hash"]}\n")
            print("[+] Eurofighter updated signatures based off latest 100 signatures matching .exe/.dll files from MalwareBazaar.")

    except requests.HTTPError as httpErr:
        print(f"[!] A status code of {httpErr} was returned and signatures could not be updated. Check if MalwareBazaar is down.")
        print(f"[!] Eurofighter could not update its signatures!")

# returns True if a match was found
def compareDigestToDB(digest):
    with open("signatures.txt", "r") as db:
        content = db.read()
        dblines = content.splitlines()
        for signature in dblines:
            if digest == signature:
                print(f"[+] A match was found between the digest and signature!\nSignature: {signature}\nDigest: {digest}")
                return True
        print(f"[+] No match was found in the DB for digest: {digest}")
        return False

