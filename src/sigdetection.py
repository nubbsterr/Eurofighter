import hashlib 
import requests
import re
import sys
import os
from dotenv import load_dotenv

AUTH_KEY = ""

def initKey():
    load_dotenv()
    global AUTH_KEY
    AUTH_KEY = os.getenv("AUTH_KEY")

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
    elif (re.fullmatch(r"\w+", usrinput, re.IGNORECASE)): # match for one or more word characters 
        # query for 100 samples of given signature
        url = "https://mb-api.abuse.ch/api/v1/"
        params = {"query": "get_siginfo", "signature": usrinput, "limit": "100"}
        httpheaders = { "Auth-Key": AUTH_KEY }
        try:
            response = requests.post(url, data=params, headers=httpheaders)
            response.raise_for_status()
            print(f"[+] A status code of 200 (OK) was returned from {response.url}.")
            jsonresponse = response.json()
            existing_hashes = set()
            # set comprehension to add each line to existing hashes to prevent dupes
            with open("signatures.txt", "r") as db:
                existing_hashes = set(line.strip() for line in db)
            with open("signatures.txt", "a+") as db:
                for element in jsonresponse["data"]: # check filetype, hash dupes
                    if element["file_type"] in ["exe", "dll"] and element["sha256_hash"] not in existing_hashes:
                        db.write(f"{element["sha256_hash"]}\n")
                        existing_hashes.add(element["sha256_hash"])
            print(f"[+] Eurofighter updated signatures based off given signature name: {usrinput}, for .exe/.dll files from MalwareBazaar.")

        except requests.RequestException as err:
            print(f"[!] A request error occured: {err}")
            print(f"[!] Eurofighter could not update its signatures!")
    else:
        print(f"[x] Eurofighter could not deduce your input: {usrinput}")
        sys.exit(1)
        
def getSignatures():
    # query for latest 100 signatures added and filter for file_type afterwards
    url = "https://mb-api.abuse.ch/api/v1/" 
    params = {"query": "get_recent", "selector": "100" }
    httpheaders = { "Auth-Key": AUTH_KEY }
    try:
        response = requests.post(url, data=params, headers=httpheaders)
        response.raise_for_status()
        print(f"[+] A status code of 200 (OK) was returned from {response.url}.")
        jsonresponse = response.json()
        existing_hashes = set()
        # set comprehension to add each line to existing hashes to prevent dupes
        with open("signatures.txt", "r") as db:
            existing_hashes = set(line.strip() for line in db)
        with open("signatures.txt", "a+") as db:
            for element in jsonresponse["data"]: # check filetype, hash dupes
                if element["file_type"] in ["exe", "dll"] and element["sha256_hash"] not in existing_hashes:
                    db.write(f"{element["sha256_hash"]}\n")
                    existing_hashes.add(element["sha256_hash"])
        print(f"[+] Eurofighter updated signatures based off 100 most recent signatures, for .exe/.dll files from MalwareBazaar.")
    except requests.RequestException as err:
        print(f"Something went wrong: {err}")
        print(f"[!] Eurofighter could not update its signatures!")

# returns True if a match was found
def compareDigestToDB(digest):
    with open("signatures.txt", "r") as db:
        dbsignatures = set(line.strip() for line in db)
        if digest in dbsignatures:
            print(f"[+] A match was found between the digest and a signature!\nDigest: {digest}")
            return True
        print(f"[+] No match was found in the DB for digest: {digest}")
        return False

