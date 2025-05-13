import sys
import re
import time

from sigdetection import initKey ,genSHA256, getSignatures, manualAdd, compareDigestToDB
from heuristics import execpStrings, parsePE

start_time = time.time()
print(r"""
 _______                    ___ _       _                      
(_______)                  / __|_)     | |     _               
 _____   _   _  ____ ___ _| |__ _  ____| |__ _| |_ _____  ____ 
|  ___) | | | |/ ___) _ (_   __) |/ _  |  _ (_   _) ___ |/ ___)
| |_____| |_| | |  | |_| || |  | ( (_| | | | || |_| ____| |    
|_______)____/|_|   \___/ |_|  |_|\___ |_| |_| \__)_____)_|    
                                 (_____|

v2.1.0 by Nubb @ https://github.com/nubbsterr/Eurofighter
[-] Eurofighter now has an ELF executable for Linux! Found in build/ directory! Testing only.
[!] Eurofighter only accepts DLL and EXE files at the moment!
[-] Enter Crtl+C if you ever need to forcefully exit!
[-] Use '--no-upgrade' to not automatically query latest signatures from MalwareBazaar when scanning files 
[-] Use '--upgrade' to immediately query latest signatures from MalwareBazaar.
      """)
def quarantine(filepath):
    # insert quarantine logic here
    print("[+] Eurofighter sucessfully quarantined file: " + filepath)

# suggest quarantine i PE or strings returns malicious details, takes filepath and message for what indicator was found
def suggestQuarantine(filepath):
    print(f"[-] Quarantine has been suggested by Eurofighter for {filepath}. Quarantine is suggested.")
    press = input("[+] Quarantine this file? Not quarantining will exit Eurofighter [y/n]: ")
    match press:
        case "y":
            quarantine(filepath)
        case "Y":
            quarantine(filepath)
        case "n":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case "N":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case _:
            quarantine(filepath)

def scan():
    scan = input("[-] Enter the absolute filepath of the file to scan or press 'q' to quit: ")
    match scan:
        case "q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case "Q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case _:
            if (re.search(r"\.exe$", scan)) or (re.search(r"\.dll$", scan)): 
                print(f"[+] Eurofighter will scan this .exe/.dll file: {scan}")
                print("[+] Beginning signature detection...")
                digest = genSHA256(scan)
                print(f"[+] Eurofighter successfully generated a hex digest: {digest}")
                if sys.argv[1] == "--no-upgrade":
                    print("[!] Eurofighter will not update the signature DB before scanning!")
                else:
                    print(f"[+] Querying latest signatures...")
                    getSignatures()
                print(f"[+] Comparing digest to DB...")
                if compareDigestToDB(digest):
                    quarantine(scan)
                else:
                    print(f"[-] Continuing to heuristic analysis...")
                    execpStrings(scan)
                    parsePE(scan)
            else:
                print("[x] Eurofighter couldn't determine if the file is an .exe/.dll file, and needs to exit.")
                sys.exit(1)

def main():
    initKey()
    if sys.argv[1] == "--no-upgrade": print("[!] Eurofighter will not update the signature DB before scanning!")
    if sys.argv[1] == "--upgrade": 
        print("[!] Eurofighter will query latest signatures then exit!")
        getSignatures()
        print(f"[-] Eurofighter finished execution after {time.time() - start_time} seconds.")
        sys.exit(0)
    press = input("[-] Enter 'q' to quit, press Enter to continue to scan a file, or 'f' to add a file, SHA256 hash or add multiple signatures to the signature database: ")
    match press:
        case "q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case "Q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case "f":
            usrinput = input("[-] Enter either the filepath, SHA256 hex digest, or signature name (e.g. Rubeus, mimikatz, CobaltStrike) of your choice: ")
            manualAdd(usrinput)
        case "F":
            usrinput = input("[-] Enter either the filepath, SHA256 hex digest, or signature name (e.g. Rubeus, Mimikatz, CobaltStrike) of your choice: ")
            manualAdd(usrinput)
        case _:
            print("[+] Continue to scan menu...")
            scan()
    print("[+] Eurofighter exited successfully.")

start_time = time.time()
main()
print(f"[-] Eurofighter finished execution after {time.time() - start_time} seconds.")
