import os
import sys
import re

from sigdetection import genSHA256, getSignatures, manualAdd, compareDigestToDB

print(r"""
 _______                    ___ _       _                      
(_______)                  / __|_)     | |     _               
 _____   _   _  ____ ___ _| |__ _  ____| |__ _| |_ _____  ____ 
|  ___) | | | |/ ___) _ (_   __) |/ _  |  _ (_   _) ___ |/ ___)
| |_____| |_| | |  | |_| || |  | ( (_| | | | || |_| ____| |    
|_______)____/|_|   \___/ |_|  |_|\___ |_| |_| \__)_____)_|    
                                 (_____|

v1.0.0
Eurofighter only accepts DLL and EXE files at the moment!

--no-upgrade to not automatically fetch new signatures from MalwareBazaar when scanning files
      """)

def quarantine(filepath):
    # insert quarantine logic here
    print("[+] Eurofighter sucessfully quarantined file: " + filepath)

def scan():
    scan = input("[-] Enter the filepath of the file to scan or press 'q' to quit: ")
    match scan:
        case "q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case "Q":
            print("[+] Eurofighter exited successfully.")
            sys.exit(0)
        case _:
            if (re.search(r"\.exe$", scan)) or (re.search(r"\.dll$", scan)): 
                print("[+] Eurofighter will scan this .exe/.dll file!")
                print("[+] Beginning signature detection...")
                digest = genSHA256(scan)
                print(f"[+] Eurofighter successfully generated a hex digest: {digest}")
                if sys.argv[1] == "--no-upgrade":
                    print("[!] Eurofighter will not update the signature DB before scanning!")
                else:
                    print(f"[+] Updating signature DB...")
                    getSignatures()
                print(f"[+] Comparing digest to DB...")
                if compareDigestToDB(digest):
                    print(f"[+] Eurofighter completed signature-based analysis.")
                else:
                    quarantine(scan)
            else:
                print("[x] Eurofighter couldn't determine if the file is an .exe/.dll file, and needs to exit.")
                sys.exit(1)

def main():
    if sys.argv[1] == "--no-upgrade": print("[!] Eurofighter will not update the signature DB before scanning!")
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
            usrinput = input("[-] Enter either the filepath, SHA256 hex digest, or signature name (e.g. Rubeus, mimikatz, CobaltStrike) of your choice: ")
            manualAdd(usrinput)
        case _:
            print("[+] Continue to scan menu...")
            scan()
    print("[+] Eurofighter exited successfully.")
main()
