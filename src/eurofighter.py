import sys, re, os, subprocess

from sigdetection import initKey, genSHA256, getSignatures, manualAdd, compareDigestToDB
from heuristics import execpStrings, parsePE

def help():
    print(r"""
[-] Use 'no-upgrade' to not automatically query latest signatures from MalwareBazaar when scanning files 
[-] Use 'upgrade' to immediately query latest signatures from MalwareBazaar.
Example Usage: `Eurofighter upgrade` or `python3 eurofighter.py upgrade` will update with signatures DB, depending on if you are executing the Python script or built executable.
      """)
    sys.exit(0)

# remove exec permissions and move to quarantine dir 
def quarantine(filepath):
    os.makedirs("eurofighter_quarantine", exist_ok=True)
    if os.name == "posix":
        subprocess.run(["sudo", "chmod", "-x", filepath], stdout=True)
        subprocess.run(["mv", filepath, "eurofighter_quarantine"], stdout=True)
    elif os.name == "nt":
        subprocess.run(["icacls", filepath, "/deny", "Everyone"], stdout=True)
        subprocess.run(["move", filepath, "eurofighter_quarantine"], stdout=True)
    else:
        print(f"[!] Operating system could not be identified. os.name shows: {os.name}?")
        sys.exit(0)
    print(f"[+] Eurofighter removed execution permissions and sent file to `eurofighter_quarantine` directory: {filepath}")
    print(f"[+] Execution permissions")

# suggest quarantine if PE or strings returns malicious details
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
                    suggestQuarantine(scan)
            else:
                print("[x] Eurofighter couldn't determine if the file is an .exe/.dll file, and needs to exit.")
                sys.exit(1)

def main():
    initKey()
    print("Eurofighter v2.2.0 by nubb (nubbsterr)")
    print("[!] Make sure you are running Eurofighter will elevated permissions!")
    print("[!] Eurofighter only accepts DLL and EXE files at the moment!")
    if sys.argv[1] == 'help': help()
    if sys.argv[1] == "no-upgrade": print("[!] Eurofighter will not update the signature DB before scanning!")
    if sys.argv[1] == "upgrade": 
        print("[!] Eurofighter will query latest signatures then exit!")
        getSignatures()
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

main()
print(f"[-] Eurofighter finished execution.")
