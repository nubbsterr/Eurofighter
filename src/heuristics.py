import base64
import re
import subprocess
import pefile
from eurofighter import suggestQuarantine

# decode base64 ciphertext,  returns decoded ASCII string
def decodeBase64(ciphertext):
    try:
        plaintext = base64.b64decode(ciphertext, validate=True).decode("utf-8")
        print(f"[+] Eurofighter successfully decoded {ciphertext} to {plaintext}")
        return plaintext
    except Exception as err:
        print(f"[!] Eurofighter encountered an error while decoding ciphertext: {ciphertext}\n It may not a base64 string or is heavily obfuscated!")
        print(f"[!] Error encountered during decoding: {err}")
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

# run strings command and parse outputs for suspicious commands and whatnot
def execpStrings(filepath):
    malstrings = {"cmd.exe", "powershell.exe", "lsass.exe", "comsvcs.dll", "advapi32.dll", "kernel32.dll", "user32.dll", "ws2_32.dll", "urlmon.dll", "shell32.dll", "msvcrt.dll", "ntdll.dll", "wininet.dll", "regsvr32.exe", "Rundll32.exe", "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary", "GetProcAddress", "NtqueryInformationProcess"}
    cmd = subprocess.run(f"strings {filepath}", shell=True, check=True, capture_output=True, encoding="utf-8")
    stringsout = cmd.stdout.splitlines() # split at newlines then iterate over predefined set of malicious strings
    for strings in stringsout:
        if isBase64(strings):
            print(f"[+] A base64 string was found in {filepath}.\nString found: {strings}")
            decoded = decodeBase64(strings)
            if decoded in malstrings: 
                print(f"[+] A potentially malicious string was found in {filepath}.\nString found: {strings}")
                suggestQuarantine(filepath)

        if strings in malstrings: 
            print(f"[+] A potentially malicious string was found in {filepath}.\nString found: {strings}")
            suggestQuarantine(filepath)
        else: pass

# parse PE for sus stuff; dlls and functions in IAT/EAT
def parsePE(filepath):
    try:
        malstrings_dll = {"comsvcs.dll", "advapi32.dll", "kernel32.dll", "user32.dll", "ws2_32.dll", "urlmon.dll", "shell32.dll", "msvcrt.dll", "ntdll.dll", "wininet.dll", "Rundll32.exe"}
        malstrings_func = {"VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory", "CreateProcessA", "OpenProcess", "TerminateProcess", "SetWindowHookExA", "CallNextHookEx", "CreateRemoteThread", "CreateThread", "LoadLibraryA", "GetProcAddress", "RegCreateKeyA", "URLDownloadToFile", "InternetOpenUrlA", "InternetOpenA", "InternetReadFile", "NtqueryInformationProcess"}
        
        # load and parse pefile 
        pe = pefile.PE(filepath)

        # access sections
        for section in pe.sections:
            print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize)) 
    
        # list imported and exported symbols
        pe.parse_data_directories()
        print("========================== START PE INFO DUMP ==========================")
        pe.dump_info()
        print("========================== END PE INFO DUMP ============================")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll in malstrings_dll: input(f"A potentially malicious DLL, {entry.dll}, is an imported symbol of this file. Enter any key to continue.")
            print(entry.dll)
            for imp in entry.imports:
                print('\t', hex(imp.address), imp.name)

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name in malstrings_func: input(f"A potentially malicious function, {exp.name}, is an exported symbol of this PE file. Enter any key to continue.")
            print (hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)
        input("[-] PE parsing is complete. Please take time to read over the above info dump and decide to quarantine or not.")
        suggestQuarantine(filepath)
    except (IOError, pefile.PEFormatError, Exception) as err:
        print(f"An unexpected error occured while trying to parse PE details: {err}")
