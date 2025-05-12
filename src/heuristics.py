import base64
import re
import subprocess
import pefile

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

# run strings command and parse outputs for suspicious commands and whatnot
def execpStrings():
    pass

# parse PE for sus stuff; dlls and functions in IAT/EAT
def parsePE(filepath):
    try:
        # load and parse pefile 
        pe = pefile.PE(filepath)

        # access sections
        for section in pe.sections:
            print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize)) 
    
        # list imported and exported symbols
        pe.parse_data_directories()
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print entry.dll
            for imp in entry.imports:
                print '\t', hex(imp.address), imp.name

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
    except (IOError, pefile.PEFormatError, Exception) as err:
        print(f"An unexpected error occured while trying to parse PE details: {err}")
