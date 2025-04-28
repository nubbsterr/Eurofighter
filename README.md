# Eurofighter
```
 _______                    ___ _       _                      
(_______)                  / __|_)     | |     _               
 _____   _   _  ____ ___ _| |__ _  ____| |__ _| |_ _____  ____ 
|  ___) | | | |/ ___) _ (_   __) |/ _  |  _ (_   _) ___ |/ ___)
| |_____| |_| | |  | |_| || |  | ( (_| | | | || |_| ____| |    
|_______)____/|_|   \___/ |_|  |_|\___ |_| |_| \__)_____)_|    
                                 (_____|
```

My very own basic AV running off signature-based detection, heuristic and behavioural analysis, written in Python.

# What is Eurofighter?
Eurofighter is my very own anti-virus software designed to run on the Windows operating system, featuring basic signature-based and heuristic detection methods. I originally decided to write this in C++ where I promptly realized that "This will take far too long and require a lot more effort for similar payout.". Yes, C++ is lovely but more the amount of extra libraries to link and alien syntax, Python is just more appealing and **simple**. 

By no means is this project supposed to be a REAL anti-virus; it is a proof-of-concept to show my knowledge of 
1) How anti-virus detects and terminates malware.
2) How to evade malware.

Yes, I do plan to discuss how to evade Eurofighter, though that shouldn't be hard. Even Defender has [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to deal with among other tools xD

# Project Status
I will start working on this when I find the time to; hopefully that will be soon since I've been wanting to start this for a very long time!

Project status and agenda can be found below. Everything is a work-in-progress and the entire project is designed to be a proof-of-concept, not a real AV (for now, maybe.) If you have suggestions, or wish to contribute, please feel free to contact me on Discord @ nubbieeee or submit a PR!

# Project Agenda
## Basic Stuff
- Get file IO figured out to get sha256 digest for samples, will use Crypto++ library unless it's incompatible for some reason.
- Find a signature DB to use online; either MalwareBazaar or Malshare.
        - Malwarebazaar: `GET https://bazaar.abuse.ch/api/v1/get_recent/?limit=100`
        - Malshare: `GET https://malshare.com/api.php?api_key=YOUR_API_KEY&action=get_recent`
        - Ensure no dup signatures by saving timestamp ft. date and time for future queries; select signatures from after previous query.
        - Add signature of malicious files to local DB.
        - Add common malware/program to DB as well; mimikatz, rubeus, etc.
    - Local storage is possible thru .txt file for signature "DB"
- Quarantine sample; put it in some protected folder, remove execution permissions, or just delete the sample forcefully.
    - Could rename malware as `malware-<computed_hash>` then move to a specified 'quarantine' folder and remove execution privileges using `icacls <malware_file.exe/dll> /remove:g <username>:X /c /t` .
    - Force delete the file using `DeleteFile(<filename.exe/dll>)` in code or just call `std::system`.
## Heuristic Analysis (100% apathy)
### Static
- Check PE info; check PE header for Import/Export Directory Tables (IAT/EAT) for DLLs and imported functions. 
    - Namely createremotethread, writeprocessmemory, virtualalloc and whatnot.
- Check .text section for malicious instructions and obfuscation in PE. If .text is small then it may be a packed sample!
- Run strings command on the sample and check its output for bad stuff 
    - Detect and decode base64 encoded strings and determine if bits are malicious or not.
    - Check for sus stuff; `cmd.exe`, `powershell.exe`, `regsvr32.exe`, `Rundll32.exe`, URLs, IPs, API functions, etc. 
        - API functions include: 
            - `VirtualAlloc`; allocate writable/readable/executable memory, first step to executing malware in memory!
            - `WriteProcessMemory`; write process code to memory then execute in thread
            - `CreateRemoteThread`; create execution thread in current memory space, easy way to execute in memory, used in tandem with WriteProcessMemory
            - `LoadLibrary`; load a DLL, next step would maybe be checking the DLL being loaded?
            - `GetProcAddress`; get address of a function in running process to potentially execute it  
            - `NtQueryInformationProcess`; malware will exit if debugger is detected for evasion
    - Will test with actual samples before doing this! See [theZoo!](https://github.com/ytisf/theZoo)
### Dynamic
- Mock sandbox solution where we:
    1) Create but suspend the malware process
    2) Inject a DLL to log API calls made by the malware; logging is done into a .txt file in real-time
        - logging will be done over a network share between the host and VM, read-only and mounted once process started.
        - DLL will have checksum post analysis to check if anything was modified.
    3) Resume thread execution
        - VM will be securely isolated to prevent malware doing VM escape or leaking onto host machine; needs research.
    4) Close the sample when needed: 
        - After elapsed time, x amount of threads/processes opened, # of incidents spotted thru bad behaviour, etc.
        - <strong>WaitForSingleObject()</strong> is a good choice since in the case of the malware PROCESS (not THREAD) it will show that the process exited on its own!
            - Return type of `WAIT_TIMEOUT` = still running, terminate sample forcefully. `WAIT_OBJECT_0` = exited succesfully. `WAIT_FAILED` = function failed, terminate sample, then run `GetLastError` and output info to console! 
            - Use `DWORD` data type to store return value!
    4) Cleanup when needed or when we note that the malware has stopped executing; whenever (Close handles will basically free system memory that is running your process. Terminate first, then CloseHandle)
- <strong>NOTE:</strong> We should run this all in a VM; take initial snapshot, run malware, rollback snapshot, repeat! VM is connected to NO networks.  
- For scripting this from start to finish, the steps would be:
    1) Boot the VM and record a snapshot
    2) Copy malware sample to host
    3) Do the above steps for setting up the process and DLL injection
    4) Collect logs once malware is running and cleanup when appropriate
    5) Copy logs from VM to host 
    6) Rollback VM then shutdown.
- <strong>NOTE!</strong> Use a read-only shared folder on the VM to store the log data so it is NOT tampered with; TBD since 

## Sources
A whole lot of Google and AI, of which  led me to consult further sources:
- [icacls MS Docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) 

