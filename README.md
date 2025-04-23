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

My very own basic AV running off signature-based detection and static heuristics (TBD).

# What is Eurofighter?
Eurofighter is my very own anti-virus software designed to run on the Windows operating system, featuring basic signature-based and heuristic detection methods. 

By no means is this project supposed to be a REAL anti-virus; it is a proof-of-concept to show my knowledge of 
1) How anti-virus detects and terminates malware.
2) How to evade malware.

Yes, I do plan to discuss how to evade Eurofighter, though that shouldn't be hard. Even Defender has [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to deal with among other tools xD

# Project Status
I will start working on this when I find the time to; hopefully that will be soon since I've been wanting to start this for a very long time!

Project status and agenda can be found below. Everything is a work-in-progress and the entire project is designed to be a proof-of-concept, not a real AV (for now, maybe.) If you have suggestions, or wish to contribute, please feel free to contact me on Discord @ nubbieeee or submit a PR!

# Project Agenda
## Basic Stuff
- Pick a language LOL; prbly C or C++, rust if i wanna learn sumn but doubt it
- Get file IO figured out to get sha256 digest for samples, need library or sumn, might as well use win crypto API
- Find a signature DB to use online 
    - use GET request to constantly update before scanning samples; might use malwarebazaar or malshare; TBD but they both can get latest signatures; 
    - local storage is possible thru CSV or .txt file
- Quarantine sample; put it in some protected folder, remove execution permissions, or just delete the sample forcefully.
## Heuristic Analysis (100% apathy)
### Static
- <strong>use [pe-parse](https://github.com/trailofbits/pe-parse) to get PE information!</strong>
- Check PE info; check PE header for Import/Export Directory Tables (IAT/EAT) for DLLs and imported functions. 
    - Namely createremotethread, writeprocessmemory, virtualalloc and whatnot.
- Check .text section for malicious instructions and obfuscation in PE. If .text is small then it may be a packed sample!
- Run strings command via `cstdlib` and `system()` function on the sample 
    - check for sus stuff; `cmd.exe`, `powershell.exe`, `regsvr32.exe`, `Rundll32.exe`, URLs, IPs, API functions, etc. 
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
    3) Resume thread execution
    4) Close the sample when needed: 
        - After elapsed time, x amount of threads/processes opened, # of incidents spotted thru bad behaviour, etc.
        - <strong>WaitForSingleObject()</strong> is a good choice since in the case of the malware PROCESS (not THREAD) it will show that the process exited on its own!
            - Return type of `WAIT_TIMEOUT` = still running, terminate sample forcefully. `WAIT_OBJECT_0` = exited succesfully. `WAIT_FAILED` = function failed, terminate sample, then run `GetLastError` and output info to console! 
            - Use `DWORD` data type to store return value!
    4) Cleanup when needed or when we note that the malware has stopped executing; whenever (Close handles will basically free system memory that is running your process. Terminate first, then CloseHandle)
- <strong>NOTE: </stromg> We should run this all in a VM; take initial snapshot, run malware, rollback snapshot, repeat! VM is connected to NO networks.  
- For scripting this from start to finish, the steps would be:
    1) Boot the VM and record a snapshot
    2) Copy malware sample to host
    3) Do the above steps for setting up the process and DLL injection
    4) Collect logs once malware is running and cleanup when appropriate
    5) Copy logs from VM to host 
    6) Rollback VM then shutdown.
- <strong>NOTE!</strong> Use a read-only shared folder on the VM to store the log data so it is NOT tampered with; TBD since 
