# Eurofighter
My very own basic AV running off signature-based detection, heuristic and behavioural analysis, written in Python.

# What is Eurofighter?
Eurofighter is my very own anti-virus software designed to run on the Windows operating system, featuring basic signature-based and heuristic detection methods. I originally decided to write this in C++ where I promptly realized that "This will take far too long and require a lot more effort for similar payout.". Yes, C++ is lovely but more the amount of extra libraries to link and alien syntax, Python is just more appealing and **simple**. 

By no means is this project supposed to be a REAL anti-virus; it is a proof-of-concept to show my knowledge of 
1) How anti-virus detects and terminates malware.
2) How to evade malware.

Yes, I do plan to discuss how to evade Eurofighter, though that shouldn't be hard. Even Defender has [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to deal with among other tools xD

# Project Status
Project status and agenda can be found below. Everything is a work-in-progress and the entire project is designed to be a proof-of-concept, not a real AV (for now, maybe.) If you have suggestions, or wish to contribute, please feel free to contact me on Discord @ nubbieeee or submit a PR!

# Project Agenda
## Basic Stuff
- Add common malware/program to DB as well; mimikatz, rubeus, etc.
- Quarantine sample; put it in some protected folder, remove execution permissions, or just delete the sample forcefully.
    - Could rename malware as `malware-<computed_hash>` then move to a specified 'quarantine' folder and remove execution privileges using `icacls <malware_file.exe/dll> /remove:g <username>:X /c /t` .
    - Force delete the file using `DeleteFile(<filename.exe/dll>)` in code or just call `std::system`.
## Heuristic Analysis (100% apathy)
### Static
- PE analysis and heuristics are almost done! Need to rest soon.
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

