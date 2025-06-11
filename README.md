# Eurofighter
My very own basic AV running off signature-based detection, heuristic and behavioural analysis, written in Python.

Eurofighter is my very own anti-virus software designed to run on Windows and Linux, featuring basic signature-based and heuristic detection methods. By no means is this project supposed to be a REAL anti-virus; it is a proof-of-concept to show my knowledge of 

1) How anti-virus detects and terminates malware.
2) How to evade malware.

Yes, I do plan to discuss how to evade Eurofighter, though that shouldn't be hard. Even Defender has [DefenderCheck](https://github.com/matterpreter/DefenderCheck) to deal with among other tools xD

# Dependencies
Eurofighter requires the `dotenv`, `pefile` and `requests` modules, which can all be installed through pip, pipx, or your own package manager if it has such modules as packages. For archlinux, pip can be installed using `yay` with `yay python-pip`. Similarly, you can run `sudo pacman -S python-pip` or `sudo pacman -S python-pipx` to install either package. `yay` can be used to install packages if you do not want to set up a Python virtual environment by running `yay [python-module_name]`. E.g. `yay python-requests`. 

# Compile From Source
You can compile Eurofighter into an executable for Linux/Windows using `pyinstaller`, if you hate calling `python3` a bunch:
1. Install `pyinstaller` using `pipx` with `pipx install pyinstaller`. You can use `pip` but I don't have a Python venv going so I resort to `pipx`.
2. Clone this repo using `git clone https://github.com/nubbsterr/Eurofighter.git`
3. `cd` Eurofighter/src to enter the source directory of Eurofighter. 
4. Compile using `pyinstaller` with the command: `pyinstaller --onefile --name Eurofighter eurofighter.py`. A Linux or Windows executable will be generated depending on what system you are on (I legit have 0 care for MacOS).

# Evading Eurofighter
Evasion can definitely be done by obfuscating the file contents. Strings and PE analysis will fail if it cannot find an exact match to the malicious function calls or DLLs, which are hard-coded. If it is base64 encoded then string *may* pick it up since it will decode any potential base64 string it finds.

You can definitely evade signature-based detection if the file does not exactly match any signature in the `signatures.txt` "database". Just change ANYTHING in the file and the hash changes. 

# Project Agenda
Static analysis and quarantine is done! No plans to continue to dynamic analysis since VM management through the terminal will prbly suck a bunch. As it stands, Eurofighter is decently complete and just needs some live testing.
## Dynamic Analysis (prbly won't implement)
- Mock sandbox solution where we:
    1) Create but suspend the malware process
    2) Inject a DLL to log API calls made by the malware; logging is done into a .txt file in real-time
        - logging will be done over a network share between the host and VM, read-only and mounted once process started.
        - DLL will have checksum post analysis to check if anything was modified.
    3) Resume thread execution
    4) Close the sample when needed: 
        - After elapsed time, x amount of threads/processes opened, # of incidents spotted thru bad behaviour, etc.
        - **WaitForSingleObject()** is a good choice since in the case of the malware PROCESS (not THREAD) it will show that the process exited on its own!
            - Return type of `WAIT_TIMEOUT` = still running, terminate sample forcefully. `WAIT_OBJECT_0` = exited succesfully. `WAIT_FAILED` = function failed, terminate sample, then run `GetLastError` and output info to console! 
            - Use `DWORD` data type to store return value!
    4) Cleanup when needed or when we note that the malware has stopped executing; whenever (Close handles will basically free system memory that is running your process. Terminate first, then CloseHandle)
- For scripting this from start to finish, the steps would be:
    1) Boot the VM and record a snapshot
    2) Copy malware sample to host
    3) Do the above steps for setting up the process and DLL injection
    4) Collect logs once malware is running and cleanup when appropriate
    5) Copy logs from VM to host 
    6) Rollback VM then shutdown.

