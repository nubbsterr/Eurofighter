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

My very own basic AV running off signature-based detection, heuristic and behavioural analysis.

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
    - ifstream for IO and 
- Find a signature DB to use online 
    - use GET request to constantly update before scanning samples; might use malwarebazaar or malshare; get recent signatures then save them to a .txt file
        - Malwarebazaar: `GET https://bazaar.abuse.ch/api/v1/get_recent/?limit=100`
        - Malshare: `GET https://malshare.com/api.php?api_key=YOUR_API_KEY&action=get_recent`
        - Ensure no dup signatures by saving timestamp ft. date and time for future queries; select signatures from after previous query.
    - local storage is possible thru CSV or .txt file
- Quarantine sample; put it in some protected folder, remove execution permissions, or just delete the sample forcefully.
    - Could rename malware as `malware-<computed_hash>` then move to a specified 'quarantine' folder and remove execution privileges using `icacls <malware_file.exe/dll> /remove:g <username>:X /c /t` .
    - Force delete the file using `DeleteFile(<filename.exe/dll>)` in code or just call `std::system`.
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
- <strong>NOTE: </stromg> We should run this all in a VM; take initial snapshot, run malware, rollback snapshot, repeat! VM is connected to NO networks.  
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
- [FileSource doc for Crypto++](https://www.cryptopp.com/wiki/FileSource)
- [HashFilter doc for Crypto++](https://cryptopp.com/wiki/HashFilter)
- [icacls MS Docs](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls) 
- [StringSink doc for Crypto++](https://www.cryptopp.com/wiki/StringSink)

1) SHA256 Digest for File Hashing
For efficient hashing of .exe and .dll files in C++, you can use libraries like OpenSSL or Crypto++, both of which provide easy-to-use methods for creating a SHA256 digest. Here’s a brief overview of how you can do it using Crypto++ (it’s lightweight, open-source, and well-suited for security-related applications):

Example using Crypto++:
#include <iostream>
#include <fstream>
#include <cryptlib.h>
#include <sha.h>
#include <hex.h>

using namespace CryptoPP;

void generateSHA256Hash(const std::string& filePath) {
    SHA256 hash;
    FileSource(filePath.c_str(), true, new HashFilter(hash));

    byte digest[SHA256::DIGESTSIZE];
    hash.TruncatedFinal(digest, SHA256::DIGESTSIZE);

    HexEncoder encoder(new FileSink(std::cout));
    encoder.Put(digest, sizeof(digest));
    encoder.MessageEnd();
}

int main() {
    std::string filePath = "path_to_your_file.exe";
    generateSHA256Hash(filePath);
    return 0;
}
This will compute the SHA256 hash of the file at filePath and output it as a hexadecimal string.

You can also use OpenSSL similarly by calling its SHA256 API.

2) Safe Way to Call Shell Commands
To avoid shell injection vulnerabilities, it’s important to not directly pass user input into shell commands (which you mentioned won't be a concern since everything is explicitly called). Here’s a safe way to call shell commands in C++:

You can use CreateProcess() or std::system() (though CreateProcess() is more powerful and flexible):

Example using CreateProcess():
cpp
Copy
Edit
#include <windows.h>
#include <iostream>

void runCommand(const std::string& command) {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    if (CreateProcess(
        NULL, // Application name (NULL if command is a string)
        (LPSTR)command.c_str(), // Command line
        NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Wait for the process to finish
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        std::cerr << "Error in creating process: " << GetLastError() << std::endl;
    }
}

int main() {
    runCommand("dir");  // Example command
    return 0;
}
Using CreateProcess() allows you to manage processes with better security and more control. Ensure that you're passing only predefined, trusted commands into it.

3) Quarantining Confirmed Malware
When dealing with malware, quarantining is a critical feature. Here are some options to safely quarantine confirmed malware:

Renaming the file: Instead of deleting it outright, you could rename the file to something like malware-<hash>.exe and move it to a "quarantine" folder. This makes it harder for the malware to "re-run" but still keeps the file available for further analysis.

Removing Execution Permissions: Changing the file’s permissions to remove execute privileges is a good precaution. On Windows, you can use icacls or manipulate security descriptors via WinAPI to remove execute rights.

Sandboxing the file: You could move the file to a sandbox environment (perhaps a separate VM or a highly restricted user environment) to analyze it more safely.

Example of removing execution permissions with icacls:

cpp
Copy
Edit
std::string command = "icacls \"path_to_malware.exe\" /deny Everyone:(X)";
runCommand(command);
Force Deletion: If you're confident in the file being malicious and want to delete it, you can simply delete it using DeleteFile() (for files) or RemoveDirectory() (for directories), but this could leave behind traces, so quarantine is generally better for analysis.

4) Dynamic Analysis with DLL Injection and Log File Transfer
Your idea of using DLL injection to monitor behavior is great, but getting the log file back safely from the sandboxed VM is tricky. Malware could potentially try to delete or modify the log, so here are some ways to mitigate this:

Write Logs to a Secure, Read-Only Location: Instead of writing logs directly to the VM's local file system, you could use network shares or cloud storage where the malware cannot tamper with the files. A separate network share or drive that’s only mounted during analysis can protect it.

Use Volatile Memory (RAM Disk): You can configure the system to write logs to a RAM disk, which would be cleared when the system is rebooted. This way, even if the malware deletes the logs, they won’t persist on disk.

One-Way Transfer (Data Diodes): A hardware-based data diode can physically prevent data from being written to the host machine from the VM but still allow data (e.g., logs) to be transferred. However, this requires specific hardware and might not be feasible in most cases.

Network Monitoring: If you have network access between the VM and the host, you could set up an isolated network where logs are periodically sent over to the host (using tools like SMB or FTP) with encryption and integrity checks to ensure the logs are not tampered with.

Encrypted Logs: Ensure the logs are written in an encrypted format (e.g., using AES) and only the host machine has the decryption key. This adds another layer of security and prevents the malware from modifying or deleting logs without detection.

Snapshotting the VM: Regularly snapshot the VM before and after the analysis. This allows you to revert the VM to a clean state if the malware tries to delete or modify the logs during or after the analysis.

Additional Tips:
Code Integrity Checks: Use checksum or hash-based verification to ensure that the injected DLL hasn’t been modified by the malware.

Virtualization Software Features: Some virtualization software allows for secure isolation, where the VM’s environment can be locked down to prevent the malware from escaping or accessing the host system.

I hope these answers help you as you build out your anti-virus software. Feel free to ask if you need further clarification or have additional questions!



You said:
For the crypto++ code, after having run FileSource, we will have a hash of the specified file contents. Please explain the following lines of code. The goal is to get back a SHA256 hash that can be compared exactly to ones in a virus signature database. Do not hallucinate.

ChatGPT said:
Sure, let's break down the code to help you understand how it works, and I’ll explain the lines related to generating the exact SHA256 hash that can be used for comparison with signatures in a database.

Here’s the relevant snippet again:

cpp
Copy
Edit
SHA256 hash;
FileSource(filePath.c_str(), true, new HashFilter(hash));

byte digest[SHA256::DIGESTSIZE];
hash.TruncatedFinal(digest, SHA256::DIGESTSIZE);

HexEncoder encoder(new FileSink(std::cout));
encoder.Put(digest, sizeof(digest));
encoder.MessageEnd();
Explanation of Each Line:
SHA256 hash;

This initializes a SHA256 object from the Crypto++ library. This object will compute the SHA256 hash of the file's contents. It's essentially a state machine that you will feed data to (in this case, the file) so that it can process and compute the hash.

FileSource(filePath.c_str(), true, new HashFilter(hash));

FileSource: This is a Crypto++ utility that reads data from the file at the path filePath.c_str() (which is the file path passed as an argument to the function).

The true argument means the file is read completely (the FileSource will not stop until the entire file is read).

HashFilter(hash): The HashFilter takes data from the FileSource and feeds it into the SHA256 hash object hash. The HashFilter computes the hash incrementally as it reads the file. After the file is read, the SHA256 object will contain the final computed hash.

So at this point, hash contains the SHA256 hash of the file’s contents, but it’s not yet in a format that you can compare to a signature database.

byte digest[SHA256::DIGESTSIZE];

This line declares a byte array digest large enough to hold the final SHA256 hash. SHA256::DIGESTSIZE is a constant defined by the Crypto++ library that specifies the length of the hash in bytes (32 bytes for SHA256).

hash.TruncatedFinal(digest, SHA256::DIGESTSIZE);

TruncatedFinal: This method finalizes the hashing process and stores the resulting hash in the digest array. After this call, the array digest will contain the final 256-bit (32-byte) SHA256 hash of the file, which is exactly what you need to compare with signatures.

digest now holds the raw bytes of the SHA256 hash.

HexEncoder encoder(new FileSink(std::cout));

The HexEncoder is used to encode the raw hash bytes into a hexadecimal string. This is useful because hashes are typically represented as hexadecimal strings (e.g., a3c7e6f382fd5a4ab237ab38c395b6f9732d96f0807f3b5d0107d3a67de4fbf8).

new FileSink(std::cout) means the output will be written to the standard output (console). The FileSink is a Crypto++ sink that writes data to the console.

encoder.Put(digest, sizeof(digest));

This line tells the HexEncoder to encode the digest array (which contains the raw SHA256 hash bytes). sizeof(digest) gives the number of bytes to encode (32 bytes for SHA256).

encoder.MessageEnd();

This finalizes the encoding process. It ensures that the HexEncoder completes the conversion of the hash bytes into a hexadecimal string and writes it to the output stream (the console, in this case).

What You Get
After running the above code, the hash will be printed in hexadecimal format. For example, if you hash a file with the correct content, the output will look something like:

nginx
Copy
Edit
a3c7e6f382fd5a4ab237ab38c395b6f9732d96f0807f3b5d0107d3a67de4fbf8
Comparing with Virus Signature Database
This output (in hexadecimal format) is exactly what you would compare against a virus signature database. Typically, virus databases store file hashes as hexadecimal strings, so by generating the hash in this way, you ensure compatibility.

To Summarize:
FileSource reads the file and feeds the data to the SHA256 object.

HashFilter computes the hash incrementally as the file is read.

TruncatedFinal finalizes the hash calculation and stores it in digest as raw bytes.

HexEncoder converts the raw hash into a hexadecimal string for easy comparison with a virus signature database.

By using this approach, you’ll be able to generate a SHA256 hash that matches what is used in signature databases, and it can be compared byte-by-byte to detect potential malware.
