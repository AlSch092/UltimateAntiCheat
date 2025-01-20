![SampleOutput](https://github.com/AlSch092/UltimateAntiCheat/assets/94417808/8e2112b8-2c82-4a38-aca8-ec54aa7d7516)

# UltimateAntiCheat: A usermode anti-cheat built in C++ (x64)

UltimateAntiCheat is an open source usermode anti-cheat system made to detect and prevent common attack vectors in game hacking, including: memory editing, module & code injection, debugging, unsigned drivers, open handles, and more. The project also features a client-server design with a heartbeat being sent every 60 seconds to clients. No privacy-invasive techniques are used. Optionally, a hybrid kernelmode + usermode approach can now be used through the settings in `main.cpp` and `Common/Settings.hpp` (but you will need to make/provide your own driver for this).

The project now supports CMake & using the LLVM/clang-cl compiler, which can be found in the `llvm-clang` branch. In the future we will attempt to add in code obfuscation via LLVM transformative passes.

## Goals & Overview
   This project is meant to serve as an educational/research tool and is not intended to be commercial software or overly complex to crack. It includes many fundamental protection techniques, and we aim to cover as many attack surfaces as possible such that the attacker is not able to gain a foothold from usermode into our process without being detected (some kernelmode or hardware-based attacks will also be detected). Any modification to a single aspect will lead to being detected: for example, if someone tries to debug our code from usermode, they will likely re-map and perform memory edits to try and disable debugger detections, which leads to their memory edit or remapping being detected. It's recommended that if possible you run a packer or obfuscator on the compiled binary for added security through obscurity (however, re-mapping will most often fail if using a packer which modifies program sections). The project should be integrated to your game or software directly as source code instead of a standalone DLL in order to avoid DLL proxying/spoofing attacks. You can also make the project into a static library if you desire. 

   If there is anything not working for you (throws unhandled exceptions, can't build, etc) please raise an issue and I will answer it ASAP. If you have code suggestions or techniques you'd like to see added, or want assistance with adding anti-cheat to your game, please send me an email. Anyone is welcome to contribute as long as your pull request is to the same standard and formatting as the existing codebase, and your addition has been regression tested. More techniques and better design will be added to the project over time, and the file `changelog.md` contains a dated updates list. Visual Studio 2022 is used as the primary IDE, and it's recommended you use it for project viewing and compilation.  

## Current Detections and protective features:
- Monitors new process creation using WMI
- Monitors modifications to important registry keys such as ones related to secure boot   
- New processes are scanned for blacklisted patterns
- Detects Open Process Handles to our process (`OpenProcess` detection)
- Blocks APC injection (undocumented  `ntdll.Ordinal8` patching)
- Debugger detection (hardware/DR, PEB, kernelmode)
- Destroys common debugger processes by creating remote threads on their `ExitProcess` function
- Hides threads from debuggers via `NtSetInformationThread`  
- Blocks Cheat Engine VEH debugger (`initializeVEH` patching, module name renaming)
- Integrity checks on program memory (`.text` & `.rdata` section checks, WINAPI hook checks, IAT hook checks)
- Remapping sections & re-re-mapping checks (anti-tamper, thanks to user [changeofpace](https://github.com/changeofpace))
- Dll load notifcations/callback & signature checks of loaded modules (thanks to user [discriminating](https://github.com/discriminating) for this contribution)
- Spoofs `NumberOfSections`, `SizeOfImage`, & `AddressOfEntryPoint` to prevent dynamic info lookups (process manipulation)
- Parent process check
- Blacklisted running process checks & whitelisted loaded modules check
- Main module name random renaming (process manipulation)
- Exported function names random renaming (process manipulation, anti-injection)
- Data obfuscation class to help hide sensitive variables
- Check for if Windows is in 'Test Signing mode' and 'debug mode'
- Secure boot enforcement (anti-bootloader cheats)
- Hypervisor check  
- TLS Callback & thread function address `ret` patching (anti-DLL/shellcode injection)
- TLS Callback spoofing (changing TLS callbacks at runtime), along with checks to ensure the TLS callback structure has not been modified or added to  
- Networked heartbeat system to ensure client is running the AC module
- Stops multiple instances of the process from being run by mapping shared memory
- Return address checks in important routines such as heartbeat generation to prevent remote calling
- Basic window title & class name checks for commonly used attack tools such as Cheat Engine
- Optional kernelmode + usermode hybrid approach (you must make/provide your own driver for this, and ideally it would be signed)

## Enabling/Disabling Networking:
Networking support is available in the project - the server can be found in the `Server` folder as its own solution. Using networking is optional, and can be turned on/off through the variable `bool bNetworkingAvailable` in the file `main.cpp` (as part of the `Settings` class). If you choose to use networking, please follow the instructions in the README.md file of the server.  

## Windows version targeting:

The preprocessor definition `_WIN32_WINNT=0x...` can be used to target different versions of Windows at compile-time. For example, using 0x0A00 will target Windows 10 and above, and 0x0601 will target Windows 7 and above. Certain features might only work on newer Windows versions and are excluded from compilation based on this value. The client will also fetch the machine's windows version at program startup, in `main.cpp`.

## Advanced Features
If you're looking for full database integration and bonus protective features for your small to mid-sized commercial game/software: a robust, load-tested backend can be provided for a small licensing fee.

## Licensing  

The GNU Affero general public license is used in this project. Please be aware of what you can and cannot do with this license: for example, you do not have permission to rip this project into your own commercial project or use this project in your own code base without it being open source. You do have permission to use this project if your project is also open source. Using this project for a "private game server" or any other stolen code/binaries automatically violates the license.

## Class Flow Diagram

Each bold line indicates the above class holds an object or pointer of the bottom class. Shared classes are generally stored as a `shared_ptr` in code, and inheritance is currently only used in the `DebuggerDetections` class. Only important classes relevant to core functionality are shown in the diagram:

![ClassDiagram](https://github.com/user-attachments/assets/1b1ea458-93dd-4e6e-a4c1-ab9f6c3cf96e)
