![image](https://github.com/AlSch092/UltimateAntiCheat/assets/94417808/bf94bb32-ab93-489e-815b-f1c35cae0c9d)

# UltimateAntiCheat: An Educational Anti-Cheat built in C++ (x64)

UltimateAntiCheat is an open-source anti-cheat system made to detect and prevent common attack vectors in game hacking, which includes: memory editing, module injection, debugging, unsigned drivers & modules, and more. The project also features a client-server design with a heartbeat being sent every 60 seconds to clients.

   This project is meant to serve as an anti-cheat program for educational purposes and is not intended to be commercial software or overly complex to crack. This example includes basic but fundamental protections, and in a production scenario we would aim to have many more detection methods along with a sophisticated server-side design. We aim to cover all attack surfaces such that the attacker is not able to gain a foothold into our process without being detected. Any modification to a single aspect will lead to being detected: for example, if someone tries to debug our code from usermode, they will likely re-map and perform memory edits to try and disable debugger detection which leads to their memory edit or remapping being detected. UltimateAntiCheat runs in usermode and has no driver associated with it. It's recommended that if possible you run VMProtect or a similar program on the compiled binary for added security through obscurity.

   If there is anything not working for you (throws exceptions, can't build, etc) please raise an issue and I will answer it ASAP. If you have code suggestions or techniques you'd like to see added, or want assistance with adding anti-cheat to your game, please send me an email. More techniques and better design will be added to the project time permitting. The file changelog.md contains a dated updates list.

## Current Detections and protective features:
- Detects unsigned Modules 
- Debugger detection (hardware, PEB, exceptions, kernelmode)
- Integrity checks on program memory (.text section checks, WINAPI hook checks, IAT hook checks)
- Remapping sections & re-re-mapping checks (anti-tamper)
- TLS Callback (anti-DLL injection)
- Parent process check
- Blacklisted Processes checks & whitelisted loaded modules check
- Loaded module name random renaming (process manipulation)
- Exported function names random renaming (process manipulation, anti-injection)
- Data/obfuscation class to help hide sensitive variables
- Check for if Windows is in 'Test Signing mode'
- TLS Callback spoofing (changing TLS callbacks @ runtime)
- Networked heartbeat system to ensure client is running the AC module (currently in-progress)

## Upcoming Features:
- Finalization of client/Server integration with anticheat class

## Enabling/Disabling Networking:
Networking is currently being added to the project, and the server can be found in the `Server` folder as its own solution. Using networking will be optional, and can be turned on/off through the variable `bool serverAvailable` in the file `API/API.hpp`. If you choose to use networking, please follow the instructions in the README.md file of the server.
