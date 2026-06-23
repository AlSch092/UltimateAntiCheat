![SampleOutput](https://github.com/AlSch092/UltimateAntiCheat/assets/94417808/8e2112b8-2c82-4a38-aca8-ec54aa7d7516)

# UltimateAntiCheat: An Educational Usermode Anti-cheat Built in C++ (x64)  

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/2.1-999999?style=flat-square&logo=Version&label=Version&labelColor=333333)

UltimateAntiCheat is an open source, educational usermode anti-cheat system made to detect and prevent common attack vectors of game hacking. The project also features an optional basic client-server mechanism, with a simple heartbeat being sent every minute to clients. No privacy-invasive techniques are used. Optionally, a hybrid kernelmode + usermode approach can now be used through the settings in `main.cpp` and `Common/Settings.hpp` (you will need to make/provide your own driver for this).

The project now supports CMake & using the LLVM/clang-cl compiler, which can be found in the `llvm-clang` branch (may be lagging behind the main branch or not be error-free, my apologies if so). In the future (time permitting) we may attempt to add in code obfuscation via LLVM transformative passes. Certain sections of the code such as the `Detections` class may be considered messy, lacking C++ design concepts, and modularity, as the project was originally written in a "plain old C-style", then later on moved into using C++14 concepts.    

If you're looking for a modular, light-weight code integrity library with far cleaner code, check out [UltimateDRM](https://github.com/AlSch092/UltimateDRM), and a much improved detection library can be found at: [DetectionEngine](https://github.com/AlSch092/DetectionEngine). These two projects will be implemented/used by UltimateAnticheat if I have time in the future to merge them and add auto-compilation scripts for each library. 

## Goals & Overview:  
The main goal is to provide a generic reference point for educational purposes, rather than be commercial software. It serves as an approximate example of what a typical defensive usermode software might look like. The project implements several fundamental and "standard" detection & integrity techniques (along with a few tricks I've found on my own), and aims to cover as many attack surfaces as possible while being limited by a usermode process environment;  such that an attacker is not able to gain a foothold from usermode into our process without being detected.  

Any modification or attempted entry through a single attack surface will lead to being detected, for example: if someone tries to debug our code from usermode, they will likely re-map image sections and change the page protections of `.text` or `.rdata` (or some other section) in order to perform memory edits to try and patch over debugger detections, which leads to their memory edits and re-mapping being detected by the program's integrity checker. Another example:  If an attacker opens a process handle to ours and allocates heap memory and writes a PE image or executable shellcode to it, the detection class will detect "manual mapping" and "external process opened a process handle to us".  

It's recommended that if possible you run an obfuscator on the compiled binary or IR (if compiled using LLVM/clang-cl, for the more savvy coders) for added security through obscurity. The project should be integrated into your game or software directly as source code/static library instead of a standalone DLL in order to avoid DLL proxying/spoofing attacks (a .lib build configuration is now supported).   

If you have code suggestions or techniques you'd like to see added, or want assistance with adding/maintaining anti-cheat in your studio's game, please send me an email. Anyone is welcome to contribute a code push as long as your contribution uses the same C++ standards (C++14) and formatting as the existing codebase, and you've successfully regression-tested your code additions with the project (all protective features must work the same or better).  

More techniques and improved design will be added to the project over time, and the file `changelog.md` contains a dated updates list. Visual Studio 2022 was used as the primary IDE, and it's recommended you use it (or a more recent version) for project viewing and compilation.  

## Current detections and preventions:    
For a list of current detections and preventions, please view the Wiki page (or click [here](https://github.com/AlSch092/UltimateAntiCheat/wiki/Detections-&-Preventions)), as there are too many to justify listing within this readme file.  

## Enabling/Disabling Networking:  
Networking support is available in the project: the server can be found in the `Server` folder as its own project solution. Using networking is optional, and can be turned on/off through the variable `bool bNetworkingAvailable` in the file `main.cpp` (as part of the `Settings` class). If you choose to use networking, please follow the instructions in the README.md file in the server folder.  

## Windows version targeting:  

The preprocessor definition `_WIN32_WINNT=0x...` can be used to target different versions of Windows at compile-time. For example, using 0x0A00 will target Windows 10 and above, and 0x0601 will target Windows 7 and above. Certain features may only work on newer Windows versions, and are excluded from compilation based on this definition. The client will also fetch the machine's Windows version at program startup, in `main.cpp`.

## Licensing   

The GNU Affero general public license is used in this project. Please be aware of what you can and cannot do with this license: for example, you **do not** have permission to rip/copy this project's code into your own commercial project or use this project in your own code base without your project also being open source. You **do** have permission to use this project if your project is fully open source. Using this project for a "private game server" or any other stolen code/leaked binaries automatically violates this license. The author takes no responsibility for any possible legal actions taken by game publishers against "private servers" which unlawfully use this project.    

## Class Flow Diagram:  

Each bold line indicates the above class holds an object or pointer of the bottom class (only classes relevant for core program features may be shown):  

![ClassDiagram](https://github.com/user-attachments/assets/1b1ea458-93dd-4e6e-a4c1-ab9f6c3cf96e)
