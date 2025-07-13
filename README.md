![SampleOutput](https://github.com/AlSch092/UltimateAntiCheat/assets/94417808/8e2112b8-2c82-4a38-aca8-ec54aa7d7516)

# UltimateAntiCheat: A usermode anti-cheat built in C++ (x64)

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![CMake](https://img.shields.io/badge/CMake-%23008FBA.svg?style=for-the-badge&logo=cmake&logoColor=white)
![MySQL](https://img.shields.io/badge/mysql-4479A1.svg?style=for-the-badge&logo=mysql&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/2.0-999999?style=flat-square&logo=Version&label=Version&labelColor=333333)

UltimateAntiCheat is an open source usermode anti-cheat system made to detect and prevent common attack vectors of game hacking. The project also features an optional client-server mechanism, with a heartbeat being sent every minute to clients. No privacy-invasive techniques are used. Optionally, a hybrid kernelmode + usermode approach can now be used through the settings in `main.cpp` and `Common/Settings.hpp` (you will need to make/provide your own driver for this).

The project now supports CMake & using the LLVM/clang-cl compiler, which can be found in the `llvm-clang` branch. In the future we will attempt to add in code obfuscation via LLVM transformative passes.

## Goals & Overview
   This project was originally meant to serve as an educational & research tool, but has evolved into being used by several people. It includes many fundamental and novel detection techniques, and aims to cover as many attack surfaces as possible (while being limited by usermode) such that an attacker is not able to gain a foothold from usermode into our process without being detected. Any modification to a single aspect will lead to being detected, for example: if someone tries to debug our code from usermode, they will likely re-map and change the page protections in order to perform memory edits to try and disable debugger detections, which leads to their memory edit and remapping being detected. It's recommended that if possible you run an obfuscator on the compiled binary  for added security through obscurity. The project should be integrated to your game or software directly as source code instead of a standalone DLL in order to avoid DLL proxying/spoofing attacks. You can also make the project into a static library if you desire. 

   If there is anything not working for you (throws unhandled exceptions, can't build, etc) please raise an issue and I will answer it ASAP. If you have code suggestions or techniques you'd like to see added, or want assistance with adding anti-cheat to your game, please send me an email. Anyone is welcome to contribute as long as your contribution is to the same standard and formatting as the existing codebase, and your code has been regression tested. More techniques and better design will be added to the project over time, and the file `changelog.md` contains a dated updates list. Visual Studio 2022 is used as the primary IDE, and it's recommended you use it for project viewing and compilation.  

## Current detections and preventions: 
For a list of current detections and preventions, please view the Wiki page (or click [here](https://github.com/AlSch092/UltimateAntiCheat/wiki/Detections-&-Preventions)).  

## Enabling/Disabling Networking:
Networking support is available in the project: the server can be found in the `Server` folder as its own project solution. Using networking is optional, and can be turned on/off through the variable `bool bNetworkingAvailable` in the file `main.cpp` (as part of the `Settings` class). If you choose to use networking, please follow the instructions in the README.md file in the server folder.  

## Windows version targeting:

The preprocessor definition `_WIN32_WINNT=0x...` can be used to target different versions of Windows at compile-time. For example, using 0x0A00 will target Windows 10 and above, and 0x0601 will target Windows 7 and above. Certain features might only work on newer Windows versions and are excluded from compilation based on this value. The client will also fetch the machine's windows version at program startup, in `main.cpp`.

## Advanced Features
This open source version is considered a minimal, or bare-bones version of the project. If you're looking for customization, database integration, user metrics, and improved protective & detective features for your small to mid-sized game/software: this can be provided for a fair licensing fee, and can run alongside your game server on the same host machine.

## Licensing  

The GNU Affero general public license is used in this project. Please be aware of what you can and cannot do with this license: for example, you **do not** have permission to rip this project into your own commercial project or use this project in your own code base without it being open source. You **do** have permission to use this project if your project is also open source. Using this project for a "private game server" or any other stolen code/binaries automatically violates the license, and makes you liable for IP-related damages. If you desperately need to use the project for your closed-source game, email me instead of ripping the code and breaking the license.

## Class Flow Diagram

Each bold line indicates the above class holds an object or pointer of the bottom class. Shared classes are generally stored as a `shared_ptr` in code, and inheritance is currently only used in the `DebuggerDetections` class. Only important classes relevant to core functionality are shown in the diagram:

![ClassDiagram](https://github.com/user-attachments/assets/1b1ea458-93dd-4e6e-a4c1-ab9f6c3cf96e)

## Conclusion

Anti-cheat systems are a great deal of work to do correctly, and easy to get wrong. There will always be new ways to get past these systems, especially since each game has a unique set of features and challenges. There will be many aspects of the project which can be improved or added to; this is by no means a perfect solution. The project tries to do as much as it can, given the limitations of usermode, and having no knowledge of the game that it's meant to protect. Going with an approach which makes use of both client-side protections and game data on the server-side will almost always be ideal, as any client-facing software will inevitably be bypassed. 
