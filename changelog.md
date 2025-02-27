## Updates
- Feb 26, '25: Add `ProtectedMemory` class (write protected and resistant to page security modifications via `SEC_NO_CHANGE`) in `AntiTamper/MapProtectedClass.hpp`, make `Settings` class object `ProtectedMemory` to prevent modification of config at runtime, remove `UnmanagedGlobals` namespace, remove `EXPECTED_SECTIONS` define and instead make it fetch at runtime (makes it compatible with any game/number of sections).  
  
- Feb 22, '25: Added caching for cert checks of loaded drivers & modules, added revoke checks in `VerifyEmbeddedSignature` and `VerifyCatalogSignature`, removed cache-only for cert checking, added `BOOL checkRevoked` for `HasSignature`. Cleaned up `API::LaunchDefenses`.  
  
- Feb 16, '25: Added extra integrity check which checks file on disc's .text section versus the runtime image's.
  
- Feb 15, '25: Started Wiki page for documentation, fixed some bugs, and several QoL improvements (thanks LucasParsy for your contributions)
  
- Feb 8, '25: Adding manually mapped image checks (not yet detecting erased PE headers, this will come next)
  
- Jan 31, '25: Added web-fetching of blacklisted byte patterns at runtime from a url, along with blacklisted/vulnerable driver list
  
- Jan 20, '25: Added `.rdata` section hashing, change section hash lists to `map<string, vector<uint64_t>>` for better scaling
  
- Jan 4, '25: Happy new year, LLVM/clang-cl compiler support has been added to the branch `llvm-clang`, which uses the LLVM compiler by default (and has a few header changes and code differences). We will work towards being able to obfuscate the project's binary/IR using LLVM transformative passes.  

- Dec 17, '24: Fixed DetectOpenHandlesToProcess to not warn for whitelisted processes

- Nov 28, '24: Added registry key modification notifications via `RegNotifyChangeKeyValue` for some important keys  

- Nov 23, '24: Added signature/byte pattern scanning on newly created processes

- Nov 23, '24: Added anti-debugger method which creates a remote thread inside common debuggers which calls their `ExitProcess` routine

- Oct 27, '24: Added process creation monitoring using WMI to detect blacklisted processes being opened  

- Oct 24, '24: Started to change important class object pointers to `std::unique_ptr`, and fixed an memory-related unhandled exception issue at cleanup/program ending. The main focus going forwards for this project will be to make better use of C++ concepts, in order to make the code more readable and scale better.  
  
- Oct 3, '24: Fixed `IsTextSectionWritable` routine, which now checks all pages in the .text section for protections other than PAGE_EXECUTE_READ. Further development of this project will likely be much slower than normal, as I'm busy with other projects.  
  
- Sept 6, '24: Added checks on TLS callback structure for anomalies (number of TLS callbacks, TLS data directory address, TLS callback addresses outside of main module, etc)  

- Aug 23, '24: Added `Settings` class for compile-time configurations, along with Hypervisor checks  

- Aug 8, '24: Added secure boot enforcement to prevent bootloader cheats  
  
- June 25, '24: Added simple window title & class name checks to help determine if the user is running Cheat Engine, x64dbg, etc. This should be considered an extra data point and not solely responsible for detecting attackers.

- June 20, '24: Added hash lists for all loaded modules `.text` sections such that specific modules can later on be checked for memory modifications. This was used to add checks on `WINTRUST.dll` to detect any hooks on signature-related routines. Since it's a bit expensive to check all loaded module hashes constantly, specific modules should be checked periodically.

- June 19, '24: Added DLL load notifications/callbacks and proper signature checks on any loaded modules (thanks to github user `discriminating` for this contribution). 

- June 13, '24: Added NT header tampering for its members `NumberOfSections`, `SizeOfImage`, `AddressOfEntryPoint`, which results in dynamic info lookups from attackers on these variables to be incorrect.

- May 29. '24: Added 'process mitigation policies' in the Preventions class

- May 28, '24: Program can now block APC injection by patching over ntdll.dll's Ordinal8 (called by KiUserApcDispatcher). This routine can also be hooked to reveal the injected APC payload's address. If your game/program relies on APC for normal execution, this technique might not be suitable.

- May 28, '24: Added `ret` patch over first byte of executed thread function in TLS callbacks if the address is not in a whitelisted range. Similar method to what was added on May 25, but will apply to any thread function trying to execute since we directly patch it inside the TLS callback. For example, if CreateRemoteThread is called on address 0x12345, the TLS callback will place a `ret` at 0x12345.

- May 25, '24: Added extended defenses against Cheat Engine's VEH debugger by patching over the first byte of `InitializeVEH` and renaming the module name of `vehdebug-x86_64.dll`.

- May 23, '24: Added open process handle checking. Our program can now detect external programs which have called `OpenProcess` to our process.

- May 20, '24: Added splash screen to make the program feel like commercial AC, added return address check functionality to prevent remote function calling, added checks on thread suspension

- May 10, '24: Client and server now communicate correctly, heartbeats will be sent every 60s to the client. Server code will be posted in the "Server" directory of the project, and will be its own C# program. Design will soon be changed to integrate the `AntiCheat` class to the networking portions.

- May 4, '24: Added TLS callback spoofing, which is compiling the program with a fake TLS callback and then modifying the pointer at runtime to our real callback.

- April 30, '24: Fixed any memory & threading issues, removed PEB spoofing & exported function renaming to ensure program works smoothly for everyone - export function renaming can sometimes pop up an error box to the end user about "Entry Point Not Found", if this error box can be supressed somehow then we can re-add the technique since it successfully prevents DLL Injection. PEB spoofing was found to create issues with thread creation at random occurences. 

- April 24, '24: IAT hook checking, further code cleanup and error checking

- April 7, '24: Added TestSigning / Windows 'test mode' detection to prevent unsigned drivers

- April 3, '24: Added WINAPI hook checking, blacklisted process checking

- March 31, '24: Detection methods have been moved to Detections class, techniques/prevention methods have been moved into Preventions class. Thus we have a set of detections and a set of preventions. Added detection looping to make the program feel more like a commercial AC. Code structure is closer now to where I had aimed originally. There's still much that can be added, stay tuned.

- March 25, '24: Beginning to move tests into their proper places and making use of the API class. Future updates will improve code structure and add threaded & looping support to make the program feel more like a commercial AC product and less like a techniques testing suite

- March 24, '24: A full re-upload was done along with various bug fixes. The program should compile without issues in x64 (x86 not supported yet, apologies). I plan on continuing work on this project in the near future. As it's been some time since making this project, lots more can be added soon with new knowledge and techniques acquired in the time between then and now. Stay tuned for further updates!
