## Updates
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
