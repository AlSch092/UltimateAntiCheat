# UltimateAntiCheat
Research project: make some basic anti-cheat to detect: memory editing, debugging, certificates (and spoofing), injected modules, multi-boxing, OS spoofing

Additionally, please provide features such as:  
-Routines which could obfuscate sections of our programs code at runtime, or shellcode which unpacks itself at runtime and executes some payload.   
-Hashing of all loaded DLLs to detect DLL injection  
-Network heartbeat with payload (hashes of code sections) to ensure no memory has been tampered  
-More advanced techniques which are not known to the public yet  

This project's is meant to serve as a very basic anti-cheat program for educational purposes, and is not intended to be commercial software. This is a limited example and includes only basic protections, in production we would aim to have at least 3-5x more detection methods along with a clever design to prevent user patching/writing bytes. The best way in my opinion is sending any routines we want to run on the client via packets - we send them shellcode to execute which is then cleared away, allowing us to scale our solution and make analysis very difficult as there will be nothing there 99.999% of the time.  

If you have any design suggestions feel free to raise an 'issue', thanks!
