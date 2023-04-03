# UltimateAntiCheat
Research project: make some basic anti-cheat to detect: memory editing, debugging, certificates (and spoofing), injected modules, multi-boxing, OS spoofing

Additionally, please provide features such as:  
-Routines which could obfuscate sections of our programs code at runtime, or shellcode which unpacks itself at runtime and executes some payload.   
-Hashing of all loaded DLLs to detect DLL injection  
-Network heartbeat with payload (hashes of code sections) to ensure no memory has been tampered  

This project's is meant to serve as a very basic anti-cheat program for educational purposes, and is not intended to be commercial software. Public development is complete, meaning there will likely be no further updates posted here.  If you want to use any functions from this project (copy paste) in your commercial software please contact me beforehand, I can also help you implement something to your game for fair compensation. This is a limited example and includes only basic protections, in production we would aim to have at least 3-5x more detection methods along with a clever design to prevent user patching/writing bytes. 

If you have any design suggestions feel free to raise an 'issue', thanks!
