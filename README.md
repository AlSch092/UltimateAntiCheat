# UltimateAntiCheat
Research project: make an anti-cheat system to detect and/or prevent things like memory editing, debugging, unsigned code/certs, injected modules, etc.

Additionally, please provide features such as:  

-Routines which could obfuscate sections of our programs code at runtime, or shellcode which unpacks itself at runtime and executes some payload.    
-Hashing of all loaded DLLs to detect DLL injection/hi-jacking  
-Network heartbeat with payload (hashes of code sections, secret key generation) to ensure no memory has been tampered and to make sure the client is executing the code we send them    
-More advanced techniques which are not known to the public yet  

This project is meant to serve as a very basic anti-cheat program for educational purposes, and is not intended to be commercial software. This is a limited example and includes only basic protections, in production we would aim to have at least 3-5x more detection methods along with a clever server-reliant design to detect user patching/writing bytes (prevention is a no-go, there will always be ways to write 'protected' memory).  

Basic networking has been added along with a Challenge-Response protocol, thus we begin to make the project server-authenticated and rely on routines sent by the server. this adds non-repudiation as each client must generate unique secret keys as replies to requests from the server, and this forces the client to execute our code in order to stay connected to the game service.  

If you have any design suggestions or code improvements/additions feel free to raise an 'issue'. You might need to move a couple of files into different folders if compilation isn't working as I'm currently changing the directory structure around. Thank you for reading!  

## Updates
- March 25, '24: Beginning to move tests into their proper places and making use of the API class. Future updates will improve code structure and add threaded & looping support to make the program feel more like a commercial AC product and less like a techniques testing suite
- March 24, '24: A full re-upload was done along with various bug fixes. The program should compile without issues in x64 (x86 not supported yet, apologies). I plan on continuing work on this project in the near future. As it's been some time since making this project, lots more can be added soon with new knowledge and techniques acquired in the time between then and now. Stay tuned for further updates!
