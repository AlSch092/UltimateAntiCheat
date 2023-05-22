# UltimateAntiCheat
    Research project: make some basic anti-cheat to detect: memory editing, debugging, certificates (and spoofing), injected modules, multi-boxing, OS spoofing, etc.

Additionally, please provide features such as:  
-Routines which could obfuscate sections of our programs code at runtime, or shellcode which unpacks itself at runtime and executes some payload.   
-Hashing of all loaded DLLs to detect DLL injection/hi-jacking  
-Network heartbeat with payload (hashes of code sections, secret key generation) to ensure no memory has been tampered and to make sure the client is executing the code we send them  
-More advanced techniques which are not known to the public yet  

    This project's is meant to serve as a very basic anti-cheat program for educational purposes, and is not intended to be commercial software. This is a limited example and includes only basic protections, in production we would aim to have at least 3-5x more detection methods along with a clever design to detect user patching/writing bytes (prevention is a no-go, there will always be ways to write 'protected' memory). The best way in my opinion is sending any routines we want to run on the client via packets - we send them shellcode to execute which is then cleared away, allowing us to scale our solution and make analysis very difficult as there will be nothing in memory 99.999% of the time. Unfortunately this does not stop emulation fully! Since it will always be a cat and mouse game, we can aim to make emulating the system 'not worth the effort' by using a server-sided approach and leaving as little binary code in the client as possible (have the server send binary instead).  

    Basic networking has been added along with a Challenge-Response protocol, thus we begin to make the project server-authenticated and rely on routines sent by the server. this adds non-repudiation as each client must generate unique secret keys as replies to requests from the server, and this forces the client to execute our code in order to stay connected to the game service. 

    If you have any design suggestions or code improvements/additions feel free to raise an 'issue'!
