/*  UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there. main.cpp contains testing of functionality

    U.A.C. is an 'in-development'/educational anti-cheat written in C++ for x64 platforms
 
    Feature list: 
    1. Anti-dll injection (multiple methods including authenticode enforcement and mitigation policy)
    2. Anti-debugging (multiple methods)
    3. Anti-tamper  (multiple methods including image remapping)
    4. PEB modification
    5. Server-generated shellcode execution (self-unpacking + containing a key in each message which is required to be sent back, ensuring the shellcode was executed), plus cipher-chaining
    6. Client-server heartbeats, version checking, licensing, APIs
    7. Modification of modules: changing loaded module names, symbol names (exports and imports)
    8. TLS callback for anti-debugging + anti-dll injection and thread management
    9. WINAPI calls via 'symbolic hashes' -> stores a list of pointers such that we can call winapi routines by a numeric hash instead of its symbol name

    There might be bugs or improvements to techniques, please raise a github issue if you'd like something in particular added or fixed

    Author: Alex S. ,  github: alsch092 .

*/

#pragma comment(linker, "/ALIGN:0x10000") //for image remapping

#include "API/API.hpp"
#include "./AntiTamper/SymbolicHash.hpp"

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved); //in a commercial setting our AC would be in a .dll and the game/process would have the Tls callback
                                                                                   //todo: find way to insert bogus Tls callback into an EXE from a DLL at runtime (modify the directory ptrs to callbacks?)
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

using namespace std;

extern "C" uint64_t shellxor(); //test routine for generating shellcode, can be removed when we are done messing around with shellcode

bool PreventingThreadCreation = false;

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
            printf("New process attached, current thread %d\n", GetCurrentThreadId());
            break;

        case DLL_THREAD_ATTACH:
            printf("New thread spawned: %d\n", GetCurrentThreadId());
            
            if(PreventingThreadCreation)
                ExitThread(0); //we can stop DLL injecting + DLL debuggers (such as VEH debugger) this way, but make sure you're handling your threads carefully
            break;

        case DLL_THREAD_DETACH:
            printf("Thread %d detached\n", GetCurrentThreadId());
            break;
    };
}


void main(int argc, char** argv)
{
    SetConsoleTitle(L"Ultimate Anti-Cheat");
    
    printf("----------------------------------------------------------------------------------------------------------\n");
    printf("|                               Welcome to Ultimate Anti-Cheat!                                          |\n");
    printf("| An in-development, non-commercial AC made to help teach you basic concepts in game security            |\n");
    printf("|       Made by AlSch092 @Github, with special thanks to changeOfPace for re-mapping method              |\n");
    printf("----------------------------------------------------------------------------------------------------------\n");

    AntiCheat* AC = new AntiCheat();

    //AC->IsPreventingThreadCreation = true; //uncommenting this will prevent some of our tests from working properly, use at your discretion 
    PreventingThreadCreation = AC->IsPreventingThreadCreation;

    API::Dispatch(AC, API::DispatchCode::INITIALIZE); //initialize AC

    printf("All tests have been executed, the program will now shut down. Thanks for trying out the project!\n");

    system("pause");
}