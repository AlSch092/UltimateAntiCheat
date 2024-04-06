/*  UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there. main.cpp contains testing of functionality

    U.A.C. is an 'in-development'/educational example of anti-cheat techniques written in C++ for x64 platforms
 
    Feature list: 
    1. Anti-dll injection (multiple methods, including authenticode enforcement and mitigation policy)
    2. Anti-debugging (multiple methods)
    3. Anti-tamper  (multiple methods including image remapping & memory integrity checking)
    4. PEB modification & spoofing
    5. Server-generated shellcode execution (self-unpacking + containing a key in each message which is required to be sent back, ensuring the shellcode was executed), plus cipher-chaining
    6. Client-server heartbeats, version checking, licensing, APIs
    7. Modification of modules: changing loaded module names, symbol names (exports and imports)
    8. TLS callback for anti-debugging + anti-dll injection and thread management
    9. WINAPI calls via 'symbolic hashes' -> stores a list of pointers such that we can call winapi routines by a numeric hash instead of its symbol name

    There might be bugs, please raise a github issue if you'd like something in particular added or fixed

    Author: AlSch092 @ Github.

*/

#pragma comment(linker, "/ALIGN:0x10000") //for remapping technique (anti-tamper)

#include "API/API.hpp"

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);
                                                                                  
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

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

bool SupressingNewThreads = false;
bool SetExceptionHandler = false;

std::list<Thread*> ThreadList; //we need access to a thread list in our TLS callback somehow, thus make this global and merge it with our managed AC class

bool AddThread(DWORD id)
{
    DWORD tid = GetCurrentThreadId();
    printf("[INFO] New thread spawned: %d\n", tid);

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;

    HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (threadHandle == NULL)
    {
        printf("[WARNING] Couldn't open thread handle @ TLS Callback: Thread %d \n", tid);
        return false;
    }
    else
    {
        Thread* t = new Thread();
        t->Id = tid;

        if (GetThreadContext(threadHandle, &context))
        {
            t->ContextFlags = context.ContextFlags;
        }
        else
        {
            printf("[WARNING] GetThreadContext failed @ TLS Callback: Thread %d \n", tid);
            return false;
        }

        ThreadList.push_back(t);
        return true;
    }
}

void RemoveThread(DWORD tid)
{
    Thread* ToRemove = NULL;

    for (Thread* t : ThreadList)
    {
        if (t->Id == tid)
            ToRemove = t;
    }

    if (ToRemove != NULL) //remove thread from our list on thread_detach
        ThreadList.remove(ToRemove);
}

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            printf("[INFO] New process attached, current thread %d\n", GetCurrentThreadId());

            if (!SetExceptionHandler)
            {
                SetUnhandledExceptionFilter(ExceptionHandler);

                if (!AddVectoredExceptionHandler(1, ExceptionHandler))
                {
                    printf("[ERROR] Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                }

                SetExceptionHandler = true;
            }

        }break;

        case DLL_PROCESS_DETACH:
        {
            for (Thread* t : ThreadList)
            {
                delete t;
            }
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list
        {        
            if (!AddThread(GetCurrentThreadId()))
            {
                printf("[ERROR] Failed to add thread to ThreadList @ TLSCallback: %d\n", GetLastError());
            }

            if (SupressingNewThreads)
                ExitThread(0); //we can stop DLL injecting + DLL debuggers (such as VEH debugger) this way, but make sure you're handling your threads carefully

        }break;

        case DLL_THREAD_DETACH:
        {
            RemoveThread(GetCurrentThreadId());
        }break;
    };
}

LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode == EXCEPTION_BREAKPOINT)
    {
        printf("[INFO] Breakpoint exception was caught in ExceptionHandler\n");
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char** argv)
{
    SetConsoleTitle(L"Ultimate Anti-Cheat");
    
    printf("----------------------------------------------------------------------------------------------------------\n");
    printf("|                               Welcome to Ultimate Anti-Cheat!                                          |\n");
    printf("|       An in-development, non-commercial AC made to help teach us basic concepts in game security       |\n");
    printf("|       Made by AlSch092 @Github, with special thanks to changeOfPace for re-mapping method              |\n");
    printf("----------------------------------------------------------------------------------------------------------\n");

    AntiCheat* AC = new AntiCheat();

    API::Dispatch(AC, API::DispatchCode::INITIALIZE); //initialize AC -> right now basic tests are run within this call 

    SupressingNewThreads = AC->GetBarrier()->IsPreventingThreadCreation;

    printf("\n-----------------------------------------------------------------------------------------\n");
    printf("All tests have been executed, the program will now loop using its detection methods for one minute. Thanks for your interest in the project!\n\n");

    Sleep(60000);

    API::Dispatch(AC, API::DispatchCode::CLIENT_EXIT); //clean up memory & threads

    system("pause");
    return 0;
}