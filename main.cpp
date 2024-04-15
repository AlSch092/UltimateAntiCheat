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

namespace UnmanagedGlobals //we track thread creation through TLS callback, thus we need some object which is visible within the tlscallback
{
    std::list<Thread*> ThreadList; 
    bool AddThread(DWORD id);
    void RemoveThread(DWORD tid);

    LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

    bool SupressingNewThreads = false;
    bool SetExceptionHandler = false;
    bool FirstProcessAttach = true;
}


int main(int argc, char** argv)
{
    SetConsoleTitle(L"Ultimate Anti-Cheat");

    cout << "----------------------------------------------------------------------------------------------------------\n";
    cout << "|                               Welcome to Ultimate Anti-Cheat!                                          |\n";
    cout << "|       An in-development, non-commercial AC made to help teach us basic concepts in game security       |\n";
    cout << "|       Made by AlSch092 @Github, with special thanks to changeOfPace for re-mapping method              |\n";
    cout << "----------------------------------------------------------------------------------------------------------\n";

    AntiCheat* AC = new AntiCheat();

    API::Dispatch(AC, API::DispatchCode::INITIALIZE); //initialize AC -> right now basic tests are run within this call 

    UnmanagedGlobals::SupressingNewThreads = AC->GetBarrier()->IsPreventingThreadCreation;

    cout << "\n-----------------------------------------------------------------------------------------\n";
    cout << "All tests have been executed, the program will now loop using its detection methods for one minute. Thanks for your interest in the project!\n\n";

    Sleep(60000);

    API::Dispatch(AC, API::DispatchCode::CLIENT_EXIT); //clean up memory & threads
    return 0;
}

bool UnmanagedGlobals::AddThread(DWORD id)
{
    DWORD tid = GetCurrentThreadId();
    Logger::logf("UltimateAnticheat.log", Info, " New thread spawned: %d\n", tid);

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;

    HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (threadHandle == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Warning, " Couldn't open thread handle @ TLS Callback: Thread %d \n", tid);
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
            Logger::logf("UltimateAnticheat.log", Warning, " GetThreadContext failed @ TLS Callback: Thread %d \n", tid);
            return false;
        }

        UnmanagedGlobals::ThreadList.push_back(t);
        return true;
    }
}

void UnmanagedGlobals::RemoveThread(DWORD tid)
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
            Logger::logf("UltimateAnticheat.log", Info, " New process attached, current thread %d\n", GetCurrentThreadId());

            if (UnmanagedGlobals::FirstProcessAttach)
            {
                if (!UnmanagedGlobals::SetExceptionHandler)
                {
                    SetUnhandledExceptionFilter(UnmanagedGlobals::ExceptionHandler);

                    if (!AddVectoredExceptionHandler(1, UnmanagedGlobals::ExceptionHandler))
                    {
                        Logger::logf("UltimateAnticheat.log", Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                    }

                    UnmanagedGlobals::SetExceptionHandler = true;
                }

                UnmanagedGlobals::FirstProcessAttach = false;
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Detection, " Some unknown process attached @ TLSCallback ");
            }

        }break;

        case DLL_PROCESS_DETACH: //program exit
        {
            for (Thread* t : UnmanagedGlobals::ThreadList)
            {
                delete t;
            }
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list
        {        
            if (!UnmanagedGlobals::AddThread(GetCurrentThreadId()))
            {
                Logger::logf("UltimateAnticheat.log", Err, " Failed to add thread to ThreadList @ TLSCallback: %d\n", GetLastError());
            }

            if (UnmanagedGlobals::SupressingNewThreads)
                ExitThread(0); //we can stop DLL injecting + DLL debuggers (such as VEH debugger) this way, but make sure you're handling your threads carefully

        }break;

        case DLL_THREAD_DETACH:
        {
            UnmanagedGlobals::RemoveThread(GetCurrentThreadId());
        }break;
    };
}

LONG WINAPI UnmanagedGlobals::ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode == EXCEPTION_BREAKPOINT)
    {
        Logger::logf("UltimateAnticheat.log", Info, " Breakpoint exception was caught in ExceptionHandler\n");
    }

    return EXCEPTION_CONTINUE_SEARCH;
}