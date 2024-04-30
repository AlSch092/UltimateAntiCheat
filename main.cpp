/*  UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there. main.cpp contains testing of functionality

    U.A.C. is an 'in-development'/educational example of anti-cheat techniques written in C++ for x64 platforms.
    
    Please view the readme for more information regarding program features.

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

int main(int argc, char** argv)
{
    SetConsoleTitle(L"Ultimate Anti-Cheat");

    cout << "----------------------------------------------------------------------------------------------------------\n";
    cout << "|                               Welcome to Ultimate Anti-Cheat!                                          |\n";
    cout << "|       An in-development, non-commercial AC made to help teach us basic concepts in game security       |\n";
    cout << "|       Made by AlSch092 @Github, with special thanks to changeOfPace for re-mapping method              |\n";
    cout << "----------------------------------------------------------------------------------------------------------\n";

    AntiCheat* AC = new AntiCheat();

    API::Dispatch(AC, API::DispatchCode::INITIALIZE); //initialize AC , this will start all detections + preventions

    UnmanagedGlobals::SupressingNewThreads = AC->GetBarrier()->IsPreventingThreads();

    cout << "\n-----------------------------------------------------------------------------------------\n";
    cout << "All tests have been executed, the program will now loop using its detection methods for one minute. Thanks for your interest in the project!\n\n";

    Sleep(60000); //let the other threads run for a bit to display monitoring, normally the game's main loop would be here but instead we will wait 60s
                  //...it's also recommended you run any anti-cheat in the main thread of the game for several reasons

    if (AC->GetMonitor()->IsUserCheater())
    {
        Logger::logf("UltimateAnticheat.log", Info, "Detected a cheater in first 60 seconds of runtime");
    }

    if (API::Dispatch(AC, API::DispatchCode::CLIENT_EXIT) == Error::OK) //clean up memory & threads
    {
        Logger::logf("UltimateAnticheat.log", Info, " Cleanup successful. Shutting down program");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "Cleanup unsuccessful... Shutting down program");
    }

    system("pause");
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

        UnmanagedGlobals::ThreadList->push_back(t);
        return true;
    }
}

void UnmanagedGlobals::RemoveThread(DWORD tid)
{
    Thread* ToRemove = NULL;

    std::list<Thread*>::iterator it;

    for (it = ThreadList->begin(); it != ThreadList->end(); ++it)
    {
        Thread* t = it._Ptr->_Myval;
        if (t->Id == tid)
            ToRemove = t;
    }

    if (ToRemove != NULL) //remove thread from our list on thread_detach
        ThreadList->remove(ToRemove);
}

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved) // todo: check if TLSCallback ptr has been changed @ runtime, if so end the program with a detected cheater
{
    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            Logger::logf("UltimateAnticheat.log", Info, " New process attached, current thread %d\n", GetCurrentThreadId());

            if (UnmanagedGlobals::FirstProcessAttach) //process creation will trigger PROCESS_ATTACH, so we can put some initialize stuff in here incase main() is hooked or statically modified by the attacker
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
                Logger::logf("UltimateAnticheat.log", Detection, " Some unknown process attached @ TLSCallback "); //this should generally never be triggered in this example
            }

        }break;

        case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated
        {
            UnmanagedGlobals::ThreadList->clear();
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

    Logger::logf("UltimateAnticheat.log", Warning, "Program threw exception: %x\n", exceptionCode);

    return EXCEPTION_CONTINUE_SEARCH;
}