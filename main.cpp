/*  
    U.A.C. is a non-invasive usermode anticheat for x64 Windows, tested on Windows 10 & 11. Usermode is used to ensure optimal end user experience
    
    Please view the readme for more information regarding program features. If you'd like to use this project in your game/software, please contact the author.

    License: Lesser GNU (LGPL), please be aware of what and what not can be done with this license.. ** you do not have the right to copy this project into your closed-source, for-profit project **

    Author: AlSch092 @ Github
*/

#include "API/API.hpp"  //API.hpp includes anticheat.hpp
#include "SplashScreen.hpp"

#pragma comment(linker, "/ALIGN:0x10000") //for remapping technique (anti-tamper) - each section gets its own region, align with system allocation granularity

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);
void NTAPI __stdcall FakeTLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#endif

PIMAGE_TLS_CALLBACK _tls_callback = FakeTLSCallback; //We're modifying our TLS callback @ runtime to trick static reversing
#pragma data_seg ()
#pragma const_seg ()

using namespace std;

unique_ptr<Settings> Settings::Instance = nullptr; //initialize settings instance singleton

int main(int argc, char** argv)
{
    const int MillisecondsBeforeShutdown = 60000;
    
    SetConsoleTitle(L"Ultimate Anti-Cheat");
  
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Splash::InitializeSplash, 0, 0, 0); //open splash window

    cout << "------------------------------------------------------------------------------------------\n";
    cout << "|                            Welcome to Ultimate Anti-Cheat!                             |\n";
    cout << "|  An in-development, non-commercial AC made to help teach concepts in game security     |\n";
    cout << "|                              Made by AlSch092 @Github                                  |\n";
    cout << "|         ...With special thanks to:                                                     |\n";
    cout << "|           changeofpace@github (remapping method)                                       |\n";
    cout << "|           discriminating@github (dll load notifcations, catalog verification)          |\n";
    cout << "------------------------------------------------------------------------------------------\n";

#ifdef _DEBUG //in debug compilation, we are more lax with our protections for easier testing purposes
    bool bEnableNetworking = false;  //change this to false if you don't want to use the server
    bool bEnforceSecureBoot = false;
    bool bEnforceDSE = false;
    bool bEnforceNoKDBG = false;
    bool bUseAntiDebugging = false;
    bool bUseIntegrityChecking = true;
    bool bCheckThreadIntegrity = true;
    bool bCheckHypervisor = false;
    bool bRequireRunAsAdministrator = true;
#else
    bool bEnableNetworking = false; //change this to false if you don't want to use the server
    bool bEnforceSecureBoot = true;
    bool bEnforceDSE = true;
    bool bEnforceNoKDBG = true;
    bool bUseAntiDebugging = true;
    bool bUseIntegrityChecking = true;
    bool bCheckThreadIntegrity = true;
    bool bCheckHypervisor = true;
    bool bRequireRunAsAdministrator = true;
#endif

    Settings* ConfigInstance = &Settings::GetInstance(bEnableNetworking, bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor, bRequireRunAsAdministrator);

    unique_ptr<AntiCheat> Anti_Cheat = make_unique<AntiCheat>(ConfigInstance); //main object of the program

    if (ConfigInstance->bEnforceSecureBoot)
    {
        if (!Services::IsSecureBootEnabled()) //enforce secure boot to stop bootloader cheats
        {
            Logger::logf("UltimateAnticheat.log", Err, "Secure boot is not enabled, thus you cannot proceed. Please enable secure boot in your BIOS.");
            return 0;
        }
    }
  
    if (ConfigInstance->bCheckHypervisor)
    {
        if (Services::IsHypervisor())  //initial check on hypervisor, do not let program proceed if a hypervisor is detected
        {
            char vendor[255]{ 0 };

            Services::GetHypervisorVendor(vendor);

            Logger::logf("UltimateAnticheat.log", Detection, "Hypervisor was present with vendor: %s", vendor);
            goto cleanup;
        }
    }

    if (API::Dispatch(Anti_Cheat.get(), API::DispatchCode::INITIALIZE) != Error::OK) //initialize AC , this will start all detections + preventions
    {
        Logger::logf("UltimateAnticheat.log", Err, "Could not initialize program: API::Dispatch failed. Shutting down.");
        goto cleanup;
    }

    if (ConfigInstance->bCheckThreads)
    {
        if (Anti_Cheat->IsAnyThreadSuspended()) //make sure that all our necessary threads aren't suspended by an attacker
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Atleast one of our threads was found suspended! All threads must be running for proper module functionality.");
            goto cleanup;
        }
    }

    UnmanagedGlobals::SupressingNewThreads = Anti_Cheat->GetBarrier()->IsPreventingThreads(); //if this is set to TRUE, we can stop the creation of any new threads via the TLS callback

    cout << "\n----------------------------------------------------------------------------------------------------------\n";
    cout << "All protections have been deployed, the program will now loop using its detection methods. Thanks for your interest in the project!\n\n";

    Sleep(MillisecondsBeforeShutdown); //let the other threads run for a bit to display monitoring, normally the game's main loop would be here but instead we will wait 60s

    if (Anti_Cheat->GetMonitor()->IsUserCheater())
    {
        Logger::logf("UltimateAnticheat.log", Info, "Detected a cheater in first %d milliseconds of runtime!", MillisecondsBeforeShutdown);
    }

cleanup: //jump to here on any error with AC initialization

    if (API::Dispatch(Anti_Cheat.get(), API::DispatchCode::CLIENT_EXIT) == Error::OK) //clean up memory & threads
    {
        Logger::logf("UltimateAnticheat.log", Info, " Cleanup successful. Shutting down program");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "Cleanup unsuccessful... Shutting down program");
    }

    return 0;
}

/*
    AddThread - adds a Thread* object to our global thread list
*/
bool UnmanagedGlobals::AddThread(DWORD id)
{
    DWORD tid = GetCurrentThreadId();
    Logger::logf("UltimateAnticheat.log", Info, " New thread spawned: %d", tid);

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;

    HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (threadHandle == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Warning, " Couldn't open thread handle @ TLS Callback: Thread %d", tid);
        return false;
    }
    else
    {
        Thread* t = new Thread(tid); //memory must be free'd after done using, this function does not free mem
        UnmanagedGlobals::ThreadList->push_back(t);
        return true;
    }
}

/*
    RemoveThread - Removes Thread* with threadid `tid` from our global thread list
*/
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

/*
The TLS callback triggers on process + thread attachment & detachment, which means we can catch any threads made by an attacker in our process space.
We can end attacker threads using ExitThread(), and let in our threads which are managed.
...An attacker can circumvent this by modifying the pointers to TLS callbacks which the program usually keeps track of, which requires re-remapping
*/
void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
    const UINT ThreadExecutionAddressStackOffset = 0x378; //** this might change on different version of window, Windows 10 is all I have access to currently

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH: //this should never be executed in legitimate program flow, our FakeTLSCallback contains the real logic for this case
        {
            ExitThread(-1);
        }break;

        case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated
        {
            UnmanagedGlobals::ThreadList->clear();
            delete UnmanagedGlobals::ThreadList;
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
        {         
            if (!UnmanagedGlobals::AddThread(GetCurrentThreadId()))
            {
                Logger::logf("UltimateAnticheat.log", Err, " Failed to add thread to ThreadList @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }

            if (UnmanagedGlobals::SupressingNewThreads)
            {
                UINT64 ThreadExecutionAddress = (UINT64)_AddressOfReturnAddress(); //check down the stack for the thread execution address, compare it to good module range, and if not in range then we've detected a rogue thread
                
                ThreadExecutionAddress += (UINT64)ThreadExecutionAddressStackOffset; //offset in stack to thread's execution address
                ThreadExecutionAddress = *(UINT64*)ThreadExecutionAddress;

                auto modules = Process::GetLoadedModules();

                for (std::vector<ProcessData::MODULE_DATA>::iterator it = modules->begin(); it != modules->end(); ++it)
                {
                    UINT64 LowAddr = (UINT64)it->dllInfo.lpBaseOfDll;
                    UINT64 HighAddr = (UINT64)it->dllInfo.lpBaseOfDll + it->dllInfo.SizeOfImage;

                    if (ThreadExecutionAddress > LowAddr && ThreadExecutionAddress < HighAddr)
                    {
                        delete modules; modules = nullptr;
                        return; //some loaded dll is making a thread, in a whitelisted address space
                    }
                }

                delete modules; modules = nullptr;

                Logger::logf("UltimateAnticheat.log", Info, " Stopping unknown thread from being created  @ TLSCallback: thread id %d", GetCurrentThreadId());
                Logger::logf("UltimateAnticheat.log", Info, " Thread id %d wants to execute function @ %llX. Patching over this address.", GetCurrentThreadId(), ThreadExecutionAddress);

                DWORD dwOldProt = 0;

                if(!VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt))
                {
                    Logger::logf("UltimateAnticheat.log", Warning, "Failed to call VirtualProtect on ThreadStart address @ TLSCallback: %llX", ThreadExecutionAddress);
                }
                else
                {
                    if(ThreadExecutionAddress != 0)
                        *(BYTE*)ThreadExecutionAddress = 0xC3; //write over any functions which are scheduled to execute next by this thread and not inside our whitelisted address range
                }
            }

        }break;

        case DLL_THREAD_DETACH:
        {
            UnmanagedGlobals::RemoveThread(GetCurrentThreadId());
        }break;
    };
}

/*
    FakeTLSCallback - Sets the TLS callback at runtime to something different than what was specified at compile time.
*/
void NTAPI __stdcall FakeTLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved) // todo: check if TLSCallback ptr has been changed @ runtime, if so end the program with a detected cheater
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH: //the DLL_PROCESS_ATTACH case only occurs once at program startup, thus logic for this case must go in the fake TLS callback
    {
        if (!Preventions::StopMultipleProcessInstances()) //prevent multi-clients by using shared memory-mapped region
        {
            Logger::logf("UltimateAnticheat.log", Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
            exit(-1);
        }

        if (!Process::ModifyTLSCallbackPtr((UINT64)&TLSCallback)) //TLSCallback is our real callback, FakeTLSCallback is set at compile time since people will try to patch over bytes in the callback to inject their dlls
        {
            Logger::logf("UltimateAnticheat.log", Err, "Could not initialize program: ModifyTLSCallback failed. Shutting down.");
            exit(-1);
        }

        UnmanagedGlobals::ModulesAtStartup = Process::GetLoadedModules();  //take a snapshot of loaded modules at program startup for later comparison. If you're loading dlls dynamically, you'll need to update this member with a new MODULE_DATA*

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

    case DLL_THREAD_ATTACH: 
    {
        ExitThread(0); //no legitimate thread should reach here, and should only occur if ModifyTLSCallback was not called properly 
    }break;

    };
}

/*
    ExceptionHandler - User defined exception handler which catches program-wide exceptions
    ...Currently we are not doing anything special with this, but we'll leave it here incase we need it later
*/
LONG WINAPI UnmanagedGlobals::ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
    Logger::logf("UltimateAnticheat.log", Warning, "Program threw exception: %x at %llX\n", exceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    
    if (exceptionCode == EXCEPTION_BREAKPOINT) //one or two of our debug checks may throw this exception
    {
    } //optionally we may be able to view the exception address and compare it to whitelisted module address space, if it's not contained then we assume it's attacker-run code

    return EXCEPTION_CONTINUE_SEARCH;
}