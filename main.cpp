/*  
    U.A.C. is a non-invasive usermode anticheat for x64 Windows, tested on Windows 10 & 11. Usermode is used to ensure an optimal end user experience. It also provides insight into how many kernelmode attack methods can be prevented from usermode, through concepts such as secure boot enforcement and DSE checking.
    
    Please view the readme for more information regarding program features. If you'd like to use this project in your game/software, please contact the author.

    License: GNU Affero general public license, please be aware of what and what not can be done with this license.. ** you do not have the right to copy this project into your closed-source, for-profit project **

    Author: AlSch092 @ Github
*/
#include <map>

#include "API/API.hpp"
#include "AntiCheat.hpp"
#include "SplashScreen.hpp"

#pragma comment(linker, "/ALIGN:0x10000") //for remapping technique (anti-tamper) - each section gets its own region, align with system allocation granularity

using namespace std;

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

shared_ptr<Settings> Settings::Instance = nullptr; //we only want a single instance of this object throughout the program (some classes might use raw pointers to this object)

int main(int argc, char** argv)
{
    // Set default options
#ifdef _DEBUG //in debug compilation, we are more lax with our protections for easier testing purposes
    const bool bEnableNetworking = false;  //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = false;
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = true;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option  
    const bool bEnableLogging = true;

    const list<wstring> allowedParents = {L"VsDebugConsole.exe", L"vsdbg.exe", L"powershell.exe", L"bash.exe", L"zsh.exe", L"explorer.exe"};
    const string logFileName = "UltimateAnticheat.log";

#else
    const bool bEnableNetworking = false; //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = false; //secure boot is recommended in distribution builds
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = true;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
    const bool bEnableLogging = true; // set to false to not create a detailed AntiCheat log file on the user's system

    const list<wstring> allowedParents = {L"explorer.exe", L"steam.exe"}; //add your launcher here
    const string logFileName = ""; //empty : does not log to file
#endif

#ifdef _DEBUG
    cout << "\tEnable logging :\t\t" << boolalpha << bEnableLogging << endl;
    cout << "Settings for this instance:\n";
    cout << "\tEnable Networking:\t" << boolalpha << bEnableNetworking << endl;
    cout << "\tEnforce Secure Boot: \t" << boolalpha << bEnforceSecureBoot << endl;
    cout << "\tEnforce DSE:\t\t" << boolalpha << bEnforceDSE << endl;
    cout << "\tEnforce No KDBG:\t" << boolalpha << bEnforceNoKDBG << endl;
    cout << "\tUse Anti-Debugging:\t" << boolalpha << bUseAntiDebugging << endl;
    cout << "\tUse Integrity Checking:\t" << boolalpha << bUseIntegrityChecking << endl;
    cout << "\tCheck Thread Integrity:\t" << boolalpha << bCheckThreadIntegrity << endl;
    cout << "\tCheck Hypervisor:\t" << boolalpha << bCheckHypervisor << endl;
    cout << "\tRequire Admin:\t\t" << boolalpha << bRequireRunAsAdministrator << endl;
    
    cout << "\tAllowed parent processes: \t\t" << endl;

    for (auto parent: allowedParents) 
    {
        wcout << parent << " ";
    }

    cout << endl;

#endif

    SetConsoleTitle(L"Ultimate Anti-Cheat");

    Thread* t = new Thread((LPTHREAD_START_ROUTINE)Splash::InitializeSplash, 0, false, true);

    cout << "------------------------------------------------------------------------------------------\n";
    cout << "|                            Welcome to Ultimate Anti-Cheat!                             |\n";
    cout << "|  An in-development, non-commercial AC made to help teach concepts in game security     |\n";
    cout << "|                              Made by AlSch092 @Github                                  |\n";
    cout << "|         ...With special thanks to:                                                     |\n";
    cout << "|           changeofpace@github (remapping method)                                       |\n";
    cout << "|           discriminating@github (dll load notifcations, catalog verification)          |\n";
    cout << "|           LucasParsy@github (testing, bug fixing)                                      |\n";
    cout << "------------------------------------------------------------------------------------------\n";

    shared_ptr<Settings> ConfigInstance = Settings::CreateInstance(bEnableNetworking, bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor, bRequireRunAsAdministrator, bUsingDriver, allowedParents, bEnableLogging, logFileName);

    unique_ptr<AntiCheat> Anti_Cheat = nullptr;

    try
    {
        Anti_Cheat = make_unique<AntiCheat>(ConfigInstance, Services::GetWindowsVersion());   //after all environmental checks (secure boot, DSE, adminmode) are performed, create the AntiCheat object
    }
    catch (const bad_alloc& e)
    {
        Logger::logf(Err, "Anticheat pointer could not be allocated @ main(): %s", e.what());
        return 1;
    }
    catch (const AntiCheatInitFail& e)
    {
        Logger::logf(Err, "Anticheat init error: %d %s", e.reasonEnum, e.what());
        return 1;
    }

    if (ConfigInstance->bCheckThreads)
    {   //typically thread should cross-check eachother to ensure nothing is suspended, in this version of the program we only check thread suspends once at the start
        if (Anti_Cheat->IsAnyThreadSuspended()) //make sure that all our necessary threads aren't suspended by an attacker
        {
            Logger::logf(Detection, "Atleast one of our threads was found suspended! All threads must be running for proper module functionality.");
            return 1;
        }
    }

    UnmanagedGlobals::SupressingNewThreads = Anti_Cheat->GetBarrier()->IsPreventingThreads(); //if this is set to TRUE, we can stop the creation of any new unknown threads via the TLS callback

    cout << "\n----------------------------------------------------------------------------------------------------------" << endl;
    cout << "All protections have been deployed, the program will now loop using its detection methods. Thanks for your interest in the project!" << endl;
    cout << "Please enter 'q' if you'd like to end the program." << endl;
    
    string userInput;

    while (true)
    {
        cin >> userInput;

        if (userInput == "q" || userInput == "Q")
        {
            cout << "Exit key was pressed, shutting down program..." << endl;
            break;
        }     
    }

    if (Anti_Cheat->GetMonitor()->IsUserCheater())
    {
        Logger::logf(Info, "Detected a possible cheater during program execution!");
    }

#ifdef _DEBUG
    list<DetectionFlags> flags = Anti_Cheat->GetMonitor()->GetDetectedFlags();
    map<DetectionFlags, const char*> explanations = 
    {
        { DetectionFlags::DEBUGGER, "Debugging method detected" },
        { DetectionFlags::PAGE_PROTECTIONS, "Image's .text section is writable, memory was re-re-mapped" },
        { DetectionFlags::CODE_INTEGRITY, "Image's memory in .text or .rdata modified" },
        { DetectionFlags::DLL_TAMPERING, "Networking or certificate-related WINAPI hooked" },
        { DetectionFlags::BAD_IAT, "Import Adress Table entry points to memory outside loaded modules" },
        { DetectionFlags::OPEN_PROCESS_HANDLES, "A process has handles to our process" },
        { DetectionFlags::UNSIGNED_DRIVERS, "Unsigned drivers running on the machine" },
        { DetectionFlags::INJECTED_ILLEGAL_PROGRAM, "Unsigned DLL loaded into the process" },
        { DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM, "Blacklisted program name running on machine" },
        { DetectionFlags::REGISTRY_KEY_MODIFICATIONS, "Changes to registry keys related to secure boot, CI, testsigning mode, etc..." },
        { DetectionFlags::MANUAL_MAPPING, "Manually mapped module written into memory" },
        { DetectionFlags::SUSPENDED_THREAD, "One or more important threads were suspended" },
        { DetectionFlags::HYPERVISOR, "A Hypervisor is running on the machine" }
    };
    for (DetectionFlags flag : flags) 
    {
        Logger::logf(Info, explanations[flag]);
    }
#endif

    delete t;

    return 0;
}

/*
    AddThread - adds a Thread* object to our global thread list -> this will likely be phased out soon
*/
bool UnmanagedGlobals::AddThread(DWORD id)
{
    DWORD tid = GetCurrentThreadId();
    Logger::logf(Info, " New thread spawned: %d", tid);

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;

    HANDLE threadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    if (threadHandle == NULL)
    {
        Logger::logf(Warning, " Couldn't open thread handle @ TLS Callback: Thread %d", tid);
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
    RemoveThread - Removes Thread* with threadid `tid` from our global thread list  -> this will likely be phased out soon
*/
void UnmanagedGlobals::RemoveThread(DWORD tid)
{
    Thread* ToRemove = NULL;

    list<Thread*>::iterator it;

    for (it = ThreadList->begin(); it != ThreadList->end(); ++it)
    {
        Thread* t = it._Ptr->_Myval;
        if (t->GetId() == tid)
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
        case DLL_PROCESS_ATTACH:
        {
            if (!Preventions::StopMultipleProcessInstances()) //prevent multi-clients by using shared memory-mapped region
            {
                Logger::logf(Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
                terminate();
            }

            Logger::logf(Info, " New process attached, current thread %d\n", GetCurrentThreadId());

            if (UnmanagedGlobals::FirstProcessAttach) //process creation will trigger PROCESS_ATTACH, so we can put some initialize stuff in here incase main() is hooked or statically modified by the attacker
            {
                if (!UnmanagedGlobals::SetExceptionHandler)
                {
                    SetUnhandledExceptionFilter(UnmanagedGlobals::ExceptionHandler);

                    if (!AddVectoredExceptionHandler(1, UnmanagedGlobals::ExceptionHandler))
                    {
                        Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                    }

                    UnmanagedGlobals::SetExceptionHandler = true;
                }

                UnmanagedGlobals::FirstProcessAttach = false;
            }
            else
            {
                Logger::logf(Detection, " Some unknown process attached @ TLSCallback "); //this should generally never be triggered in this example
            }
        }break;

        case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated
        {
            UnmanagedGlobals::ThreadList->clear();
            delete UnmanagedGlobals::ThreadList;
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
        {         
#ifndef _DEBUG
            if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
            {
                Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }
#endif
            if (!UnmanagedGlobals::AddThread(GetCurrentThreadId()))
            {
                Logger::logf(Err, " Failed to add thread to ThreadList @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }

            if (UnmanagedGlobals::SupressingNewThreads)
            {
                if (Services::GetWindowsVersion() == Windows11) //Windows 11 no longer has the thread's start address on the its stack, bummer
                    return;

                UINT64 ThreadExecutionAddress = *(UINT64*)((UINT64)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset); //check down the stack for the thread execution address, compare it to good module range, and if not in range then we've detected a rogue thread
                
                if (ThreadExecutionAddress == 0) //this generally should never be 0, but we'll add a check for good measure incase the offset changes on different W10 builds
                    return;

                auto modules = Process::GetLoadedModules();

                for (auto module : modules)
                {
                    UINT64 LowAddr = (UINT64)module.dllInfo.lpBaseOfDll;
                    UINT64 HighAddr = (UINT64)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage;

                    if (ThreadExecutionAddress > LowAddr && ThreadExecutionAddress < HighAddr) //a properly loaded DLL is making the thread, so allow it to execute
                    {
                        //if any unsigned .dll is loaded, it will be caught in the DLL load callback/notifications, so we shouldnt need to cert check in this routine (this will cause slowdowns in execution, also cert checking inside the TLS callback doesn't seem to work properly here)
                        return; //any manually mapped modules' threads will be stopped since they arent using the loader and thus won't be in the loaded modules list
                    }
                }

                Logger::logf(Detection, " Stopping unknown thread from being created  @ TLSCallback: thread id %d", GetCurrentThreadId());
                Logger::logf(Detection, " Thread id %d wants to execute function @ %llX. Patching over this address.", GetCurrentThreadId(), ThreadExecutionAddress);

                DWORD dwOldProt = 0;

                if(!VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt)) //make thread start address writable
                {
                    Logger::logf(Warning, "Failed to call VirtualProtect on ThreadStart address @ TLSCallback: %llX", ThreadExecutionAddress);
                }
                else
                {
                    if (ThreadExecutionAddress != 0)
                    {
                        *(BYTE*)ThreadExecutionAddress = 0xC3; //write over any functions which are scheduled to execute next by this thread and not inside our whitelisted address range
                    }
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
    ExceptionHandler - User defined exception handler which catches program-wide exceptions
    ...Currently we are not doing anything special with this, but we'll leave it here incase we need it later
*/
LONG WINAPI UnmanagedGlobals::ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode != EXCEPTION_BREAKPOINT) //one or two of our debug checks may throw this exception
    {
        Logger::logf(Warning, "Program threw exception: %x at %llX\n", exceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    } //optionally we may be able to view the exception address and compare it to whitelisted module address space, if it's not contained then we assume it's attacker-run code

    return EXCEPTION_CONTINUE_SEARCH;
}
