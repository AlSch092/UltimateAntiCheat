/*  
    U.A.C. is a non-invasive usermode client-run anticheat for x64 Windows, tested on Windows 7, 10 & 11. 
    
    While everything works fine, parts of the code are messy and could use a cleanup

    Please view the readme and/or github wiki page for more a full list of techniques and design information

    License: GNU Affero general public license, please be aware of what and what not can be done with this license.. ** you do not have the right to copy this project into your closed-source, for-profit project **

    Author: AlSch092 @ Github
*/

#ifndef _LIB_ //building in LibRelease, so we don't want to include the main.cpp file

#include "Core/AntiCheat.hpp"
#include "SplashScreen.hpp"
#include "AntiTamper/MapProtectedClass.hpp" //to make Settings class object write-protected (see https://github.com/AlSch092/RemapProtectedClass)
#include "Obscure/XorStr.hpp"
#include "Common/Settings.hpp"
#include "Common/DetectionFlags.hpp"
#include "Process/Thread.hpp"
#include <unordered_map>

#pragma comment(linker, "/ALIGN:0x10000") //for remapping technique (anti-tamper) - each section gets its own region, align with system allocation granularity
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")

void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved);

EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB") //store tls callback inside the correct section
const
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

bool SupressingUnknownThreads = true; //we need some variables in both our TLS callback and main()

LONG WINAPI g_ExceptionHandler(__in EXCEPTION_POINTERS* ExceptionInfo);


/**
 * @brief Entry point function which creates an anticheat object and loops until the user wants to exit
 *
 * @details serves as a proof of concept for the anticheat, and demonstrates how to use the AntiCheat class. this file is excluded if building in `LibRelease`
 *
 * @param argc Number of command line arguments
 * @param argv Each command line argument
 *
 * @return int 0 on success, non-zero on failure
 */
int main(int argc, char** argv)
{
	std::string userKeyboardInput; //for looping until user wants to exit

    std::unordered_map<DetectionFlags, const char*> explanations;
    std::list<DetectionFlags> flags; //for explanation output after the program is finished running

    // Set default options
#ifdef _DEBUG //in debug compilation, we are more lax with our protections for easier testing purposes
    const bool bEnableNetworking = false;  //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = true;
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = false;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option  
    const bool bEnableLogging = true;

    std::wstring DriverCertSubject = L"YourGameCompany";

    if (bUsingDriver)
        DriverCertSubject = L"";

    const std::list<std::wstring> allowedParents = {L"VsDebugConsole.exe", L"vsdbg.exe", L"powershell.exe", L"bash.exe", L"zsh.exe", L"explorer.exe"};
    const std::string logFileName = "UltimateAnticheat.log";

    const std::string serverIP = "127.0.0.1";
    const uint16_t serverPort = 5445;
#else
    const bool bEnableNetworking = false; //change this to false if you don't want to use the server
    const bool bEnforceSecureBoot = false; //secure boot is recommended in distribution builds
    const bool bEnforceDSE = true;
    const bool bEnforceNoKDBG = true;
    const bool bUseAntiDebugging = true;
    const bool bUseIntegrityChecking = true;
    const bool bCheckThreadIntegrity = true;
    const bool bCheckHypervisor = false;
    const bool bRequireRunAsAdministrator = true;
    const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
    std::wstring DriverCertSubject = L"YourGameCompany";
    
    if (bUsingDriver)
        DriverCertSubject = L"";

    const bool bEnableLogging = true; // set to false to not create a detailed AntiCheat log file on the user's system

    constexpr auto parent_1 = make_encrypted(L"explorer.exe"); //in release build we can encrypt strings at compile time and decrypt them at runtime
    constexpr auto parent_2 = make_encrypted(L"powershell.exe"); //ideally this type of thing would be done via LLVM passes or some post-compilation tool

    const std::list<std::wstring> allowedParents = { parent_1.decrypt(), parent_2.decrypt()}; //add your launcher here
    const std::string logFileName = "UltimateAnticheat.log"; //empty : does not log to file

    const std::string serverIP = "127.0.0.1";
    const uint16_t serverPort = 5445;
#endif

#ifdef _DEBUG

    cout << "Settings for this instance:\n";
    cout << "\t Enable Networking:\t" << boolalpha << bEnableNetworking << endl;
    cout << "\t Enforce Secure Boot: \t" << boolalpha << bEnforceSecureBoot << endl;
    cout << "\t Enforce DSE:\t\t" << boolalpha << bEnforceDSE << endl;
    cout << "\t Enforce No KDBG:\t" << boolalpha << bEnforceNoKDBG << endl;
    cout << "\t Use Anti-Debugging:\t" << boolalpha << bUseAntiDebugging << endl;
    cout << "\t Use Integrity Checking:\t" << boolalpha << bUseIntegrityChecking << endl;
    cout << "\t Check Thread Integrity:\t" << boolalpha << bCheckThreadIntegrity << endl;
    cout << "\t Check Hypervisor:\t" << boolalpha << bCheckHypervisor << endl;
    cout << "\t Require Admin:\t\t" << boolalpha << bRequireRunAsAdministrator << endl;
    cout << "\t Using Kernelmode Driver:\t\t" << boolalpha << bUsingDriver << endl;
    cout << "\t Enable logging :\t\t" << boolalpha << bEnableLogging << endl;
    cout << "\t Allowed parent processes: \t\t" << endl;

    for (const auto& parent: allowedParents) 
    {
        std::wcout << parent << " ";
    }

    std::cout << std::endl;

#endif

    SetConsoleTitle(L"Ultimate Anti-Cheat");

    Thread* t = new Thread((LPTHREAD_START_ROUTINE)Splash::InitializeSplash, 0, false, true);

    std::cout << "*----------------------------------------------------------------------------------------*\n";
    std::cout << "|                           Welcome to Ultimate Anti-Cheat (UAC)!                        |\n";
    std::cout << "|       A non-commercial, educational AC made to help teach concepts in game security    |\n";
    std::cout << "|                              Made by AlSch092 @Github                                  |\n";
    std::cout << "|         ...With special thanks to:                                                     |\n";
    std::cout << "|           changeofpace (remapping method)                                              |\n";
    std::cout << "|           discriminating (dll load notifcations, catalog verification)                 |\n";
    std::cout << "|           LucasParsy (testing, bug fixing)                                             |\n";
    std::cout << "*----------------------------------------------------------------------------------------*\n";

    std::unique_ptr<AntiCheat> Anti_Cheat = nullptr;

    ProtectedMemory ProtectedSettingsMemory(sizeof(Settings));

    Settings* Config = ProtectedSettingsMemory.Construct<Settings>(
        serverIP,
        serverPort,
        bEnableNetworking, 
        bEnforceSecureBoot, 
        bEnforceDSE, 
        bEnforceNoKDBG, 
        bUseAntiDebugging, 
        bUseIntegrityChecking, 
        bCheckThreadIntegrity, 
        bCheckHypervisor, 
        bRequireRunAsAdministrator, 
        bUsingDriver,
        DriverCertSubject,
        allowedParents, 
        bEnableLogging, 
        logFileName);

    try
    {
        ProtectedSettingsMemory.Protect(); //make the Settings object write-protect and resistant to page security changes
    }
    catch (const std::runtime_error& ex)
    {
        Logger::logf(Err, "Settings could not be initialized. Closing application...");
        goto Cleanup;
    }

    try
    {
        Anti_Cheat = std::make_unique<AntiCheat>(Config);   //after all environmental checks (secure boot, DSE, adminmode) are performed, create the AntiCheat object
    }
    catch (const std::bad_alloc& e)
    {
        Logger::logf(Err, "Anticheat pointer could not be allocated @ main(): %s", e.what());
        goto Cleanup;
    }
    catch (const AntiCheatInitFail& e)
    {
        Logger::logf(Err, "Anticheat init error: %d %s", e.reasonEnum, e.what());
        goto Cleanup;
    }

    if (Config->bCheckThreads)
    {   //typically thread should cross-check eachother to ensure nothing is suspended, in this version of the program we only check thread suspends once at the start
        if (Anti_Cheat->IsAnyThreadSuspended()) //make sure that all our necessary threads aren't suspended by an attacker
        {
            Logger::logf(Detection, "Atleast one of our threads was found suspended! All threads must be running for proper module functionality.");
            goto Cleanup;
        }
    }

    SupressingUnknownThreads = Anti_Cheat->GetBarrier()->IsPreventingThreads(); //if this is set to TRUE, we can stop the creation of any new unknown threads via the TLS callback

    std::cout << "\n----------------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << "All protections have been deployed, the program will now loop using its detection methods. Thanks for your interest in the project!" << std::endl;
    std::cout << "Please enter 'q' if you'd like to end the program." << std::endl;
    
    while (true)
    {
        std::cin >> userKeyboardInput;

        if (userKeyboardInput == "q" || userKeyboardInput == "Q")
        {
            std::cout << "Exit key was pressed, shutting down program..." << std::endl;
            break;
        }     
    }

    if (Anti_Cheat->GetMonitor()->IsUserCheater())
    {
        Logger::logf(Info, "Detected a possible cheater during program execution!");
    }

    Anti_Cheat->FastCleanup();

#ifdef _DEBUG

    flags = Anti_Cheat->GetMonitor()->GetDetectedFlags();
    explanations = 
    {
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
        { DetectionFlags::HYPERVISOR, "A Hypervisor is running on the machine" },
        { DetectionFlags::DEBUG_WINAPI_DEBUGGER, "A debugging method was detected via `IsDebuggerPresent()`" },
        { DetectionFlags::DEBUG_PEB, "A debugging method was detected via `BeingDebugged` flag in the PEB" },
        { DetectionFlags::DEBUG_DBK64_DRIVER, "A debugging method was detected via DBK64.sys being loaded" },
        { DetectionFlags::DEBUG_CLOSEHANDLE, "A debugging method was detected via `CloseHandle(NULL)`" },
        { DetectionFlags::DEBUG_DEBUG_OBJECT, "A debugging method was detected via debug object" },
        { DetectionFlags::DEBUG_DEBUG_PORT, "A debugging method was detected via debug port" },
        { DetectionFlags::DEBUG_HEAP_FLAG, "A debugging method was detected via heap flags" },
        { DetectionFlags::DEBUG_KERNEL_DEBUGGER, "A debugging method was detected via OS-managed kernelmode debugging option" },
        { DetectionFlags::DEBUG_HARDWARE_REGISTERS, "A debugging method was detected via hardware debug registers" },
        { DetectionFlags::DEBUG_INT2C, "A debugging method was detected via INT 2C instruction" },
        { DetectionFlags::DEBUG_TRAP_FLAG, "A debugging method was detected via trap flag enabled" },
        { DetectionFlags::DEBUG_INT3, "A debugging method was detected via INT3 instruction" },
    };
    for (DetectionFlags flag : flags) 
    {
        Logger::logf(Info, explanations[flag]);
    }
#endif

Cleanup:
    if(t != nullptr) //cleanup splash screen thread obj
        delete t;

	Anti_Cheat.reset(); //we need to call AntiCheat's destructor before ~ProtectedMemory, since AntiCheat destructor will reference the Settings object
    ProtectedSettingsMemory.Reset();

    return 0;
}


/**
 * @brief TLS callback helper to end unknown threads without patching over their start address or calling ExitThread
 *
 * This function is executed by writing over the start address of new unknown threads in the tls callback

 * @return None
 *
 * @usage
 *  N/A
 */
void ExitThreadGracefully()
{
}

/**
 * @brief TLS callback triggers on process + thread attachment & detachment
 *
 * @details Can be used to prevent rogue threads from being created, or to initialize certain anti-cheat features
 *
 * @param pHandle handle to the current module
 * @param dwReason action that occured to trigger the callback
 * @param Reserved N/A, unused
 *
 * @return void
 *
 */
void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
    const uintptr_t ThreadExecutionAddressStackOffset = 0x378; //** this might change on different version of window, Windows 10 is all I have access to currently

    static bool FirstProcessAttach = true;
    static bool SetExceptionHandler = false;
	static WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;

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

            if (FirstProcessAttach) //process creation will trigger PROCESS_ATTACH, so we can put some initialize stuff in here incase main() is hooked or statically modified by the attacker
            {
                WinVersion = Services::GetWindowsVersion();

                if (!SetExceptionHandler)
                {
                    SetUnhandledExceptionFilter(g_ExceptionHandler);

                    if (!AddVectoredExceptionHandler(1, g_ExceptionHandler))
                    {
                        Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                    }

                    SetExceptionHandler = true;
                }

                FirstProcessAttach = false;
            }
            else
            {
                Logger::logf(Detection, " Some unknown process attached @ TLSCallback "); //this should generally never be triggered in this example
            }
        }break;

        case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated if required
        {
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
        {         
#ifndef _DEBUG
            if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
            {
                Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }
#endif

            if (SupressingUnknownThreads)
            {
                if (WinVersion == Windows11) //Windows 11 no longer has the thread's start address on the its stack, bummer. don't have a W11 machine either at home
                    return;

                uintptr_t stackThreadStartSlot = (uintptr_t)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset;
                uintptr_t ThreadExecutionAddress = *(uintptr_t*)((uintptr_t)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset); //check down the stack for the thread execution address, compare it to good module range, and if not in range then we've detected a rogue thread
                
                if (ThreadExecutionAddress == 0) //this generally should never be 0, but we'll add a check for good measure incase the offset changes on different W10 builds
                    return;

                auto modules = Process::GetLoadedModules();

                for (const auto& module : modules)
                {
                    uintptr_t LowAddr = (uintptr_t)module.dllInfo.lpBaseOfDll;
                    uintptr_t HighAddr = (uintptr_t)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage;

                    if (ThreadExecutionAddress > LowAddr && ThreadExecutionAddress < HighAddr) //a properly loaded DLL is making the thread, so allow it to execute
                    {
                        //if any unsigned .dll is loaded, it will be caught in the DLL load callback/notifications, so we shouldnt need to cert check in this routine (this will cause slowdowns in execution, also cert checking inside the TLS callback doesn't seem to work properly here)
                        return; //any manually mapped modules' threads will be stopped since they arent using the loader and thus won't be in the loaded modules list
                    }
                }

                Logger::logf(Detection, " Stopping unknown thread from being created  @ TLSCallback: thread id %d", GetCurrentThreadId());
                *(uintptr_t*)stackThreadStartSlot = (uintptr_t)&ExitThreadGracefully;
            }

        }break;

        case DLL_THREAD_DETACH:
        {
        }break;
    };
}

/**
 * @brief Vectored exception handler that logs unhandled exceptions in the process
 *
 * @param ExceptionInfo Structure containing info about the exception
 *
 * @return EXCEPTION_CONTINUE_SEARCH to keep looking for handlers
 *
 * @usage
 * AddVectoredExceptionHandler(1, g_ExceptionHandler);
 */
LONG WINAPI g_ExceptionHandler(__in EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
    DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

    if (exceptionCode != EXCEPTION_BREAKPOINT) //one or two of our debug checks may throw this exception
    {
        Logger::logf(Warning, "Program threw exception: %x at %llX\n", exceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
    } //optionally we may be able to view the exception address and compare it to whitelisted module address space, if it's not contained then we assume it's attacker-run code

    return EXCEPTION_CONTINUE_SEARCH;
}


#endif  // _LIB_