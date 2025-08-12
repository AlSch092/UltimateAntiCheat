#include "AntiCheatLib.hpp"
#include "AntiCheatInitFail.hpp"
#include "Detections.hpp"
#include "Preventions.hpp"
#include "../Common/Logger.hpp"
#include "../Common/Settings.hpp"
#include "../AntiDebug/DebuggerDetections.hpp"
#include "../AntiTamper/MapProtectedClass.hpp" //to make Settings class object write-protected (see https://github.com/AlSch092/RemapProtectedClass)
#include "../SplashScreen.hpp"

#pragma comment(linker, "/ALIGN:0x10000") //for section remapping
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

/**
 * @brief the Impl structure is used to hide implementation details of the AntiCheat class, using the PIMPL idiom
 */
struct AntiCheat::Impl
{
    ProtectedMemory* ProtectedSettings = nullptr;
    
    WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;
    
    unique_ptr<Detections> Monitor = nullptr;  //cheat detections
    
    unique_ptr<Preventions> Barrier = nullptr;  //cheat preventions
    
    unique_ptr<DebuggerDetections> AntiDebugger = nullptr;
    
    shared_ptr <NetClient> NetworkClient = nullptr; //for client-server comms, our other classes need access to this to send detected flags to the server
    
	Settings* Config = nullptr; //protected settings object, which is write-protected via ProtectedMemory class

    EvidenceLocker* Evidence = nullptr;

    Impl(Settings* settings)
    {
        this->ProtectedSettings = new ProtectedMemory(sizeof(Settings));

        this->WinVersion = Services::GetWindowsVersion();

        this->Config = this->ProtectedSettings->Construct<Settings>( //remake settings object inside our protected section
            settings->serverIP,
            settings->serverPort,
            settings->bNetworkingEnabled,
            settings->bEnforceSecureBoot,
            settings->bEnforceDSE,
            settings->bEnforceNoKDbg,
            settings->bUseAntiDebugging,
            settings->bCheckIntegrity,
            settings->bCheckThreads,
            settings->bCheckHypervisor,
            settings->bRequireRunAsAdministrator,
            settings->bUsingDriver,
            settings->DriverSignerSubject,
            settings->allowedParents,
            settings->bEnableLogging,
            settings->logFileName);

        try
        {
            this->ProtectedSettings->Protect(); //remap the protected memory to prevent tampering (this doesn't call DRM::Protect)
        }
        catch (const std::runtime_error& ex)
        {
            throw std::runtime_error("Could not create protected memory for DRM settings");
        }
          
        if (!DoPreInitializeChecks())
        {
            Logger::logfw(Err, L"Pre-initialize checks did not pass @ AntiCheat::AntiCheat.");
            throw AntiCheatInitFail(AntiCheatInitFailReason::PreInitializeChecksDidNotPass);
        }
            
        try
        {
            this->NetworkClient = make_shared<NetClient>();

            this->Evidence = new EvidenceLocker(this->NetworkClient.get());

            this->AntiDebugger = make_unique<DebuggerDetections>(Config, this->Evidence);

            this->Monitor = make_unique<Detections>(Config, this->Evidence, NetworkClient);

            this->Barrier = make_unique<Preventions>(Config, true, Monitor.get()->GetIntegrityChecker());
        }
        catch (const std::bad_alloc& _)
        {
            throw AntiCheatInitFail(AntiCheatInitFailReason::BadAlloc);
        }

        if (Config->bUsingDriver) //register + load the driver if it's correctly signed, unload it when the program is exiting
        {
            wchar_t absolutePath[MAX_PATH] = { 0 };

            if (!GetFullPathName(Config->GetKMDriverPath().c_str(), MAX_PATH, absolutePath, nullptr))
            {
                throw AntiCheatInitFail(AntiCheatInitFailReason::DriverNotFound);
            }

            //additionally, we need to check the signature on our driver to make sure someone isn't spoofing it. this will be added soon after initial testing is done
            wstring driverCertSubject = Authenticode::GetSignerFromFile(absolutePath);

            if (driverCertSubject.size() == 0 || driverCertSubject != Config->DriverSignerSubject) //check if driver cert has correct sign subject
            {
                throw AntiCheatInitFail(AntiCheatInitFailReason::DriverUnsigned);
            }

            if (!Services::LoadDriver(GetConfig()->GetKMDriverName().c_str(), absolutePath)) //Remove this call, along with Services::LoadDriver and Services::UnloadDriver
            {
                throw AntiCheatInitFail(AntiCheatInitFailReason::DriverLoadFail);
            }

            Logger::logfw(Info, L"Loaded driver: %s from path %s", GetConfig()->GetKMDriverName().c_str(), absolutePath);
        }

		if (this->Initialize("GAMECODE-COOLGAME1") != Error::OK) //initialize AC , this will start all detections + preventions
		{
			Logger::logf(Err, "Failed to initialize AntiCheat @ Impl::Impl(). Shutting down.");
			throw AntiCheatInitFail(AntiCheatInitFailReason::StartupFailed);
		}

        if (this->LaunchDefenses() != Error::OK)
        {
			Logger::logf(Err, "Failed to launch defenses @ Impl::Impl(). Shutting down.");
			throw AntiCheatInitFail(AntiCheatInitFailReason::StartupFailed);
        }
    }

    ~Impl()
    {
        this->ProtectedSettings->Reset();
        delete this->ProtectedSettings;
    }

    Error Initialize(std::string licenseKey);
    Error Cleanup();
    Error FastCleanup();

    bool DoPreInitializeChecks();
    bool IsAnyThreadSuspended();
    Error LaunchDefenses();

    DebuggerDetections* GetAntiDebugger() const { return this->AntiDebugger.get(); }

    weak_ptr<NetClient> GetNetworkClient() const { return this->NetworkClient; }

    Preventions* GetBarrier() const { return this->Barrier.get(); }  //pointer lifetime stays within the Anticheat class, these 'Get' functions should only be used to call functions of these classes

    Detections* GetMonitor() const { return this->Monitor.get(); }

    Settings* GetConfig() const { return this->Config; }
};

/**
 * @brief Constructs an AntiCheat object with the provided settings
 *
 * @param settings Pointer to the settings object containing configuration for the anti-cheat system

 * @return Anticheat class object
 *
 * @usage
 * AntiCheat* antiCheat = new AntiCheat(settings);
 */
AntiCheat::AntiCheat(Settings* settings) : pImpl(new AntiCheat::Impl(settings))
{
}

/**
 * @brief Cleans up resources and deletes the current AntiCheat instance
 *
 *
 * @return void
 *
 * @usage
 * anticheat->Destroy();
 */
void AntiCheat::Destroy()
{
    if (this->pImpl != nullptr)
    {
        this->pImpl->Cleanup(); //clean up the anticheat
        delete this->pImpl;
        this->pImpl = nullptr;
    }
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
LONG WINAPI g_ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)  //handler that will be called whenever an unhandled exception occurs in any thread of the process
{
	DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;

	if (exceptionCode != EXCEPTION_BREAKPOINT) //one or two of our debug checks may throw this exception
	{
		Logger::logf(Warning, "Program threw exception: %x at %llX\n", exceptionCode, ExceptionInfo->ExceptionRecord->ExceptionAddress);
	} //optionally we may be able to view the exception address and compare it to whitelisted module address space, if it's not contained then we assume it's attacker-run code

	return EXCEPTION_CONTINUE_SEARCH;
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
    const UINT ThreadExecutionAddressStackOffset = 0x378; //** this might change on different version of window, Windows 10 is all I have access to currently

    static bool SupressingNewThreads = true; //we need some variables in both our TLS callback and main()
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

        if (SupressingNewThreads)
        {
            if (WinVersion == Windows11) //Windows 11 no longer has the thread's start address on the its stack, bummer. don't have a W11 machine either at home
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

            if (!VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt)) //make thread start address writable
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
    }break;
    };
}

/**
 * @brief Signals threads to shutdown and waits for them
 *
 *
 * @return Error::OK on success, otherwise an error code indicating the failure reason
 *
 * @usage
 * anticheat->pImpl->Cleanup();
 */
Error AntiCheat::Impl::Cleanup()
{
    if (Config->bUseAntiDebugging && GetAntiDebugger() != nullptr && GetAntiDebugger()->GetDetectionThread() != nullptr) //stop anti-debugger thread
    {
        GetAntiDebugger()->GetDetectionThread()->SignalShutdown(true);
        GetAntiDebugger()->GetDetectionThread()->JoinThread();
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetMonitorThread() != nullptr) //stop anti-cheat monitor thread
    {
        GetMonitor()->GetMonitorThread()->SignalShutdown(true);
        GetMonitor()->GetMonitorThread()->JoinThread();
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetProcessCreationMonitorThread() != nullptr) //stop process creation monitor thread
    {
        GetMonitor()->GetProcessCreationMonitorThread()->SignalShutdown(true);
        GetMonitor()->GetProcessCreationMonitorThread()->JoinThread();
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetRegistryMonitorThread() != nullptr) //stop registry monitor
    {
        GetMonitor()->GetRegistryMonitorThread()->SignalShutdown(true);
        GetMonitor()->GetRegistryMonitorThread()->JoinThread();
    }

    auto client = GetNetworkClient().lock();

    if (client)
    {
        if (client->GetRecvThread() != nullptr) //stop anti-cheat monitor thread
        {
            client->GetRecvThread()->SignalShutdown(true);
            client->GetRecvThread()->JoinThread();
        }
    }
    else
    {
        Logger::logf(Err, "Couldn't fetch/lock netclient @  API::Cleanup");
        return Error::NULL_MEMORY_REFERENCE;
    }

    return Error::OK;
}

/**
 * @brief Terminates threads and cleans up resources, used for fast cleanup in case of critical errors or shutdowns
 *
 * @return Error::OK on success, otherwise an error code indicating the failure reason
 *
 * @usage
 * anticheat->pImpl->FastCleanup();
 */
Error AntiCheat::Impl::FastCleanup()
{
    if (Config != nullptr && Config->bUsingDriver)
    {
        if (!Services::UnloadDriver(Config->GetKMDriverName()))
        {
            Logger::logf(Warning, "Failed to unload kernelmode driver!");
        }
    }

    if (Config != nullptr && Config->bNetworkingEnabled)
    {
        auto client = GetNetworkClient().lock();

        if (client)
        {
            if (client->GetRecvThread() != nullptr) //stop anti-cheat monitor thread
            {
                client->EndConnection(0);
                TerminateThread(client->GetRecvThread()->GetHandle(), 0);
            }
        }
        else
        {
            Logger::logf(Warning, "Couldn't fetch/lock netclient @  AntiCheat::FastCleanup");
        }
    }

    if (Config != nullptr && Config->bUseAntiDebugging && GetAntiDebugger()->GetDetectionThread() != nullptr) //stop anti-debugger thread
    {
        TerminateThread(GetAntiDebugger()->GetDetectionThread()->GetHandle(), 0);
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetMonitorThread() != nullptr) //stop anti-cheat monitor thread
    {
        TerminateThread(GetMonitor()->GetMonitorThread()->GetHandle(), 0);
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetProcessCreationMonitorThread() != nullptr) //stop process creation monitor thread
    {
        TerminateThread(GetMonitor()->GetProcessCreationMonitorThread()->GetHandle(), 0);
    }

    if (GetMonitor() != nullptr && GetMonitor()->GetRegistryMonitorThread() != nullptr) //stop registry monitor
    {
        TerminateThread(GetMonitor()->GetRegistryMonitorThread()->GetHandle(), 0);
    }

    return Error::OK;
}

/**
 * @brief Performs checks to ensure security config on the system is appropriate based on program settings
 *
 * @return true if all checks pass, false otherwise
 *
 * @usage
 * bool safeToRun = anticheat->pImpl->DoPreInitializeChecks();
 */
bool AntiCheat::Impl::DoPreInitializeChecks()
{
    if (Config->bRequireRunAsAdministrator)
    {
        if (!Services::IsRunningAsAdmin()) //enforce secure boot to stop bootloader cheats
        {
            MessageBoxA(0, "Program must be running as administrator in order to proceed, or change `bRequireRunAsAdministrator` to false.", "UltimateAntiCheat", 0);
            Logger::logf(Detection, "Program must be running as administrator in order to proceed, or change `bRequireRunAsAdministrator` to false.");
            return false;
        }
    }

    if (Config->bEnforceSecureBoot)
    {
        if (!Services::IsSecureBootEnabled()) //enforce secure boot to stop bootloader cheats
        {
            MessageBoxA(0, "Secure boot is not enabled, you cannot proceed. Please enable secure boot in your BIOS or change `bEnforceSecureBoot` to false.", "UltimateAntiCheat", 0);
            Logger::logf(Detection, "Secure boot is not enabled, thus you cannot proceed. Please enable secure boot in your BIOS or change `bEnforceSecureBoot` to false.");
            return false;
        }
    }

    if (Config->bEnforceDSE)
    {
        if (Services::IsTestsigningEnabled()) //check test signing mode before startup
        {
            MessageBoxA(0, "Test signing was enabled, you cannot proceed. Please turn off test signing via `bcdedit.exe`, or change `bEnforceDSE` to false.", "UltimateAntiCheat", 0);
            Logger::logf(Detection, "Test signing was enabled, thus you cannot proceed. Please turn off test signing via `bcdedit.exe`, or change `bEnforceDSE` to false.");
            return false;
        }
    }

    if (Config->bCheckHypervisor)
    {
        if (Services::IsHypervisorPresent()) //we can either block all hypervisors to try and stop SLAT/EPT manipulation, or only allow certain vendors.
        {
            string vendor = Services::GetHypervisorVendor(); //...however, many custom hypervisors will likely spoof their vendorId to be 'HyperV' or 'VMWare' 

            if (vendor.size() == 0)
            {
                Logger::logf(Detection, "Hypervisor vendor was empty, some custom hypervisor may be hooking cpuid instruction");
            }
            else if (vendor == "Microsoft Hv" || vendor == "VMwareVMware" || vendor == "XenVMMXenVMM" || vendor == "VBoxVBoxVBox")
            {
                Logger::logf(Detection, "Hypervisor was present with vendor: %s", vendor.c_str());
            }
            else
            {
                Logger::logf(Detection, "Hypervisor was present with unknown/non-standard vendor: %s.", vendor.c_str());
            }

            return false;
        }
    }

    return true;
}

/**
 * @brief Checks if any core functionality threads are suspended, which may indicate abnormal program execution or tampering
 *
 * @return true any thread is suspended, false otherwise
 *
 * @usage
 * bool anyThreadSuspended = anticheat->pImpl->IsAnyThreadSuspended();
 */
bool AntiCheat::Impl::IsAnyThreadSuspended()
{
    if (Monitor != nullptr && Monitor->GetMonitorThread() != nullptr && Thread::IsThreadSuspended(Monitor->GetMonitorThread()->GetId()))
    {
        Logger::logf(Detection, "Monitor was found suspended! Abnormal program execution.");
        return true;
    }
    else if (Monitor != nullptr && Monitor->GetProcessCreationMonitorThread() != nullptr && Thread::IsThreadSuspended(Monitor->GetProcessCreationMonitorThread()->GetId()))
    {
        Logger::logf(Detection, "Monitor's process creation thread was found suspended! Abnormal program execution.");
        return true;
    }
    else if (Config->bUseAntiDebugging && AntiDebugger != nullptr && AntiDebugger->GetDetectionThread() != nullptr && Thread::IsThreadSuspended(AntiDebugger->GetDetectionThread()->GetId()))
    {
        Logger::logf(Detection, "Anti-debugger was found suspended! Abnormal program execution.");
        return true;
    }
    else if (NetworkClient != nullptr && NetworkClient->GetRecvThread() != nullptr && Thread::IsThreadSuspended(NetworkClient->GetRecvThread()->GetId()))
    {
        Logger::logf(Detection, "Netclient comms thread was found suspended! Abnormal program execution.");
        return true;
    }

    return false;
}

/**
 * @brief Checks parent process, initializes the networking components (if applicable)
 *
 * @param gameCode a unique code identifying the game or service being protected
 * @return Error::OK on success, otherwise an error describing the failure cause
 *
 * @usage
 * Error err = anticheat->pImpl->Initialize("GAMECODE-COOLGAME1");
 */
Error AntiCheat::Impl::Initialize(std::string gameCode)
{
    Error errorCode = Error::OK;
    bool isLicenseValid = false;

    std::list<wstring> allowedParents = GetConfig()->allowedParents;
    auto it = std::find_if(allowedParents.begin(), allowedParents.end(), [](const wstring& parentName)
    {
        return Process::CheckParentProcess(parentName, true);
    });

    if (it != allowedParents.end())
    {
        GetMonitor()->GetProcessObj()->SetParentName(*it);
    }
    else //bad parent process detected, or parent process mismatch, shut down the program (and optionally report the error to the server)
    {
        Logger::logfw(Detection, L"Parent process '%s' was not whitelisted, shutting down program!", Process::GetProcessName(Process::GetParentProcessId()).c_str());
        errorCode = Error::PARENT_PROCESS_MISMATCH;
    }

    if (Config->bNetworkingEnabled)
    {
        Logger::logf(Info, "Starting networking component...");

        auto client = GetNetworkClient().lock();

        if (client)
        {
            if (client->Initialize(Config->serverIP, Config->serverPort, gameCode) != Error::OK) //initialize client is separate from license key auth
            {
                errorCode = Error::CANT_STARTUP;		//don't allow AC startup if network portion doesn't succeed
                goto end;
            }
        }
        else
        {
            Logger::logf(Err, "Could not fetch/lock network client, exiting...");
            return Error::NULL_MEMORY_REFERENCE;
        }
    }
    else
    {
        Logger::logf(Info, "Networking is currently disabled, no heartbeats will occur");
    }

end:
    return errorCode;
}


/**
 * @brief Executes cheat prevention routines, along with starting the anti-cheat monitor and anti-debugger threads
 *
 * @return Error::OK on success, otherwise an error describing the failure cause
 *
 * @usage
 * Error err = anticheat->pImpl->LaunchDefenses();
 */
Error AntiCheat::Impl::LaunchDefenses()
{
    if (GetMonitor() == nullptr || GetAntiDebugger() == nullptr || GetBarrier() == nullptr)
        return Error::NULL_MEMORY_REFERENCE;

    Error errorCode = Error::OK;

    if (GetBarrier()->DeployBarrier() == Error::OK) //activate all techniques to stop cheaters
    {
        Logger::logf(Info, " Barrier techniques were applied successfully!");
    }
    else
    {
        Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
        errorCode = Error::CANT_APPLY_TECHNIQUE;
    }

    if (!GetMonitor()->StartMonitor()) //start looped detections
    {
        Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
        errorCode = Error::CANT_STARTUP;
    }

    GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

    //AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services -> currently not in use

    if (!Process::CheckParentProcess(GetMonitor()->GetProcessObj()->GetParentName(), true)) //parent process check, the parent process would normally be set using our API methods
    {
        Logger::logf(Detection, "Parent process was not in whitelist!");
        errorCode = Error::PARENT_PROCESS_MISMATCH;
    }

    return errorCode;
}