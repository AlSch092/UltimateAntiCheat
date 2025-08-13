#include "AntiCheat.hpp"

#ifndef _LIB_ 

/*
 * @brief Constructs an AntiCheat object with the provided settings
 *
 * @param config Pointer to the settings object containing configuration for the anti-cheat system
 *
 * @return Anticheat class object
 *
 * @usage
 * AntiCheat* antiCheat = new AntiCheat(config);
 */ 
AntiCheat::AntiCheat(__in Settings* config) : Config(config)
{
	if (config == nullptr)
	{
		throw AntiCheatInitFail(AntiCheatInitFailReason::NullSettings);
	}

	this->WinVersion = Services::GetWindowsVersion();

	{
		bool usingVirtualMachine = false;

		if (usingVirtualMachine)
		{
			//call `DoPreInitializeChecks()` through VM as a concept proof 
			std::unique_ptr<VirtualMachine> VM = std::make_unique<VirtualMachine>(128);
	
			bool (AntiCheat::*callAddr)() = &AntiCheat::DoPreInitializeChecks; //check various things such as secure boot, DSE, kdebugging, if they are enabled in settings
			_UINT address = (_UINT)&callAddr; //get address to non-static function
	
	#ifdef USING_OBFUSCATE
			_UINT bytecode[]
			{
				(_UINT)VM_Opcode::VM_PUSH OBFUSCATE, (_UINT)(this) OBFUSCATE,
				(_UINT)VM_Opcode::VM_CALL OBFUSCATE, 1 OBFUSCATE, *(_UINT*)address OBFUSCATE, //1 parameter (this ptr since DoPreInitializeChecks() has an implicit class pointer passed into RCX )
				(_UINT)VM_Opcode::VM_END_FUNC OBFUSCATE
			};
	#else
			_UINT bytecode[] 
			{
				(_UINT)VM_Opcode::VM_PUSH, (_UINT)(this),
				(_UINT)VM_Opcode::VM_CALL, 1, *(_UINT*)address, //1 parameter (this ptr)
				(_UINT)VM_Opcode::VM_END_FUNC
			};
	#endif
			if (!VM->Execute<bool>(bytecode, sizeof(bytecode) / sizeof(_UINT)))  //execute bytecode in VM
			{
				Logger::logfw(Err, L"One or more pre-initialize checks did not pass @ AntiCheat::AntiCheat.");
				throw AntiCheatInitFail(AntiCheatInitFailReason::PreInitializeChecksDidNotPass);
			}
		}
		else
		{
			if (!DoPreInitializeChecks())
			{
				Logger::logfw(Err, L"Pre-initialize checks did not pass @ AntiCheat::AntiCheat.");
				throw AntiCheatInitFail(AntiCheatInitFailReason::PreInitializeChecksDidNotPass);
			}
		}
	}

	Preventions::StopAPCInjection(); //patch over ntdll.dll Ordinal8 unnamed function: we do this here or else integrity checker will show as nttdll.dll being modified

	try
	{
		this->NetworkClient = make_shared<NetClient>();

		this->Evidence = new EvidenceLocker(this->NetworkClient.get()); //make shared evidence log (change this to shared_ptr later)

		this->AntiDebugger = make_unique<DebuggerDetections>(config, this->Evidence); //any detection methods need the netclient for comms

		this->Monitor = make_unique<Detections>(config, this->Evidence, NetworkClient);

		this->Barrier = make_unique<Preventions>(config, true); //true = prevent new threads from being made
	}
	catch (const std::bad_alloc& _)
	{
		throw AntiCheatInitFail(AntiCheatInitFailReason::BadAlloc);
	}

	if (config->bUsingDriver) //register + load the driver if it's correctly signed, unload it when the program is exiting
	{
		wchar_t absolutePath[MAX_PATH] = { 0 };

		if (!GetFullPathName(Config->GetKMDriverPath().c_str(), MAX_PATH, absolutePath, nullptr))
		{
			throw AntiCheatInitFail(AntiCheatInitFailReason::DriverNotFound);
		}

		//additionally, we need to check the signature on our driver to make sure someone isn't spoofing it. this will be added soon after initial testing is done
		wstring driverCertSubject = Authenticode::GetSignerFromFile(absolutePath);

		if (driverCertSubject.size() == 0 || driverCertSubject != GetConfig()->DriverSignerSubject) //check if driver cert has correct sign subject
		{
			throw AntiCheatInitFail(AntiCheatInitFailReason::DriverUnsigned);
		}

		if (!Services::LoadDriver(Config->GetKMDriverName().c_str(), absolutePath)) //Remove this call, along with Services::LoadDriver and Services::UnloadDriver
		{
			throw AntiCheatInitFail(AntiCheatInitFailReason::DriverLoadFail);
		}

		Logger::logfw(Info, L"Loaded driver: %s from path %s", Config->GetKMDriverName().c_str(), absolutePath);
	}

	if (Initialize("GAMECODE-COOLGAME1", GetConfig()->bNetworkingEnabled) != Error::OK) //initialize AC , this will start all detections + preventions
	{
		throw AntiCheatInitFail(AntiCheatInitFailReason::DispatchFail);
	}

	if (LaunchDefenses() != Error::OK) //start all the threads and defenses
	{
		Logger::logf(Err, "Failed to launch defenses @ AntiCheat::AntiCheat(). Shutting down.");
		throw AntiCheatInitFail(AntiCheatInitFailReason::StartupFailed);
	}
}

/**
 * @brief Cleans up resources and deletes the current AntiCheat instance
 *
 * @return void
 *
 * @usage
 * anticheat->Destroy();
 */
AntiCheat::~AntiCheat()
{
	if (Config != nullptr && Config->bUsingDriver) //unload the KM driver
	{
		if (!Services::UnloadDriver(Config->GetKMDriverName()))
		{
			Logger::logf(Warning, "Failed to unload kernelmode driver!");
		}
	}

	if (Cleanup() == Error::OK)
	{
		Logger::logf(Info, " Cleanup successful. Shutting down program");
	}
	else
	{
		Logger::logf(Warning, "Cleanup unsuccessful... Shutting down program");
	}
}

/**
 * @brief Cleans up resources and stops all threads started by the AntiCheat class
 *
 * @return Error::OK on success, otherwise an error code indicating the failure reason
 *
 * @usage
 *
*/
Error AntiCheat::Cleanup()
{
	if ((GetConfig() != nullptr && GetConfig()->bUseAntiDebugging) 
		&& (GetAntiDebugger() != nullptr && GetAntiDebugger()->GetDetectionThread() != nullptr)) //stop anti-debugger thread
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
		Logger::logf(Err, "Couldn't fetch/lock netclient @  AntiCheat::Cleanup");
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
 * anticheat->FastCleanup();
*/
Error AntiCheat::FastCleanup()
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

	if (GetConfig()->bUseAntiDebugging && GetAntiDebugger() != nullptr && GetAntiDebugger()->GetDetectionThread() != nullptr) //stop anti-debugger thread
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

/* *
 * @brief Performs pre-initialization checks to ensure the environment is secure and meets the requirements for running the anti-cheat system
 *
 * @return true if all checks pass, false otherwise
 *
 * @usage
 * if (!anticheat->DoPreInitializeChecks())
 * {
 *     // Handle failure case
 * }
*/
bool AntiCheat::DoPreInitializeChecks()
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


/* *
 * @brief Checks if any of the critical threads in the anti-cheat system are suspended, indicating potential tampering or abnormal execution
 *
 * @return true if any thread is suspended, false otherwise
 *
 * @usage
 * if (anticheat->IsAnyThreadSuspended())
 * {
 *     // Handle abnormal execution case
 * }
*/
bool AntiCheat::IsAnyThreadSuspended()
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

/* *
	@brief Initializes the anti-cheat system with the provided license key and checks for server availability
	@param licenseKey The license key to authenticate the anti-cheat system
	@param isServerAvailable Flag indicating if the server is available for communication
	@return Error::OK on success, otherwise an error code indicating the failure reason
	@usage
	Error err = anticheat->Initialize("YOUR_LICENSE_KEY", true);
*/
Error AntiCheat::Initialize(std::string licenseKey, bool isServerAvailable)
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

	if (isServerAvailable)
	{
		Logger::logf(Info, "Starting networking component...");

		auto client = GetNetworkClient().lock();

		if (client)
		{
			if (client->Initialize(Config->serverIP, Config->serverPort, licenseKey) != Error::OK) //initialize client is separate from license key auth
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

/*
 * @brief Launches the anti-cheat defenses, including starting the monitor and anti-debugger threads, and applying prevention techniques
 *
 * @return Error::OK on success, otherwise an error code indicating the failure reason
 *
 * @usage
 * Error err = anticheat->LaunchDefenses();
 */
Error AntiCheat::LaunchDefenses()
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

#endif //_LIB_