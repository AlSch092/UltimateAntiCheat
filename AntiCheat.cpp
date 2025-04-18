#include "AntiCheat.hpp"

AntiCheat::AntiCheat(__in Settings* config, __in const WindowsVersion WinVersion) : Config(config), WinVersion(WinVersion)
{
	if (config == nullptr)
	{
		throw AntiCheatInitFail(AntiCheatInitFailReason::NullSettings);
	}

	{   //call `DoPreInitializeChecks()` through VM as a concept proof 
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

	try
	{
		this->NetworkClient = make_shared<NetClient>();

		this->Evidence = new EvidenceLocker(this->NetworkClient.get()); //make shared evidence log (change this to shared_ptr later)

		this->AntiDebugger = make_unique<DebuggerDetections>(config, this->Evidence, NetworkClient); //any detection methods need the netclient for comms

		this->Monitor = make_unique<Detections>(config, this->Evidence, false, NetworkClient);

		this->Barrier = make_unique<Preventions>(config, true, Monitor.get()->GetIntegrityChecker()); //true = prevent new threads from being made
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

		if (driverCertSubject.size() == 0 || driverCertSubject != DriverSignerSubject) //check if driver cert has correct sign subject
		{
			throw AntiCheatInitFail(AntiCheatInitFailReason::DriverUnsigned);
		}

		if (!Services::LoadDriver(Config->GetKMDriverName().c_str(), absolutePath))
		{
			throw AntiCheatInitFail(AntiCheatInitFailReason::DriverLoadFail);
		}

		Logger::logfw(Info, L"Loaded driver: %s from path %s", Config->GetKMDriverName().c_str(), absolutePath);
	}

	if (API::Dispatch(this, API::DispatchCode::INITIALIZE) != Error::OK) //initialize AC , this will start all detections + preventions
	{
		throw AntiCheatInitFail(AntiCheatInitFailReason::DispatchFail);
	}
}

AntiCheat::~AntiCheat()
{
	if (Config != nullptr && Config->bUsingDriver) //unload the KM driver
	{
		if (!Services::UnloadDriver(Config->GetKMDriverName()))
		{
			Logger::logf(Warning, "Failed to unload kernelmode driver!");
		}
	}

	if (API::Dispatch(this, API::DispatchCode::CLIENT_EXIT) == Error::OK)
	{
		Logger::logf(Info, " Cleanup successful. Shutting down program");
	}
	else
	{
		Logger::logf(Warning, "Cleanup unsuccessful... Shutting down program");
	}
}


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


/*
	IsAnyThreadSuspended - Checks the looping threads of class members to ensure the program is running as normal. An attacker may try to suspend threads to either remap or disable functionalities
	returns true if any thread is found suspended
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