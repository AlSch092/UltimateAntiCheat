//By AlSch092 @ Github
#include "API.hpp"
#include "../AntiCheat.hpp"

/*
	Initialize - Initializes the anti-cheat module by connecting to the auth server (if available) and sending it the game's unique code, and checking the parent process to ensure a rogue launcher wasn't used
	returns Error::OK on success.
*/
Error API::Initialize(AntiCheat* AC, string licenseKey, bool isServerAvailable)
{
	Error errorCode = Error::OK;
	bool isLicenseValid = false;

	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	std::list<wstring> allowedParents = AC->GetConfig()->allowedParents;
	auto it = std::find_if(allowedParents.begin(), allowedParents.end(), [](const wstring& parentName) 
	{
		return Process::CheckParentProcess(parentName);
	});

	if (it != allowedParents.end()) 
	{
		AC->GetMonitor()->GetProcessObj()->SetParentName(*it);
	}
	else //bad parent process detected, or parent process mismatch, shut down the program (and optionally report the error to the server)
	{
		Logger::logfw(Detection, L"Parent process '%s' was not whitelisted, shutting down program!", Process::GetProcessName(Process::GetParentProcessId()).c_str());
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	if (isServerAvailable)
	{
		Logger::logf(Info, "Starting networking component...");

		auto client = AC->GetNetworkClient().lock();

		if (client)
		{
			if (client->Initialize(API::ServerEndpoint, API::ServerPort, licenseKey) != Error::OK) //initialize client is separate from license key auth
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
	Cleanup - signals thread shutdowns and deletes memory associated with the Anticheat* object `AC`
	returns Error::OK on success
*/
Error API::Cleanup(AntiCheat* AC)
{
	if (AC == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	if (AC->GetConfig()->bUseAntiDebugging && AC->GetAntiDebugger() != nullptr && AC->GetAntiDebugger()->GetDetectionThread() != nullptr) //stop anti-debugger thread
	{
		AC->GetAntiDebugger()->GetDetectionThread()->SignalShutdown(true);
		AC->GetAntiDebugger()->GetDetectionThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetMonitorThread() != nullptr) //stop anti-cheat monitor thread
	{
		AC->GetMonitor()->GetMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetMonitorThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetProcessCreationMonitorThread() != nullptr) //stop process creation monitor thread
	{
		AC->GetMonitor()->GetProcessCreationMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetProcessCreationMonitorThread()->JoinThread();
	}

	if (AC->GetMonitor() != nullptr && AC->GetMonitor()->GetRegistryMonitorThread() != nullptr) //stop registry monitor
	{
		AC->GetMonitor()->GetRegistryMonitorThread()->SignalShutdown(true);
		AC->GetMonitor()->GetRegistryMonitorThread()->JoinThread();
	}

	auto client = AC->GetNetworkClient().lock();

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

/*
	LaunchDefenses - Initialize detections, preventions, and ADbg techniques
	returns Error::OK on success
*/
Error API::LaunchDefenses(AntiCheat* AC) //currently in the process to split these tests into Detections or Preventions
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	Error errorCode = Error::OK;

	if (AC->GetBarrier()->DeployBarrier() == Error::OK) //activate all techniques to stop cheaters
	{
		Logger::logf(Info, " Barrier techniques were applied successfully!");
	}
	else
	{
		Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
		errorCode = Error::CANT_APPLY_TECHNIQUE;
	}

	if (!AC->GetMonitor()->StartMonitor()) //start looped detections
	{
		Logger::logf(Err, "Could not initialize the barrier @ API::LaunchBasicTests");
		errorCode = Error::CANT_STARTUP;
	}

	AC->GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

	AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services

	if (AC->GetMonitor()->GetServiceManager()->GetLoadedDrivers()) //enumerate drivers, will be re-added soon
	{
		list<wstring> unsigned_drivers = AC->GetMonitor()->GetServiceManager()->GetUnsignedDrivers(); //unsigned drivers, take further action if needed
	}

	if (!Process::CheckParentProcess(AC->GetMonitor()->GetProcessObj()->GetParentName())) //parent process check, the parent process would normally be set using our API methods
	{
		Logger::logf(Detection, "Parent process was not in whitelist! cheater detected!\n");
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	return errorCode;
}

/*
	Dispatch - handles sending requests through the AntiCheat class `AC`, mainly for initialization & cleanup
	returns Error::OK on successful execution
*/
Error API::Dispatch(AntiCheat* AC, DispatchCode code)
{
	Error errorCode = Error::OK;

	switch (code)
	{
		case INITIALIZE:
		{			
			errorCode = Initialize(AC, "GAMECODE-XyIlqRmRj", AC->GetConfig()->bNetworkingEnabled); //if explorer.exe isn't our parent process, shut 'er down!

			if (errorCode == Error::OK)
			{
				if (LaunchDefenses(AC) != Error::OK)
				{
					Logger::logf(Warning, " At least one technique experienced abnormal behavior when launching tests.");
					return Error::CANT_APPLY_TECHNIQUE;
				}
			}
			else
			{
				Logger::logf(Warning, "Couldn't start up, either the parent process was wrong or no auth server was present.");
				return Error::CANT_CONNECT;
			}
		}break;

		case CLIENT_EXIT:
		{
			Error err = Cleanup(AC); //clean up memory, shut down any threads

			if (err == Error::OK) 			
			{
				errorCode = Error::OK;
			}
			else
			{
				errorCode = Error::NULL_MEMORY_REFERENCE;
			}
		} break;

		default:
			Logger::logf(Warning, "Unrecognized dispatch code @ API::Dispatch: %d\n", code);
			break;
	};

	return errorCode;
}