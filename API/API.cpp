//By AlSch092 @ Github
#include "API.hpp"

/*
	Initialize - Initializes the anti-cheat module by connecting to the auth server (if available) and sending it the game's unique code, and checking the parent process to ensure a rogue launcher wasn't used
	returns Error::OK on success.
*/
Error API::Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerAvailable)
{
	Error errorCode = Error::OK;
	bool isLicenseValid = false;

	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	if (Process::CheckParentProcess(parentProcessName)) //check parent process before startup, kick out if bad
	{
		AC->GetMonitor()->GetProcessObj()->SetParentName(parentProcessName);
	}
	else //bad parent process detected, or parent process mismatch, shut down the program (and optionally report the error to the server)
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Parent process was not whitelisted, shutting down program! Make sure parent process is the same as specified in API.hpp. If you are using VS to debug, this might become VsDebugConsole.exe, rather than explorer.exe");
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	if (isServerAvailable)
	{
		Logger::logf("UltimateAnticheat.log", Info, "Starting networking component...");

		if (AC->GetNetworkClient()->Initialize(API::ServerEndpoint, API::ServerPort, licenseKey) != Error::OK) //initialize client is separate from license key auth
		{
			errorCode = Error::CANT_STARTUP;		//don't allow AC startup if network portion doesn't succeed
			goto end;
		}
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Info, "Networking is currently disabled, no heartbeats will occur");
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

	if (AC->GetAntiDebugger()->GetDetectionThread() != NULL) //stop anti-debugger thread
	{
		AC->GetAntiDebugger()->GetDetectionThread()->ShutdownSignalled = true;
		WaitForSingleObject(AC->GetAntiDebugger()->GetDetectionThreadHandle(), 3000); //this thread normally sleeps for 2000ms each loop, so we wait 3000ms for good measures
	}

	if (AC->GetMonitor()->GetMonitorThread() != NULL) //stop anti-cheat monitor thread
	{
		AC->GetMonitor()->GetMonitorThread()->ShutdownSignalled = true;
		WaitForSingleObject(AC->GetMonitor()->GetMonitorThread()->handle, 6000); //this thread normally sleeps for 5000ms each loop, so we wait 6000ms for good measures
	}

	if (AC->GetNetworkClient()->GetRecvThread() != NULL) //stop anti-cheat monitor thread
	{
		AC->GetNetworkClient()->GetRecvThread()->ShutdownSignalled = true;
		WaitForSingleObject(AC->GetNetworkClient()->GetRecvThread()->handle, 5000); //this thread normally sleeps for 5000ms each loop, so we wait 6000ms for good measures
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
		Logger::logf("UltimateAnticheat.log", Info, " Barrier techniques were applied successfully!");
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Err, "Could not initialize the barrier @ API::LaunchBasicTests");
		errorCode = Error::GENERIC_FAIL;
	}

	AC->GetMonitor()->StartMonitor();
	AC->GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

	AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services

	//if (AC->GetMonitor()->GetServiceManager()->GetLoadedDrivers()) //enumerate drivers
	//{
	//	list<wstring> unsigned_drivers = AC->GetMonitor()->GetServiceManager()->GetUnsignedDrivers(); //unsigned drivers, take further action if needed
	//}

	if (!Process::CheckParentProcess(AC->GetMonitor()->GetProcessObj()->GetParentName())) //parent process check, the parent process would normally be set using our API methods
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Parent process was not % s! cheater detected!\n", API::whitelistedParentProcess);
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	return errorCode;
}

/*
	Dispatch - handles sending requests through the AntiCheat class `AC`, mainly for initialization & cleanup
	returns Error::OK on successful execution
*/
Error __declspec(dllexport) API::Dispatch(AntiCheat* AC, DispatchCode code)
{
	Error errorCode = Error::OK;

	switch (code)
	{
		case INITIALIZE:
		{			
			errorCode = Initialize(AC, "GAMECODE-XyIlqRmRj", whitelistedParentProcess, serverAvailable); //if explorer.exe isn't our parent process, shut 'er down!

			if (errorCode == Error::OK)
			{
				if (LaunchDefenses(AC) != Error::OK)
				{
					Logger::logf("UltimateAnticheat.log", Warning, " At least one technique experienced abnormal behavior when launching tests.");
					return Error::CANT_APPLY_TECHNIQUE;
				}
			}
			else
			{
				Logger::logf("UltimateAnticheat.log", Warning, "Couldn't start up, either the parent process was wrong or no auth server was present.");
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
			Logger::logf("UltimateAnticheat.log", Warning, "Unrecognized dispatch code @ API::Dispatch: %d\n", code);
			break;
	};

	return errorCode;
}