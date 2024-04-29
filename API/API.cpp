#include "API.hpp"

Error API::Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerAvailable)
{
	Error errorCode = Error::OK;
	bool isLicenseValid = false;

	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	if (isServerAvailable) //for testing/teaching purposes, we can get rid of the need to a server as most GitHub users trying the project out won't have the server code
	{
		if (AC->GetNetworkClient()->Initialize(API::ServerEndpoint, API::ServerPort) != Error::OK) //initialize client is separate from license key auth
		{
			errorCode = Error::CANT_STARTUP;		//don't allow startup if networking doesn't work
			goto end;
		}
	}

	if (Process::CheckParentProcess(parentProcessName)) //check parent process, kick out if bad
	{
		AC->GetMonitor()->GetProcessObj()->SetParentName(parentProcessName);
		errorCode = Error::OK;
	}
	else //bad parent process detected, or parent process mismatch, shut down the program after reporting the error to the server
	{
		Logger::logf("UltimateAnticheat.log", Detection, "  Parent process was not whitelisted, shutting down program! Make sure parent process is the same as specified in API.hpp. If you are using VS to debug, this might become VsDebugConsole.exe, rather than explorer.exe");
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	//isLicenseValid = g_AC->GetNetworkClient()->CheckLicense();  	//TODO: check licenseKey against some centralized web server, possibly using HTTP requests. once we have verified our license, we can try to connect using Initialize(
end:	
	return errorCode;
}

Error API::SendHeartbeat(AntiCheat* AC) //todo: finish this!
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	return Error::OK;
}

Error API::Cleanup(AntiCheat* AC)
{
	if (AC == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	if (AC->GetAntiDebugger()->GetDetectionThread() != NULL) //stop anti-debugger monitor
	{
		Thread* t = AC->GetAntiDebugger()->GetDetectionThread();
		t->ShutdownSignalled = true;
		//WaitForSingleObject(t->handle, INFINITE);
		
		if (t->handle != INVALID_HANDLE_VALUE || t->handle == NULL)
		{
			TerminateThread(t->handle, 0); //todo: use thread signals instead of terminatethread
			delete t;
			AC->GetAntiDebugger()->SetDetectionThread(NULL);
		}
	}

	if (AC->GetMonitor()->GetMonitorThread() != NULL) //stop anti-cheat monitor
	{
		Thread* t = AC->GetMonitor()->GetMonitorThread();

		if (t->handle != INVALID_HANDLE_VALUE)
		{
			TerminateThread(t->handle, 0); //todo: use thread signals instead of terminatethread
			delete t;
			AC->GetMonitor()->SetMonitorThread(NULL);
		}
	}

	delete AC;
	return Error::OK;
}

Error API::LaunchBasicTests(AntiCheat* AC) //currently in the process to split these tests into Detections or Preventions
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(NULL);

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

	if (AC->GetMonitor()->GetServiceManager()->GetLoadedDrivers()) //enumerate drivers
	{
		list<wstring> unsigned_drivers = AC->GetMonitor()->GetServiceManager()->GetUnsignedDrivers(); //unsigned drivers, take further action if needed
	}

	//AC->TestNetworkHeartbeat(); //tests executing a payload within server-fed data

	if (!Process::CheckParentProcess(AC->GetMonitor()->GetProcessObj()->GetParentName())) //parent process check, the parent process would normally be set using our API methods
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Parent process was not % s! cheater detected!\n", API::whitelistedParentProcess);
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	return errorCode;
}

//meant to be called by process hosting the anti-cheat module - interface between AC and game
Error __declspec(dllexport) API::Dispatch(AntiCheat* AC, DispatchCode code)
{
	Error errorCode = Error::OK;

	switch (code)
	{
		case INITIALIZE:
		{
			errorCode = Initialize(AC, "LICENSE-ABC123", whitelistedParentProcess, false); //if explorer.exe isn't our parent process, shut 'er down!

			if (errorCode == Error::OK)
			{
				isPostInitialization = true;

				if (LaunchBasicTests(AC) != Error::OK)
				{
					Logger::logf("UltimateAnticheat.log", Warning, " At least one technique experienced abnormal behavior when launching tests.");
					return Error::CANT_APPLY_TECHNIQUE;
				}
			}
			else
			{
				Logger::logf("UltimateAnticheat.log", Warning, "Couldn't start up, make sure server is running and re-try.");
				return Error::CANT_CONNECT;
			}
		}		break;

		case HEARTBEAT:
		{
			errorCode = SendHeartbeat(AC);
		}	break;

		case CLIENT_EXIT:
		{
			Error err = Cleanup(AC); //clean up memory, shut down any threads

			if (err == Error::OK) 			
			{
				Logger::logf("UltimateAnticheat.log", Info, " Cleanup successful. Shutting down program");
				errorCode = Error::OK;
			}
			else
			{
				Logger::logf("UltimateAnticheat.log", Err, "Cleanup unsuccessful. Shutting down program");
				errorCode = Error::NULL_MEMORY_REFERENCE;
			}
		} break;

		default:
			Logger::logf("UltimateAnticheat.log", Warning, "Unrecognized dispatch code @ API::Dispatch: %d\n", code);
			break;
	};

	return errorCode;
}