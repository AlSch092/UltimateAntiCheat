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
		}
	}

	if (Process::CheckParentProcess(parentProcessName)) //check parent process, kick out if bad
	{
		AC->GetBarrier()->GetProcessObject()->SetParentName(parentProcessName);
		errorCode = Error::OK;
	}
	else //bad parent process detected, or parent process mismatch, shut down the program after reporting the error to the server
	{
		printf("Parent process was not whitelisted, shutting down program! Make sure parent process is the same as specified in API.hpp. If you are using VS to debug, this might become VsDebugConsole.exe, rather than explorer.exe\n");
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	//isLicenseValid = g_AC->GetNetworkClient()->CheckLicense();  	//TODO: check licenseKey against some centralized web server, possibly using HTTP requests. once we have verified our license, we can try to connect using Initialize(
		
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
		TerminateThread(AC->GetAntiDebugger()->GetDetectionThread(), 0);
		AC->GetAntiDebugger()->SetDetectionThread(NULL);
	}

	if (AC->GetMonitor()->GetMonitorThread() != NULL) //stop generic monitor
	{
		TerminateThread(AC->GetMonitor()->GetMonitorThread(), 0);
		AC->GetMonitor()->SetMonitorThread(NULL);
	}

	delete AC;
	return Error::OK;
}

Error API::LaunchBasicTests(AntiCheat* AC) //soon we'll split these tests into their own categories or routines, and add looping to any tests that need periodic checks such a debugger checks
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(NULL);

	Error errorCode = Error::OK;

	printf("[INFO] Starting API::LaunchBasicTests\n");

	AC->GetMonitor()->StartMonitor();

	AC->GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

	AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services

	if (AC->GetMonitor()->GetServiceManager()->GetLoadedDrivers()) //enumerate drivers
	{
		printf("Driver enumeration complete!\n");
		list<wstring> unsigned_drivers = AC->GetMonitor()->GetServiceManager()->GetUnsignedDrivers(); //unsigned drivers, take further action if needed
	}

	if (Integrity::IsUnknownDllPresent()) //authenticode winapis
	{
		printf("Found unsigned dll loaded: We ideally only want verified, signed dlls in our application (which is still subject to spoofing)!\n");		
		errorCode = Error::BAD_MODULE;
	}

	AC->TestNetworkHeartbeat(); //tests executing a payload within server-fed data

	if (!AC->GetBarrier()->GetProcessObject()->GetProgramSections("UltimateAnticheat.exe")) //we can stop a routine like this from working if we patch NumberOfSections to 0
	{
		printf("Failed to parse program sections?\n");
		errorCode = Error::NULL_MEMORY_REFERENCE;
	}

	if (!Process::CheckParentProcess(AC->GetBarrier()->GetProcessObject()->GetParentName())) //parent process check, the parent process would normally be set using our API methods
	{
		wprintf(L"Parent process was not %s! hekker detected!\n", API::whitelistedParentProcess); //sometimes people will launch a game from their own process, which we can easily detect if they haven't spoofed it
		errorCode = Error::PARENT_PROCESS_MISMATCH;
	}

	//SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //shows how we can call CreateThread without directly calling winapi, we call our pointer instead which then invokes createthread

	if (AC->GetBarrier()->DeployBarrier() == Error::OK) //remapping method
	{
		printf("[INFO] Barrier techniques were applied successfully!\n");
	}
	else
	{
		printf("[ERROR] Could not initialize the barrier.\n");
		errorCode = Error::GENERIC_FAIL;
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
					printf("At least one technique experienced abnormal behavior when launching tests!\n");
				}
			}
			else
			{
				printf("Couldn't start up, make sure server is running and re-try\n");
				return Error::CANT_CONNECT;
			}
		}		break;

		case HEARTBEAT:
		{
			errorCode = SendHeartbeat(AC);
		}	break;

		case CLIENT_EXIT:
		{
			Error err = Cleanup(AC);

			if (err == Error::OK) 			//clean up memory, shut down any threads
			{
				printf("[INFO] Cleanup successful. Shutting down program.\n");
				errorCode = Error::OK;
			}
			else
			{
				printf("[ERROR] Cleanup unsuccessful. Shutting down program.\n");
				errorCode = Error::NULL_MEMORY_REFERENCE;
			}
		} break;

		default:
			printf("[WARNING] Unrecognized dispatch code @ API::Dispatch: %d\n", code);
			break;
	};

	return errorCode;
}