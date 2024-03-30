#include "API.hpp"

int API::Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerAvailable)
{
	int errorCode = Error::OK;
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

int API::SendHeartbeat(AntiCheat* AC) //todo: finish this!
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	return Error::OK;
}

int API::LaunchBasicTests(AntiCheat* AC) //soon we'll split these tests into their own categories or routines, and add looping to any tests that need periodic checks such a debugger checks
{
	if (AC == NULL)
		return Error::NULL_MEMORY_REFERENCE;

	int errorCode = Error::OK;

	AC->GetAntiDebugger()->StartAntiDebugThread(); //start debugger checks in a seperate thread

	AC->GetMonitor()->GetServiceManager()->GetServiceModules(); //enumerate services

	if (AC->GetMonitor()->GetServiceManager()->GetLoadedDrivers()) //enumerate drivers
	{
		printf("Driver enumeration complete!\n");
		list<wstring> unsigned_drivers = AC->GetMonitor()->GetServiceManager()->GetUnsignedDrivers(); //unsigned drivers, take further action if needed
	}

	//BYTE* newPEBBytes = CopyAndSetPEB();

	//if (newPEBBytes == NULL)
	//{
	//	printf("Failed to copy PEB!\n");
	//	exit(0);
	//}

	//_MYPEB* ourPEB = (_MYPEB*)&newPEBBytes[0];
	//printf("Being debugged (PEB Spoofing test): %d. Address of new PEB : %llx\n", ourPEB->BeingDebugged, (UINT64) &newPEBBytes[0]);

	ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(NULL);

	if (Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryA", "ANTI-INJECT1") &&   ///prevents DLL injection from any method relying on calling LoadLibrary in the host process.
		Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryW", "ANTI-INJECT2") &&
		Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExA", "ANTI-INJECT3") &&
		Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExW", "ANTI-INJECT4"))
		printf("Wrote over LoadLibrary export names successfully!\n");

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

	AC->TestMemoryIntegrity(); //check program headers + peb to make sure nothing was tampered

	//SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //shows how we can call CreateThread without directly calling winapi, we call our pointer instead which then invokes createthread

	std::wstring newModuleName = L"new_name";

	if (Process::ChangeModuleName((wchar_t*)L"UltimateAnticheat.exe", (wchar_t*)newModuleName.c_str())) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
	{
		wprintf(L"Changed module name to %s!\n", newModuleName.c_str());
	}

	//if (AntiCheat::IsVTableHijacked((void*)AC)) //this routine needs to be re-written and checked, stay tuned for the next update
	//{
	//	printf("VTable of Anticheat has been compromised/hooked.\n");
	//}

	if (!AC->GetBarrier()->GetProcessObject()->ProtectProcess()) //todo: find way to stop process attaching or OpenProcess succeeding
	{
		printf("Could not protect process.\n");
	}

	Preventions::RemapAndCheckPages(); //remapping method

	return errorCode;
}

//meant to be called by process hosting the anti-cheat module - interface between AC and game
int __declspec(dllexport) API::Dispatch(AntiCheat* AC, DispatchCode code)
{
	int errorCode = 0;

	switch (code)
	{
		case INITIALIZE:

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
		break;

		case HEARTBEAT:
			errorCode = SendHeartbeat(AC);
			break;

		default:
			printf("[INFO] Unrecognized dispatch code @ API::Dispatch: %d\n", code);
			break;
	};

	return errorCode;
}