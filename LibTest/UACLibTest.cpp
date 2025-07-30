// UACLibTest.cpp : Test program for checking .lib build of ultimateanticheat

#define _CRT_SECURE_NO_WARNINGS
#include "..\\Core\\AntiCheatLib.hpp"

#pragma comment(lib, "../x64/LibRelease/UltimateAnticheat.lib")

int main()
{
	bool isCI = (std::getenv("GITHUB_ACTIONS") != nullptr);

	std::list<std::wstring> validParents = { L"explorer.exe", L"powershell.exe", L"cmd.exe", L"pwsh.exe", L"VsDebugConsole.exe" };

	std::unique_ptr<Settings> settings = nullptr;
	std::unique_ptr<AntiCheat> anticheat = nullptr;

	const bool bNetworkingEnabled = false;
	const bool bEnforceSecureBoot = false;
	const bool bEnforceDSE = true;
	const bool bEnforceNoKDBG = true;
	const bool bUseAntiDebugging = true;
	const bool bUseIntegrityChecking = true;
	const bool bCheckThreadIntegrity = true;
	const bool bCheckHypervisor = false;
	bool bRequireRunAsAdministrator = true;
	const bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
	std::wstring DriverCertSubject = L"YourGameCompany";

	if (bUsingDriver)
		DriverCertSubject = L"";

	const bool bEnableLogging = true;
	const std::string logFIleName = "UltimateAnticheatLib.log";

	if (isCI)
		bRequireRunAsAdministrator = false; //don't require admin on CI, since it runs in a container

	try
	{
		if (isCI) //github actions runner will hang/run forever, forced to turn off most features since it runs in a VM
		{
			std::cout << "[CI MODE] Disabling admin check, anti-debugging, hypervisor checks" << std::endl;

			settings = std::make_unique<Settings>(
				"127.0.0.1", 5445, false, // no networking
				false, false, false,      // disable secure boot, DSE, KDBG
				false, false, false,      // disable anti-debugging/integrity checks
				false,                    // disable hypervisor
				false, false, L"",        // no admin, no driver
				validParents,
				false, "");                 // disable logging
		}
		else
		{
			settings = std::make_unique<Settings>("127.0.0.1", 5445, bNetworkingEnabled,
				bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor,
				bRequireRunAsAdministrator, bUsingDriver, DriverCertSubject, validParents, bEnableLogging, logFIleName);
		}

		anticheat = std::make_unique<AntiCheat>(settings.get());
	}
	catch (const std::bad_alloc& e)
	{
		std::cerr << "Exception caught: " << e.what() << std::endl;
		return 1;
	}

	//Since this file is being used with Github actions, remove any infinite loops and explicitly destroy object 
	anticheat->Destroy();

	return 0;
}

