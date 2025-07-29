// UACLibTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define _CRT_SECURE_NO_WARNINGS
#include "..\\Core\\AntiCheatLib.hpp"

#pragma comment(lib, "../x64/LibRelease/UltimateAnticheat.lib")

int main()
{
	std::list<std::wstring> validParents = { L"explorer.exe", L"powershell.exe", L"cmd.exe", L"VsDebugConsole.exe" };
	
    std::unique_ptr<Settings> settings = nullptr;
    std::unique_ptr<AntiCheat> anticheat = nullptr;

    const bool bNetworkingEnabled = false; //change this to false if you don't want to use the server
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

    const bool bEnableLogging = true;
    const std::string logFIleName = "UltimateAnticheatLib.log";

    try
    {
        settings = std::make_unique<Settings>("127.0.0.1", 5445, bNetworkingEnabled, 
            bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor, 
            bRequireRunAsAdministrator, bUsingDriver, DriverCertSubject, validParents, bEnableLogging, logFIleName);
       
        anticheat = std::make_unique<AntiCheat>(settings.get());
    }
	catch (const std::bad_alloc& e)
	{
		std::cerr << "Exception caught: " << e.what() << std::endl;
		return 1; // Exit with error code -> test failed
	}
   
    cout << "\n----------------------------------------------------------------------------------------------------------" << endl;
    cout << "All protections have been deployed, the program will now loop using its detection methods" << endl;
    cout << "Please enter 'q' if you'd like to end the program." << endl;

    std::string userKeyboardInput;

    while (true)
    {
        cin >> userKeyboardInput;

        if (userKeyboardInput == "q" || userKeyboardInput == "Q")
        {
            cout << "Exit key was pressed, shutting down program..." << endl;
            break;
        }
    }

	return 0;
}

