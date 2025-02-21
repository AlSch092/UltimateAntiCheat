//By AlSch092 @ Github
#pragma once
#include "../Common/Logger.hpp"
#include "../AntiTamper/NAuthenticode.hpp"
#include "../Common/Utility.hpp"
#include "../Network/HttpClient.hpp"
#include <Psapi.h>
#include <TlHelp32.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <intrin.h>
#include <sstream>

#pragma comment(lib, "setupapi.lib")

using namespace std;

extern "C" NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW * lpVersionInformation); //used in GetWindowsVersion

struct Service
{
	wstring displayName;
	wstring serviceName;
	DWORD pid;
	bool isRunning;
};

struct Device
{
	string InstanceID;
	string Description;
};

struct DeviceW
{
	wstring InstanceID;
	wstring Description;
};

enum WindowsVersion
{									//Major,Minor :
	Windows2000 = 50,				//5,0
	WindowsXP = 51,			    //5,1
	WindowsXPProfessionalx64 = 52,	//5,2
	WindowsVista = 60,				//6,0
	Windows7 = 61,					//6,1
	Windows8 = 62,					//6,2
	Windows8_1 = 63,				//6,3
	Windows10 = 10,					//10
	Windows11 = 11,					//10  -> build number changes 

	ErrorUnknown = 0
};

/*
The Services class deals with keeping track of loaded drivers & services/recurring tasks on the system, along with misc helpful windows functions such as DSE checks, secure boot, device enumeration, etc
*/
class Services final
{
public:

	Services(__in const bool Initialize)
	{
		if (Initialize)
		{
			HardwareDevices = GetHardwareDevicesW(); //fetch PCI devices
			GetLoadedDrivers();
			GetServiceModules();

			//these 3 drivers are unsigned, and have no file on disk but cant still run in memory while secure boot & DSE is on - crash-dump related drivers windows uses
			WhitelistedUnsignedDrivers.emplace_back(L"\\SystemRoot\\System32\\Drivers\\dump_diskdump.sys");
			WhitelistedUnsignedDrivers.emplace_back(L"\\SystemRoot\\System32\\Drivers\\dump_storahci.sys");
			WhitelistedUnsignedDrivers.emplace_back(L"\\SystemRoot\\System32\\Drivers\\dump_dumpfve.sys");

			FetchBlacklistedDrivers(BlacklistedDriversRepository);
		}
	}

	~Services()
	{
		for (auto it = ServiceList.begin(); it != ServiceList.end(); ++it) 
			if(*it != nullptr)
				delete* it;
		
		ServiceList.clear();
	}

	Services operator+(Services& other) = delete; //delete all arithmetic operators, unnecessary for context
	Services operator-(Services& other) = delete;
	Services operator*(Services& other) = delete;
	Services operator/(Services& other) = delete;

	BOOL GetLoadedDrivers(); //adds to `DriverPaths`
	BOOL GetServiceModules(); //adds to `ServiceList`

	list<wstring> GetUnsignedDrivers();

	static BOOL IsTestsigningEnabled();
	static BOOL IsDebugModeEnabled();
	
	static BOOL IsSecureBootEnabled();
	static BOOL IsSecureBootEnabled_RegKey(); //check by reg key

	static string GetWindowsDrive();
	static wstring GetWindowsDriveW();

	static BOOL IsRunningAsAdmin();

	static list<DeviceW> GetHardwareDevicesW();
	static BOOL CheckUSBDevices();

	static WindowsVersion GetWindowsVersion();
	
	static bool IsHypervisorPresent();
	static string GetHypervisorVendor();
	static string GetCPUVendor();

	static bool LoadDriver(__in const std::wstring& driverName, __in const std::wstring& driverPath);
	static bool UnloadDriver(__in const std::wstring& driverName); 
	
	static string GetProcessDirectory(__in const DWORD pid);
	static wstring GetProcessDirectoryW(__in const DWORD pid);

	static list<DWORD> EnumerateProcesses();

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths;

	list<DeviceW> HardwareDevices;

	list<wstring> BlacklistedDrivers; //vulnerable driver list (BYOVD concept) which allow an attacker to read/write mem while having test signing or secure boot enabled 
	list<wstring> FoundBlacklistedDrivers; //any drivers which are loaded and blacklisted

	list<wstring> WhitelistedUnsignedDrivers; // dump_diskdump.sys, dump_storahci.sys, dump_dumpfve.sys

	bool FetchBlacklistedDrivers(__in const char* url);
	const char* BlacklistedDriversRepository = "https://raw.githubusercontent.com/AlSch092/UltimateAntiCheat/refs/heads/main/MiscFiles/BlacklistedDriverList.txt"; 
};