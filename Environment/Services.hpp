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

extern "C" NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW * lpVersionInformation); //used in GetWindowsVersion

struct Service
{
	std::wstring displayName;
	std::wstring serviceName;
	DWORD pid;
	bool isRunning;
};

struct Device
{
	std::string InstanceID;
	std::string Description;
};

struct DeviceW
{
	std::wstring InstanceID;
	std::wstring Description;
};

enum WindowsVersion
{									//Major,Minor :
	Windows2000 = 50,				//5,0
	WindowsXP = 51,			                //5,1
	WindowsXPProfessionalx64 = 52,	                //5,2
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

	Services()
	{

		HardwareDevices = GetHardwareDevicesW(); //fetch PCI devices
		GetLoadedDrivers();
		GetServiceModules();

		//these 3 drivers are unsigned, and have no file on disk but cant still run in memory while secure boot & DSE is on - crash-dump related drivers windows uses
		WhitelistedUnsignedDrivers.emplace_back(std::wstring(L"\\SystemRoot\\System32\\Drivers\\dump_diskdump.sys"));
		WhitelistedUnsignedDrivers.emplace_back(std::wstring(L"\\SystemRoot\\System32\\Drivers\\dump_storahci.sys"));
		WhitelistedUnsignedDrivers.emplace_back(std::wstring(L"\\SystemRoot\\System32\\Drivers\\dump_dumpfve.sys"));

		FetchBlacklistedDrivers(BlacklistedDriversRepository);		
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

	std::list<std::wstring> GetUnsignedDrivers();
	std::list<std::wstring> GetUnsignedDrivers(__in std::list<std::wstring>& cachedVerifiedDriverList);

	static BOOL IsTestsigningEnabled();
	static BOOL IsDebugModeEnabled();
	static BOOL IsSecureBootEnabled();

	static std::string GetWindowsDrive();
	static std::wstring GetWindowsDriveW();

	static BOOL IsRunningAsAdmin();

	static std::list<DeviceW> GetHardwareDevicesW();
	static BOOL CheckUSBDevices();

	static WindowsVersion GetWindowsVersion();
	
	static bool IsHypervisorPresent();
	static std::string GetHypervisorVendor();
	static std::string GetCPUVendor();
	
	static std::string GetProcessDirectory(__in const DWORD pid); //fetch the directory of `pid`
	static std::wstring GetProcessDirectoryW(__in const DWORD pid); //fetch the directory of `pid`

	static std::list<DWORD> EnumerateProcesses(); //fetch process list

	static bool LoadDriver(__in const std::wstring& serviceName, __in const std::wstring& driverPath); //load `driverPath` with service name `driverName`
	static bool UnloadDriver(__in const std::wstring& serviceName);
	static bool IsDriverRunning(__in const std::wstring& serviceName); //check if a driver is loaded & in a running state

private:

	std::list<Service*> ServiceList;

	std::list <std::wstring> DriverPaths; //list of all loaded drivers

	std::list<DeviceW> HardwareDevices;

	std::list<std::wstring> BlacklistedDrivers; //vulnerable driver list (BYOVD concept) which allow an attacker to read/write mem while having test signing or secure boot enabled 
	std::list<std::wstring> FoundBlacklistedDrivers; //any drivers which are loaded and blacklisted

	std::list<std::wstring> WhitelistedUnsignedDrivers; // dump_diskdump.sys, dump_storahci.sys, dump_dumpfve.sys

	bool FetchBlacklistedDrivers(__in const char* url);
	const char* BlacklistedDriversRepository = "https://raw.githubusercontent.com/AlSch092/UltimateAntiCheat/refs/heads/main/MiscFiles/BlacklistedDriverList.txt"; 
};