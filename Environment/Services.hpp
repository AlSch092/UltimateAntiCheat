#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string>
#include <list>
#include "../AntiTamper/NAuthenticode.hpp"
#include "../Common/Logger.hpp"
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tchar.h>

#pragma comment(lib, "setupapi.lib")

using namespace std;

extern "C" NTSTATUS NTAPI RtlGetVersion(RTL_OSVERSIONINFOW * lpVersionInformation); //used in GetWindowsMajorVersion

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

/*
The Services class deals with keeping track of loaded drivers & services/recurring tasks on the system, along with misc windows functions
*/
class Services
{
public:

	Services(bool Initialize)
	{
		if (Initialize)
		{
		    GetLoadedDrivers();
		    GetServiceModules();
		}
	}

	~Services()
	{
		for (auto it = ServiceList.begin(); it != ServiceList.end(); ++it) 
			delete* it;
		
		ServiceList.clear();
	}

	BOOL GetLoadedDrivers();
	BOOL GetServiceModules();

	list<wstring> GetUnsignedDrivers();

	static BOOL IsTestsigningEnabled();
	static BOOL IsDebugModeEnabled();
	
	static BOOL IsSecureBootEnabled();
	static BOOL IsSecureBootEnabled_RegKey(); //check by reg key

	static string GetWindowsDrive();
	static wstring GetWindowsDriveW();

	static BOOL IsRunningAsAdmin();

	static BOOL LaunchProcess(__in string path, __in string commandLine);

	static list<DeviceW> GetHardwareDevicesW();
	static BOOL CheckUSBDevices();

	static int GetWindowsMajorVersion();
	
	static bool IsHypervisor();
	static void GetHypervisorVendor(__out char vendor[13]);

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths;
};

