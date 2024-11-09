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
The Services class deals with keeping track of loaded drivers & services/recurring tasks on the system, along with misc windows functions
*/
class Services final
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
	
	static bool IsHypervisor();
	static void GetHypervisorVendor(__out char vendor[13]);

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths;
};