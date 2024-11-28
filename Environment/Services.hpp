//By AlSch092 @ Github
#pragma once
#include "../Common/Logger.hpp"
#include "../AntiTamper/NAuthenticode.hpp"
#include "../Common/Utility.hpp"
#include <Psapi.h>
#include <TlHelp32.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <tchar.h>
#include <intrin.h>

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

	Services(bool Initialize)
	{
		if (Initialize)
		{
			HardwareDevices = GetHardwareDevicesW(); //fetch PCI devices

			//in a real world application we would of course obfuscate these strings at compile time
			BlacklistedDrivers.push_back(L"ntguard.sys"); //Net-Ease anti-cheat -> Vulnerable
			BlacklistedDrivers.push_back(L"BEDaisy.sys"); //battleEye older versions are vulnerable to read/write kernel memory
			BlacklistedDrivers.push_back(L"Gdrv.sys"); //gigabyte, vulnerable IOCTLs to r/w to physical memory
			BlacklistedDrivers.push_back(L"AsIO.sys"); //asus utilities
			BlacklistedDrivers.push_back(L"AsUpIO.sys");  //asus utilities
			BlacklistedDrivers.push_back(L"CPUID.sys"); //direct memory access & manipulation
			BlacklistedDrivers.push_back(L"ENE.sys"); //older versions vulnerable
			BlacklistedDrivers.push_back(L"iqvw64e.sys"); //direct memory access, used in manually mapping drivers
			BlacklistedDrivers.push_back(L"hxctl.sys"); //Huorong Security, allow execute kernel code
			BlacklistedDrivers.push_back(L"kprocesshacker.sys"); //process hacker's driver allows reading + writing to phys memory
			BlacklistedDrivers.push_back(L"kprocesshacker2.sys"); //process hacker's driver allows reading + writing to phys memory
			BlacklistedDrivers.push_back(L"EIO64.sys");
			BlacklistedDrivers.push_back(L"IOMap64.sys");
			BlacklistedDrivers.push_back(L"ATSZIO64.sys");
			BlacklistedDrivers.push_back(L"atillk64.sys");
			BlacklistedDrivers.push_back(L"aswVmm.sys"); //ssdt hooking
			BlacklistedDrivers.push_back(L"BS_Flash64.sys");
			BlacklistedDrivers.push_back(L"Capcom.sys");
			BlacklistedDrivers.push_back(L"cpuz141.sys"); //phys read/write
			BlacklistedDrivers.push_back(L"WinRing0x64.sys");
			BlacklistedDrivers.push_back(L"FairplayKD.sys");
			BlacklistedDrivers.push_back(L"pgldqpoc.sys");
			BlacklistedDrivers.push_back(L"HwOs2Ec10x64.sys"); //APC injection
			BlacklistedDrivers.push_back(L"Phymemx64.sys");
			BlacklistedDrivers.push_back(L"Monitor_win10_x64.sys");
			BlacklistedDrivers.push_back(L"driver.sys");
			BlacklistedDrivers.push_back(L"lha.sys");
			BlacklistedDrivers.push_back(L"Mslo64.sys");
			BlacklistedDrivers.push_back(L"NTIOLib_x64.sys");
			BlacklistedDrivers.push_back(L"pcdsrvc_x64.pkms");
			BlacklistedDrivers.push_back(L"HWiNFO64A.sys");
			BlacklistedDrivers.push_back(L"rzpnk.sys"); //CVE-2017-9769
			BlacklistedDrivers.push_back(L"magdrvamd64.sys");
			BlacklistedDrivers.push_back(L"speedfan.sys");
			BlacklistedDrivers.push_back(L"zam64.sys");
			
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

	list<DeviceW> HardwareDevices;

	list<wstring> BlacklistedDrivers; //vulnerable driver list (BYOVD concept) which allow an attacker to read/write mem while having test signing/secure boot enabled 
	list<wstring> FoundBlacklistedDrivers; //any drivers which are loaded and blacklisted
};
