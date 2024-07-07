#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string>
#include <list>
#include "../AntiTamper/NAuthenticode.hpp"
#include "../Logger.hpp"

using namespace std;

struct Service
{
	wstring displayName;
	wstring serviceName;
	DWORD pid;
	bool isRunning;
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

	static string GetWindowsDrive();
	static wstring GetWindowsDriveW();

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths;
};