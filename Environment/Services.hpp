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
The Services class deals with keeping track of loaded drivers & services on the system
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

private:

	list<Service*> ServiceList;
	list <wstring> DriverPaths;
};