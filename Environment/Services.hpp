#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <string>
#include <list>
#include <Softpub.h>
#include <wincrypt.h>
#pragma comment(lib, "wintrust")

using namespace std;

struct Service
{
	wstring displayName;
	wstring serviceName;
	DWORD pid;
	bool isRunning;
};

class Services
{
public:

	BOOL GetLoadedDrivers();
	BOOL GetServiceModules();

	list<wstring> GetUnsignedDrivers();

	static BOOL IsDriverSigned(wstring driverPath);

private:

	list<Service*> ServiceList;

	list <wstring> DriverPaths;
};