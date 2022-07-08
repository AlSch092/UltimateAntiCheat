#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <dbghelp.h>
#include <winternl.h>
#include <string>

using namespace std;
using myNtQueryInformationThread = NTSTATUS(NTAPI*)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);

class Services
{
public:

	bool GetRunningServices();
	bool GetServiceModules(string ServiceName);
	void StopEventLog();

private:
	wstring wsServices[128];
	HMODULE hModules[256] = {};

};
