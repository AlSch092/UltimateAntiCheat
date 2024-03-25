#pragma once
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <string>

using namespace std;
using myNtQueryInformationThread = NTSTATUS(NTAPI*)(IN HANDLE ThreadHandle, IN THREADINFOCLASS ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength);

class Services
{
public:

	static BOOL IsDriverRunning(wstring name);

	BOOL GetRunningServices();
	BOOL GetServiceModules(string ServiceName);
	BOOL StopEventLog();

private:
	wstring wsServices[128];
	HMODULE hModules[256] = {};

};
