#include "Services.hpp"

BOOL Services::StopEventLog() //suspends all threads associated with the EventLog service
{
	HANDLE serviceProcessHandle = 0;
	HANDLE snapshotHandle = 0;
	HANDLE threadHandle = 0;

	SIZE_T modulesSize = sizeof(this->hModules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[1024] = {};
	HMODULE serviceModule = NULL;
	MODULEINFO serviceModuleInfo = {};
	DWORD_PTR threadStartAddress = 0;
	DWORD bytesNeeded = 0;
	HMODULE modules[512] = {};

	myNtQueryInformationThread NtQueryInformationThread = (myNtQueryInformationThread)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"));

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);

	SC_HANDLE service = OpenServiceA(sc, "EasyAntiCheat", MAXIMUM_ALLOWED);

	SERVICE_STATUS_PROCESS serviceStatusProcess = {};

	QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD servicePID = serviceStatusProcess.dwProcessId;

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL, // lookup privilege on local system
		L"SeDebugPrivilege", // privilege to lookup
		&luid)) // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege or disable all privileges.
	HANDLE currProc = GetCurrentProcess();
	HANDLE procToken;
	if (!OpenProcessToken(currProc, TOKEN_ADJUST_PRIVILEGES, &procToken))
	{
		wprintf(L"\nOpenProcessToken failed \n");
			return FALSE;
	}

	if (!AdjustTokenPrivileges(
		procToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		wprintf(L"\nAdjustTokenPrivileges error: %d\n", GetLastError());
		return FALSE;
	}

	CloseHandle(procToken);
	CloseHandle(currProc);

	serviceProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, servicePID); //open svchost.exe. this will deny access if SeDebugPrivileges are not enabled here (above code enables it).
	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (!EnumProcessModules(serviceProcessHandle, modules, modulesSize, &modulesSizeNeeded))
	{
		printf("EnumProcesssModules failed! %d\n", GetLastError());
		return FALSE;
	}

	modulesCount = modulesSizeNeeded / sizeof(HMODULE);

	printf("Modules Count: %lld, service pid: %d\n", modulesCount, servicePID);

	for (size_t i = 0; i < modulesCount; i++)
	{
		serviceModule = modules[i];
		wsServices[i] = remoteModuleName;

		GetModuleBaseName(serviceProcessHandle, serviceModule, remoteModuleName, sizeof(remoteModuleName));
		wprintf(L"%s\n", wsServices[i].c_str());

		if (wcscmp(remoteModuleName, L"wevtsvc.dll") == 0)
		{
			printf("Windows EventLog module %S at %p\n\n", remoteModuleName, serviceModule);
			GetModuleInformation(serviceProcessHandle, serviceModule, &serviceModuleInfo, sizeof(MODULEINFO));
		}
	}

	Thread32First(snapshotHandle, &threadEntry);
	while (Thread32Next(snapshotHandle, &threadEntry))
	{
		if (threadEntry.th32OwnerProcessID == servicePID)
		{
			threadHandle = OpenThread(MAXIMUM_ALLOWED, FALSE, threadEntry.th32ThreadID);
			NtQueryInformationThread(threadHandle, (THREADINFOCLASS)0x9, &threadStartAddress, sizeof(DWORD_PTR), NULL);

			printf("Suspending EventLog thread %d with start address %llX\n", threadEntry.th32ThreadID, threadStartAddress);

			if (threadStartAddress == NULL)
			{
				printf("ThreadStartAddress was NULL!\n");
				return FALSE;
			}

			if(threadHandle != NULL)
				SuspendThread(threadHandle);

			Sleep(2000);
		}
	}

	return TRUE;
}

BOOL Services::GetServiceModules(string ServiceName)
{
	HANDLE serviceProcessHandle;
	HANDLE snapshotHandle;
	
	SIZE_T modulesSize = sizeof(this->hModules);
	DWORD modulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T modulesCount = 0;
	WCHAR remoteModuleName[512] = {};
	HMODULE serviceModule = NULL;
	MODULEINFO serviceModuleInfo = {};
	DWORD_PTR threadStartAddress = 0;
	DWORD bytesNeeded = 0;

	myNtQueryInformationThread NtQueryInformationThread = (myNtQueryInformationThread)(GetProcAddress(GetModuleHandleA("ntdll"), "NtQueryInformationThread"));

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	SC_HANDLE sc = OpenSCManagerA(".", NULL, MAXIMUM_ALLOWED);
	
	SC_HANDLE service = OpenServiceA(sc, ServiceName.c_str(), MAXIMUM_ALLOWED);

	SERVICE_STATUS_PROCESS serviceStatusProcess = {};

	QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatusProcess, sizeof(serviceStatusProcess), &bytesNeeded);
	DWORD servicePID = serviceStatusProcess.dwProcessId;

	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL, // lookup privilege on local system
		L"SeDebugPrivilege", // privilege to lookup
		&luid)) // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return false;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege or disable all privileges.
	HANDLE currProc = GetCurrentProcess();
	HANDLE procToken;
	if (!OpenProcessToken(currProc, TOKEN_ADJUST_PRIVILEGES, &procToken))
	{
		wprintf(L"\nOpenProcessToken failed \n");
		return false;
	}

	if (!AdjustTokenPrivileges(
		procToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		wprintf(L"\nAdjustTokenPrivileges error: %d\n", GetLastError());

		return false;
	}

	CloseHandle(procToken);
	CloseHandle(currProc);

	serviceProcessHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, servicePID); //open svchost.exe

	if (!serviceProcessHandle)
	{
		printf("OpenProcess failed with %d\n!", GetLastError());
	}

	snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	EnumProcessModules(serviceProcessHandle, this->hModules, modulesSize, &modulesSizeNeeded);
	modulesCount = modulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < modulesCount; i++)
	{
		serviceModule = this->hModules[i];
		wsServices[i] = remoteModuleName;

		wprintf(L"Module: %s\n", wsServices[i].c_str());

		if (!GetModuleBaseName(serviceProcessHandle, serviceModule, remoteModuleName, sizeof(remoteModuleName)))
		{
			printf("GetModuleBaseName failed! %d\n", GetLastError());
		}
	}

	return true;
}

BOOL Services::IsDriverRunning(wstring name)
{
	// Get a handle to the current process
	HANDLE hProcess = GetCurrentProcess();

	// Get an array of handles to the currently loaded drivers
	HMODULE hModules[1024];
	DWORD cbNeeded;
	if (EnumDeviceDrivers((LPVOID*)hModules, sizeof(hModules), &cbNeeded))
	{
		// Calculate the number of handles in the array
		int numModules = cbNeeded / sizeof(HMODULE);

		// Print the base name of each driver
		for (int i = 0; i < numModules; i++)
		{
			TCHAR szModName[MAX_PATH];
			if (GetDeviceDriverBaseName(hModules[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
			{
				wprintf(L"%d: %s\n", i + 1, szModName);

				if (wcscmp(name.c_str(), szModName) == 0)
				{
					wprintf(L"Found driver: %s\n", szModName);
					return TRUE;
				}

			}
		}
	}

	// Close the handle to the current process
	CloseHandle(hProcess);

	return FALSE;
}