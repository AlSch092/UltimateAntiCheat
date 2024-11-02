#include "DebuggerDetections.hpp"

using namespace Debugger;

bool DebuggerDetections::_IsKernelDebuggerPresent()
{
	typedef long NTSTATUS;
	HANDLE hProcess = GetCurrentProcess();

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { bool DebuggerEnabled; bool DebuggerNotPresent; } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS(__stdcall* ZW_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	ZW_QUERY_SYSTEM_INFORMATION ZwQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	HMODULE hModule = GetModuleHandleA("ntdll.dll");

	if (hModule == NULL)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Error fetching module ntdll.dll @ _IsKernelDebuggerPresent: %d", GetLastError());
		return false;
	}

	ZwQuerySystemInformation = (ZW_QUERY_SYSTEM_INFORMATION)GetProcAddress(hModule, "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation == NULL)
		return false;

	if (!ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL))
	{
		if (Info.DebuggerEnabled && !Info.DebuggerNotPresent)
		{
			if (!Flag(Detections::KERNEL_DEBUGGER))
			{
				Logger::logf("UltimateAnticheat.log", Warning, "Failed to notify server of debugging method (server may be offline or duplicate entry)");
			}

			return true;
		}			
		else
			return false;
	}

	return false;
}

bool DebuggerDetections::_IsKernelDebuggerPresent_SharedKData()
{
	_KUSER_SHARED_DATA* sharedData = USER_SHARED_DATA;

	if (sharedData->KdDebuggerEnabled)
	{
		if (!Flag(Detections::KERNEL_DEBUGGER))
		{
			Logger::logf("UltimateAnticheat.log", Warning, "Failed to notify server of debugging method (server may be offline or duplicate entry)");
		}
	}

	return sharedData->KdDebuggerEnabled;
}

bool DebuggerDetections::_IsDebuggerPresent_HeapFlags()
{
#ifdef _M_IX86
	DWORD_PTR pPeb64 = (DWORD_PTR)__readfsdword(0x30);
#else
	DWORD_PTR pPeb64 = (DWORD_PTR)__readgsqword(0x60);
#endif


	if (pPeb64)
	{
		PVOID ptrHeap = (PVOID) * (PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)ptrHeap + 0x74);

		__try
		{
			if (*heapForceFlagsPtr >= 0x40000060)
			{
				if (!Flag(Detections::HEAP_FLAG))
				{ //optionally take further action, `Flag` will already log a warning
				}

				return true;
			}
				
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	return false;
}

bool DebuggerDetections::_IsDebuggerPresent_CloseHandle()
{
#ifndef _DEBUG
	__try
	{
		CloseHandle((HANDLE)1);
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		if (!Flag(Detections::CLOSEHANDLE))
		{ //optionally take further action, `Flag` will already log a warning
		}

		return true;
	}
#endif
	return false;
}

bool DebuggerDetections::_IsDebuggerPresent_RemoteDebugger()
{
	BOOL bDebugged = false;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged))
		if (bDebugged)
		{
			if (!Flag(Detections::REMOTE_DEBUGGER))
			{ //optionally take further action, `Flag` will already log a warning
			}

			return true;
		}
			
	return false;
}

bool DebuggerDetections::_IsDebuggerPresent_DbgBreak()
{
#ifdef _DEBUG
	return false;  //only use __fastfail in release build , since it will trip up our execution when debugging this project
#else
	__try
	{
		DebugBreak();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	Logger::logf("UltimateAnticheat.log", Info, "Calling __fastfail() to prevent further execution since a debugger was found running.");

	if (!Flag(Detections::DBG_BREAK))
	{//optionally take further action, `Flag` will already log a warning
	}

	__fastfail(1); //code should not reach here unless process is being debugged
	return true;
#endif
}

/*
	_IsDebuggerPresent_VEH - Checks if vehdebug-x86_64.dll is loaded and exporting InitiallizeVEH. If so, the first byte of this routine is patched and the module's internal name is changed to STOP_CHEATING
	returns true if CE's VEH debugger is found, but this won't stop home-rolled VEH debuggers via APC injection
*/
bool DebuggerDetections::_IsDebuggerPresent_VEH()
{
	bool bFound = false;

	HMODULE veh_debugger = GetModuleHandleA("vehdebug-x86_64.dll"); //if someone renames this dll we'll still stop them from debugging since our TLS callback patches over first byte of new thread funcs

	if (veh_debugger != NULL)
	{
		UINT64 veh_addr = (UINT64)GetProcAddress(veh_debugger, "InitializeVEH"); //check for named exports of cheat engine's VEH debugger

		if (veh_addr > 0)
		{
			bFound = true;

			if (!Flag(Detections::VEH_DEBUGGER))
			{//optionally take further action, `Flag` will already log a warning
			}

			DWORD dwOldProt = 0;

			if (!VirtualProtect((void*)veh_addr, 1, PAGE_EXECUTE_READWRITE, &dwOldProt))
			{
				Logger::logf("UltimateAnticheat.log", Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
			}

			memcpy((void*)veh_addr, "\xC3", sizeof(BYTE)); //patch first byte of `InitializeVEH` with a ret, stops call to InitializeVEH from succeeding.

			if (!VirtualProtect((void*)veh_addr, 1, dwOldProt, &dwOldProt)) //change back to old prot's
			{
				Logger::logf("UltimateAnticheat.log", Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
			}

			if (Process::ChangeModuleName(L"vehdebug-x86_64.dll", L"STOP_CHEATING"))
			{
				Logger::logf("UltimateAnticheat.log", Info, "Changed module name of vehdebug-x86_64.dll to STOP_CHEATING to prevent VEH debugging.");
			}
		}
	}

	return bFound;
}

bool DebuggerDetections::_IsDebuggerPresent_PEB()
{
#ifdef _M_IX86
	MYPEB* _PEB = (MYPEB*)__readfsdword(0x30);
#else
	MYPEB* _PEB = (MYPEB*)__readgsqword(0x60);
#endif

	if (_PEB->BeingDebugged)
	{
		if (!Flag(Detections::VEH_DEBUGGER))
		{//optionally take further action, `Flag` will already log a warning
		}
	}

	return _PEB->BeingDebugged;
}

/*
	_IsDebuggerPresent_DebugPort - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x07 to check for debuggers
*/
bool DebuggerDetections::_IsDebuggerPresent_DebugPort()
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			const PROCESS_INFORMATION_CLASS ProcessDebugPort = (PROCESS_INFORMATION_CLASS)7;
			DWORD dwProcessDebugPort, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &dwProcessDebugPort, sizeof(DWORD), &dwReturned);

			if (NT_SUCCESS(status) && (dwProcessDebugPort == -1))
			{
				if (!Flag(Detections::DEBUG_PORT))
				{//optionally take further action, `Flag` will already log a warning
				}

				return true;
			}				
		}
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_DebugPort ");
	}

	return false;
}

/*
	_IsDebuggerPresent_ProcessDebugFlags - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x1F to check for debuggers
*/
bool DebuggerDetections::_IsDebuggerPresent_ProcessDebugFlags()
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength);

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

	if (hNtdll)
	{
		auto pfnNtQueryInformationProcess = (TNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

		if (pfnNtQueryInformationProcess)
		{
			PROCESS_INFORMATION_CLASS pic = (PROCESS_INFORMATION_CLASS)0x1F;
			DWORD dwProcessDebugFlags, dwReturned;
			NTSTATUS status = pfnNtQueryInformationProcess(GetCurrentProcess(), pic, &dwProcessDebugFlags, sizeof(DWORD), &dwReturned);

			if (NT_SUCCESS(status) && (dwProcessDebugFlags == 0))
			{
				if (!Flag(Detections::PROCESS_DEBUG_FLAGS))
				{//optionally take further action, `Flag` will already log a warning
				}

				return true;
			}			
		}
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_ProcessDebugFlags ");
	}
	return false;
}
