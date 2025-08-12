#include "DebuggerDetections.hpp"

using namespace Debugger;

DetectionFlags DebuggerDetections::_IsDebuggerPresent()
{
	return (IsDebuggerPresent() ? DetectionFlags::DEBUG_WINAPI_DEBUGGER : DetectionFlags::NONE);
}

DetectionFlags DebuggerDetections::_IsKernelDebuggerPresent()
{
	typedef long NTSTATUS;
	HANDLE hProcess = GetCurrentProcess();

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { bool DebuggerEnabled; bool DebuggerNotPresent; } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS(__stdcall* NT_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	HMODULE hModule = GetModuleHandleA("ntdll.dll");

	if (hModule == NULL)
	{
		Logger::logf(Err, "Error fetching module ntdll.dll @ _IsKernelDebuggerPresent: %d", GetLastError());
		return EXECUTION_ERROR;
	}

	NtQuerySystemInformation = (NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(hModule, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL)
		return EXECUTION_ERROR;

	if (NtQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL))
	{
		if (Info.DebuggerEnabled || !Info.DebuggerNotPresent)
		{
			return DEBUG_KERNEL_DEBUGGER;
		}
	}
	else
		return EXECUTION_ERROR;

	return NONE;
}

DetectionFlags DebuggerDetections::_IsKernelDebuggerPresent_SharedKData()
{
	_KUSER_SHARED_DATA* sharedData = USER_SHARED_DATA;
	bool bDebuggerEnabled = false;

	if (sharedData != nullptr && sharedData->KdDebuggerEnabled)
	{
		bDebuggerEnabled = true;
	}

	return bDebuggerEnabled ? DEBUG_KERNEL_DEBUGGER : NONE;
}

/*
	_IsDebuggerPresent_HeapFlags - checks heap flags in the PEB, certain combination can indicate a debugger is present
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_HeapFlags()
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

		if (ptrHeap && heapForceFlagsPtr)
		{
			if (*heapForceFlagsPtr >= 0x40000060)
			{
				return DEBUG_HEAP_FLAG;
			}
		}
	}

	return NONE;
}

/*
  _IsDebuggerPresent_CloseHandle - calls CloseHandle with an invalid handle, if an exception is thrown then a debugger is present
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_CloseHandle()
{
#ifndef _DEBUG
	__try
	{
		CloseHandle((HANDLE)1);
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return DEBUG_CLOSEHANDLE;
	}
#endif
	return NONE;
}

DetectionFlags DebuggerDetections::_IsDebuggerPresent_RemoteDebugger()
{
	BOOL bDebugged = FALSE;

	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged))
	{
		if (bDebugged)
		{
			return DEBUG_REMOTE_DEBUGGER;
		}
	}

	return NONE;
}

/*
	_IsDebuggerPresent_VEH - Checks if vehdebug-x86_64.dll is loaded and exporting InitiallizeVEH. If so, the first byte of this routine is patched and the module's internal name is changed to STOP_CHEATING
	returns true if CE's VEH debugger is found, but this won't stop home-rolled VEH debuggers via APC injection
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_VEH()
{
	bool bFound = false;

	HMODULE veh_debugger = GetModuleHandleA("vehdebug-x86_64.dll"); //if someone renames this dll we'll still stop them from debugging since our TLS callback patches over first byte of new thread funcs

	if (veh_debugger != NULL)
	{
		uintptr_t veh_addr = (uintptr_t)GetProcAddress(veh_debugger, "InitializeVEH"); //check for named exports of cheat engine's VEH debugger

		if (veh_addr > 0)
		{
			bFound = true;

			DWORD dwOldProt = 0;

			if (!VirtualProtect((void*)veh_addr, 1, PAGE_EXECUTE_READWRITE, &dwOldProt))
			{
				Logger::logf(Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
				return DEBUG_VEH_DEBUGGER; //return true since we found the routine, even though we can't patch over it. if virtualprotect fails, the program will probably crash if trying to patch it
			}

			memcpy((void*)veh_addr, "\xC3", sizeof(BYTE)); //patch first byte of `InitializeVEH` with a ret, stops call to InitializeVEH from succeeding.

			if (!VirtualProtect((void*)veh_addr, 1, dwOldProt, &dwOldProt)) //change back to old prot's
			{
				Logger::logf(Warning, "VirtualProtect failed @ _IsDebuggerPresent_VEH");
			}
		}
	}

	return (bFound ? DEBUG_VEH_DEBUGGER : NONE);
}

/*
     _IsDebuggerPresent_PEB - checks the PEB for the BeingDebugged flag
     returns `true` if byte is set to 1, indicating a debugger is present
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_PEB()
{
#ifdef _M_IX86
	MYPEB* _PEB = (MYPEB*)__readfsdword(0x30);
#else
	MYPEB* _PEB = (MYPEB*)__readgsqword(0x60);
#endif

	bool bDebuggerPresent = false;

	if (_PEB != nullptr && _PEB->BeingDebugged)
	{
		bDebuggerPresent = true;
	}

	return (bDebuggerPresent ? DEBUG_PEB : NONE);
}

/*
	_IsDebuggerPresent_DebugPort - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x07 to check for debuggers
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_DebugPort()
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
				return DEBUG_DEBUG_PORT;
			}
		}
		else
		{
			Logger::logf(Warning, "Failed to fetch NtQueryInformationProcess address @ _IsDebuggerPresent_DebugPort ");
			return EXECUTION_ERROR;
		}
	}
	else
	{
		Logger::logf(Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_DebugPort ");
		return EXECUTION_ERROR;
	}

	return NONE;
}

/*
	_IsDebuggerPresent_ProcessDebugFlags - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x1F to check for debuggers
*/
DetectionFlags DebuggerDetections::_IsDebuggerPresent_ProcessDebugFlags()
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
				return DEBUG_PROCESS_DEBUG_FLAGS;
			}
		}
	}
	else
	{
		Logger::logf(Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_ProcessDebugFlags ");
		return EXECUTION_ERROR;
	}

	return NONE;
}


/*
	_ExitCommonDebuggers - create remote thread on `ExitProcess` in any common debugger processes
	This can of course be bypassed with a simple process name change, preferrably we would use a combination of artifacts to find these processes
*/
DetectionFlags DebuggerDetections::_ExitCommonDebuggers()
{
	bool triedEndDebugger = false;

	for (const std::wstring& debugger : this->CommonDebuggerProcesses)
	{
		std::list<DWORD> pids = Process::GetProcessIdsByName(debugger);

		for (const auto pid : pids)
		{
			uintptr_t K32Base = (uintptr_t)GetModuleHandleW(L"kernel32.dll");

			if (K32Base == NULL)
			{
				Logger::logf(Warning, "Failed to fetch kernel32.dll address @ _ExitCommonDebuggers ");
				return EXECUTION_ERROR;
			}

			uintptr_t ExitProcessAddr = (uintptr_t)GetProcAddress((HMODULE)K32Base, "ExitProcess");

			if (ExitProcessAddr == NULL)
			{
				Logger::logf(Warning, "Failed to fetch ExitProcess address @ _ExitCommonDebuggers ");
				return EXECUTION_ERROR;
			}

			uintptr_t ExitProcessOffset = ExitProcessAddr - K32Base;

			HANDLE remoteProcHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

			if (remoteProcHandle)
			{
				uintptr_t FunctionAddr_ExitProcess = (uintptr_t)Process::GetRemoteModuleBaseAddress(pid, L"kernel32.dll") + ExitProcessOffset;
				HANDLE RemoteThread = CreateRemoteThread(remoteProcHandle, 0, 0, (LPTHREAD_START_ROUTINE)FunctionAddr_ExitProcess, 0, 0, 0);
				triedEndDebugger = true;
				CloseHandle(remoteProcHandle);
				Logger::logf(Info, "Created remote thread at %llX address", FunctionAddr_ExitProcess);
			}
			else
			{
				Logger::logf(Warning, "Failed to open process handle for pid %d @ _ExitCommonDebuggers", pid);
			}
		}
	}

	return (triedEndDebugger ? DEBUG_KNOWN_DEBUGGER_PROCESS : NONE);
}

