#include "AntiDebugger.hpp"

void Debugger::AntiDebug::StartAntiDebugThread()
{
	HANDLE thread = this->GetDetectionThread();
	thread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Debugger::AntiDebug::CheckForDebugger, (LPVOID)this, 0, 0);
}

inline bool Debugger::AntiDebug::_IsDebuggerPresent()
{
	if (IsDebuggerPresent()) //winapi
	{
		DebuggerMethodsDetected = DebuggerMethodsDetected | WINAPI_DEBUGGER;
		return true;
	}
	else
	{
		return false;
	}
}



bool Debugger::AntiDebug::_IsHardwareDebuggerPresent()
{
	DWORD ProcessId = GetCurrentProcessId(); //this can be replaced later, or a process that is not us

	//first we must iterate on all threads in process
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}
	
	//WOW64: The handle must also have THREAD_QUERY_INFORMATION access.
	// Now walk the thread list of the system,
	// and display information about each thread
	// associated with the specified process
	do
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
			printf(("\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);

			CONTEXT lpContext;
			memset(&lpContext, 0, sizeof(CONTEXT));
			lpContext.ContextFlags = CONTEXT_FULL;

			HANDLE _tThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

			if (_tThread)
			{
				if (GetThreadContext(_tThread, &lpContext))
				{
					if (lpContext.Dr0 || lpContext.Dr1 || lpContext.Dr2 || lpContext.Dr3 )
					{
						printf("Found a debug register enabled!\n");
						CloseHandle(hThreadSnap);
						CloseHandle(_tThread);
						return true;
					}
				}
				else
				{
					printf("GetThreadContext failed with: %d\n", GetLastError());
          CloseHandle(_tThread);
					continue;
				}
			}
			else
			{
				printf("Could not call openthread! %d\n", GetLastError());
				continue;
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	printf(("\n"));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return false;
}


bool Debugger::AntiDebug::_IsKernelDebuggerPresent()
{
	typedef long NTSTATUS;
	HANDLE hProcess = GetCurrentProcess();

	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION { bool DebuggerEnabled; bool DebuggerNotPresent; } SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	enum SYSTEM_INFORMATION_CLASS { SystemKernelDebuggerInformation = 35 };
	typedef NTSTATUS(__stdcall* ZW_QUERY_SYSTEM_INFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, IN OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength);
	ZW_QUERY_SYSTEM_INFORMATION ZwQuerySystemInformation;
	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;

	HMODULE hModule = LoadLibraryA("ntdll.dll");
	ZwQuerySystemInformation = (ZW_QUERY_SYSTEM_INFORMATION)GetProcAddress(hModule, "ZwQuerySystemInformation");
	if (ZwQuerySystemInformation == NULL)
		return false;

	if (!ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL)) {
		if (Info.DebuggerEnabled && !Info.DebuggerNotPresent)
			return true; 
		else
			return false;
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresentHeapFlags()
{
	DWORD_PTR pPeb64 = (DWORD_PTR)pPEB::GetPEB();

	if (pPeb64)
	{
		PVOID ptrHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)ptrHeap + 0x74);

		if (*heapForceFlagsPtr == 0x40000060)
			return true;
	}

	return false;
}

