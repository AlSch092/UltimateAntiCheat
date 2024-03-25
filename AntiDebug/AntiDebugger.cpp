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

	return false;	
}

bool Debugger::AntiDebug::_IsHardwareDebuggerPresent()
{
	DWORD ProcessId = GetCurrentProcessId(); //this can be replaced later, or a process that is not us

	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))
	{
		CloseHandle(hThreadSnap);
		return(FALSE);
	}
	
	do
	{
		if (te32.th32OwnerProcessID == ProcessId)
		{
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
						printf("Found at least one debug register enabled\n");
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

	if (!ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), NULL)) 
	{ // 0 = STATUS_SUCCESS
		if (Info.DebuggerEnabled && !Info.DebuggerNotPresent)
			return true; 
		else
			return false;
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresentHeapFlags()
{
	DWORD_PTR pPeb64 = (DWORD_PTR)__readgsqword(0x60);

	if (pPeb64)
	{
		PVOID ptrHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)ptrHeap + 0x74);

		__try
		{
			if (*heapForceFlagsPtr >= 0x40000060)
				return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER) //incase of mem read exception
		{
			return false;
		}
	}

	return false;
}


void Debugger::AntiDebug::CheckForDebugger(LPVOID AD)
{
	Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

	//Basic winAPI check
	bool basicDbg = AntiDbg->_IsDebuggerPresent();

	if (basicDbg)
	{
		AntiDbg->DebuggerMethodsDetected = AntiDbg->DebuggerMethodsDetected | WINAPI_DEBUGGER;
		printf("Found debugger: WINAPI_DEBUGGER!\n");
	}

	if (AntiDbg->_IsDebuggerPresent_PEB())
	{
		AntiDbg->DebuggerMethodsDetected = AntiDbg->DebuggerMethodsDetected | PEB_FLAG;
		printf("Found debugger: PEB_FLAG!\n");
	}

	if (AntiDbg->_IsHardwareDebuggerPresent() || AntiDbg->_IsDebuggerPresentHeapFlags() || AntiDbg->_IsKernelDebuggerPresent())
	{
		printf("Debugger found.\n");
	}

	//if (AntiDbg->_IsDebuggerPresent_Int2c()) //was throwing false positives, need to re-check
	//{
	//	printf("Debugger found 0x2c.\n");
	//}

	if (AntiDbg->_IsDebuggerPresent_DbgBreak())
	{
		printf("Debugger found DebugBreak handled exception.\n");
	}

	if (AntiDbg->_IsDebuggerPresent_WaitDebugEvent())
	{
		printf("Debugger found WaitDebugEvent.\n");
	}

	if (AntiDbg->_IsDebuggerPresent_VEH())
	{
		printf("VEH debugger found!\n");
	}

	if (AntiDbg->DebuggerMethodsDetected)
	{
		printf("Atleast one method has caught a running debugger!\n");
	}
}

#ifdef ENVIRONMENT32
//these routines more or less check to see if an exception is consumed or not by some already attached debugger
bool Debugger::AntiDebug::_IsDebuggerPresent_TrapFlag()
{
	__try
	{
		__asm
		{
			pushfd
			or word ptr[esp], 0x100
			popfd
			nop
		}
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_ICEBreakpoint()
{
	__try
	{
		__asm __emit 0xF1
	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}

//bool Debugger::AntiDebug::_IsDebuggerPresent_INT2D()
//{
//	__try
//	{
//		__asm int 0x2d
//	}
//	__except (1)
//	{
//		return FALSE;
//	}
//	return TRUE;
//}
//
//bool Debugger::AntiDebug::_IsDebuggerPresent_Int2c()
//{
//	__try
//	{
//		__asm int 0x2c
//	}
//	__except (1)
//	{
//		return FALSE;
//	}
//	return TRUE;
//}

#else

#endif

bool Debugger::AntiDebug::_IsDebuggerPresentCloseHandle()
{
	__try
	{
		CloseHandle((HANDLE)NULL);
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode()
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH)
	{
		return true;
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_RemoteDebugger()
{
	BOOL bDebugged = false;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugged))
		if (bDebugged)
			return true;

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_IllegalInstruction()
{
	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_Int2c()
{
	char cBuf[] = { 0x0F, 0x0B, 0xC3 };

	DWORD pOldProt = 0;
	if (!VirtualProtect((LPVOID)cBuf, 3, PAGE_EXECUTE_READWRITE, &pOldProt))
	{
		printf("VirtualProtect failed at _IsDebuggerPresent_Int2c: %d\n", GetLastError());
		return false;
	}

	__try
	{
		void (*fun_ptr)() = (void(*)(void))(&cBuf);
		fun_ptr();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return true;
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_Int2d()
{
	char cBuf[2] = { 0x2D, 0xC3 };

	DWORD pOldProt = 0;
	if (!VirtualProtect((LPVOID)cBuf, 2, PAGE_EXECUTE_READ, &pOldProt))
	{
		printf("VirtualProtect failed at _IsDebuggerPresent_Int2d: %d\n", GetLastError());
		return false;
	}

	__try
	{
		void (*fun_ptr)() = (void(*)(void))(&cBuf);
		fun_ptr();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_DbgBreak()
{
	__try
	{
		DebugBreak(); //same as int3 basically
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

int FilterException(int code, PEXCEPTION_POINTERS ex) {
	
	printf("filterException: %x, ex->ContextRecord->DebugControl: %llx\n", code, *ex->ExceptionRecord->ExceptionInformation);

	bool bFound = false;

	switch (code)
	{
		case 0xc0000005:

		break;
	};

	return EXCEPTION_EXECUTE_HANDLER;
}

inline bool Debugger::AntiDebug::_IsDebuggerPresent_VEH()
{
	bool bFound = false;

	if (GetModuleHandleA("vehdebug-x86_64.dll") != NULL) //first the easiest way to check. most people using a VEH debugger are probably using cheat engine's.
	{
		UINT64 veh_addr = (UINT64)GetProcAddress(GetModuleHandleA("vehdebug-x86_64.dll"), "InitializeVEH");
		
		if (veh_addr > 0)
		{
			bFound = true;
		}
	}

	//some people will try to rename this DLL in their own cheat engine builds. we can thus look for the exported functions instead
	return bFound;
}

inline bool Debugger::AntiDebug::_IsDebuggerPresent_WaitDebugEvent()
{
	bool bFound = false;
	LPDEBUG_EVENT lpd_e = { 0 };

	if (WaitForDebugEvent(lpd_e, INFINITE))
	{
		bFound = true;
	}

	//some people will try to rename this DLL in their own cheat engine builds. we can thus look for the exported functions instead
	return bFound;
}

inline bool  Debugger::AntiDebug::_IsDebuggerPresent_PEB()
{
	MYPEB* _PEB = (MYPEB*)__readgsqword(0x60);
	return _PEB->BeingDebugged;
}