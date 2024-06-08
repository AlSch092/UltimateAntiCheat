//By AlSch092 @github
#include "AntiDebugger.hpp"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

/*
	StartAntiDebugThread - creates a new thread on `CheckForDebugger`
*/
void Debugger::AntiDebug::StartAntiDebugThread()
{
	this->DetectionThread = new Thread();

	this->DetectionThread->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Debugger::AntiDebug::CheckForDebugger, (LPVOID)this, 0, &this->DetectionThread->Id);

	if (this->DetectionThread->handle == INVALID_HANDLE_VALUE || this->DetectionThread->handle == NULL)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Couldn't start anti-debug thread @ Debugger::AntiDebug::StartAntiDebugThread");
		//optionally shut down here
	}

	Logger::logf("UltimateAnticheat.log", Info, "Created Debugger detection thread with Id: %d", this->DetectionThread->Id);

	this->DetectionThread->CurrentlyRunning = true;
}

/*
	CheckForDebugger - Thread function which loops and checks for the presense of debuggers
*/
void Debugger::AntiDebug::CheckForDebugger(LPVOID AD)
{
	if (AD == nullptr)
	{
		Logger::logf("UltimateAnticheat.log", Err, "AntiDbg class was NULL @ CheckForDebugger");
		return;
	}

	Logger::logf("UltimateAnticheat.log", Info, "STARTED Debugger detection thread");

	bool MonitoringDebugger = true;

	while (MonitoringDebugger)
	{
		Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

		if (AntiDbg == NULL)
		{
			Logger::logf("UltimateAnticheat.log", Err, "AntiDbg class was NULL @ CheckForDebugger");
			return;
		}

		if (AntiDbg->DetectionThread->ShutdownSignalled)
		{
			Logger::logf("UltimateAnticheat.log", Info, "Shutting down Debugger detection thread with Id: %d", AntiDbg->DetectionThread->Id);
			AntiDbg->DetectionThread->CurrentlyRunning = false;
			return; //exit thread
		}

		//Basic winAPI check
		bool basicDbg = AntiDbg->_IsDebuggerPresent();

		if (basicDbg)
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: WINAPI_DEBUGGER");
			AntiDbg->Flag(WINAPI_DEBUGGER);
		}

		if (AntiDbg->_IsDebuggerPresent_PEB())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: PEB");
			AntiDbg->Flag(PEB);
		}

		HANDLE HWDebugCheck = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Debugger::AntiDebug::_IsHardwareDebuggerPresent, AntiDbg, 0, 0);

		if (AntiDbg->_IsDebuggerPresent_HeapFlags())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: HEAP_FLAG");
			AntiDbg->Flag(HEAP_FLAG);
		}

		if (AntiDbg->_IsKernelDebuggerPresent())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: KERNEL_DEBUGGER");
			AntiDbg->Flag(KERNEL_DEBUGGER);
		}

		if (AntiDbg->_IsKernelDebuggerPresent_SharedKData())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: KUSER_SHARED_DATA flags");
			AntiDbg->Flag(KERNEL_DEBUGGER);
		}

		if (AntiDbg->_IsDebuggerPresent_DbgBreak())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: DbgBreak Excpetion Handler");
			AntiDbg->Flag(INT3);
		}

		if (AntiDbg->_IsDebuggerPresent_VEH()) //also patches over InitializeVEH's first byte if the dll is found
		{			
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: Cheat Engine VEH");
			AntiDbg->Flag(VEH_DEBUGGER);
		}

		if (AntiDbg->_IsDebuggerPresent_DebugPort())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: DebugPort");
			AntiDbg->Flag(DEBUG_PORT);
		}

		if (AntiDbg->_IsDebuggerPresent_ProcessDebugFlags())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: ProcessDebugFlags");
			AntiDbg->Flag(PROCESS_DEBUG_FLAGS);
		}

		if (AntiDbg->_IsDebuggerPresent_CloseHandle())
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: CloseHandle");
			AntiDbg->Flag(CLOSEHANDLE);
		}
		
		if (AntiDbg->DebuggerMethodsDetected.size() > 0)
		{
			Logger::logf("UltimateAnticheat.log", Info, "Atleast one method has caught a running debugger!");
		}	

		Sleep(2000);
	}
}

/*
	_IsHardwareDebuggerPresent - suspends threads + Checks debug registers for Dr0-3,6,7 being > 0
*/
void Debugger::AntiDebug::_IsHardwareDebuggerPresent(LPVOID AD)
{
	if (AD == nullptr)
	{
		Logger::logf("UltimateAnticheat.log", Err, "AntiDbg class was NULL @ _IsHardwareDebuggerPresent");
		return;
	}

	Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE) 
	{
		printf("Error: unable to create toolhelp snapshot\n");
		return;
	}

	DWORD currentProcessID = GetCurrentProcessId();

	if (Thread32First(hThreadSnap, &te32)) 
	{
		do 
		{
			if (te32.th32OwnerProcessID == currentProcessID && te32.th32ThreadID != GetCurrentThreadId()) 
			{
				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
				
				if (hThread == NULL) 
				{
					printf("Error: unable to open thread %d\n", te32.th32ThreadID);
					continue;
				}

				SuspendThread(hThread);

				CONTEXT context;
				context.ContextFlags = CONTEXT_DEBUG_REGISTERS;

				if (GetThreadContext(hThread, &context)) 
				{
					if (context.Dr0 || context.Dr1 || context.Dr2 || context.Dr3 || context.Dr6 || context.Dr7)
					{
						Logger::logf("UltimateAnticheat.log", Detection, "Found at least one debug register enabled (hardware debugging)");
						ResumeThread(hThread);
						CloseHandle(hThreadSnap);
						CloseHandle(hThread);
						
						if (!AntiDbg->Flag(Detections::HARDWARE_REGISTERS))
						{
							Logger::logf("UltimateAnticheat.log", Warning, "Failed to notify server of hardware debugging.");
						}

						return;
					}
				}
				else 
				{
					Logger::logf("UltimateAnticheat.log", Err, "GetThreadContext failed with: %d", GetLastError());								
					ResumeThread(hThread);
					CloseHandle(hThread);
					continue;
				}

				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hThreadSnap, &te32));
	}
	else 
	{
		Logger::logf("UltimateAnticheat.log", Err, "Thread32First Failed: %d\n", GetLastError());			
		return;
	}

	CloseHandle(hThreadSnap);
	return;
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
			return true; 
		else
			return false;
	}

	return false;
}

inline bool Debugger::AntiDebug::_IsKernelDebuggerPresent_SharedKData()
{
	_KUSER_SHARED_DATA* sharedData = USER_SHARED_DATA;
	return sharedData->KdDebuggerEnabled;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_HeapFlags()
{
#ifdef _M_IX86
	DWORD_PTR pPeb64 = (DWORD_PTR)__readfsdword(0x30);
#else
	DWORD_PTR pPeb64 = (DWORD_PTR)__readgsqword(0x60);
#endif


	if (pPeb64)
	{
		PVOID ptrHeap = (PVOID)*(PDWORD_PTR)((PBYTE)pPeb64 + 0x30);
		PDWORD heapForceFlagsPtr = (PDWORD)((PBYTE)ptrHeap + 0x74);

		__try
		{
			if (*heapForceFlagsPtr >= 0x40000060)
				return true;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_CloseHandle()
{
#ifndef _DEBUG
	__try
	{
		CloseHandle((HANDLE)1);
	}
	__except (EXCEPTION_INVALID_HANDLE == GetExceptionCode() ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
	{
		return true;
	}
#endif
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

bool Debugger::AntiDebug::_IsDebuggerPresent_Int2c()
{
	__try
	{
		__int2c();
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return true;
	}

	return false;
}

bool Debugger::AntiDebug::_IsDebuggerPresent_Int2d()
{
	unsigned char cBuf[2] = { 0x2D, 0xC3 };

	DWORD pOldProt = 0;
	if (!VirtualProtect((LPVOID)cBuf, 2, PAGE_EXECUTE_READ, &pOldProt))
	{
		Logger::logf("UltimateAnticheat.log", Err, "VirtualProtect failed at _IsDebuggerPresent_Int2d: %d", GetLastError());
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
	__fastfail(1); //code should not reach here unless process is being debugged
	return true;
#endif
}

/*
	_IsDebuggerPresent_VEH - Checks if vehdebug-x86_64.dll is loaded and exporting InitiallizeVEH. If so, the first byte of this routine is patched and the module's internal name is changed to STOP_CHEATING
	returns true if CE's VEH debugger is found, but this won't stop home-rolled VEH debuggers via APC injection
*/
inline bool Debugger::AntiDebug::_IsDebuggerPresent_VEH()
{
	bool bFound = false;

	HMODULE veh_debugger = GetModuleHandleA("vehdebug-x86_64.dll"); //if someone renames this dll we'll still stop them from debugging since our TLS callback patches over first byte of new thread funcs

	if (veh_debugger != NULL) 
	{
		UINT64 veh_addr = (UINT64)GetProcAddress(veh_debugger, "InitializeVEH"); //check for named exports of cheat engine's VEH debugger
		
		if (veh_addr > 0)
		{
			bFound = true;

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

inline bool  Debugger::AntiDebug::_IsDebuggerPresent_PEB()
{
#ifdef _M_IX86
	MYPEB* _PEB = (MYPEB*)__readfsdword(0x30);
#else
	MYPEB* _PEB = (MYPEB*)__readgsqword(0x60);
#endif
	
	return _PEB->BeingDebugged;
}

/*
    _IsDebuggerPresent_DebugPort - calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS 0x07 to check for debuggers
*/
inline bool Debugger::AntiDebug::_IsDebuggerPresent_DebugPort()
{
	typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(IN HANDLE ProcessHandle, IN PROCESS_INFORMATION_CLASS ProcessInformationClass,OUT PVOID ProcessInformation,IN ULONG ProcessInformationLength,OUT PULONG ReturnLength);

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
				return true;
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
inline bool Debugger::AntiDebug::_IsDebuggerPresent_ProcessDebugFlags()
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
				return true;
		}
	}
        else
	{
	    Logger::logf("UltimateAnticheat.log", Warning, "Failed to fetch ntdll.dll address @ _IsDebuggerPresent_ProcessDebugFlags ");
	}
	return false;
}

/*
	AddDetectedFlag - adds `flag` to DebuggerMethodsDetected after checking for duplicate entry
	returns FALSE if `flag` is duplicate entry
*/
inline bool Debugger::AntiDebug::AddDetectedFlag(Detections flag)
{
	bool isDuplicate = false;

	for (Detections f : this->DebuggerMethodsDetected)
	{
		if (f == flag)
		{
			isDuplicate = true;
		}
	}

	if (!isDuplicate)
		this->DebuggerMethodsDetected.push_back(flag);

	return isDuplicate;
}

/*
	Flag - adds `flag` to detected methods list and tells server we've caught a debugger
	returns false on error, true on success
*/
bool Debugger::AntiDebug::Flag(Debugger::Detections flag)
{
	bool wasDuplicate = AddDetectedFlag(flag);

	if (wasDuplicate)
		return true; //function still succeeds even though it was duplicate (no error)

	if (this->GetNetClient() != nullptr)
	{
		if (this->GetNetClient()->FlagCheater(DetectionFlags::DEBUGGER) != Error::OK) //the type of debugger doesn't really matter at the server-side, we can optionally modify the outbound packet to make debugger detections more granular
		{
			Logger::logf("UltimateAnticheat.log", Err, "Failed to notify server of caught debugger status");
			return false;
		}
	}
	else
	{
		Logger::logf("UltimateAnticheat.log", Err, "NetClient was NULL @ AntiDebug::Flag");
		return false;
	}

	return true;
}
