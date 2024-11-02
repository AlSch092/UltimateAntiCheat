//By AlSch092 @github
#include "AntiDebugger.hpp"

/*
	StartAntiDebugThread - creates a new thread on `CheckForDebugger`
*/
void Debugger::AntiDebug::StartAntiDebugThread()
{
	if (!this->GetSettings()->bUseAntiDebugging)
	{
		Logger::logf("UltimateAnticheat.log", Info, "Anti-Debugger was disabled in settings, debugging will be allowed");
		return;
	}

	this->DetectionThread = new Thread((LPTHREAD_START_ROUTINE)Debugger::AntiDebug::CheckForDebugger, (LPVOID)this, true);

	if (this->DetectionThread->GetHandle() == INVALID_HANDLE_VALUE || this->DetectionThread->GetHandle() == NULL)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Couldn't start anti-debug thread @ Debugger::AntiDebug::StartAntiDebugThread");
		//optionally shut down here if thread creation fails
	}

	Logger::logf("UltimateAnticheat.log", Info, "Created Debugger detection thread with Id: %d", this->DetectionThread->GetId());
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

	Debugger::AntiDebug* AntiDbg = reinterpret_cast<Debugger::AntiDebug*>(AD);

	Logger::logf("UltimateAnticheat.log", Info, "STARTED Debugger detection thread");

	bool MonitoringDebugger = true;

	while (MonitoringDebugger)
	{
		if (AntiDbg == NULL)
		{
			Logger::logf("UltimateAnticheat.log", Err, "AntiDbg class was NULL @ CheckForDebugger");
			return;
		}

		if (AntiDbg->DetectionThread->IsShutdownSignalled())
		{
			Logger::logf("UltimateAnticheat.log", Info, "Shutting down Debugger detection thread with Id: %d", AntiDbg->DetectionThread->GetId());
			//AntiDbg->DetectionThread->CurrentlyRunning = false;
			return; //exit thread
		}

		if (AntiDbg->RunDetectionFunctions())
		{

		}

		////Basic winAPI check
		//bool basicDbg = AntiDbg->_IsDebuggerPresent();

		//if (basicDbg)
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: WINAPI_DEBUGGER");
		//	AntiDbg->Flag(WINAPI_DEBUGGER);
		//}

		//if (AntiDbg->_IsDebuggerPresent_PEB())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: PEB");
		//	AntiDbg->Flag(PEB);
		//}

		//HANDLE HWDebugCheck = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Debugger::AntiDebug::_IsHardwareDebuggerPresent, AntiDbg, 0, 0);

		//if (AntiDbg->_IsDebuggerPresent_HeapFlags())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: HEAP_FLAG");
		//	AntiDbg->Flag(HEAP_FLAG);
		//}

		//if (AntiDbg->_IsKernelDebuggerPresent())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: KERNEL_DEBUGGER");
		//	AntiDbg->Flag(KERNEL_DEBUGGER);
		//}

		//if (AntiDbg->_IsKernelDebuggerPresent_SharedKData())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: KUSER_SHARED_DATA flags");
		//	AntiDbg->Flag(KERNEL_DEBUGGER);
		//}

		//if (AntiDbg->_IsDebuggerPresent_DbgBreak())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: DbgBreak Excpetion Handler");
		//	AntiDbg->Flag(INT3);
		//}

		//if (AntiDbg->_IsDebuggerPresent_VEH()) //also patches over InitializeVEH's first byte if the dll is found
		//{			
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: Cheat Engine VEH");
		//	AntiDbg->Flag(VEH_DEBUGGER);
		//}

		//if (AntiDbg->_IsDebuggerPresent_DebugPort())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: DebugPort");
		//	AntiDbg->Flag(DEBUG_PORT);
		//}

		//if (AntiDbg->_IsDebuggerPresent_ProcessDebugFlags())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: ProcessDebugFlags");
		//	AntiDbg->Flag(PROCESS_DEBUG_FLAGS);
		//}

		//if (AntiDbg->_IsDebuggerPresent_CloseHandle())
		//{
		//	Logger::logf("UltimateAnticheat.log", Detection, "Found debugger: CloseHandle");
		//	AntiDbg->Flag(CLOSEHANDLE);
		//}
		
		if (AntiDbg->DebuggerMethodsDetected.size() > 0)
		{
			Logger::logf("UltimateAnticheat.log", Info, "Atleast one method has caught a running debugger!");
		}	

		Sleep(2000);
	}
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

/*
	PreventWindowsDebuggers - experimental, patches over some common debugging routines
*/
bool Debugger::AntiDebug::PreventWindowsDebuggers()
{
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");

	if (!ntdll)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed to find ntdll.dll @ AntiDebug::PreventWindowsDebuggers");
		return false;
	}

	DWORD dwOldProt = 0;

	UINT64 DbgBreakpoint_Address = (UINT64)GetProcAddress(ntdll, "DbgBreakPoint");
	UINT64 DbgUiRemoteBreakin_Address = (UINT64)GetProcAddress(ntdll, "DbgUiRemoteBreakin");

	if (DbgBreakpoint_Address)
	{
		if (VirtualProtect((LPVOID)DbgBreakpoint_Address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			__try
			{
				*(BYTE*)DbgBreakpoint_Address = 0xC3;
			}
			__except(EXCEPTION_EXECUTE_HANDLER)
			{
				Logger::logf("UltimateAnticheat.log", Err, "Failed to patch over DbgBreakpoint @ AntiDebug::PreventWindowsDebuggers");
				return false;
			}

			VirtualProtect((LPVOID)DbgBreakpoint_Address, 1, dwOldProt, &dwOldProt);
		}
	}

	if (DbgUiRemoteBreakin_Address)
	{
		if (VirtualProtect((LPVOID)DbgUiRemoteBreakin_Address, 1, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			__try
			{
				*(BYTE*)DbgUiRemoteBreakin_Address = 0xC3;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				Logger::logf("UltimateAnticheat.log", Err, "Failed to patch over DbgUiRemoteBreakin @ AntiDebug::PreventWindowsDebuggers");
				return false;
			}

			VirtualProtect((LPVOID)DbgUiRemoteBreakin_Address, 1, dwOldProt, &dwOldProt);
		}
	}

	return true;

}