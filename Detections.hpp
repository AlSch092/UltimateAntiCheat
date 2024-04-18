//By AlSch092 @github
#pragma once
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Environment/Services.hpp"

class Detections
{
public:

	Detections(bool StartMonitor)
	{
		_Services = new Services(false);
		integrityChecker = new Integrity();

		if (StartMonitor)
			this->StartMonitor();

		BlacklistedProcesses.push_back(L"Cheat Engine.exe"); //these strings can be encrypted for better hiding ability
		BlacklistedProcesses.push_back(L"CheatEngine.exe"); //in addition, we can scan for window class names, possible exported functions, specific text inside windows, etc.
		BlacklistedProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");
		
		BlacklistedProcesses.push_back(L"x64dbg.exe");
		BlacklistedProcesses.push_back(L"windbg.exe");
		BlacklistedProcesses.push_back(L"Procmon64.exe");
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;

		if (MonitorThread != NULL)
			delete MonitorThread;
	}

	void SetCheater(BOOL cheating) { this->CheaterWasDetected = cheating; }
	BOOL IsUserCheater() { return this->CheaterWasDetected; }

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	list<Module::Section*> SetSectionHash(const char* module, const char* sectionName);
	bool CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	static void Monitor(LPVOID thisPtr); //activate all

	Thread* GetMonitorThread() { return this->MonitorThread; }
	void SetMonitorThread(Thread* h) {  this->MonitorThread = h; }

	void StartMonitor() 
	{ 
		Thread* monitorThread = new Thread();
		monitorThread->ShutdownSignalled = false;

		if (MonitorThread == NULL)
		{
			monitorThread->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, 0, &monitorThread->Id);
		}

		if (monitorThread->handle == INVALID_HANDLE_VALUE)
		{
			Logger::logf("UltimateAnticheat.log", Err, " Failed to create monitor thread  @ Detections::StartMonito\n");
			exit(-1);
		}

		this->MonitorThread = monitorThread;
	}

	BOOL IsBlacklistedProcessRunning(); //process checking, can be circumvented easily

	BOOL DoesFunctionAppearHooked(const char* moduleName, const char* functionName); //checks for jumps or calls as the first byte on a function

private:

	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;

	Thread* MonitorThread = NULL;

	BOOL CheaterWasDetected = FALSE;

	list<wstring> BlacklistedProcesses;
};