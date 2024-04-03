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

		BlacklistedProcesses.push_back(L"Cheat Engine.exe");
		BlacklistedProcesses.push_back(L"CheatEngine.exe");
		BlacklistedProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");
		
		BlacklistedProcesses.push_back(L"x64dbg.exe");
		BlacklistedProcesses.push_back(L"windbg.exe");
		BlacklistedProcesses.push_back(L"Procmon64.exe");
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;
	}

	void SetCheater(BOOL cheating) { this->CheaterWasDetected = cheating; }
	BOOL IsUserCheater() { return this->CheaterWasDetected; }

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	list<Module::Section*> SetSectionHash(const char* module, const char* sectionName);
	bool CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	//Vtable checking
	bool AllVTableMembersPointToCurrentModule(void* pClass); //needs fixing!
	static bool IsVTableHijacked(void* pClass); //needs fixing

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);  //needs fixing

	static void Monitor(LPVOID thisPtr); //activate all

	HANDLE GetMonitorThread() { return this->MonitorThread; }
	void SetMonitorThread(HANDLE h) { this->MonitorThread = h; }

	void StartMonitor() 
	{ 
		if(MonitorThread == NULL)
			MonitorThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, 0, &MonitorThreadId);  
	}

	BOOL IsBlacklistedProcessRunning();

private:

	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;

	HANDLE MonitorThread = NULL;
	DWORD MonitorThreadId = 0;

	BOOL CheaterWasDetected = FALSE;

	list<wstring> BlacklistedProcesses;
};