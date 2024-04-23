//By AlSch092 @github
#pragma once
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Environment/Services.hpp"
#include "Obscure/Obfuscation.hpp"

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

		this->CheaterWasDetected = new ProtectedData<uint8_t>((bool)false);
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;

		if (MonitorThread != NULL)
			delete MonitorThread;
	}

	void SetCheater(BOOL cheating) { this->CheaterWasDetected->SetData(cheating); }
	BOOL IsUserCheater() { return this->CheaterWasDetected->GetData(); }

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	list<Module::Section*> SetSectionHash(const char* module, const char* sectionName);
	bool CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	static void Monitor(LPVOID thisPtr); //activate all

	Thread* GetMonitorThread() { return this->MonitorThread; }
	void SetMonitorThread(Thread* h) {  this->MonitorThread = h; }

	void StartMonitor() 
	{ 
		Thread* t = new Thread();
		t->ShutdownSignalled = false;

		if (MonitorThread == NULL)
		{
			t->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, 0, &t->Id);
		}

		if (t->handle == INVALID_HANDLE_VALUE || t->handle == NULL)
		{
			Logger::logf("UltimateAnticheat.log", Err, " Failed to create monitor thread  @ Detections::StartMonito\n");
			exit(-1);
		}

		this->MonitorThread = t;
	}

	BOOL IsBlacklistedProcessRunning(); //process checking, can be circumvented easily
	BOOL DoesFunctionAppearHooked(const char* moduleName, const char* functionName); //checks for jumps or calls as the first byte on a function
	static BOOL DoesIATContainHooked();

private:

	ProtectedData<uint8_t>* CheaterWasDetected = NULL; //using bool as the type does not work properly with obfuscation since the compiler uses true/false, so use uint8_t instead and cast to BOOL when needed

	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;

	Thread* MonitorThread = NULL;

	list<wstring> BlacklistedProcesses;
};