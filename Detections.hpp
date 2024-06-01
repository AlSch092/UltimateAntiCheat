//By AlSch092 @github
#pragma once
#include "Network/NetClient.hpp"
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Environment/Services.hpp"
#include "Obscure/Obfuscation.hpp"
#include "Common/Globals.hpp"

/*
	The detections class contains a set of static functions to help detect fragments of cheating, along with a thread for looping detections
*/
class Detections
{
public:

	Detections(BOOL StartMonitor, NetClient* client)
	{
		_Services = new Services(FALSE);
		integrityChecker = new Integrity();

		BlacklistedProcesses.push_back(L"Cheat Engine.exe"); //todo: hide these strings
		BlacklistedProcesses.push_back(L"CheatEngine.exe"); //in addition, we can scan for window class names, possible exported functions, specific text inside windows, etc.
		BlacklistedProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");	
		BlacklistedProcesses.push_back(L"x64dbg.exe");
		BlacklistedProcesses.push_back(L"windbg.exe");
		BlacklistedProcesses.push_back(L"Procmon64.exe");

		this->CheaterWasDetected = new ObfuscatedData<uint8_t>((bool)false);

		if (client != nullptr)
			netClient = client;

		if (StartMonitor)
			this->StartMonitor();
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;

		if (MonitorThread != NULL) //by the time this destructor is called the monitorthread should be exited, but adding in a 'thread running' check might still be handy here
			delete MonitorThread;
	}

	NetClient* GetNetClient() { return this->netClient; }

	void SetCheater(BOOL cheating) { this->CheaterWasDetected->SetData((uint8_t)cheating); } //obfuscated bool/int variable. cast to uint8 to avoid getting stuck as 0/1 by compilers bool interpretation
	BOOL IsUserCheater() { return this->CheaterWasDetected->GetData(); }

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	list<ProcessData::Section*>* SetSectionHash(const char* module, const char* sectionName);
	BOOL CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	static void Monitor(LPVOID thisPtr); //activate all -> thread function

	Thread* GetMonitorThread() { return this->MonitorThread; }
	void SetMonitorThread(Thread* h) {  this->MonitorThread = h; }

	Process* GetProcessObj() { return this->_Proc; }
	void SetProcessObj(Process* obj) { this->_Proc = obj; }

	void StartMonitor(); //begin threading

	BOOL IsBlacklistedProcessRunning();

	static BOOL DoesFunctionAppearHooked(const char* moduleName, const char* functionName); //checks for jumps or calls as the first byte on a function
	static BOOL DoesIATContainHooked();
	static BOOL IsTextSectionWritable();
	static bool CheckOpenHandles(); //detect any open handles to our process, very useful since this will detect most external cheats

	void AddDetectedFlag(DetectionFlags f); //add to DetectedFlags without duplicates
	bool Flag(DetectionFlags flag);

private:

	ObfuscatedData<uint8_t>* CheaterWasDetected = NULL; //using bool as the type does not work properly with obfuscation since the compiler uses true/false, so use uint8_t instead and cast to BOOL when needed

	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;

	Thread* MonitorThread = NULL;

	list<wstring> BlacklistedProcesses;

	Process* _Proc = new Process(); //keep track of our sections, loaded modules, etc

	NetClient* netClient = nullptr; //send any detections to the server

	list<DetectionFlags> DetectedFlags;
};