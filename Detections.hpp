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
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;
	}

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	static void Monitor(LPVOID thisPtr); //activate all

	list<Module::Section*> SetSectionHash(const char* module, const char* sectionName);
	bool CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	//Vtable checking
	bool AllVTableMembersPointToCurrentModule(void* pClass); //needs fixing!
	static bool IsVTableHijacked(void* pClass); //needs fixing

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);  //needs fixing

	void SetCheater(BOOL cheating) { this->CheaterWasDetected = cheating; }
	BOOL IsUserCheater() { return this->CheaterWasDetected; }

	void StartMonitor()
	{
		MonitorThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, 0, &MonitorThreadId);
	}

private:
	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;

	HANDLE MonitorThread = NULL;
	DWORD MonitorThreadId = 0;

	BOOL CheaterWasDetected = FALSE;
};