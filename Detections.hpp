//By AlSch092 @github
#pragma once
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Environment/Services.hpp"

class Detections
{
public:

	Detections()
	{
		_Services = new Services(false);
		integrityChecker = new Integrity();
	}

	~Detections()
	{
		delete _Services;
		delete integrityChecker;
	}

	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	void StartMonitor(); //activate all

	//Vtable checking
	bool AllVTableMembersPointToCurrentModule(void* pClass); //needs fixing!
	static bool IsVTableHijacked(void* pClass); //needs fixing

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);  //needs fixing

	//winapi hook checking (to do)

private:
	Services* _Services = NULL;
	Integrity* integrityChecker = NULL;
};