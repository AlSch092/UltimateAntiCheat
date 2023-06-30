#pragma once
// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#include <iostream>
#include "Network/NetClient.hpp"
#include "Process/Process.hpp"
#include "Process/Exports.hpp" //added June 30, 2023
#include "Process/Memory/remap.hpp" //added March 2023 or so
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Services.hpp"
#include "Obfuscation.hpp"

class AntiCheat //contains all the sub-classes for detection goals
{
public:

	NetClient* GetNetworkClient() { return this->Client; }
	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }
	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	typedef void (*FunctionTypePtr)();
	inline void ShellcodeTests(); //can/should be removed after done testing

	bool AllVTableMembersPointToCurrentModule(void* pClass);
	static bool IsVTableHijacked(void* pClass);

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();
	Integrity* integrityChecker = new Integrity();
	NetClient* Client = new NetClient();
};
