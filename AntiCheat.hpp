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
#include "Environment/Services.hpp"
#include "Obscure/Obfuscation.hpp"
#include "Obscure/SymbolicHash.hpp"

class AntiCheat
{
public:

	AntiCheat()
	{
		_Proc = new Process();
		_AntiDebugger = new Debugger::AntiDebug();
		integrityChecker = new Integrity();
		_Services = new Services(false);
		Client = new NetClient();
	}

	~AntiCheat()
	{
		delete _Proc;
		delete _AntiDebugger;
		delete integrityChecker;
		delete _Services;
		delete Client;
	}

	Process* GetProcessObject() { return this->_Proc; }	
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }
	NetClient* GetNetworkClient() { return this->Client; }
	Services* GetServiceManager() { return this->_Services; }
	Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	inline void ShellcodeTests();

	bool AllVTableMembersPointToCurrentModule(void* pClass); //needs fixing!
	static bool IsVTableHijacked(void* pClass); //needs fixing

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);  //needs fixing

	static bool RemapAndCheckPages();

	void TestNetworkHeartbeat();
	bool TestMemoryIntegrity();

	bool IsPreventingThreadCreation = false; //used in TLS callback

protected:

private:
	
	Process* _Proc = NULL;
	Debugger::AntiDebug* _AntiDebugger = NULL;
	Integrity* integrityChecker = NULL;
	Services* _Services = NULL;
	NetClient* Client = NULL;
};