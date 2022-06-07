#pragma once
#include "Process.hpp"
#include "Debug.hpp"
#include "Integrity.hpp"

extern "C" bool NoStaticAnalysis(); //the goal here is to get the compiler to inline our function (although apparently not possible on x64) which breaks the static analysis of REing tools.

class AntiCheat //main class of the program, or 'hub'
{
public:

	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }

	inline static void DestroyStaticAnalysis() { NoStaticAnalysis(); }
	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

protected:

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();

	Integrity* integrityChecker = new Integrity();

};
