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
#include "Process/Process.hpp"
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"
#include "Services.hpp"
#include "Obfuscation.hpp"
#include "Process/Memory/remap.hpp"

extern "C" __forceinline bool MisleadingFunction(); //the goal here is to get the compiler to inline our function (although apparently not possible on x64) which breaks the static analysis of REing tools.
extern "C" void inline_test(); //using macros within masm file

class AntiCheat //main class of the program, or 'hub'. contains all the detection methods
{
public:

	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }

	typedef void (*FunctionTypePtr)();

	inline void ShellcodeTests();

	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

	static bool IsVTableHijacked(void* pClass);

	template<class T>
	static inline void** GetVTableArray(T* pClass, int* pSize);

protected:

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();

	Integrity* integrityChecker = new Integrity();
};
