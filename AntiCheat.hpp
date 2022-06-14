#pragma once
#include "Process/Process.hpp"
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"

extern "C" __inline bool MisleadingProc(); //make a function which can be decompiled but gives a completely wrong result


class AntiCheat //main class of the program, or 'hub'. contains all the detection methods
{
public:

	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }
	
	inline void ShellcodeProc() { 
		
		NoStaticAnalysis(); 
		
		byte* buffer = (byte*)"\x53\x47\x82\xEB\x07\x47\x8A\x43\x23\x0F\xFE\xDF";
		// push rsp 
		// sub rsp, 8
		// mov rsp, [rax+10h]
		// jmp rax
		
		DWORD dOldProt = 0;
		VirtualProtect((LPVOID)buffer, 13, PAGE_EXECUTE_READWRITE, &dOldProt);

		for (int i = 0; i < 13; i++)
		{
			buffer[i] = buffer[i] + 1;
		}

		printf("Transformed bytes!\n");

		void (*foo)();
		foo = (void(*)())(buffer);
		foo();
	}


	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

protected:

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();

	Integrity* integrityChecker = new Integrity();
};
