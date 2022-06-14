#pragma once
#include "Process/Process.hpp"
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"

extern "C" __forceinline bool MisleadingFunction(); 
extern "C" void inline_test(); //using macros within masm file

class AntiCheat //main class of the program, or 'hub'. contains all the detection methods
{
public:

	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }

	typedef void (*FunctionTypePtr)();

	inline void ShellcodeTests() { 
			
		byte* buffer = (byte*)"\x53\x47\x82\xEB\x07\x47\x8A\x43\x23\x0F\xFE\xDF";

		DWORD dOldProt = 0;
		VirtualProtect((LPVOID)buffer, 13, PAGE_EXECUTE_READWRITE, &dOldProt);

		for (int i = 0; i < 13; i++) //basic transform of bytes
			buffer[i] = buffer[i] + 1;

		void (*foo)();
		foo = (void(*)())(buffer);
		foo(); //shellcode call

		///Part 2: virtualalloc + shellcode func call

		LPVOID p = VirtualAlloc(NULL, 13, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
				
		if (p != 0)
		{
			printf("&P: %llX\n", &p);
			printf("P: %llX\n", p);

			memcpy(p, buffer, 13);

			foo = (void(*)())(p);
			foo(); //shellcode call
			printf("Called p!\n");

			//...just to check how compilers treat each of these calls
			FunctionTypePtr* foo2 = (void(**)())&p; 
			(*foo2)();  //actually works
			printf("Called foo2: %llX!\n", *foo2);
			
			
			VirtualFree(p, 0, MEM_RELEASE);	 //memory begone
		}
	}


	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

protected:

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();

	Integrity* integrityChecker = new Integrity();
};
