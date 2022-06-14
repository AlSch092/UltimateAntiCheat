#pragma once
#include "Process/Process.hpp"
#include "AntiDebug/AntiDebugger.hpp"
#include "AntiTamper/Integrity.hpp"

extern "C" __forceinline bool NoStaticAnalysis(); //we want to make a function which is misleading to decompilers, but still decompiles.
extern "C" void inline_test(); //using macros within masm file

class AntiCheat //main class of the program, or 'hub'. contains all the detection methods
{
public:

	Process* GetProcessObject() { return this->_Proc; }
	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }

	typedef void (*FunctionFunc)();

	inline void ShellcodeTests() { //works now
		
		//NoStaticAnalysis(); 
		
		byte* buffer = (byte*)"\x53\x47\x82\xEB\x07\x47\x8A\x43\x23\x0F\xFE\xDF"; //it would be ideal if some server sent this buffer, thus we could create custom code execution

		DWORD dOldProt = 0;
		VirtualProtect((LPVOID)buffer, 13, PAGE_EXECUTE_READWRITE, &dOldProt);

		for (int i = 0; i < 13; i++) //basic transform of bytes
			buffer[i] = buffer[i] + 1;

		void (*foo)();
		foo = (void(*)())(buffer);
		foo(); //shellcode call

		//VirtualProtect((LPVOID)buffer, 13, PAGE_NOACCESS, &dOldProt);

		///Part 2: virtualalloc + shellcode func call

		LPVOID p = VirtualAlloc(NULL, 13, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		printf("p:%llx\n", p);
		
		if (p != 0)
		{
			printf("&P: %llX\n", &p);
			printf("P: %llX\n", p);

			memcpy(p, buffer, 13);

			foo = (void(*)())(p);
			foo(); //shellcode call
			printf("Called p!\n");

			void (*foo2)() = (void(*)())p; //maybe we can call buffer in some sneaky way inside the virtual mem
			foo2();

			VirtualFree(p, 0, MEM_RELEASE);	 //this will make the memory poof

		}
		
		//we can use virtualalloc to quickly allocate some mem, copy some buffer to it, transform it, then call it and release the mem to help combat attackers as this will only stay in memory for a split-moment
		//...and we can now make this much more complicated! 
		
	}


	inline Integrity* GetIntegrityChecker() { return this->integrityChecker; }

protected:

private:
	
	Process* _Proc = new Process();
	Debugger::AntiDebug* _AntiDebugger = new Debugger::AntiDebug();

	Integrity* integrityChecker = new Integrity();
};
