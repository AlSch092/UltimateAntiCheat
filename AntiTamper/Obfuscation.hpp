#pragma once
#include <iostream>
#include <Windows.h>

/*
this class allows us to call winapi or other library symbolic named funcs without actually referencing the function. if you view the assembly instructions here, you'll get something along 'push 0x554043, call RDI' instead of Call CreateThread or whatever function.
*/
class SymbolicHash
{
public:

	static PDWORD getFunctionAddressByHash(char* library, DWORD hash);
	static DWORD getHashFromString(char* str);

	static HANDLE CreateThread_Hash(LPSECURITY_ATTRIBUTES   lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);

private:

};

class MemoryObfuscator
{
public:


};