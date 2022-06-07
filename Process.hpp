#pragma once
#include "PEB.hpp"
#include <stdint.h>
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <list>

using namespace std;

#define MAX_DLLS_LOADED 128
#define MAX_FILE_PATH_LENGTH 512

namespace Module
{
	struct MODULE_DATA
	{
		char fileName[MAX_FILE_PATH_LENGTH];
		MODULEINFO dllInfo;
		HMODULE module;
	};
}


class Process
{
public:

	uint32_t GetThisProcessId();

	static void GetBaseAddressByName(DWORD processId, TCHAR* processName);

private:

	//all aspects of a process should be here, preferrably in some order

	pPEB::_MYPEB* _PEB = new pPEB::_MYPEB();
	//Memory* Sections; //todo: some class to represent sections in memory if we can (.text, .data, etc)
	
	uint32_t _ProcessId;
	HANDLE _Mutant;

	string _ProcessName;
	string _WindowClassName;
	string _WindowTitle;

	list<Module::MODULE_DATA*> ModuleList;
};
