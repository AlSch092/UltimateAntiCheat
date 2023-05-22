#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "PEB.hpp"
#include <stdint.h>
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <list>

using namespace std;

#define MAX_DLLS_LOADED 128
#define MAX_FILE_PATH_LENGTH 256

namespace Module
{
	struct MODULE_DATA
	{
		char fileName[MAX_FILE_PATH_LENGTH];
		MODULEINFO dllInfo;
		HMODULE module;
	};

	struct Section
	{
		string name;
		unsigned int size;
		UINT64 address;

		union {
			DWORD   PhysicalAddress;
			DWORD   VirtualSize;
		} Misc;

		UINT64 PointerToRawData;
		UINT64 PointerToRelocations;
		DWORD NumberOfLinenumbers;
		UINT64 PointerToLinenumbers;
	};
}

class Process
{
public:

	uint32_t GetThisProcessId();
	uint64_t GetBaseAddress();
	uint32_t GetMemorySize();

	bool ProtectProcess(); 
	bool GetProgramSections(string module);

	_MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }

	static BOOL IsProcessElevated();

	void SetElevated(BOOL bElevated) { this->_Elevated = bElevated; }
	BOOL GetElevated() { return this->_Elevated; }

	wstring GetParentName() { return this->_ParentProcessName; }
	uint32_t GetParentId() { return this->_ParentProcessId; }

	void SetParentName(wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(uint32_t id) { this->_ParentProcessId = id; }

	bool ProtectProcessMemory(DWORD processId);

	//set of routines to patch PEB over @ runtime, combining enough of these will break certain analysis tools
	static bool ChangeModuleName(wchar_t* szModule, wchar_t* newName);
	static bool ChangeModuleBase(const wchar_t* szModule, uint64_t moduleBaseAddress);
	static bool ChangeModulesChecksum(const wchar_t* szModule, DWORD checksum);
	static void RemovePEHeader(HANDLE GetModuleBase);
	static void ChangePEEntryPoint(DWORD newEntry);
	static void ChangeImageSize(DWORD newImageSize);
	static void ChangeSizeOfCode(DWORD newSizeOfCode);
	static void ChangeImageBase(UINT64 newImageBase);

	static bool HasExportedFunction(string dllName, string functionName);

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(wstring desiredParent);

	static DWORD GetProcessIdByName(wstring procName);

private:

	//all aspects of a process should be here, preferrably in some order

	_MYPEB* _PEB = new _MYPEB();
	
	//Header* procHeader = new Header(); //process header
	
	list<Module::Section*> _sections;
	
	uint32_t _ProcessId;
	HANDLE _Mutant;

	wstring _ProcessName;
	wstring _WindowClassName;
	wstring _WindowTitle;

	wstring _ParentProcessName;
	uint32_t _ParentProcessId;

	list<Module::MODULE_DATA*> ModuleList;
	list<uint64_t>* ModuleHashes;

	bool _Elevated;
};
