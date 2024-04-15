//Process.hpp by Alsch092 @ Github
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "PEB.hpp"
#include "Thread.hpp"
#include "../Logger.hpp"
#include <stdint.h>
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <list>

using namespace std;

#define MAX_DLLS_LOADED 128
#define MAX_FILE_PATH_LENGTH 512

namespace Module
{
	struct MODULE_DATA
	{
		char fileName[MAX_FILE_PATH_LENGTH]; //this could potentially buffer overflow if a large length path is provided, should be changed to dynamic alloc
		MODULEINFO dllInfo;
		HMODULE module;
	};

	struct Section
	{
		string name;
		unsigned int size;
		UINT64 address;

		union 
		{
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
	uint64_t GetBaseAddress(const wchar_t* module);
	uint32_t GetMemorySize();

	bool GetProgramSections(string module); //fills the _sections parameter

	static list<Module::Section*> GetSections(string module);

	_MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }

	static BOOL IsProcessElevated();

	void SetElevated(BOOL bElevated) { this->_Elevated = bElevated; }
	BOOL GetElevated() { return this->_Elevated; }

	wstring GetParentName() { return this->_ParentProcessName; }
	uint32_t GetParentId() { return this->_ParentProcessId; }

	void SetParentName(wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(uint32_t id) { this->_ParentProcessId = id; }

	static bool ChangeModuleName(const wchar_t* szModule, const wchar_t* newName);
	static bool ChangeModuleBase(const wchar_t* szModule, uint64_t moduleBaseAddress);
	static bool ChangeModulesChecksum(const wchar_t* szModule, DWORD checksum);
	static void RemovePEHeader(HANDLE moduleBase);
	static bool ChangePEEntryPoint(DWORD newEntry);
	static bool ChangeImageSize(DWORD newImageSize);
	static bool ChangeSizeOfCode(DWORD newSizeOfCode);
	static bool ChangeImageBase(UINT64 newImageBase);

	static bool HasExportedFunction(string dllName, string functionName);

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(wstring desiredParent);

	static DWORD GetProcessIdByName(wstring procName);

	static UINT64 GetSectionAddress(const char* moduleName, const char* sectionName);

	static BYTE* GetBytesAtAddress(UINT64 address, UINT size);

private:

	_MYPEB* _PEB = new _MYPEB();

	uint32_t _ProcessId;
	HANDLE _Mutant;

	wstring _ProcessName;
	wstring _WindowClassName;
	wstring _WindowTitle;

	wstring _ParentProcessName;
	uint32_t _ParentProcessId;

	list<Module::Section*> _sections;

	list<Module::MODULE_DATA*> ModuleList;
	list<uint64_t>* ModuleHashes;

	bool _Elevated;
};