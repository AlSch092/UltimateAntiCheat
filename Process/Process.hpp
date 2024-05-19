//Process.hpp by Alsch092 @ Github
#pragma once
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

#define _CRT_SECURE_NO_WARNINGS

#define MAX_DLLS_LOADED 128
#define MAX_FILE_PATH_LENGTH 512

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

namespace ProcessData
{
	struct MODULE_DATA
	{
		wchar_t name[MAX_FILE_PATH_LENGTH];
		MODULEINFO dllInfo;
		HMODULE hModule;
	};

	struct Section
	{
		char name[256];
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

	struct ImportFunction
	{
		HMODULE Module;
		std::string AssociatedModuleName;
		std::string FunctionName;
		UINT64 AddressOfData;
	};

	typedef NTSTATUS(WINAPI* pfnNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

	typedef struct _SYSTEM_HANDLE
	{
		ULONG       ProcessId;
		BYTE        ObjectTypeNumber;
		BYTE        Flags;
		USHORT      Handle;
		PVOID       Object;
		ACCESS_MASK GrantedAccess;
	} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

	typedef struct _SYSTEM_HANDLE_INFORMATION
	{
		ULONG NumberOfHandles;
		SYSTEM_HANDLE Handles[1];
	} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
}

/*
	The `Process` class provides a representation of the current process and provides several static utility functions
	Aspects of a process such as sections, modules, threads, etc are contained in this class
*/
class Process
{
public:

	Process()
	{
		_PEB = new _MYPEB();
		
		if (!FillModuleList())
		{
			Logger::logf("UltimateAnticheat.log", Err, "Unable to traverse loaded modules @ ::Process() .\n");
		}
	}

	~Process()
	{
		for (ProcessData::MODULE_DATA* s : ModuleList)
			delete s;
	}

	uint32_t GetMemorySize();

	static list<ProcessData::Section*>* GetSections(string module);

	_MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }

	static BOOL IsProcessElevated();

	void SetElevated(BOOL bElevated) { this->_Elevated = bElevated; }
	BOOL GetElevated() { return this->_Elevated; }

	wstring GetParentName() { return this->_ParentProcessName; }
	uint32_t GetParentId() { return this->_ParentProcessId; }

	void SetParentName(wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(uint32_t id) { this->_ParentProcessId = id; }

	static bool ChangeModuleName(const wstring szModule, const wstring newName); //these `ChangeXYZ` routines all modify aspects of the NT headers
	static bool ChangeModuleBase(const wchar_t* szModule, uint64_t moduleBaseAddress);
	static bool ChangeModulesChecksum(const wchar_t* szModule, DWORD checksum);
	static bool ChangePEEntryPoint(DWORD newEntry);
	static bool ChangeImageSize(DWORD newImageSize);
	static bool ChangeSizeOfCode(DWORD newSizeOfCode);
	static bool ChangeImageBase(UINT64 newImageBase);
	static bool ChangeNumberOfSections(string module, DWORD newSectionsCount);
	static bool ModifyTLSCallbackPtr(UINT64 NewTLSFunction);
	static void RemovePEHeader(HANDLE moduleBase);

	static bool HasExportedFunction(string dllName, string functionName);

	static FARPROC _GetProcAddress(PCSTR Module, LPCSTR lpProcName); //GetProcAddress without winAPI call

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(wstring desiredParent);

	static DWORD GetProcessIdByName(wstring procName);

	static UINT64 GetSectionAddress(const char* moduleName, const char* sectionName);

	static BYTE* GetBytesAtAddress(UINT64 address, UINT size);

	static DWORD GetModuleSize(HMODULE module);

	static list<ProcessData::ImportFunction*> GetIATEntries(); //start of IAT hook checks

	static list<ProcessData::SYSTEM_HANDLE>* GetProcessHandles(DWORD processId);

	bool FillModuleList();

	static bool IsReturnAddressInModule(UINT64 RetAddr, const wchar_t* module);

private:

	_MYPEB* _PEB = NULL;

	uint32_t _ProcessId = 0;
	HANDLE _Mutant = INVALID_HANDLE_VALUE;

	wstring _ProcessName;
	wstring _WindowClassName;
	wstring _WindowTitle;

	wstring _ParentProcessName;
	uint32_t _ParentProcessId = 0;

	list<ProcessData::Section*> _sections;

	list<ProcessData::MODULE_DATA*> ModuleList; //todo: make routine to fill this member

	bool _Elevated;
};