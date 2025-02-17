//Process.hpp by Alsch092 @ Github
#pragma once
#include "PEB.hpp"
#include "Thread.hpp"
#include "Handles.hpp"
#include <string>
#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <list>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")

using namespace std;

#define EXPECTED_SECTIONS 6 //change this to however many sections your program has by default. if your program adds/removes sections, you'll need to do further tracking

#define MAX_DLLS_LOADED 128
#define MAX_FILE_PATH_LENGTH 512

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

namespace ProcessData
{
	typedef enum _PROCESS_INFORMATION_CLASS 
	{
		ProcessMemoryPriority,
		ProcessMemoryExhaustionInfo,
		ProcessAppMemoryInfo,
		ProcessInPrivateInfo,
		ProcessPowerThrottling,
		ProcessReservedValue1,
		ProcessTelemetryCoverageInfo,
		ProcessProtectionLevelInfo,
		ProcessLeapSecondInfo,
		ProcessMachineTypeInfo,
		ProcessOverrideSubsequentPrefetchParameter,
		ProcessMaxOverridePrefetchParameter,
		ProcessInformationClassMax
	} PROCESS_INFORMATION_CLASS;

	struct MODULE_DATA
	{
		wchar_t baseName[MAX_FILE_PATH_LENGTH/2];
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
}

/*
	The `Process` class provides a representation of the current process and provides several static utility functions
	Aspects of a process such as sections, modules, threads, etc are contained in this class
*/
class Process final
{
public:

	Process(int nProgramSections) //we manually set number of program sections in order to spoof it at runtime to 0 or 1, and not have the program be confused
	{
		_PEB = new _MYPEB();
		
		if (!FillModuleList())
		{
			Logger::logf(Err, "Unable to traverse loaded modules @ ::Process() .\n");
		}

		SetParentName(GetProcessName(GetParentProcessId()));
		SetElevated(IsProcessElevated());

		NumberOfSections = nProgramSections; //save original # of program sections so that we can modify NumberOfSections in the NT headers and still achieve program functionality
	}

	~Process()
	{
		for (ProcessData::MODULE_DATA* s : ModuleList)
			delete s;
	}

	bool FillModuleList();

	uint32_t GetMemorySize();

	static list<ProcessData::Section*>* GetSections(string module);

#ifdef _M_IX86
	static _MYPEB* GetPEB() { return (_MYPEB*)__readfsdword(0x30); }
#else
	static _MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }
#endif

	static wstring GetProcessName(DWORD pid);
	static DWORD GetProcessIdByName(wstring procName);
	static list<DWORD> GetProcessIdsByName(wstring procName);

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(wstring desiredParent);

	static BOOL IsProcessElevated();

	void SetElevated(BOOL bElevated) { this->_Elevated = bElevated; }
	BOOL GetElevated() { return this->_Elevated; }

	wstring GetParentName() { return this->_ParentProcessName; }
	uint32_t GetParentId() { return this->_ParentProcessId; }

	void SetParentName(wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(uint32_t id) { this->_ParentProcessId = id; }

	static bool ChangeModuleName(const wstring szModule, const wstring newName); //these `ChangeXYZ` routines all modify aspects of the PEB
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

	static UINT64 GetSectionAddress(const char* moduleName, const char* sectionName);

	static BYTE* GetBytesAtAddress(UINT64 address, UINT size);

	static DWORD GetModuleSize(HMODULE module);

	static list<ProcessData::ImportFunction*> GetIATEntries(); //start of IAT hook checks

	static bool IsReturnAddressInModule(UINT64 RetAddr, const wchar_t* module);

	static std::vector<ProcessData::MODULE_DATA> GetLoadedModules();
	static ProcessData::MODULE_DATA* GetModuleInfo(const wchar_t* name);
	
	static HMODULE GetModuleHandle_Ldr(const wchar_t* moduleName);

	int SetNumberOfSections(int nSections) { this->NumberOfSections = nSections; }
	int GetNumberOfSections() { return this->NumberOfSections; }

	static DWORD GetTextSectionSize(HMODULE hModule);

	static HMODULE GetRemoteModuleBaseAddress(DWORD processId, const wchar_t* moduleName);

	static bool GetRemoteTextSection(HANDLE hProcess, uintptr_t& baseAddress, SIZE_T& sectionSize);
	static std::vector<BYTE> ReadRemoteTextSection(DWORD pid);

private:

	_MYPEB* _PEB = NULL;

	uint32_t _ProcessId = 0;

	wstring _ProcessName;
	wstring _WindowClassName;
	wstring _WindowTitle;

	wstring _ParentProcessName;
	uint32_t _ParentProcessId = 0;

	list<ProcessData::Section*> _sections;

	list<ProcessData::MODULE_DATA*> ModuleList; //todo: make routine to fill this member

	bool _Elevated;

	int NumberOfSections = 0;
};