//Process.hpp by Alsch092 @ Github
#pragma once
#include "PEB.hpp"
#include "Thread.hpp"
#include "Handles.hpp"
#include "../AntiTamper/NAuthenticode.hpp"

#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <list>
#include <ImageHlp.h>

#pragma comment(lib, "ImageHlp")

using namespace std;

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
		wstring baseName;
		wstring name;
		MODULEINFO dllInfo;
		HMODULE hModule;
	};

	struct Section
	{
		string name = "";
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

	Process(__in const int nProgramSections) //we manually set number of program sections in order to spoof it at runtime to 0 or 1, and not have the program be confused
	{
		_PEB = new _MYPEB();
		
		if (!FillModuleList())
		{
			Logger::logf(Err, "Unable to traverse loaded modules @ ::Process() .\n");
		}

		SetParentName(GetProcessName(GetParentProcessId()));

		Process::SetNumSections(nProgramSections); //save original # of program sections so that we can modify NumberOfSections in the NT headers and still achieve program functionality
	}

	~Process()
	{
		for (ProcessData::MODULE_DATA* s : ModuleList)
			if(s != nullptr)
			    delete s;
	}

	bool FillModuleList();

	static list<ProcessData::Section*> GetSections(__in const string module);

#ifdef _M_IX86
	static _MYPEB* GetPEB() { return (_MYPEB*)__readfsdword(0x30); }
#else
	static _MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }
#endif

	static wstring GetProcessName(__in const DWORD pid);
	static DWORD GetProcessIdByName(__in const wstring procName);
	static list<DWORD> GetProcessIdsByName(__in const wstring procName);

	static DWORD GetParentProcessId();
	static BOOL CheckParentProcess(__in const wstring desiredParent, __in const bool bShouldCheckSignature);

	void SetElevated(__in const BOOL bElevated) { this->_Elevated = bElevated; }
	BOOL GetElevated() { return this->_Elevated; }

	wstring GetParentName() const { return this->_ParentProcessName; }
	uint32_t GetParentId() const { return this->_ParentProcessId; }

	void SetParentName(__in const wstring parentName) { this->_ParentProcessName = parentName; }
	void SetParentId(__in const uint32_t id) { this->_ParentProcessId = id; }

	static bool ChangeModuleName(__in const  wstring szModule, __in const  wstring newName); //these `ChangeXYZ` routines all modify aspects of the PEB
	static bool ChangeModuleBase(__in const  wchar_t* szModule, __in const  uint64_t moduleBaseAddress);
	static bool ChangeModulesChecksum(__in const  wchar_t* szModule, __in const DWORD checksum);
	static bool ChangePEEntryPoint(__in const DWORD newEntry);
	static bool ChangeImageSize(__in const DWORD newImageSize);
	static bool ChangeSizeOfCode(__in const DWORD newSizeOfCode);
	static bool ChangeImageBase(__in const UINT64 newImageBase);
	static bool ChangeNumberOfSections(__in const string module, __in const DWORD newSectionsCount);
	
	static bool ModifyTLSCallbackPtr(__in const UINT64 NewTLSFunction);


	static bool HasExportedFunction(__in const string dllName, __in const string functionName);

	static FARPROC _GetProcAddress(__in const PCSTR Module, __in const  LPCSTR lpProcName); //GetProcAddress without winAPI call

	static UINT64 GetSectionAddress(__in const  char* moduleName, __in const  char* sectionName);

	static BYTE* GetBytesAtAddress(__in const UINT64 address, __in const UINT size);

	static DWORD GetModuleSize(__in const HMODULE module);

	static list<ProcessData::ImportFunction*> GetIATEntries(); //start of IAT hook checks

	static bool IsReturnAddressInModule(__in const UINT64 RetAddr, __in const  wchar_t* module);

	static std::vector<ProcessData::MODULE_DATA> GetLoadedModules();
	static ProcessData::MODULE_DATA* GetModuleInfo(__in const  wchar_t* name);
	
	static HMODULE GetModuleHandle_Ldr(__in const  wchar_t* moduleName);

	static DWORD GetTextSectionSize(__in const HMODULE hModule);

	static HMODULE GetRemoteModuleBaseAddress(__in const DWORD processId, __in const  wchar_t* moduleName);

	static bool GetRemoteTextSection(__in const HANDLE hProcess, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize);
	static std::vector<BYTE> ReadRemoteTextSection(__in const DWORD pid); //fetch .text of a running process (can improve this by making it any section instead of just .text)

	static int GetNumSections() { return NumSections; }
	static void SetNumSections(int nSections) { NumSections = nSections; }

	static wstring GetExecutableModuleName() { return ExecutableModuleNameW; }
	static void SetExecutableModuleName(wstring name) { ExecutableModuleNameW = name; }

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

	bool _Elevated = false;

	static int NumSections;
	static wstring ExecutableModuleNameW;
};