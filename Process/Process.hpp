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
		HMODULE hModule = 0;
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
		uintptr_t AddressToFuncPtr;
		uintptr_t AddressOfData;
		uintptr_t FunctionPtr;
	};
}

/*
	The `Process` class provides a representation of the current process and provides several static utility functions
	Aspects of a process such as sections, modules, threads, etc are contained in this class
*/
class Process final
{
public:

	Process(__in const unsigned int nProgramSections) //we manually set number of program sections in order to spoof it at runtime to 0 or 1, and not have the program be confused
	{
		_PEB = new _MYPEB();
		
		if (!FillModuleList())
		{
			Logger::logf(Err, "Unable to traverse loaded modules @ ::Process() .\n");
		}

		DWORD parentPid = GetParentProcessId();

		if (parentPid != 0)
		{
			SetParentName(GetProcessName(parentPid));
			SetParentId(parentPid);
		}
		else
		{
			Logger::logf(Warning, "Could not fetch parent process ID");
		}

		Process::SetNumSections(nProgramSections); //save original # of program sections so that we can modify NumberOfSections in the NT headers and still achieve program functionality
	}

	~Process()
	{
	}

	bool FillModuleList();

	static list<ProcessData::Section> GetSections(__in const string& module);

#ifdef _M_IX86
	static _MYPEB* GetPEB() { return (_MYPEB*)__readfsdword(0x30); }
#else
	static _MYPEB* GetPEB() { return (_MYPEB*)__readgsqword(0x60); }
#endif

	static wstring GetProcessName(__in const DWORD pid);
	static DWORD GetProcessIdByName(__in const wstring procName);
	static list<DWORD> GetProcessIdsByName(__in const wstring procName);

	static DWORD GetParentProcessId();
	static bool CheckParentProcess(__in const wstring desiredParent, __in const bool bShouldCheckSignature);

	wstring GetParentName() const noexcept { return this->_ParentProcessName; }
	uint32_t GetParentId() const noexcept { return this->_ParentProcessId; }

	void SetParentName(__in const wstring parentName) noexcept { if(!parentName.empty()) this->_ParentProcessName = parentName; }
	void SetParentId(__in const uint32_t id) noexcept { this->_ParentProcessId = id; }

	static bool ChangeModuleName(__in const  wstring szModule, __in const  wstring newName); //these `ChangeXYZ` routines all modify aspects of the PEB
	static bool ChangeNumberOfSections(__in const string module, __in const DWORD newSectionsCount);
	
	static bool ModifyTLSCallbackPtr(__in const uintptr_t NewTLSFunction);

	static bool HasExportedFunction(__in const string dllName, __in const string functionName);

	static FARPROC _GetProcAddress(__in const PCSTR Module, __in const  LPCSTR lpProcName); //GetProcAddress without winAPI call

	static uintptr_t GetSectionAddress(__in const char* moduleName, __in const char* sectionName);

	static BYTE* GetBytesAtAddress(__in const uintptr_t address, __in const UINT size);

	static DWORD GetModuleSize(__in const HMODULE module);

	static list<ProcessData::ImportFunction> GetIATEntries(const std::string& module);

	static bool IsReturnAddressInModule(__in const uintptr_t RetAddr, __in const  wchar_t* module);

	static std::vector<ProcessData::MODULE_DATA> GetLoadedModules();

	static ProcessData::MODULE_DATA GetModuleInfo(__in const  wchar_t* name);
	
	static HMODULE GetModuleHandle_Ldr(__in const  wchar_t* moduleName);

	static DWORD GetSectionSize(__in const HMODULE hModule, __in const std::string section);

	static HMODULE GetRemoteModuleBaseAddress(__in const DWORD processId, __in const  wchar_t* moduleName);

	static bool GetRemoteTextSection(__in const HANDLE hProcess, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize);
	static std::vector<BYTE> ReadRemoteTextSection(__in const DWORD pid); //fetch .text of a running process (can improve this by making it any section instead of just .text)

	static int GetNumSections() { return NumSections; }
	static void SetNumSections(__in const unsigned int nSections) { NumSections = nSections; }

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

	list<ProcessData::Section> MainModuleSections;

	list<ProcessData::MODULE_DATA> ModuleList; //todo: make routine to fill this member

	static int NumSections;
	static wstring ExecutableModuleNameW;
};