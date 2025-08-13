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
		wstring nameWithPath;
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
	static uintptr_t GetSectionAddress(__in const HMODULE hModule, __in const  char* sectionName);

	static BYTE* GetBytesAtAddress(__in const uintptr_t address, __in const UINT size);

	static DWORD GetModuleSize(__in const HMODULE module);

	static list<ProcessData::ImportFunction> GetIATEntries(const std::string& module);

	static bool IsReturnAddressInModule(__in const uintptr_t RetAddr, __in const  wchar_t* module);

	static std::vector<ProcessData::MODULE_DATA> GetLoadedModules();

	static ProcessData::MODULE_DATA GetModuleInfo(__in const  wchar_t* nameWithPath);
	
	static HMODULE GetModuleHandle_Ldr(__in const  wchar_t* moduleName);

	static DWORD GetSectionSize(__in const HMODULE hModule, __in const std::string section);

	static HMODULE GetRemoteModuleBaseAddress(__in const DWORD processId, __in const  wchar_t* moduleName);

	static bool GetRemoteTextSection(__in const HANDLE hProcess, __out uintptr_t& baseAddress, __out SIZE_T& sectionSize);
	static std::vector<BYTE> ReadRemoteTextSection(__in const DWORD pid); //fetch .text of a running process (can improve this by making it any section instead of just .text)

	static int GetNumSections() { return NumSections; }
	static void SetNumSections(__in const unsigned int nSections) { NumSections = nSections; }

	static wstring GetExecutableModuleName() { return ExecutableModuleNameW; }
	static void SetExecutableModuleName(wstring nameWithPath) { ExecutableModuleNameW = nameWithPath; }

	static std::list<ProcessData::Section> FindNonWritableSections(__in const std::string module);

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

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize, // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // s: PROCESS_IO_PORT_HANDLER_INFORMATION // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask, // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // q: HANDLE // 30
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: PROCESS_HANDLE_TRACING_ENABLE[_EX] or void to disable
	ProcessIoPriority, // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags, // qs: ULONG (MEM_EXECUTE_OPTION_*)
	ProcessTlsInformation, // PROCESS_TLS_INFORMATION // ProcessResourceManagement
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority, // qs: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback, // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]; s: void
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // qs: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation, // s: PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION
	ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable, // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode, // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation, // q: UNICODE_STRING // 60
	ProcessProtectionInformation, // q: PS_PROTECTION
	ProcessMemoryExhaustion, // s: PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation, // s: PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation, // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation, // qs: PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
	ProcessAllowedCpuSetsInformation, // qs: SYSTEM_CPU_SET_INFORMATION[5]
	ProcessSubsystemProcess, // s: void // EPROCESS->SubsystemProcess
	ProcessJobMemoryInformation, // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate, // q: BOOLEAN; s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation, // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation, // qs: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues, // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES_V1
	ProcessPowerThrottlingState, // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessReserved3Information, // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation, // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets, // s: BOOLEAN // 80
	ProcessWakeInformation, // q: PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState, // qs: PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump, // q: ULONG
	ProcessTelemetryCoverage, // q: TELEMETRY_COVERAGE_HEADER; s: TELEMETRY_COVERAGE_POINT
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging, // qs: PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation, // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection, // q: HANDLE
	ProcessDebugAuthInformation, // s: CiTool.exe --device-id // PplDebugAuthorization // since RS4 // 90
	ProcessSystemResourceManagement, // s: PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber, // q: ULONGLONG
	ProcessLoaderDetour, // since RS5
	ProcessSecurityDomainInformation, // q: PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation, // s: PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging, // qs: PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation, // qs: PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation, // s: PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation, // s: PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation, // s: PROCESS_SYSCALL_PROVIDER_INFORMATION // since 20H1 // 100
	ProcessDynamicEHContinuationTargets, // s: PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges, // s: PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange, // since WIN11
	ProcessApplyStateChange,
	ProcessEnableOptionalXStateFeatures, // s: ULONG64 // optional XState feature bitmask
	ProcessAltPrefetchParam, // qs: OVERRIDE_PREFETCH_PARAMETER // App Launch Prefetch (ALPF) // since 22H1
	ProcessAssignCpuPartitions, // HANDLE
	ProcessPriorityClassEx, // s: PROCESS_PRIORITY_CLASS_EX
	ProcessMembershipInformation, // q: PROCESS_MEMBERSHIP_INFORMATION
	ProcessEffectiveIoPriority, // q: IO_PRIORITY_HINT // 110
	ProcessEffectivePagePriority, // q: ULONG
	ProcessSchedulerSharedData, // SCHEDULER_SHARED_DATA_SLOT_INFORMATION // since 24H2
	ProcessSlistRollbackInformation,
	ProcessNetworkIoCounters, // q: PROCESS_NETWORK_COUNTERS
	ProcessFindFirstThreadByTebValue, // PROCESS_TEB_VALUE_INFORMATION
	ProcessEnclaveAddressSpaceRestriction, // since 25H2
	ProcessAvailableCpus, // PROCESS_AVAILABLE_CPUS_INFORMATION
	MaxProcessInfoClass
} PROCESSINFOCLASS;