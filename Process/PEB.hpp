//By AlSch092 @ Github
#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include "../Logger.hpp"

#ifdef _WIN64
#define IS_64_BIT 1
#else
#define IS_64_BIT 0
#endif

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct MY_PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	PVOID ShutdownThreadId;
} MY_PEB_LDR_DATA, * MY_PPEB_LDR_DATA;

typedef enum _LDR_DLL_LOAD_REASON 
{
	LoadReasonStaticDependency,
	LoadReasonStaticLoad,
	LoadReasonDynamicLoad,
	LoadReasonAsImageLoad,
	LoadReasonAsDataLoad,
	LoadReasonEnclavePrimary,
	LoadReasonEnclaveDependency,
	LoadReasonPatchImage,
	LoadReasonUnknownReason = -1
} LDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	// Windows 10 specific fields
	PVOID LoadedImports;
	PVOID EntryPointActivationContext; // Since Windows 10 1607 (Anniversary Update)
	PVOID PatchInformation;
	LDR_DLL_LOAD_REASON LoadReason;
} MY_LDR_DATA_TABLE_ENTRY, * MY_PLDR_DATA_TABLE_ENTRY;

typedef struct _MYPEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	MY_PEB_LDR_DATA* Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID FastPebLockRoutine;
	PVOID FastPebUnlockRoutine;
	ULONG EnvironmentUpdateCount;
	PVOID* KernelCallbackTable;
	PVOID EventLogSection;
	PVOID EventLog;
	PVOID FreeList;
	ULONG TlsExpansionCounter;
	PVOID TlsBitmap;
	ULONG TlsBitmapBits[0x2];
	PVOID ReadOnlySharedMemoryBase;
	PVOID ReadOnlySharedMemoryHeap;
	PVOID* ReadOnlyStaticServerData;
	PVOID AnsiCodePageData;
	PVOID OemCodePageData;
	PVOID UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	UCHAR Spare2[0x4];
	ULARGE_INTEGER CriticalSectionTimeout;
	ULONG HeapSegmentReserve;
	ULONG HeapSegmentCommit;
	ULONG HeapDeCommitTotalFreeThreshold;
	ULONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	PVOID** ProcessHeaps;
	PVOID GdiSharedHandleTable;
	PVOID ProcessStarterHelper; //PPS_POST_PREOCESS_INIT_ROUTINE?
	PVOID GdiDCAttributeList;
	PVOID LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	ULONG OSBuildNumber;
	ULONG OSPlatformId;
	ULONG ImageSubSystem;
	ULONG ImageSubSystemMajorVersion;
	ULONG ImageSubSystemMinorVersion;
	ULONG GdiHandleBuffer[0x22];
	PVOID ProcessWindowStation;
} MYPEB, * PMYPEB;

#if IS_64_BIT
UINT64 GetPEBPointerAddress();
PVOID GetPEBAddress();
void SetPEBAddress(UINT64 address);
#else
PVOID GetPEBAddress();
void SetPEBAddress(DWORD address);
#endif

BYTE* CopyPEBBytes(unsigned int pebSize);
BYTE* CopyAndSetPEB();


