//By AlSch092 @github
#pragma once
#include <windows.h>
#include <iostream>
#include <vector>
#include "../Common/Logger.hpp"
#include "../Process/Process.hpp"

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

namespace Handles
{
    typedef enum _SYSTEM_INFORMATION_CLASS 
    {
        SystemBasicInformation = 0,
        SystemPerformanceInformation = 2,
        SystemTimeOfDayInformation = 3,
        SystemProcessInformation = 5,
        SystemProcessorPerformanceInformation = 8,
        SystemInterruptInformation = 23,
        SystemExceptionInformation = 33,
        SystemRegistryQuotaInformation = 37,
        SystemLookasideInformation = 45
    } SYSTEM_INFORMATION_CLASS;

    typedef NTSTATUS(NTAPI* NtQuerySystemInformationFunc)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    typedef struct _SYSTEM_HANDLE
    {
        ULONG ProcessId;
        BYTE ObjectTypeNumber;
        BYTE Flags;
        USHORT Handle;
        PVOID Object;
        ACCESS_MASK GrantedAccess;
        BOOL ReferencingOurProcess; //my own addition to the structure, we fill this member in ::DetectOpenHandlesToProcess
    } SYSTEM_HANDLE, * PSYSTEM_HANDLE;

    typedef struct _SYSTEM_HANDLE_INFORMATION
    {
        ULONG HandleCount;
        SYSTEM_HANDLE Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    std::vector<SYSTEM_HANDLE> GetHandles();
    std::vector<SYSTEM_HANDLE>  DetectOpenHandlesToProcess();

    bool DoesProcessHaveOpenHandleToUs(DWORD pid, std::vector <Handles::SYSTEM_HANDLE> handleList);

#ifdef _DEBUG //in addition to checking process names, we should check the file's certificate to ensure a whitelisted process can't be spoofed to obtain a whitelisted handle
    static const wchar_t* Whitelisted[] = { {L"conhost.exe"}, {L"devenv.exe"}, {L"VsDebugConsole.exe"} }; //on different people's PC's, different processes might be opening handles to our process. 
#else
    static const wchar_t* Whitelisted[] = { {L"conhost.exe"} }; //non-console version of this project will be different and conhost should not be considered whitelisted 
#endif
}
