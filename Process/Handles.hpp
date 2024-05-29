//By AlSch092 @github
#pragma once
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include "../Logger.hpp"

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

namespace Handles
{
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

    bool DoesProcessHaveOpenHandleTous(DWORD pid, std::vector <Handles::SYSTEM_HANDLE> handleList);

#ifdef _DEBUG
    static const wchar_t* Whitelisted[] = { {L"conhost.exe"}, {L"devenv.exe"}, {L"VsDebugConsole.exe"} };
#else
    static const wchar_t* Whitelisted[] = { {L"conhost.exe"} };
#endif
}

