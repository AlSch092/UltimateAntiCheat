#include "Process/Process.hpp"

uint32_t Process::GetThisProcessId()
{
	this->_ProcessId = GetCurrentProcessId();
	return this->_ProcessId;
}

uint64_t Process::GetBaseAddress()
{
    TCHAR szProcessName[MAX_PATH] = TEXT("UltimateAnticheat.exe");
    wstring processName = L"UltimateAnticheat.exe";
    DWORD ProcessId = GetCurrentProcessId();

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, ProcessId);

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod),
            &cbNeeded, LIST_MODULES_32BIT | LIST_MODULES_64BIT))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
            if (!_tcsicmp(processName.c_str(), szProcessName)) {
                wprintf(L"Base address of %s: %llx\n", processName.c_str(), hMod);
                CloseHandle(hProcess);
                return (uint64_t)hMod;
            }
        }
    }

    if(hProcess != NULL)
        CloseHandle(hProcess);

    return 0; //unfound case/error
}

uint32_t Process::GetMemorySize() //returns uint32_t value of combined byte size of all mem regions of the process on disk
{
    DWORD dOldProt = 0;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 moduleEntry;

    // Take a snapshot of all modules in the specified process
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE)
        return false;

    // Set the size of the structure before using it
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first module (current process)
    if (!Module32First(hModuleSnap, &moduleEntry))
    {
        CloseHandle(hModuleSnap);
        return false;
    }

    UINT_PTR ulBaseAddress = reinterpret_cast<UINT_PTR>(moduleEntry.modBaseAddr);
    UINT_PTR ulBaseSize = moduleEntry.modBaseSize;

    return (uint32_t)ulBaseSize;
}


/*
Routine to prevent DLL injection and possibly memory writing
..One way of doing this is hooking/patching loadlibrary and other module related routines, this is easily worked around though
*/
bool Process::ProtectProcess()
{
    if (this->GetBaseAddress())
    {
        uint32_t size = this->GetMemorySize();
    }
    else
    {
        printf("Could not protect the process at run time!\n");
        return false;
    }

    return true;
}

