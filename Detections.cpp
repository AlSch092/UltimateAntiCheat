//By AlSch092 @github
#include "Detections.hpp"

//in an actual game scenario this would be single threaded and included in the game's main execution
void Detections::Monitor(LPVOID thisPtr) 
{
    printf("[INFO] Starting  Detections::Monitor \n");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        printf("[ERROR] Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    list<Module::Section*> sections = Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text

    if (sections.size() == 0)
    {
        printf("[ERROR] Sections size was 0 @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    UINT64 CachedSectionAddress = 0;
    DWORD CachedSectionSize = 0;

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA("UltimateAntiCheat.exe");

    if (ModuleAddr == 0)
    {
        printf("[ERROR] Module couldn't be retrieved @ Detections::Monitor. Aborting execution! (%d)\n", GetLastError());
        return;
    }

    for (Module::Section* s : sections)
    {
        if (s->name == ".text")
        {
            CachedSectionAddress = s->address + ModuleAddr;
            CachedSectionSize = s->size - 100;  //check most of .text section
        }
    }
  
    //Main Monitor Loop, continuous detections go in here
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring)
    {
        if (Monitor->CheckSectionHash(CachedSectionAddress, CachedSectionSize)) //track the .text section for changes -> most expensive CPU-wise
        {
            printf("[DETECTION] Found modified .text section!\n");
            Monitor->SetCheater(true); //report back to server that someone's cheating
        }

        if (Monitor->IsBlacklistedProcessRunning())
        {
            printf("[DETECTION] Found blacklisted process!\n");
            Monitor->SetCheater(true);
        }

        if (Monitor->DoesFunctionAppearHooked("ws2_32.dll", "send") || Monitor->DoesFunctionAppearHooked("ws2_32.dll", "recv"))   //ensure you use this routine on functions that don't have jumps or calls as their first byte
        {
            printf("[DETECTION] networking WINAPI was hooked!\n"); //WINAPI hooks doesn't always determine someone is cheating since AV and other software can write the hooks
            Monitor->SetCheater(true); //..but for simplicity in this project we will set them as a cheater
        }

        Sleep(MonitorLoopMilliseconds);
    }

    printf("[INFO] Stopping  Detections::Monitor \n");
}

list<Module::Section*> Detections::SetSectionHash(const char* module, const char* sectionName) //Currently only scans the program headers/peb (first 0x1000 bytes) -> add parameters for startAddress + size to scan
{
    list<Module::Section*> sections = Process::GetSections(module);

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(module);

    if (sections.size() == 0)
    {
        printf("[ERROR] sections.size() was 0 @ TestMemoryIntegrity\n");
        return sections;
    }

    for (Module::Section* s : sections)
    {
        if (s->name == sectionName)
        {
            list<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size - 100); //check most of .text section

            if (hashes.size() > 0)
            {
                GetIntegrityChecker()->SetMemoryHashList(hashes);
            }
        }
    }

    return sections;
}

bool Detections::CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize)
{
    printf("Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetMemoryHashList())) //compares hash to one gathered previously
    {
        printf("[INFO] Hashes match: Program's .text section appear genuine.\n");
    }
    else
    {
        printf("[DETECTION] .text section of program is modified!\n");
        return true;
    }

    return false;
}

BOOL Detections::IsBlacklistedProcessRunning()
{
    BOOL foundBlacklistedProcess = FALSE;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        printf("Failed to create snapshot of processes. Error code: %d\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) 
    {
        printf("Failed to get first process. Error code:  %d\n", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do 
    {
        for (wstring blacklisted : BlacklistedProcesses)
        {
            if (Utility::wcscmp_insensitive(blacklisted.c_str(), pe32.szExeFile))
            {
                wprintf(L"[DETECTION] Blacklisted : %s\n", pe32.szExeFile);
                foundBlacklistedProcess = true;
                break;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return foundBlacklistedProcess;
}

BOOL Detections::DoesFunctionAppearHooked(const char* moduleName, const char* functionName)
{
    if (moduleName == nullptr || functionName == nullptr)
        return FALSE;

    BOOL FunctionPreambleIsJump = FALSE;

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (hMod == NULL)
    {
        printf("[ERROR] Couldn't fetch module @ Detections::DoesFunctionAppearHooked: %s\n", moduleName);
        return FALSE;
    }

    UINT64 AddressFunction = (UINT64)GetProcAddress(hMod, functionName);

    if (AddressFunction == NULL)
    {
        printf("[ERROR] Couldn't fetch address of function @ Detections::DoesFunctionAppearHooked: %s\n", functionName);
        return FALSE;
    }

    __try
    {
        if (*(BYTE*)AddressFunction == 0xE8 || *(BYTE*)AddressFunction == 0xE9 || *(BYTE*)AddressFunction == 0xEA || *(BYTE*)AddressFunction == 0xEB) //0xEB = short jump, 0xE8 = call X, 0xE9 = long jump, 0xEA = "jmp oper2:oper1"
            FunctionPreambleIsJump = TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE; //couldn't read memory at function
    }

    return FunctionPreambleIsJump;
}

template<class T>
static inline void** Detections::GetVTableArray(T* pClass, int* pSize)  //needs to be re-written : crashes
{
    void** ppVTable = *(void***)pClass;

    if (pSize)
    {
        *pSize = 0;

        while (!IsBadReadPtr(ppVTable[*pSize], sizeof(unsigned __int64)))
            (*pSize)++;
    }

    return ppVTable;
}

bool Detections::IsVTableHijacked(void* pClass) //needs to be checked again when I have time
{
    DWORD dOldProt = 0;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 moduleEntry;


    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE)
        return false;

    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &moduleEntry))
    {
        CloseHandle(hModuleSnap);
        return false;
    }

    UINT_PTR ulBaseAddress = reinterpret_cast<UINT_PTR>(moduleEntry.modBaseAddr);
    UINT_PTR ulBaseSize = moduleEntry.modBaseSize;

    int nMethods;
    void** ppVTable = GetVTableArray(pClass, &nMethods);

    VirtualProtect(ppVTable, nMethods * sizeof(UINT_PTR), PAGE_EXECUTE, &dOldProt);

    CloseHandle(hModuleSnap);

    for (int i = 0; i < nMethods; ++i)
    {
        UINT_PTR ulFuncAddress = reinterpret_cast<UINT_PTR>(ppVTable[i]);
        printf("vTable member points to address: %llX\n", ulFuncAddress);

        if (ulFuncAddress < ulBaseAddress || ulFuncAddress > ulBaseAddress + ulBaseSize)
            return false;
    }

    return true;
}

bool Detections::AllVTableMembersPointToCurrentModule(void* pClass)
{
    DWORD dOldProt = 0;
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 moduleEntry;

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hModuleSnap == INVALID_HANDLE_VALUE)
        return false;

    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (!Module32First(hModuleSnap, &moduleEntry))
    {
        CloseHandle(hModuleSnap);
        return false;
    }

    UINT_PTR ulBaseAddress = reinterpret_cast<UINT_PTR>(moduleEntry.modBaseAddr);
    UINT_PTR ulBaseSize = moduleEntry.modBaseSize;

    int nMethods;
    void** ppVTable = GetVTableArray(pClass, &nMethods);

#ifdef VTABLE_FAKING
    // Allow patching
    VirtualProtect(ppVTable, nMethods * sizeof(UINT_PTR), PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // Now take the next module and set the first VTable pointer to point to an
    // invalid address, outside of the current module's address range
    Module32Next(hModuleSnap, &moduleEntry);
    ppVTable[0] = moduleEntry.modBaseAddr;
#endif

    VirtualProtect(ppVTable, nMethods * sizeof(UINT_PTR), PAGE_EXECUTE, &dOldProt);

    CloseHandle(hModuleSnap);

    for (int i = 0; i < nMethods; ++i)
    {
        UINT_PTR ulFuncAddress = reinterpret_cast<UINT_PTR>(ppVTable[i]);
        printf("vTable member points to address: %llX\n", ulFuncAddress);

        if (ulFuncAddress < ulBaseAddress || ulFuncAddress > ulBaseAddress + ulBaseSize)
            return false;
    }

    return true;
}
