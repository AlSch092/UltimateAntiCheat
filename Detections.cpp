//By AlSch092 @github
#include "Detections.hpp"

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
            CachedSectionSize = s->size - 1000;  //check most of .text section
        }
    }
  
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring)
    {
        if (Monitor->CheckSectionHash(CachedSectionAddress, CachedSectionSize)) //track the .text section for changes
        {
            Monitor->SetCheater(true); //report back to server that someone's cheating
        }

        if (Monitor->IsBlacklistedProcessRunning())
        {
            printf("Found blacklisted process!\n");
            Monitor->SetCheater(true);
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
            list<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size - 1000); //check most of .text section

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
    printf("Checking: %llx (%d)\n", cachedAddress, cachedSize);

    if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetMemoryHashList())) //compares hash to one gathered previously
    {
        printf("[INFO] Hashes match: Program's .text section appear genuine.\n");
    }
    else
    {
        printf("[DETECTION] .text section of program is modified!\n");
        return true;
    }
}

template<class T>
static inline void** Detections::GetVTableArray(T* pClass, int* pSize)  //needs to be re-written : crashes on debug compilation
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

bool Detections::IsVTableHijacked(void* pClass) //needs to be checked again when I have time, throws errors on debug compile
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

    // Grab the base address and size of our module (the address range where
    // the VTable can validly point to)
    UINT_PTR ulBaseAddress = reinterpret_cast<UINT_PTR>(moduleEntry.modBaseAddr);
    UINT_PTR ulBaseSize = moduleEntry.modBaseSize;

    // Get the VTable array and VTable member count
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

    // Don't allow people to overwrite VTables (can easily be bypassed, so make
    // sure you check the VirtualProtect status of the VTable regularly with
    // VirtualQuery)
    VirtualProtect(ppVTable, nMethods * sizeof(UINT_PTR), PAGE_EXECUTE, &dOldProt);

    // Clean up the snapshot object
    CloseHandle(hModuleSnap);

    // Ensure all VTable pointers are in our current module's address range
    for (int i = 0; i < nMethods; ++i)
    {
        // Get address of the method this VTable pointer points to
        UINT_PTR ulFuncAddress = reinterpret_cast<UINT_PTR>(ppVTable[i]);
        printf("vTable member points to address: %llX\n", ulFuncAddress);
        // Check the address is within our current module range
        if (ulFuncAddress < ulBaseAddress || ulFuncAddress > ulBaseAddress + ulBaseSize)
            return false;
    }

    return true;
}

BOOL Detections::IsBlacklistedProcessRunning()
{
    BOOL foundBlacklistedProcess = FALSE;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        std::cerr << "Failed to create snapshot of processes. Error code: " << GetLastError() << std::endl;
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) 
    {
        std::cerr << "Failed to get first process. Error code: " << GetLastError() << std::endl;
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do 
    {
        for (wstring blacklisted : BlacklistedProcesses)
        {
            if (Utility::wcscmp_insensitive(blacklisted.c_str(), pe32.szExeFile))
            {
                foundBlacklistedProcess = true;
                break;
            }
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return foundBlacklistedProcess;
}