//By AlSch092 @github
#include "Detections.hpp"

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