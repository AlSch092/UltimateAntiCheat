#include "Common/Utility.hpp"
#include <tlhelp32.h>
#include <stdio.h>

//thanks to https://stackoverflow.com/questions/2705927/get-specific-process-memory-space, however need to test this thoroughly to make sure it works as intended
bool Utility::IsVTableHijacked(void* pClass) //checks some class ptr's vtable to see if any functions jump outside of this module. sort of neat but unlikely anyone would be hooking here, and if they are it means theyre already leaving other fingerprints
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
