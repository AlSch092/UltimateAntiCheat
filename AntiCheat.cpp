#include "AntiCheat.hpp"

void AntiCheat::ShellcodeTests()
{
	//NoStaticAnalysis(); 

	byte* buffer = (byte*)"\x53\x47\x82\xEB\x07\x47\x8A\x43\x23\x0F\xFE\xDF"; //will be executed as a function, is 'unpacked' at runtime

	DWORD dOldProt = 0;
	VirtualProtect((LPVOID)buffer, sizeof(buffer), PAGE_EXECUTE_READWRITE, &dOldProt);

	for (int i = 0; i < sizeof(buffer); i++) //basic transform of bytes, add 1 to each
		buffer[i] = buffer[i] + 1;

	void (*foo)();
	foo = (void(*)())(buffer);
	foo(); //shellcode call

	///Part 2: virtualalloc + shellcode func call

	LPVOID p = VirtualAlloc(NULL, 13, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (p != 0)
	{
		memcpy(p, buffer, 13);

		foo = (void(*)())(p);
		foo(); //shellcode call

		FunctionTypePtr* foo2 = (void(**)()) & p; //same as above line technically
		(*foo2)(); //just to check how compilers treat each of these calls
		//the above actually works just fine 

		printf("Called foo2: %p!\n", *foo2);

		VirtualFree(p, 0, MEM_RELEASE);	 //memory begone
	}
	
}

template<class T>
static inline void** AntiCheat::GetVTableArray(T* pClass, int* pSize) 
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

bool AntiCheat::IsVTableHijacked(void* pClass) //checks some class ptr's vtable to see if any functions jump outside of this module. sort of neat but unlikely anyone would be hooking here, and if they are it means theyre already leaving other fingerprints
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
