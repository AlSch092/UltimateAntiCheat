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

        typedef void (*FunctionTypePtr)();
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

bool AntiCheat::AllVTableMembersPointToCurrentModule(void* pClass)
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

//this function re-maps the process memory and then checks if someone else has re-re-mapped it by querying page protections
bool AntiCheat::RemapAndCheckPages()
{
    ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(L"UltimateAnticheat.exe");
    bool remap_succeeded = false;

    if (ImageBase)
    {
        __try
        {
            if (!RmpRemapImage(ImageBase)) //re-mapping of image to stop patching, and of course we can easily detect if someone bypasses this
            {
                printf("RmpRemapImage failed.\n");
            }
            else
            {
                printf("Successfully remapped\n");
                remap_succeeded = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            printf("Remapping image failed with an exception, you might need to place this at the top of your code before other security mechanisms are in place\n");
            return false;
        }

        //remapping protects mainly the .text section from writes, which means we should query this section to see if it was changed to writable (re-re-mapping check)
        UINT64 textSection = Process::GetTextSectionAddress(NULL);

        //check page protections, if they're writable then some cheater has re-re-mapped our image to make it write-friendly
        MEMORY_BASIC_INFORMATION mbi = {};

        if (remap_succeeded)
        {
            if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)textSection, &mbi, sizeof(mbi))) //check if someone else re-mapped our process with writable permissions after we remapped it
            {
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED) //after remapping, mbi.Type will be MEM_MAPPED instead of MEM_IMAGE, and memState will be COMMIT instead of RESERVE
                {
                    printf("Cheater! Change back the protections NOW!\n");
                    exit(Error::PAGE_PROTECTIONS_MISMATCH);
                }
            }
            else
            {
                printf("VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
        else //remapping failed for us - check if pages are writable anyway
        {
            if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)textSection, &mbi, sizeof(mbi))) //case where remapping fails but page protections are still tampered (PAGE_EXECUTE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_READONLY
            {
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_RESERVE && mbi.Type == MEM_IMAGE) //if remapping failed, it will still be MEM_IMAGE
                {
                    printf("Cheater! Change back the protections NOW!\n");
                    exit(Error::PAGE_PROTECTIONS_MISMATCH);
                }
            }
            else
            {
                printf("VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
    }
    else
    {
        printf("Imagebase was NULL!\n");
        exit(Error::NULL_MEMORY_REFERENCE);
    }

    return remap_succeeded;
}