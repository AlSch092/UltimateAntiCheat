#include "Process.hpp"
#pragma comment(lib, "ImageHlp")

/*
    GetMemorySize - retrieves memory size of current process module
    returns the size of current process module or 0 if the function fails.
*/
uint32_t Process::GetMemorySize() //returns uint32_t value of combined byte size of all mem regions of the process
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
        return 0;
    }

    UINT_PTR ulBaseAddress = reinterpret_cast<UINT_PTR>(moduleEntry.modBaseAddr);
    UINT_PTR ulBaseSize = moduleEntry.modBaseSize;

    return (uint32_t)ulBaseSize;
}
/*
    CheckParentProcess - checks if the parent process is the process name `desiredParent`
    returns TRUE if our parameter desiredParent is the same process name as our parent process ID
*/
BOOL Process::CheckParentProcess(wstring desiredParent)
{
    if (GetParentProcessId() == GetProcessIdByName(desiredParent))
        return true;
    
    return false;
}

/*
   IsProcessElevated - Check if we are running as administrator
   returns TRUE if the current process is elevated
*/
BOOL Process::IsProcessElevated() 
{
    auto fRet = FALSE;
    auto hToken = (HANDLE)NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) 
    {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) 
    {
        CloseHandle(hToken);
    }

    return fRet;
}

/*
    HasExportedFunction checks a loaded module if it's exported `functionName`. Useful for anti-VEH debuggers, since these generally inject themselves into the process and export initialization routines
    returns   true if `dllName` has `functionName` exported.
*/
bool Process::HasExportedFunction(string dllName, string functionName)
{
    DWORD* dNameRVAs(0); //addresses of export names
    _IMAGE_EXPORT_DIRECTORY* ImageExportDirectory;
    unsigned long cDirSize;
    _LOADED_IMAGE LoadedImage;
    string sName;

    bool bFound = false;

    if (MapAndLoad(dllName.c_str(), NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

        if (ImageExportDirectory != NULL)
        {
            //load list of function names from DLL, the third parameter is an RVA to the data we want
            dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfNames; i++)
            {
                //get RVA 
                sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

                if (strcmp(functionName.c_str(), sName.c_str()) == 0)
                    bFound = true;           
            }
        }
        else
            Logger::log("UltimateAnticheat.log", Err, " ImageExportDirectory was NULL @ Process::HasExportedFunction");
        
        UnMapAndLoad(&LoadedImage);
    }
    else
        Logger::logf("UltimateAnticheat.log", Err, "MapAndLoad failed: %d @ Process::HasExportedFunction \n", GetLastError());
    

    return bFound;
}

/*
    GetSections - gathers a list of ProcessData::Section* from the current process
    returns list<ProcessData::Section*>*, and an empty list if the routine fails
*/
list<ProcessData::Section*>* Process::GetSections(string module)
{
    list<ProcessData::Section*>* Sections = new list<ProcessData::Section*>();

    PIMAGE_SECTION_HEADER sectionHeader;
    HINSTANCE hInst = NULL;  
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS64 pNtH;

    hInst= GetModuleHandleA(module.c_str());
    
    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    if (pDoH == NULL || hInst == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " PIMAGE_DOS_HEADER or hInst was NULL at Process::GetSections\n");
        return Sections;
    }

    pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));
    sectionHeader = IMAGE_FIRST_SECTION(pNtH);

    int nSections = pNtH->FileHeader.NumberOfSections;

    for (int i = 0; i < nSections; i++)
    {
        ProcessData::Section* s = new ProcessData::Section();

        s->address = sectionHeader[i].VirtualAddress;

        strcpy_s(s->name, (const char*)sectionHeader[i].Name);
 
        s->Misc.VirtualSize = sectionHeader[i].Misc.VirtualSize;
        s->size = s->Misc.VirtualSize;
        s->PointerToRawData = sectionHeader[i].PointerToRawData;
        s->PointerToRelocations = sectionHeader[i].PointerToRelocations;
        s->NumberOfLinenumbers = sectionHeader[i].NumberOfLinenumbers;
        s->PointerToLinenumbers = sectionHeader[i].PointerToLinenumbers;

        Sections->push_back(s);
    }

    return Sections;
}

/*
    ChangeModuleName - Modifies the module name of a loaded module at runtime, which might trip up attackers and make certain parts of their code fail. Please see my project "ChangeModuleName" for more details
    requirements: ensure the new module name is the same or less length of the one you are changing or else you need to shift memory properly where all module names are being stored, and requires additions to this code.
    
    returns `true` on success.
*/
bool Process::ChangeModuleName(const wstring szModule, const wstring newName)
{
    PPEB PEB = (PPEB)__readgsqword(0x60);
    _LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;
    bool Found = FALSE;
    int count = 0;

    while (!Found && count < 256) //traverse module list , stops at 256 loops to prevent infinite looping incase szModule isn't found
    {
        PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(dataEntry->FullDllName.Buffer, szModule.c_str()))
        {
            wcscpy_s(dataEntry->FullDllName.Buffer, szModule.size() + 1, newName.c_str()); //..then modify the string modulename to newName
            Found = TRUE;
            return true;
        }

        f = dataEntry->InMemoryOrderLinks.Flink;
        count++;
    }

    return false;
}

/*
    ChangeModuleBase - Changes the DllBase member in the PLDR_DATA_TABLE_ENTRY structure at Ldr->InMemoryOrderLinks. Not confirmed yet if this can trip up attackers, need to do a bit more testing
    returns true on success
*/
bool Process::ChangeModuleBase(const wchar_t* szModule, uint64_t moduleBaseAddress)
{
    PPEB PEB = (PPEB)__readgsqword(0x60);
    _LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;
    bool Found = FALSE;
    int count = 0;

    while (!Found && count < 256)
    {
        PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(dataEntry->FullDllName.Buffer, szModule))
        {
            dataEntry->DllBase = (PVOID)moduleBaseAddress;
            Found = TRUE;
            return true;
        }

        f = dataEntry->InMemoryOrderLinks.Flink;
        count++;
    }

    return false;
}

/*
    ChangeModulesChecksum - Changes the `CheckSum` member in the PLDR_DATA_TABLE_ENTRY structure at Ldr->InMemoryOrderLinks
    returns `true` on success
*/
bool Process::ChangeModulesChecksum(const wchar_t* szModule, DWORD checksum)
{
    PPEB PEB = (PPEB)__readgsqword(0x60);
    _LIST_ENTRY* f = PEB->Ldr->InMemoryOrderModuleList.Flink;
    bool Found = FALSE;
    int count = 0;

    while (!Found && count < 256)
    {
        PLDR_DATA_TABLE_ENTRY dataEntry = CONTAINING_RECORD(f, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr(dataEntry->FullDllName.Buffer, szModule))
        {
            dataEntry->CheckSum = checksum;
            Found = TRUE;
            return true;
        }

        f = dataEntry->InMemoryOrderLinks.Flink;
        count++;
    }

    return false;
}


/*
ChangePEEntryPoint - modifies the `OptionalHeader.AddressOfEntryPoint` in the NT headers to throw off runtime querying by attackers
returns true on success
*/
bool Process::ChangePEEntryPoint(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect = 0;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) 
        return false;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);
    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH) 
    {
        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.AddressOfEntryPoint;

        if (pEntry)
        {
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_READWRITE, &protect);

            __try
            {
                memcpy((void*)&pEntry, (void*)&newEntry, sizeof(DWORD));
                VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
                return false;
            }
        }
    }
    
    return false;
}

/*
ChangeImageSize - modifies the `OptionalHeader.SizeOfImage` in the NT headers to throw off runtime querying by attackers
returns true on success
*/
bool Process::ChangeImageSize(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) 
        return false;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (!pNtH) 
    { 
        Logger::logf("UltimateAnticheat.log", Err, "NTHeader was somehow NULL at ChangeImageSize\n");
        return false;
    }

    UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.SizeOfImage;

    if (!VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &protect))
    {
        Logger::logf("UltimateAnticheat.log", Err, "VirtualProtect failed at ChangeImageSize: %d\n", GetLastError());
        return false;
    }

    if (pEntry)
    {
        __try
        {
            *(DWORD*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect); //reset old protections
            return false;
        }
    }

    return false;
}

/*
    ChangeSizeOfCode - modifies the `OptionalHeader.SizeOfCode` in the NT headers to throw off runtime querying by attackers
    returns true on success
*/
bool Process::ChangeSizeOfCode(DWORD newEntry) //modify the 'sizeofcode' variable in the optionalheader
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) 
        return false;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (!pNtH)
    {
        Logger::logf("UltimateAnticheat.log", Err, " NTHeader was somehow NULL @ ChangeSizeOfCode\n");
        return false;
    }

    UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.SizeOfCode;

    if (!VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &protect))
        return false;

    if (pEntry)
    {
        __try
        {
            *(DWORD*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect); //reset old protections
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect); //reset old protections
            return false;
        }
    }
    
    return false;
}

/*
    ChangeNumberOfSections - changes the number of sections in the NT Headers to `newSectionsCount`, which can stop attackers from traversing sections in our program
    returns true on success
*/
bool Process::ChangeNumberOfSections(string module, DWORD newSectionsCount)
{
    PIMAGE_SECTION_HEADER sectionHeader = 0;
    HINSTANCE hInst = NULL;
    PIMAGE_DOS_HEADER pDoH = 0;
    PIMAGE_NT_HEADERS64 pNtH = 0;

    hInst = GetModuleHandleA(module.c_str());

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    if (pDoH == NULL || hInst == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " PIMAGE_DOS_HEADER or hInst was NULL @ Process::ChangeNumberOfSections");
        return false;
    }

    pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));
    sectionHeader = IMAGE_FIRST_SECTION(pNtH);

    DWORD dwOldProt = 0;

    if (!VirtualProtect((LPVOID)&pNtH->FileHeader.NumberOfSections, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        Logger::logf("UltimateAnticheat.log", Err, " VirtualProtect failed @ Process::ChangeNumberOfSections");
        return false;
    }

    memcpy((void*)&pNtH->FileHeader.NumberOfSections, (void*)&newSectionsCount, sizeof(DWORD));

    if (!VirtualProtect((LPVOID)&pNtH->FileHeader.NumberOfSections, sizeof(DWORD), dwOldProt, &dwOldProt))
    {
        Logger::logf("UltimateAnticheat.log", Err, " VirtualProtect (2nd call) failed @ Process::ChangeNumberOfSections");
        return false;
    }

    return true;
}

/*
    ChangeImageBase - Modifies the `OptionalHeader.ImageBase` variable in the NT headers, which might throw off attackers who query this variable
    returns true on success
*/
bool Process::ChangeImageBase(UINT64 newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) return false;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (!pNtH)
    {
        Logger::logf("UltimateAnticheat.log", Err, "NTHeader was somehow NULL at ChangeImageBase\n");
        return false;
    }

    UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.ImageBase;

    VirtualProtect((LPVOID)pEntry, sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &protect);

    if (pEntry)
    {
        __try
        {
            *(UINT64*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect); //reset old protections
            return false;
        }
    }

    return false;
}

/*
GetParentProcessId - Get the process ID of the parents process
returns the pid of the current process parent process. used to check for illegal launchers (an attacker's launcher code spawned our process, for example)
*/
DWORD Process::GetParentProcessId()
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try 
    {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do 
        {
            if (pe32.th32ProcessID == pid) 
            {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally 
    {
        if (hSnapshot != INVALID_HANDLE_VALUE) 
            CloseHandle(hSnapshot);
    }
    return ppid;
}

/*
    GetProcessIdByName - Get pid given a process name
    returns a DWORD pid if procName is a running process, otherwise returns 0
*/
DWORD Process::GetProcessIdByName(wstring procName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
            if (wcscmp(entry.szExeFile, procName.c_str()) == 0)
                pid = entry.th32ProcessID;
                   
    }

    CloseHandle(snapshot);
    return pid;
}


/*
RemovePEHeader - Experimental method to zero the memory of the NT headers, not recommended in production code but should trip up quite a few tools in theory

*/
void Process::RemovePEHeader(HANDLE moduleBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);

    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return;

    if (pNTHeader->FileHeader.SizeOfOptionalHeader)
    {
        DWORD Protect;
        WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
        VirtualProtect((void*)moduleBase, Size, PAGE_EXECUTE_READWRITE, &Protect);
        RtlZeroMemory((void*)moduleBase, Size);
        VirtualProtect((void*)moduleBase, Size, Protect, &Protect);
    }
}

/*
    GetSectionAddress - Get the address of a named section of the module with the named `moduleName`
    returns a memory address of the section if found, and 0 if no section is found or an error occurs
*/
UINT64 Process::GetSectionAddress(const char* moduleName, const char* sectionName)
{
    HMODULE hModule = GetModuleHandleA(moduleName);

    if (hModule == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Failed to get module handle: %d @ GetSectionAddress\n", GetLastError());
        return 0;
    }

    UINT64 baseAddress = (UINT64)hModule;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Invalid DOS header @ GetSectionAddress.\n");
        return 0;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Invalid NT header @ GetSectionAddress.\n");
        return 0;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)  //the `NumberOfSections` variable can also be modified @ runtime to throw off attackers and prevent section traversal!
    {
        if (strcmp((const char*)pSectionHeader->Name, sectionName) == 0)
        {
            return baseAddress + pSectionHeader->VirtualAddress;
        }

        pSectionHeader++;
    }

    Logger::logf("UltimateAnticheat.log", Warning, ".text section not found.\n");
    return 0;
}

/*
    GetBytesAtAddress - return bytes from an address given `size`.
    returns a BYTE array filled with values from `address` for `size` number of bytes
*/
BYTE* Process::GetBytesAtAddress(UINT64 address, UINT size) //remember to free bytes if not NULL ret
{
    BYTE* memBytes = new BYTE[size];

    __try
    {
        memcpy((void*)memBytes, (void*)address, size);
        return memBytes;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        delete[] memBytes;
        return NULL;
    }
}

/*
    GetIATEntries -Returns a list of ImportFunction* from the program IAT , for later hook checks
    returns a list of ProcessData::ImportFunction* such that lists can be compared for modifications 
*/
list<ProcessData::ImportFunction*> Process::GetIATEntries() 
{
    HMODULE hModule = GetModuleHandleW(NULL);

    if (hModule == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Couldn't fetch module handle @ Process::GetIATEntries ");
        return (list<ProcessData::ImportFunction*>)NULL;
    }

    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;

    if (dosHeader == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Couldn't fetch dosHeader @ Process::GetIATEntries ");
        return (list<ProcessData::ImportFunction*>)NULL;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    list <ProcessData::ImportFunction*> importList;

    while (importDesc->OriginalFirstThunk != 0) 
    {    
        const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

        if (dllName == NULL)
            continue;

        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)hModule + importDesc->FirstThunk);

        while (iat->u1.AddressOfData != 0) 
        {
            ProcessData::ImportFunction* import = new ProcessData::ImportFunction();
            import->AssociatedModuleName = dllName;
            import->Module = GetModuleHandleA(dllName);
            import->AddressOfData = iat->u1.AddressOfData;         
            importList.push_back(import);
            iat++;
        }

        importDesc++;
    }

    return importList;
}

/*
    GetModuleSize - get size of a module at address `hModule`
    returns the size of hModule, and 0 if hModule is invalid or error occurs
*/
DWORD Process::GetModuleSize(HMODULE hModule)
{
    if (hModule == NULL) 
    {
        return 0;
    }

    MODULEINFO moduleInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) 
    {
        return 0;
    }

    DWORD moduleSize = moduleInfo.SizeOfImage;
    return moduleSize;
}

/*
    FillModuleList - fills the `ModuleList` class member with a list of module information
    returns true on success
*/
bool Process::FillModuleList()
{
    HMODULE hModules[256];
    DWORD cbNeeded = 0;

    // Get the module handles for the current process
    if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) 
    {
        if (this->ModuleList.size() >= (cbNeeded / sizeof(HMODULE))) //already filled previously?
            return false;

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) 
        {
            ProcessData::MODULE_DATA* module = new ProcessData::MODULE_DATA();
            
            TCHAR szModuleName[MAX_PATH];
            MODULEINFO moduleInfo;

            if (GetModuleFileNameEx(GetCurrentProcess(), hModules[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) 
            {
                wcscpy_s(module->name, szModuleName);

                module->hModule = hModules[i];

                if (GetModuleInformation(GetCurrentProcess(), hModules[i], &moduleInfo, sizeof(moduleInfo)))
                {
                    module->dllInfo.lpBaseOfDll = moduleInfo.lpBaseOfDll;
                    module->dllInfo.SizeOfImage = moduleInfo.SizeOfImage;
                }
                else
                {
                    Logger::logf("UltimateAnticheat.log", Err, "Unable to parse module information @ Process::FillModuleList");
                    return false;
                }

                this->ModuleList.push_back(module);
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Err, "Unable to parse module named @ Process::FillModuleList");
                return false;
            }
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "EnumProcessModules failed @ Process::FillModuleList");
        return false;
    }

    return true;
}

/*
    ModifyTLSCallbackPtr - changes the program TLS callback at runtime by modifying the data directory ptr (IMAGE_DIRECTORY_ENTRY_TLS)
    returns true on success
*/
bool Process::ModifyTLSCallbackPtr(UINT64 NewTLSFunction)
{
    HMODULE hModule = GetModuleHandle(NULL);
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)((BYTE*)dosHeader + dosHeader->e_lfanew);

    IMAGE_TLS_DIRECTORY* tlsDir = (IMAGE_TLS_DIRECTORY*)((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

    if (tlsDir == nullptr)
        return false;

    DWORD dwOldProt = 0;
    if (VirtualProtect((LPVOID)tlsDir->AddressOfCallBacks, sizeof(UINT64), PAGE_EXECUTE_READWRITE, &dwOldProt))
    {
        __try
        {
            memcpy((void*)(tlsDir->AddressOfCallBacks), (const void*)&NewTLSFunction, sizeof(UINT64));
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to write TLS callback ptr  @ Process::ModifyTLSCallbackPtr");
            return false;
        }
    }

    return false;
}

/*
    _GetProcAddress - Attempt to retrieve address of function of `Module`, given `lpProcName`
    Meant to be used for function lookups without calling GetProcAddress explicitly (may require dynamic analysis instead of static for an attacker)
*/
FARPROC Process::_GetProcAddress(LPCSTR Module, LPCSTR lpProcName)
{
    if (Module == nullptr || lpProcName == nullptr)
        return (FARPROC)NULL;

    DWORD* dNameRVAs(0); //array: addresses of export names
    DWORD* dFunctionRVAs(0);
    WORD* dOrdinalRVAs(0);

    _IMAGE_EXPORT_DIRECTORY* ImageExportDirectory = NULL;
    unsigned long cDirSize = 0;
    _LOADED_IMAGE LoadedImage;
    char* sName = NULL;

    UINT64 AddressFound = NULL;

    UINT64 ModuleBase = (UINT64)GetModuleHandleA(Module); //last remaining artifacts for detection. TODO: Use PEB to fetch this instead of API

    if (ModuleBase == NULL)
        return NULL;

    if (MapAndLoad(Module, NULL, &LoadedImage, TRUE, TRUE))
    {
        ImageExportDirectory = (_IMAGE_EXPORT_DIRECTORY*)ImageDirectoryEntryToData(LoadedImage.MappedAddress, false, IMAGE_DIRECTORY_ENTRY_EXPORT, &cDirSize);

        if (ImageExportDirectory != NULL)
        {
            dNameRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNames, NULL);
            dFunctionRVAs = (DWORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfFunctions, NULL);
            dOrdinalRVAs = (WORD*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, ImageExportDirectory->AddressOfNameOrdinals, NULL);

            for (size_t i = 0; i < ImageExportDirectory->NumberOfFunctions; i++)
            {
                sName = (char*)ImageRvaToVa(LoadedImage.FileHeader, LoadedImage.MappedAddress, dNameRVAs[i], NULL);

                if (strcmp(sName, lpProcName) == 0)
                {
                    AddressFound = ModuleBase + dFunctionRVAs[dOrdinalRVAs[i]];
                    break;
                }
            }
        }
        else
        {
            Logger::logf("UltimateAnticheat.log", Err, "ImageExportDirectory was NULL @ Process::_GetProcAddress with module %s and function %s", Module, lpProcName);
            UnMapAndLoad(&LoadedImage);
            return NULL;
        }

        UnMapAndLoad(&LoadedImage);
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "MapAndLoad failed @ Process::_GetProcAddress with module %s and function %s", Module, lpProcName);
        return (FARPROC)NULL;
    }

    return (FARPROC)AddressFound;
}

/*
    GetProcessHandles - fetches all open handles from the current process as a list<> object
    returns a list of PSYSTEM_HANDLE_INFORMATION on success, nullptr on failure
*/
list<ProcessData::SYSTEM_HANDLE>* Process::GetProcessHandles(DWORD processId)
{
    if (processId == 0)
        return nullptr;

    list<ProcessData::SYSTEM_HANDLE>* HandleList = new list<ProcessData::SYSTEM_HANDLE>();

    HMODULE hNtDll = GetModuleHandle(TEXT("ntdll.dll"));
    if (hNtDll == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to get handle to ntdll.dll @ GetProcessHandles");
        delete HandleList;
        return nullptr;
    }

    ProcessData::pfnNtQuerySystemInformation pNtQuerySystemInformation = (ProcessData::pfnNtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to get address of NtQuerySystemInformation @ GetProcessHandles");
        delete HandleList;
        return nullptr;
    }

    ULONG bufferSize = 0x10000; // Start with a 64KB buffer
    ProcessData::PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    NTSTATUS status = 0;

    do 
    {
        pHandleInfo = (ProcessData::PSYSTEM_HANDLE_INFORMATION)realloc(pHandleInfo, bufferSize);
        if (pHandleInfo == NULL)
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to allocate memory @ GetProcessHandles");
            delete HandleList;
            return nullptr;
        }

        // Query system handle information
        status = pNtQuerySystemInformation(SystemHandleInformation, pHandleInfo, bufferSize, &bufferSize);
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (status != 0) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "NtQuerySystemInformation failed: 0x%08X\n", status);
        free(pHandleInfo);
        delete HandleList;
        return nullptr;
    }

    int nHandles = 0;

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i) 
    {
        if (pHandleInfo->Handles[i].ProcessId == GetCurrentProcessId())
        {
            HandleList->push_back(pHandleInfo->Handles[i]);
            nHandles++;
        }
    }

    free(pHandleInfo);
    return HandleList;
}

/*
    IsReturnAddressInModule - returns true if RetAddr is module's mem region
    Used to detect attackers calling our functions such as heartbeat generation, since they may try to spoof or emulate the net client
*/
bool Process::IsReturnAddressInModule(UINT64 RetAddr, const wchar_t* module)
{
    if (RetAddr == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "RetAddr was 0 @ : Process::IsReturnAddressInModule");
        return false;
    }

    HMODULE retBase = 0;

    if (module == NULL)
    {
        retBase = (HMODULE)GetModuleHandleW(NULL);
    }
    else
    {
        retBase = (HMODULE)GetModuleHandleW(module);
    }

    DWORD size = Process::GetModuleSize(retBase);

    if (size == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "size was 0 @ : Process::IsReturnAddressInModule");
        return false;
    }

    if (RetAddr >= (UINT64)retBase && RetAddr < ((UINT64)retBase + size))
    {
        return true;
    }

    return false;
}