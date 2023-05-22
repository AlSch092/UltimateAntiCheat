#include "Process.hpp"

#pragma comment(lib, "ImageHlp")

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
                wprintf(L"Base address of %s: %llx\n", processName.c_str(), (UINT64)hMod);
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
    if (this->GetBaseAddress()) //todo: finish this!
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

//returns TRUE if our parameter desiredParent is the same process name as our parent process ID
BOOL Process::CheckParentProcess(wstring desiredParent)
{
    return GetParentProcessId() != GetProcessIdByName(desiredParent) ? 0 : 1;
}

BOOL Process::IsProcessElevated() {

    auto fRet = FALSE;
    auto hToken = (HANDLE)NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }

    return fRet;
}

bool Process::ProtectProcessMemory(DWORD processId)
{
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    
    if (processHandle == NULL)  
        return false;
    
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);

    MEMORY_BASIC_INFORMATION memInfo;
    LPVOID address = systemInfo.lpMinimumApplicationAddress;
    while (VirtualQueryEx(processHandle, address, &memInfo, sizeof(memInfo)) == sizeof(memInfo))
    {
        if (memInfo.State == MEM_COMMIT && memInfo.Type == MEM_PRIVATE)
        {
            DWORD oldProtect;
            if (VirtualProtectEx(processHandle, memInfo.BaseAddress, memInfo.RegionSize, PAGE_READONLY, &oldProtect) == FALSE)
            {
                CloseHandle(processHandle);
                return false;
            }
        }

        address = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + memInfo.RegionSize);
    }

    CloseHandle(processHandle);
    return true;
}

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
            printf("[ERROR] ImageExportDirectory was NULL!\n");
        
        UnMapAndLoad(&LoadedImage);
    }
    else
        printf("MapAndLoad failed: %d\n", GetLastError());
    

    return bFound;
}

bool Process::GetProgramSections(string module)
{
    PIMAGE_SECTION_HEADER sectionHeader;
    HINSTANCE hInst = GetModuleHandleW(NULL);
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS64 pNtH;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS64)((PIMAGE_NT_HEADERS64)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));
    sectionHeader = IMAGE_FIRST_SECTION(pNtH);

    int nSections = pNtH->FileHeader.NumberOfSections;

    for (int i = 0; i < nSections; i++)
    {
        Module::Section* s = new Module::Section();

        s->address = sectionHeader[i].VirtualAddress;
        s->name = string((const char*)sectionHeader[i].Name);
        s->Misc.PhysicalAddress = sectionHeader[i].Misc.PhysicalAddress;
        s->Misc.VirtualSize = sectionHeader[i].Misc.VirtualSize;
        s->PointerToRawData = sectionHeader[i].PointerToRawData;
        s->PointerToRelocations = sectionHeader[i].PointerToRelocations;
        s->NumberOfLinenumbers = sectionHeader[i].NumberOfLinenumbers;
        s->PointerToLinenumbers = sectionHeader[i].PointerToLinenumbers;

        this->_sections.push_back(s);
    }

    return true;
}

bool Process::ChangeModuleName(wchar_t* szModule, wchar_t* newName)
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
            wcscpy(dataEntry->FullDllName.Buffer, newName);
            Found = TRUE;
            wprintf(L"Changed module name from %s to %s!\n", szModule, newName);
            return true;
        }

        f = dataEntry->InMemoryOrderLinks.Flink;
        count++;
    }

    return false;
}


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


void Process::RemovePEHeader(HANDLE GetModuleBase)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleBase;
    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + (DWORD)pDosHeader->e_lfanew);

    if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
        return;

    if (pNTHeader->FileHeader.SizeOfOptionalHeader)
    {
        DWORD Protect;
        WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
        VirtualProtect((void*)GetModuleBase, Size, PAGE_EXECUTE_READWRITE, &Protect);
        RtlZeroMemory((void*)GetModuleBase, Size);
        VirtualProtect((void*)GetModuleBase, Size, Protect, &Protect);
    }
}

void Process::ChangePEEntryPoint(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect = 0;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) return;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH) {

        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.AddressOfEntryPoint;

        if (pEntry)
        {
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_READWRITE, &protect);

            printf("pEntry: %llX\n", (UINT64)pEntry);
            memcpy((void*)&pEntry, (void*)&newEntry, sizeof(DWORD));
            printf("new AddressOfEntryPoint: %llx\n", (long long)pNtH->OptionalHeader.AddressOfEntryPoint);

            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
        }
    }
}


void Process::ChangeImageSize(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) return;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH) {

        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.SizeOfImage;

        VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &protect);

        if (pEntry)
        {
            *(DWORD*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
        }
    }
}

void Process::ChangeSizeOfCode(DWORD newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) return;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH) {

        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.SizeOfCode;

        VirtualProtect((LPVOID)pEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &protect);

        if (pEntry)
        {
            *(DWORD*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
        }
    }
}

void Process::ChangeImageBase(UINT64 newEntry)
{
    PIMAGE_DOS_HEADER pDoH;
    PIMAGE_NT_HEADERS pNtH;
    DWORD protect;
    HINSTANCE hInst = GetModuleHandleW(NULL);

    if (!hInst) return;

    pDoH = (PIMAGE_DOS_HEADER)(hInst);

    pNtH = (PIMAGE_NT_HEADERS)((PIMAGE_NT_HEADERS)((PBYTE)hInst + (DWORD)pDoH->e_lfanew));

    if (pNtH) {

        UINT64 pEntry = (UINT64)&pNtH->OptionalHeader.ImageBase;

        VirtualProtect((LPVOID)pEntry, sizeof(ULONGLONG), PAGE_EXECUTE_READWRITE, &protect);

        if (pEntry)
        {
            *(UINT64*)(pEntry) = newEntry;
            VirtualProtect((LPVOID)pEntry, sizeof(DWORD), protect, &protect);
        }
    }
}

DWORD Process::GetParentProcessId()
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    }
    return ppid;
}

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
