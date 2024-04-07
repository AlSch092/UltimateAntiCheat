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

        if (Monitor->GetIntegrityChecker()->IsUnknownModulePresent()) //authenticode call and check against whitelisted module list
        {
            printf("[DETECTION] Found unsigned dll loaded: We ideally only want verified, signed dlls in our application (which is still subject to spoofing)!\n");
        }

        if (Services::IsMachineAllowingSelfSignedDrivers())
        {
            printf("[DETECTION] Testsigning is enabled! In most cases we don't allow the game/process to continue if testsigning is enabled.\n");
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
        printf("[INFO] Hashes match: Program's .text section appears genuine.\n");
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