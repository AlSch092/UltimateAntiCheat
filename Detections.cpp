//By AlSch092 @github
#include "Detections.hpp"

//in an actual game scenario this would be single threaded and included in the game's main execution
void Detections::Monitor(LPVOID thisPtr) 
{
    Logger::logf("UltimateAnticheat.log", Info, "Starting  Detections::Monitor \n");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    list<Module::Section*> sections = Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text

    if (sections.size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Sections size was 0 @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    UINT64 CachedSectionAddress = 0;
    DWORD CachedSectionSize = 0;

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA("UltimateAntiCheat.exe");

    if (ModuleAddr == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Module couldn't be retrieved @ Detections::Monitor. Aborting execution! (%d)\n", GetLastError());
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
            Logger::logf("UltimateAnticheat.log", Detection, "Found modified .text section!\n");
            Monitor->SetCheater(true); //report back to server that someone's cheating
        }

        if (Monitor->IsBlacklistedProcessRunning())
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found blacklisted process!\n");
            Monitor->SetCheater(true);
        }

        if (Monitor->DoesFunctionAppearHooked("ws2_32.dll", "send") || Monitor->DoesFunctionAppearHooked("ws2_32.dll", "recv"))   //ensure you use this routine on functions that don't have jumps or calls as their first byte
        {
            Logger::logf("UltimateAnticheat.log", Detection, "networking WINAPI was hooked!\n"); //WINAPI hooks doesn't always determine someone is cheating since AV and other software can write the hooks
            Monitor->SetCheater(true); //..but for simplicity in this project we will set them as a cheater
        }

        if (Monitor->GetIntegrityChecker()->IsUnknownModulePresent()) //authenticode call and check against whitelisted module list
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found unsigned dll loaded : We ideally only want verified, signed dlls in our application!\n");
        }

        if (Services::IsMachineAllowingSelfSignedDrivers())
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Testsigning is enabled! In most cases we don't allow the game/process to continue if testsigning is enabled.\n");
            Monitor->SetCheater(true);
        }

        if (Detections::DoesIATContainHooked())
        {
            Logger::logf("UltimateAnticheat.log", Detection, "IAT was hooked! One or more functions lead to addresses outside their respective modules!\n");
            Monitor->SetCheater(true);
        }

        Sleep(MonitorLoopMilliseconds);
    }

    Logger::logf("UltimateAnticheat.log", Info, "Stopping  Detections::Monitor \n");
}

list<Module::Section*> Detections::SetSectionHash(const char* module, const char* sectionName) //Currently only scans the program headers/peb (first 0x1000 bytes) -> add parameters for startAddress + size to scan
{
    list<Module::Section*> sections = Process::GetSections(module);

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(module);

    if (sections.size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "sections.size() of section %s was 0 @ TestMemoryIntegrity\n", sectionName);
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
    Logger::logf("UltimateAnticheat.log", Info, "Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetMemoryHashList())) //compares hash to one gathered previously
    {
        Logger::logf("UltimateAnticheat.log", Info, "Hashes match: Program's .text section appears genuine.\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Detection, " .text section of program is modified!\n");
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to create snapshot of processes. Error code: %d @ Detections::IsBlacklistedProcessRunning\n", GetLastError());
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to get first process. Error code:  %d @ Detections::IsBlacklistedProcessRunning\n", GetLastError());
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

BOOL Detections::DoesFunctionAppearHooked(const char* moduleName, const char* functionName)
{
    if (moduleName == nullptr || functionName == nullptr)
        return FALSE;

    BOOL FunctionPreambleHooked = FALSE;

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (hMod == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch module @ Detections::DoesFunctionAppearHooked: %s\n", moduleName);
        return FALSE;
    }

    UINT64 AddressFunction = (UINT64)GetProcAddress(hMod, functionName);

    if (AddressFunction == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch address of function @ Detections::DoesFunctionAppearHooked: %s\n", functionName);
        return FALSE;
    }

    __try
    {
        if (*(BYTE*)AddressFunction == 0xE8 || *(BYTE*)AddressFunction == 0xE9 || *(BYTE*)AddressFunction == 0xEA || *(BYTE*)AddressFunction == 0xEB) //0xEB = short jump, 0xE8 = call X, 0xE9 = long jump, 0xEA = "jmp oper2:oper1"
            FunctionPreambleHooked = TRUE;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        Logger::logf("UltimateAnticheat.log", Warning, " Couldn't read bytes @ Detections::DoesFunctionAppearHooked: %s\n", functionName);
        return FALSE; //couldn't read memory at function
    }

    return FunctionPreambleHooked;
}

BOOL Detections::DoesIATContainHooked() //we can collect this info inside the TLS callback then compare later versions against that info to check if somoene has modified the IAT at runtime to outside the regular modules
{
    list<Module::ImportFunction*> IATFunctions = Process::GetIATEntries();




    return FALSE;
}