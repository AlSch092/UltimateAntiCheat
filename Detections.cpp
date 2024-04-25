//By AlSch092 @github
#include "Detections.hpp"

//in an actual game scenario this would be single threaded and included in the game's main execution
void Detections::Monitor(LPVOID thisPtr)
{
    if (thisPtr == NULL)
        return;

    Logger::logf("UltimateAnticheat.log", Info, "Starting  Detections::Monitor \n");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    list<Module::Section*>* sections = Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text

    if (sections->size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Sections size was 0 @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    UINT64 CachedSectionAddress = 0;
    DWORD CachedSectionSize = 0;

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA("UltimateAnticheat.exe");

    if (ModuleAddr == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Module couldn't be retrieved @ Detections::Monitor. Aborting execution! (%d)\n", GetLastError());
        return;
    }

    std::list<Module::Section*>::iterator it;

    for (it = sections->begin(); it != sections->end(); ++it)
    {
        Module::Section* s = it._Ptr->_Myval;

        if (s == nullptr)
            continue;

        if (strcmp(s->name, ".text") == 0)
        {
            CachedSectionAddress = s->address + ModuleAddr;
            CachedSectionSize = s->size - 100;
            break;
        }
    }

    //Main Monitor Loop, continuous detections go in here. we need access to CachedSectionAddress variables so this loop doesnt get its own function.
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring && !Monitor->IsUserCheater())
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

/*
SetSectionHash sets the member variable `_MemorySectionHashes` via SetMemoryHashList() call after finding the `sectionName` named section (.text in our case)
 Returns a list<Section*>  which we can use in later hashing calls to compare sets of these hashes and detect memory tampering within the section
*/
list<Module::Section*>* Detections::SetSectionHash(const char* moduleName, const char* sectionName)
{
    if (moduleName == NULL)
    {
        return nullptr;
    }

    list<Module::Section*>* sections = Process::GetSections(moduleName);
    
    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(moduleName);

    if (ModuleAddr == 0)
    {
        return nullptr;
    }

    if (sections->size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "sections.size() of section %s was 0 @ TestMemoryIntegrity\n", sectionName);
        return sections;
    }


    std::list<Module::Section*>::iterator it;

    for (it = sections->begin(); it != sections->end(); ++it) 
    {
        Module::Section* s = it._Ptr->_Myval;

        if (s == nullptr)
            continue;

        if (strcmp(s->name, sectionName) == 0)
        {
            list<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size - 100); //check most of .text section

            if (hashes.size() > 0)
            {
                GetIntegrityChecker()->SetMemoryHashList(hashes);
            }
            break;
        }
    }

    return sections;
}

/*
    CheckSectionHash  compares our collected hash list from ::SetSectionHash() , we use cached address + size to prevent spoofing (sections can be renamed at runtime by an attacker)
    Returns true if the two sets of hashes do not match, implying memory was modified
*/
BOOL Detections::CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize)
{
    Logger::logf("UltimateAnticheat.log", Info, "Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetMemoryHashList())) //compares hash to one gathered previously
    {
        Logger::logf("UltimateAnticheat.log", Info, "Hashes match: Program's .text section appears genuine.\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Detection, " .text section of program is modified!\n");
        return TRUE;
    }

    return FALSE;
}

/*
    IsBlacklistedProcessRunning returns TRUE if a blacklisted program is running in the background
*/
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

/*
    Returns TRUE if the looked up function contains a jump or call as its first instruction
*/
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

/*
    Returns TRUE if any routines in the IAT lead to pointers outside their respective modules

    if the attacker writes their hooks in the dll's address space then they can get around this detection
*/
BOOL Detections::DoesIATContainHooked()
{
    list<Module::ImportFunction*> IATFunctions = Process::GetIATEntries();

    for (Module::ImportFunction* IATEntry : IATFunctions)
    {
        DWORD moduleSize = Process::GetModuleSize(IATEntry->Module);

        if (moduleSize != 0) //some K32 functions redirect to ntdll.dll ..... this destroys this function
        {
            //UINT64 MinAddress = (UINT64)IATEntry->Module;
            //UINT64 MaxAddress = (UINT64)IATEntry->Module + (UINT64)moduleSize;

            UINT64 MinAddress = 0x00007FF400000000; //crummy workaround for the fact that some routines point to other module functions and throw a false positive in our check (some k32 points to ntdll routines on my windows version)
            UINT64 MaxAddress = 0x00007FFFFFFFFFFF; //ideal way would be to use the commented lines above and then 'whitelist' whatever functions are known to redirect to other dlls

            if (IATEntry->AddressOfData <= MinAddress || IATEntry->AddressOfData >= MaxAddress)
            {
                Logger::logf("UltimateAnticheat.log", Info, " IAT function was hooked: %llX, %s\n", IATEntry->AddressOfData, IATEntry->AssociatedModuleName.c_str());
                return TRUE;
            }
        }
        else //error, we shouldnt get here!
        {
            Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch  module size @ Detections::DoesIATContainHooked\n");
            return FALSE;
        }
    }

    return FALSE;
}