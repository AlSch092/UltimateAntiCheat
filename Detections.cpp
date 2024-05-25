//By AlSch092 @github
#include "Detections.hpp"

/*
    Detections::StartMonitor - use class member MonitorThread to start our main detections loop
*/
void Detections::StartMonitor()
{
    if (this->MonitorThread != NULL)
        return;

    this->MonitorThread = new Thread();
    this->MonitorThread->handle = INVALID_HANDLE_VALUE;
    this->MonitorThread->ShutdownSignalled = false; //ShutdownSignalled is used to prevent calling TerminateThread from other threads

    this->MonitorThread->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, 0, &this->MonitorThread->Id);

    Logger::logf("UltimateAnticheat.log", Info, "Created monitoring thread with ID %d\n", this->MonitorThread->Id);
    
    if (this->MonitorThread->handle == INVALID_HANDLE_VALUE || this->MonitorThread->handle == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Failed to create monitor thread  @ Detections::StartMonitor\n");
        return;
    }

    this->MonitorThread->CurrentlyRunning = true;
}


/*
    Detections::Monitor(LPVOID thisPtr)
     Routine which monitors aspects of the process for fragments of cheating, loops continuously until the thread is signalled to shut down
*/
void Detections::Monitor(LPVOID thisPtr)
{
    if (thisPtr == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "thisPtr was NULL @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    Logger::logf("UltimateAnticheat.log", Info, "Starting  Detections::Monitor \n");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!\n");
        return;
    }

    list<ProcessData::Section*>* sections = Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text

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

    std::list<ProcessData::Section*>::iterator it;
    for (it = sections->begin(); it != sections->end(); ++it)
    {
        ProcessData::Section* s = it._Ptr->_Myval;

        if (s == nullptr)
            continue;

        if (strcmp(s->name, ".text") == 0) //cache our .text sections address and memory size, since an attacker could possibly spoof the section name or # of sections in ntheaders to prevent section traversing
        {
            CachedSectionAddress = s->address + ModuleAddr;
            CachedSectionSize = s->size - 100;
            break;
        }
    }

    //Main Monitor Loop, continuous detections go in here. we need access to CachedSectionAddress variables so this loop doesnt get its own function.
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring) //&& !Monitor->IsUserCheater()) //uncomment if you'd like monitoring to stop once a cheater has been detected
    {
        if (Monitor->GetMonitorThread()->ShutdownSignalled)
        {
            Logger::logf("UltimateAnticheat.log", Info, "STOPPING  Detections::Monitor , ending detections thread\n");
            Monitor->GetMonitorThread()->CurrentlyRunning = false;
            return;
        }

        if (Monitor->CheckSectionHash(CachedSectionAddress, CachedSectionSize)) //compare hashes of .text for modifications
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found modified .text section!\n");
            Monitor->SetCheater(true); //report back to server that someone's cheating
        }

        if (Monitor->IsBlacklistedProcessRunning()) //external applications running on machine
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found blacklisted process!\n");
            Monitor->SetCheater(true);
        }

        //make sure ws2_32.dll is actually loaded if this gives an error, on my build the dll is not loaded but we'll pretend it is
        if (Monitor->DoesFunctionAppearHooked("ws2_32.dll", "send") || Monitor->DoesFunctionAppearHooked("ws2_32.dll", "recv"))   //ensure you use this routine on functions that don't have jumps or calls as their first byte
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Networking WINAPI (send | recv) was hooked!\n"); //WINAPI hooks doesn't always determine someone is cheating since AV and other software can write the hooks
            Monitor->SetCheater(true); //..but for simplicity in this project we will set them as a cheater
        }

        if (Monitor->GetIntegrityChecker()->IsUnknownModulePresent()) //authenticode call and check against whitelisted module list
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found at least one unsigned dll loaded : We ideally only want verified, signed dlls in our application!\n");
        }

        if (Services::IsTestsigningEnabled()) //test signing enabled, self-signed drivers
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Testsigning is enabled! In most cases we don't allow the game/process to continue if testsigning is enabled.\n");
            Monitor->SetCheater(true);
        }

        if (Detections::DoesIATContainHooked()) //iat hook check
        {
            Logger::logf("UltimateAnticheat.log", Detection, "IAT was hooked! One or more functions lead to addresses outside their respective modules!\n");
            Monitor->SetCheater(true);
        }

        if (Detections::IsTextSectionWritable()) //page protections check
        {
            Logger::logf("UltimateAnticheat.log", Detection, ".text section was writable, which means someone re-re-mapped our memory regions! (or you ran this in DEBUG build)");
            Monitor->SetCheater(true);
        }

        if (Detections::CheckOpenHandles()) //open handles to our process check
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found open process handles to our process from other processes");
            Monitor->SetCheater(true);
        }

        Sleep(MonitorLoopMilliseconds);
    }
}

/*
SetSectionHash sets the member variable `_MemorySectionHashes` via SetMemoryHashList() call after finding the `sectionName` named section (.text in our case)
 Returns a list<Section*>  which we can use in later hashing calls to compare sets of these hashes and detect memory tampering within the section
*/
list<ProcessData::Section*>* Detections::SetSectionHash(const char* moduleName, const char* sectionName)
{
    if (moduleName == NULL || sectionName == NULL)
    {
        return nullptr;
    }

    list<ProcessData::Section*>* sections = Process::GetSections(moduleName);
    
    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(moduleName);

    if (ModuleAddr == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "ModuleAddr was 0 @ SetSectionHash\n", sectionName);
        return nullptr;
    }

    if (sections->size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "sections.size() of section %s was 0 @ SetSectionHash\n", sectionName);
        return nullptr;
    }

    std::list<ProcessData::Section*>::iterator it;

    for (it = sections->begin(); it != sections->end(); ++it) 
    {
        ProcessData::Section* s = it._Ptr->_Myval;

        if (s == nullptr)
            continue;

        if (strcmp(s->name, sectionName) == 0)
        {
            list<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size - 100); //check most of section, a few short to stop edge read cases

            if (hashes.size() > 0)
            {
                GetIntegrityChecker()->SetMemoryHashList(hashes);
                break;
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Err, "hashes.size() was 0 @ SetSectionHash\n", sectionName);
                return nullptr;
            }
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
    if (cachedAddress == 0 || cachedSize == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Parameters were 0 @ Detections::CheckSectionHash");
        return FALSE;
    }

    Logger::logf("UltimateAnticheat.log", Info, "Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetMemoryHashList())) //compares hash to one gathered previously
    {
        Logger::logf("UltimateAnticheat.log", Info, "Hashes match: Program's .text section appears genuine.\n");
        return FALSE;
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Detection, " .text section of program is modified!\n");
        return TRUE;
    }
}

/*
    IsBlacklistedProcessRunning 
    returns TRUE if a blacklisted program is running in the background, blacklisted processes can be found in the class constructor
*/
BOOL __forceinline Detections::IsBlacklistedProcessRunning()
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
*   DoesFunctionAppearHooked - Checks if first bytes of a routine are a jump or call. Please make sure the function you use with this doesnt normally start with a jump or call.
    Returns TRUE if the looked up function contains a jump or call as its first instruction
*/
BOOL __forceinline Detections::DoesFunctionAppearHooked(const char* moduleName, const char* functionName)
{
    if (moduleName == nullptr || functionName == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "moduleName or functionName was NULL @ Detections::DoesFunctionAppearHooked");
        return FALSE;
    }

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
    DoesIATContainHooked - Returns TRUE if any routines in the IAT lead to addresses outside their respective modules
    Until I come up with a better solution, we just check against the common memory range where system DLLs such as kernel32 and ntdll load into (0x00007FF400000000 - 0x00007FFFFFFFFFFF or so)
    if the attacker writes their hooks in the dll's address space then they can get around this detection
*/
BOOL __forceinline Detections::DoesIATContainHooked()
{
    list<ProcessData::ImportFunction*> IATFunctions = Process::GetIATEntries();

    for (ProcessData::ImportFunction* IATEntry : IATFunctions)
    {
        DWORD moduleSize = Process::GetModuleSize(IATEntry->Module);

        if (moduleSize != 0)
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

/*
Detections::IsTextSectionWritable() - Simple memory protections check on page in the .text section
    returns TRUE if the page was writable, which imples someone re-re-mapped our process memory and wants to write patches.
*/
BOOL __forceinline Detections::IsTextSectionWritable()
{
    UINT64 textAddr = Process::GetSectionAddress(NULL, ".text");
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (textAddr == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "textAddr was NULL @ Detections::IsTextSectionWritable");
        return FALSE;
    }

    VirtualQuery((LPCVOID)textAddr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

    if (mbi.AllocationProtect != PAGE_EXECUTE_READ)
    {
        return TRUE;
    }

    return FALSE;
}

/*
    CheckOpenHandles - Checks if any processes have open handles to our process
    returns true if some other process has an open process handle to the current process
*/
bool Detections::CheckOpenHandles()
{
    bool foundHandle = false;
    std::vector<Handles::_SYSTEM_HANDLE> handles = Handles::DetectOpenHandlesToProcess();

    for (auto& handle : handles)
    {
        if (Handles::DoesProcessHaveOpenHandleTous(handle.ProcessId, handles))
        {
            wstring procName = Process::GetProcessName(handle.ProcessId);
            Logger::logfw("UltimateAnticheat.log", Detection, L"Process %s has open process handle to our process.", procName.c_str());
            foundHandle = true;
        }
    }

    return foundHandle;
}