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

    Logger::logf("UltimateAnticheat.log", Info, "Created monitoring thread with ID %d", this->MonitorThread->Id);
    
    if (this->MonitorThread->handle == INVALID_HANDLE_VALUE || this->MonitorThread->handle == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Failed to create monitor thread  @ Detections::StartMonitor");
        return;
    }

    this->MonitorThread->CurrentlyRunning = true;
}

/*
    LdrpDllNotification - This function is called whenever a new module is loaded into the process space, called before TLS callbacks
*/

VOID CALLBACK Detections::OnDllNotification(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context)
{
    Detections* Monitor = reinterpret_cast<Detections*>(Context);
    
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        LPCWSTR FullDllName = NotificationData->Loaded.FullDllName->pBuffer;
        Logger::logfw("UltimateAnticheat.log", Info, L"[LdrpDllNotification Callback] dll loaded: %s, verifying signature...\n", FullDllName);

        if (!Authenticode::HasSignature(FullDllName))
        {
			Logger::logfw("UltimateAnticheat.log", Detection, L"Failed to verify signature of %s\n", FullDllName);

            Monitor->Flag(DetectionFlags::INJECTED_ILLEGAL_PROGRAM);
        }
    }

}

/*
    Detections::Monitor(LPVOID thisPtr)
     Routine which monitors aspects of the process for fragments of cheating, loops continuously until the thread is signalled to shut down
*/
void Detections::Monitor(LPVOID thisPtr)
{
    if (thisPtr == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "thisPtr was NULL @ Detections::Monitor. Aborting execution!");
        return;
    }

    Logger::logf("UltimateAnticheat.log", Info, "Starting  Detections::Monitor");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!");
        return;
    }

    UINT64 CachedSectionAddress = 0;
    DWORD CachedSectionSize = 0;

    if (Monitor->GetSettings()->bCheckIntegrity) //integrity check setup if option is enabled
    {
        list<ProcessData::Section*>* sections = Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text

        if (sections == nullptr)
        {
            Logger::logf("UltimateAnticheat.log", Err, "Sections was NULLPTR @ Detections::Monitor. Aborting execution!");
            return;
        }

        if (sections->size() == 0)
        {
            Logger::logf("UltimateAnticheat.log", Err, "Sections size was 0 @ Detections::Monitor. Aborting execution!");
            return;
        }

        UINT64 ModuleAddr = (UINT64)GetModuleHandleA(NULL);

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
                CachedSectionSize = s->size;
                break;
            }
        }
    }
    
    //Main Monitor Loop, continuous detections go in here. we need access to CachedSectionAddress variables so this loop doesnt get its own function.
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring) //&& !Monitor->IsUserCheater()) //uncomment if you'd like monitoring to stop once a cheater has been detected
    {
        if (Monitor->GetMonitorThread()->ShutdownSignalled)
        {
            Logger::logf("UltimateAnticheat.log", Info, "STOPPING  Detections::Monitor , ending detections thread");
            Monitor->GetMonitorThread()->CurrentlyRunning = false;
            return;
        }

        if (Monitor->GetIntegrityChecker()->IsTLSCallbackStructureModified()) //check various aspects of the TLS callback structure for modifications
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found modified TLS callback structure section (atleast one aspect of the TLS data directory structure was modified)");
            Monitor->Flag(DetectionFlags::CODE_INTEGRITY);
        }

        if (Monitor->GetSettings()->bCheckIntegrity)
        {
            if (Monitor->CheckSectionHash(CachedSectionAddress, CachedSectionSize)) //compare hashes of .text for modifications
            {
                Logger::logf("UltimateAnticheat.log", Detection, "Found modified .text section (or you're debugging with software breakpoints)!\n");
                Monitor->Flag(DetectionFlags::CODE_INTEGRITY);
            }
        }

        if (Monitor->GetIntegrityChecker()->IsModuleModified(L"WINTRUST.dll")) //check hashes of wintrust.dll for signing-related hooks
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found modified .text section in WINTRUST.dll!");
            Monitor->Flag(DetectionFlags::CODE_INTEGRITY);
        }

        if (Monitor->IsBlacklistedProcessRunning()) //external applications running on machine
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found blacklisted process!");
            Monitor->Flag(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
        }

        //make sure ws2_32.dll is actually loaded if this gives an error, on my build the dll is not loaded but we'll pretend it is
        if (Monitor->DoesFunctionAppearHooked("ws2_32.dll", "send") || Monitor->DoesFunctionAppearHooked("ws2_32.dll", "recv"))   //ensure you use this routine on functions that don't have jumps or calls as their first byte
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Networking WINAPI (send | recv) was hooked!\n"); //WINAPI hooks doesn't always determine someone is cheating since AV and other software can write the hooks
            Monitor->Flag(DetectionFlags::DLL_TAMPERING);
        }

        if (Monitor->GetIntegrityChecker()->IsUnknownModulePresent()) //authenticode call and check against whitelisted module list
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found at least one unsigned dll loaded : We ideally only want verified, signed dlls in our application!\n");
            Monitor->Flag(DetectionFlags::INJECTED_ILLEGAL_PROGRAM);
        }

        if (Services::IsTestsigningEnabled() || Services::IsDebugModeEnabled()) //test signing enabled, self-signed drivers
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Testsigning or debugging mode is enabled! In most cases we don't allow the game/process to continue if testsigning is enabled.");
            Monitor->Flag(DetectionFlags::UNSIGNED_DRIVERS);
        }

        if (Detections::DoesIATContainHooked()) //iat hook check
        {
            Logger::logf("UltimateAnticheat.log", Detection, "IAT was hooked! One or more functions lead to addresses outside their respective modules!\n");
            Monitor->Flag(DetectionFlags::BAD_IAT);
        }

        if (Detections::IsTextSectionWritable()) //page protections check, can be made more granular or loop over all mem pages
        {
            Logger::logf("UltimateAnticheat.log", Detection, ".text section was writable, which means someone re-re-mapped our memory regions! (or you ran this in DEBUG build)");
            
#ifndef _DEBUG           //in debug build we are not remapping, and software breakpoints in VS may cause page protections to be writable
            Monitor->Flag(DetectionFlags::PAGE_PROTECTIONS);
#endif
        }

        if (Detections::CheckOpenHandles()) //open handles to our process check
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found open process handles to our process from other processes");
            Monitor->Flag(DetectionFlags::OPEN_PROCESS_HANDLES);
        }

        if (Monitor->IsBlacklistedWindowPresent())
        {
            Logger::logf("UltimateAnticheat.log", Detection, "Found blacklisted window text!");
            Monitor->Flag(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
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
            vector<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size); //check most of section, a few short to stop edge read cases

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
    if the attacker writes their hooks in the dll's address space then they can get around this detection
*/
BOOL __forceinline Detections::DoesIATContainHooked()
{
    list<ProcessData::ImportFunction*> IATFunctions = Process::GetIATEntries();

    auto modules = Process::GetLoadedModules();

    if (modules == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch  module list @ Detections::DoesIATContainHooked");
        return FALSE;
    }

    for (ProcessData::ImportFunction* IATEntry : IATFunctions)
    {
        DWORD moduleSize = Process::GetModuleSize(IATEntry->Module);

        if (moduleSize != 0)
        {   //some IAT functions in k32 can point to ntdll, thus we have to compare IAT to each other whitelisted DLL range
            for (std::vector<ProcessData::MODULE_DATA>::iterator it = modules->begin(); it != modules->end(); ++it)
            {
                UINT64 LowAddr = (UINT64)it->dllInfo.lpBaseOfDll;
                UINT64 HighAddr = (UINT64)it->dllInfo.lpBaseOfDll + it->dllInfo.SizeOfImage;

                if (IATEntry->AddressOfData > LowAddr && IATEntry->AddressOfData < HighAddr)
                {
                    delete modules; modules = nullptr;
                    return FALSE; //IAT function was found to be inside address range of loaded DLL, thus its not hooked
                }
            }
        }
        else //error, we shouldnt get here!
        {
            Logger::logf("UltimateAnticheat.log", Err, " Couldn't fetch  module size @ Detections::DoesIATContainHooked");
            delete modules; modules = nullptr;
            return FALSE;
        }
    }

    delete modules; modules = nullptr;
    return TRUE;
}


/*
Detections::IsTextSectionWritable() - Simple memory protections check on page in the .text section
    returns address where the page was writable, which imples someone re-re-mapped our process memory and wants to write patches.
*/
UINT64 __forceinline Detections::IsTextSectionWritable()
{
    UINT64 textAddr = Process::GetSectionAddress(NULL, ".text");
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    SIZE_T result;
    UINT64 address = textAddr;

    const int pageSize = 0x1000;

    if (textAddr == NULL)
    {
        Logger::logf("UltimateAnticheat.log", Err, "textAddr was NULL @ Detections::IsTextSectionWritable");
        return 0;
    }

    UINT64 max_addr = textAddr + Process::GetTextSectionSize(GetModuleHandle(NULL));

    while ((result = VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) != 0)     //Loop through all pages in .text
    {
        if(address >= max_addr)
            break;

        if ((mbi.Protect == PAGE_EXECUTE_WRITECOPY) || (mbi.Protect == PAGE_EXECUTE_READWRITE))
        {
            Logger::logfw("UltimateAnticheat.log", Detection, L"Memory region at address %p is not PAGE_EXECUTE_READ - attacker likely re-re-mapped\n", address);
            return address;
        }
        
        address += pageSize;
    }

    return 0;
}

/*
    CheckOpenHandles - Checks if any processes have open handles to our process, excluding whitelisted processes such as conhost.exe
    returns true if some other process has an open process handle to the current process
*/
BOOL Detections::CheckOpenHandles()
{
    BOOL foundHandle = FALSE;
    std::vector<Handles::_SYSTEM_HANDLE> handles = Handles::DetectOpenHandlesToProcess();

    for (auto& handle : handles)
    {
        if (Handles::DoesProcessHaveOpenHandleTous(handle.ProcessId, handles))
        {
            wstring procName = Process::GetProcessName(handle.ProcessId);
            int size = sizeof(Handles::Whitelisted) / sizeof(UINT64);

            for (int i = 0; i < size; i++)
            {
                if (wcscmp(Handles::Whitelisted[i], procName.c_str()) == 0) //whitelisted program has open handle
                {
                    goto inner_break;
                }
            }

            Logger::logfw("UltimateAnticheat.log", Detection, L"Process %s has open process handle to our process.", procName.c_str());
            foundHandle = TRUE;

        inner_break:
            continue;
        }
    }

    return foundHandle;
}

/*
    AddDetectedFlags - adds DetectionFlags `flag` to the list of detected flags. Does not add if the flag is already in the list.
*/
bool Detections::AddDetectedFlag(DetectionFlags flag)
{
    bool isDuplicate = false;

    for (DetectionFlags f : this->DetectedFlags)
    {
        if (f == flag)
        {
            isDuplicate = true;
        }
    }

    if (!isDuplicate)
        this->DetectedFlags.push_back(flag);

    return isDuplicate;
}

/*
    Flag - function adds flag to the detected list and sends a message to the server informing of the detection

*/
bool Detections::Flag(DetectionFlags flag)
{
    bool wasDuplicate = AddDetectedFlag(flag);
    this->SetCheater(true);

    if (wasDuplicate) //prevent duplicate server comms
        return true;

    NetClient* client = this->GetNetClient();  //report back to server that someone's cheating
    if (client != nullptr)
    {
        if (client->FlagCheater(flag) != Error::OK) //cheat engine attachment can be detected this way
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to notify server of cheating status.");
            return false;
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "NetClient was NULL @ Detections::Flag");
        return false;
    }

    return true;
}

/*
    EnumWindowsProc - window traversal callback used in Detections::IsBlacklistedWindowPresent
*/
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
{
    char windowTitle[256]{ 0 };
    char className[256]{ 0 };
    const int xorKey1 = 0x44;
    const int xorKey2 = 0x47;
    Detections* Monitor = reinterpret_cast<Detections*>(lParam); //maybe put blacklisted xor'd strings into a list in Detections?

    unsigned char CheatEngine[] = {
        'C' ^ xorKey1, 'h' ^ xorKey1, 'e' ^ xorKey1, 'a' ^ xorKey1, 't' ^ xorKey1, ' ' ^ xorKey1,
        'E' ^ xorKey1, 'n' ^ xorKey1, 'g' ^ xorKey1, 'i' ^ xorKey1, 'n' ^ xorKey1, 'e' ^ xorKey1
    };

    unsigned char LuaScript[] = {
        'L' ^ xorKey2, 'u' ^ xorKey2, 'a' ^ xorKey2, ' ' ^ xorKey2,
        's' ^ xorKey2, 'c' ^ xorKey2, 'r' ^ xorKey2, 'i' ^ xorKey2,
        'p' ^ xorKey2, 't' ^ xorKey2, ':' ^ xorKey2
    };

    char original_CheatEngine[13]{ 0 };
    char original_LUAScript[12]{ 0 };

    for (int i = 0; i < 13 - 1; i++) //13 - 1 to stop last 00 from being xor'd
    {
        original_CheatEngine[i] = (char)(CheatEngine[i] ^ xorKey1);
    }

    for (int i = 0; i < 12; i++)
    {
        original_LUAScript[i] = (char)(CheatEngine[i] ^ xorKey2);
    }

    if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle)))
    {
        if (GetClassNameA(hwnd, className, sizeof(className)))
        {
            if (strstr(windowTitle, (const char*)original_CheatEngine) || strstr(windowTitle, (const char*)original_CheatEngine) != NULL)
            {
                Monitor->SetCheater(true);
                Monitor->Flag(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
                Logger::logf("UltimateAnticheat.log", Detection, "Detected cheat engine window");
                return FALSE;
            }
            else if (strstr(windowTitle, (const char*)original_LUAScript))
            {
                Monitor->SetCheater(true);
                Monitor->Flag(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
                Logger::logf("UltimateAnticheat.log", Detection, "Detected cheat engine's lua script window");
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
    IsBlacklistedWindowPresent - Checks if windows with specific title or class names are present
*/
BOOL Detections::IsBlacklistedWindowPresent()
{
    typedef BOOL(WINAPI* ENUMWINDOWS)(WNDENUMPROC, LPARAM);
    HMODULE hUser32 = GetModuleHandleA("USER32.dll");

    if (hUser32 != NULL)
    {
        ENUMWINDOWS pEnumWindows = (ENUMWINDOWS)GetProcAddress(hUser32, "EnumWindows");
        if (pEnumWindows != NULL)
        {
            EnumWindows(EnumWindowsProc, (LPARAM)this);
        }
        else
        {
            Logger::logf("UltimateAnticheat.log", Err, "GetProcAddress failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "GetModuleHandle failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
        return FALSE;
    }

    return FALSE;
}
