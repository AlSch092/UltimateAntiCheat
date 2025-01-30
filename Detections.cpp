//By AlSch092 @github
#include "Detections.hpp"

/*
    Detections::StartMonitor - use class member MonitorThread to start our main detections loop
*/
BOOL Detections::StartMonitor()
{
    if (this->MonitorThread != nullptr) //prevent accidental double calls to this function/double thread creation
        return FALSE;

    this->MonitorThread = new Thread((LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, true);

    //Logger::logf("UltimateAnticheat.log", Info, "Created monitoring thread with ID %d", this->MonitorThread->GetId());
    
    if (this->MonitorThread->GetHandle() == NULL || this->MonitorThread->GetHandle() == INVALID_HANDLE_VALUE)
    {
        Logger::logf("UltimateAnticheat.log", Err, " Failed to create monitor thread  @ Detections::StartMonitor");
        return FALSE;
    }

    this->ProcessCreationMonitorThread = new Thread((LPTHREAD_START_ROUTINE)&Detections::MonitorProcessCreation, this, true);

    this->RegistryMonitorThread = new Thread((LPTHREAD_START_ROUTINE)&MonitorImportantRegistryKeys, (LPVOID)this, true);

    return TRUE;
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

    UINT64 CachedTextSectionAddress = 0;
    DWORD CachedTextSectionSize = 0;

    UINT64 CachedRDataSectionAddress = 0;
    DWORD CachedRDataSectionSize = 0;

    if (Monitor->Config->bCheckIntegrity) //integrity check setup if option is enabled
    {
        list<ProcessData::Section*>* sections = Process::GetSections("UltimateAnticheat.exe");
            
        Monitor->SetSectionHash("UltimateAnticheat.exe", ".text"); //set our memory hashes of .text
        Monitor->SetSectionHash("UltimateAnticheat.exe", ".rdata");

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
                CachedTextSectionAddress = s->address + ModuleAddr; //any strings such as ".text" can be encrypted at compile time and decrypted at runtime to make reversing a bit more difficult
                CachedTextSectionSize = s->size;
            }
            else if (strcmp(s->name, ".rdata") == 0)
            {
                CachedRDataSectionAddress = s->address + ModuleAddr;
                CachedRDataSectionSize = s->size;
            }
        }
    }
    
    //Main Monitor Loop, continuous detections go in here. we need access to CachedSectionAddress variables so this loop doesnt get its own function.
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring) //&& !Monitor->IsUserCheater()) //uncomment if you'd like monitoring to stop once a cheater has been detected
    {
        if (Monitor->GetMonitorThread()->IsShutdownSignalled())
        {
            Logger::logf("UltimateAnticheat.log", Info, "STOPPING  Detections::Monitor , ending detections thread");
            //Monitor->GetMonitorThread()->CurrentlyRunning = false;
            return;
        }

        if (Monitor->Config->bCheckIntegrity)
        {
            if (Monitor->GetIntegrityChecker()->IsTLSCallbackStructureModified()) //check various aspects of the TLS callback structure for modifications
            {
                Logger::logf("UltimateAnticheat.log", Detection, "Found modified TLS callback structure section (atleast one aspect of the TLS data directory structure was modified)");
                Monitor->Flag(DetectionFlags::CODE_INTEGRITY);
            }

            if (Monitor->IsSectionHashUnmatching(CachedTextSectionAddress, CachedTextSectionSize, ".text")) //compare hashes of .text for modifications
            {
                Logger::logf("UltimateAnticheat.log", Detection, "Found modified .text section (or you're debugging with software breakpoints)!\n");
                Monitor->Flag(DetectionFlags::CODE_INTEGRITY);
            }

            if (Monitor->IsSectionHashUnmatching(CachedRDataSectionAddress, CachedRDataSectionSize, ".rdata")) //compare hashes of .text for modifications
            {
                Logger::logf("UltimateAnticheat.log", Detection, "Found modified .rdata section!\n");
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
            Logger::logf("UltimateAnticheat.log", Detection, "Found at least one unsigned dll loaded : We ideally only want verified, signed dlls in our application!");
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
SetSectionHash sets the member variable `_TextSectionHashes` or `_RDataSectionHashes` via SetSectionHashList() call after finding the `sectionName` named section (.text in our case)
 Returns a list<Section*>  which we can use in later hashing calls to compare sets of these hashes and detect memory tampering within the section
*/
BOOL Detections::SetSectionHash(const char* moduleName, const char* sectionName)
{
    if (moduleName == NULL || sectionName == NULL)
    {
        return FALSE;
    }

    list<ProcessData::Section*>* sections = Process::GetSections(moduleName);
    
    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(moduleName);

    if (ModuleAddr == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "ModuleAddr was 0 @ SetSectionHash\n", sectionName);
        return FALSE;
    }

    if (sections->size() == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "sections.size() of section %s was 0 @ SetSectionHash\n", sectionName);
        return FALSE;
    }

    std::list<ProcessData::Section*>::iterator it;

    for (it = sections->begin(); it != sections->end(); ++it) 
    {
        ProcessData::Section* s = it._Ptr->_Myval;

        if (s == nullptr)
            continue;

        if (strcmp(s->name, sectionName) == 0)
        {
            vector<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)s->address + ModuleAddr, s->size);

            if (hashes.size() > 0)
            {
                GetIntegrityChecker()->SetSectionHashList(hashes, sectionName);
                break;
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Err, "hashes.size() was 0 @ SetSectionHash\n", sectionName);
                return FALSE;
            }
        }
    }

    return TRUE;
}

/*
    IsSectionHashUnmatching  compares our collected hash list from ::SetSectionHash() , we use cached address + size to prevent spoofing (sections can be renamed at runtime by an attacker)
    Returns true if the two sets of hashes do not match, implying memory was modified
*/
BOOL Detections::IsSectionHashUnmatching(UINT64 cachedAddress, DWORD cachedSize, const string section)
{
    if (cachedAddress == 0 || cachedSize == 0)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Parameters were 0 @ Detections::CheckSectionHash");
        return FALSE;
    }

    Logger::logf("UltimateAnticheat.log", Info, "Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (section == ".text")
    {
        if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetSectionHashList(".text"))) //compares hash to one gathered previously
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
    else if (section == ".rdata")
    {
        if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetSectionHashList(".rdata"))) //compares hash to one gathered previously
        {
            Logger::logf("UltimateAnticheat.log", Info, "Hashes match: Program's .text section appears genuine.\n");
            return FALSE;
        }
        else
        {
            Logger::logf("UltimateAnticheat.log", Detection, " .rdata section of program is modified!\n");
            return TRUE;
        }
    }

    return FALSE;
}

/*
    IsBlacklistedProcessRunning 
    returns TRUE if a blacklisted program is running in the background, blacklisted processes can be found in the class constructor
*/
BOOL __forceinline Detections::IsBlacklistedProcessRunning() const
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
        {   //some IAT functions in k32 can point to ntdll (forwarding), thus we have to compare IAT to each other whitelisted DLL range
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
UINT64 Detections::IsTextSectionWritable()
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
        if (address >= max_addr)
            break;

        if (mbi.Protect != PAGE_EXECUTE_READ) //check if its not RX protections
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
        if (Handles::DoesProcessHaveOpenHandleToUs(handle.ProcessId, handles))
        {
            wstring procName = Process::GetProcessName(handle.ProcessId);
            int size = sizeof(Handles::Whitelisted) / sizeof(UINT64);

            for (int i = 0; i < size; i++)
            {
                if (wcscmp(Handles::Whitelisted[i], procName.c_str()) == 0) //whitelisted program has open handle
                {
                    goto inner_break; //break out of inner for() loop without triggering foundHandle=true
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
            break;
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

    weak_ptr<NetClient> client = this->GetNetClient();  //report back to server that someone's cheating

    if (auto _client = client.lock())
    {
        if (_client->FlagCheater(flag) != Error::OK) //cheat engine attachment can be detected this way
        {
            Logger::logf("UltimateAnticheat.log", Err, "Failed to notify server of cheating status.");
            return false;
        }
    }
    else
    {
        return Logger::LogErrorAndReturn("NetClient was NULL @ Detections::Flag");
    }

    return true;
}

/*
    IsBlacklistedWindowPresent - Checks if windows with specific title or class names are present.
    *Note* this function should not be used on its own to determine if someone is running a cheat tool, it should be combined with other methods. An opened folder with a blacklisted name will be caught but doesn't imply the actual program is opened, for example
*/
BOOL Detections::IsBlacklistedWindowPresent()
{
    typedef BOOL(WINAPI* ENUMWINDOWS)(WNDENUMPROC, LPARAM);
    HMODULE hUser32 = GetModuleHandleA("USER32.dll");

    if (hUser32 != NULL)
    {
        auto WindowCallback = [](HWND hwnd, LPARAM lParam) -> BOOL 
        {
            char windowTitle[256]{ 0 };
            char className[256]{ 0 };
            const int xorKey1 = 0x44;
            const int xorKey2 = 0x47;

            Detections* Monitor = reinterpret_cast<Detections*>(lParam); //optionally, make blacklisted xor'd strings into a list in Detections class

            unsigned char CheatEngine[] =  //"Cheat Engine"
            { 
                'C' ^ xorKey1, 'h' ^ xorKey1, 'e' ^ xorKey1, 'a' ^ xorKey1, 't' ^ xorKey1, ' ' ^ xorKey1,
                'E' ^ xorKey1, 'n' ^ xorKey1, 'g' ^ xorKey1, 'i' ^ xorKey1, 'n' ^ xorKey1, 'e' ^ xorKey1
            };

            unsigned char LuaScript[] = // //"Lua script:"
            { 
                'L' ^ xorKey2, 'u' ^ xorKey2, 'a' ^ xorKey2, ' ' ^ xorKey2,
                's' ^ xorKey2, 'c' ^ xorKey2, 'r' ^ xorKey2, 'i' ^ xorKey2,
                'p' ^ xorKey2, 't' ^ xorKey2, ':' ^ xorKey2
            };

            char original_CheatEngine[13]{ 0 };
            char original_LUAScript[12]{ 0 };

            for (int i = 0; i < sizeof(original_CheatEngine) - 1; i++) //13 - 1 to stop last 00 from being xor'd
            {
                original_CheatEngine[i] = (char)(CheatEngine[i] ^ xorKey1);
            }

            for (int i = 0; i < sizeof(original_LUAScript) - 1; i++)
            {
                original_LUAScript[i] = (char)(LuaScript[i] ^ xorKey2);
            }

            if (GetWindowTextA(hwnd, windowTitle, sizeof(windowTitle)))
            {
                if (GetClassNameA(hwnd, className, sizeof(className)))
                {
                    if (strcmp(windowTitle, (const char*)original_CheatEngine) == 0  || strstr(windowTitle, (const char*)original_CheatEngine) != NULL) //*note* this will detect open folders named "Cheat Engine" also, which doesn't imply the actual program is opened.
                    {
                        Monitor->SetCheater(true);
                        Monitor->Flag(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
                        Logger::logf("UltimateAnticheat.log", Detection, "Detected a window named 'Cheat Engine' (includes open folder names)");
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
        };

        ENUMWINDOWS pEnumWindows = (ENUMWINDOWS)GetProcAddress(hUser32, "EnumWindows");
        if (pEnumWindows != NULL)
        {
            EnumWindows(WindowCallback, (LPARAM)this);
        }
        else
        {
            Logger::logf("UltimateAnticheat.log", Err, "GetProcAddress failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
            return FALSE;
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, "GetModuleHandle failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
        return FALSE;
    }

    return FALSE;
}

/*
    Detections::MonitorNewProcesses - Monitors process creation events via WMI
    Intended thread function, has no return value as it logs in real-time
*/
void Detections::MonitorProcessCreation(LPVOID thisPtr)
{
    if (thisPtr == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Monitor Ptr was NULL @ MonitorNewProcesses");
        return;
    }

    Detections* monitor = reinterpret_cast<Detections*>(thisPtr);
    monitor->MonitoringProcessCreation = true;

    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to initialize COM library @ MonitorNewProcesses");
        return;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to initialize security @ MonitorNewProcesses");
        CoUninitialize();
        return;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to create IWbemLocator object @ MonitorProcessCreation");
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Could not connect to WMI namespace @ MonitorProcessCreation");
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Could not set proxy blanket @ MonitorProcessCreation");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecNotificationQuery((wchar_t*)L"WQL", (wchar_t*)L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (FAILED(hres))
    {
        Logger::logf("UltimateAnticheat.log", Err, "Query for process creation events failed @ MonitorProcessCreation");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    if (monitor->GetMonitorThread() != nullptr)
        monitor->GetMonitorThread()->UpdateTick();

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator && monitor->MonitoringProcessCreation) //keep looping while MonitoringProcessCreation is set to true
    {
        if (monitor->GetProcessCreationMonitorThread() != nullptr)
        {
            if (monitor->GetProcessCreationMonitorThread()->IsShutdownSignalled())
            {
                break;
            }
        }

        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

        if (0 == uReturn) 
            continue;

        VARIANT vtProp;

        hr = pclsObj->Get(L"TargetInstance", 0, &vtProp, 0, 0);

        if (SUCCEEDED(hr) && (vtProp.vt == VT_UNKNOWN))
        {
            IUnknown* str = vtProp.punkVal;
            IWbemClassObject* pClassObj = NULL;
            str->QueryInterface(IID_IWbemClassObject, (void**)&pClassObj);

            if (pClassObj)
            {
                VARIANT vtName;
                pClassObj->Get(L"Name", 0, &vtName, 0, 0);

                for (wstring blacklistedProcess : monitor->BlacklistedProcesses)
                {
                    if (Utility::wcscmp_insensitive(blacklistedProcess.c_str(), vtName.bstrVal))
                    {
                        Logger::logfw("UltimateAnticheat.log", Detection, L"Blacklisted process was spawned: %s", vtName.bstrVal);
                    }
                }

                if (monitor->FindBlacklistedProgramsThroughByteScan(Process::GetProcessIdByName(vtName.bstrVal)))
                {
                    Logger::logfw("UltimateAnticheat.log", Detection, L"Blacklisted process was found through byte signature: %s", vtName.bstrVal);
                }

                VariantClear(&vtName);
                pClassObj->Release();
            }
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        
        if(monitor->GetMonitorThread() != nullptr)
            monitor->GetMonitorThread()->UpdateTick(); //update tick on each loop, then we can check this value from a different thread to see if someone has suspended it

        Sleep(50); //ease the CPU a bit
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}

/*
    InitializeBlacklistedProcessesList - add static list of blacklisted process names to our Detections object
    ...we should also scan for window class names, possible exported functions (in any DLLs running in those programs), etc.
    Most people will of course just rename any common cheat tool names
*/
void Detections::InitializeBlacklistedProcessesList()
{
    this->BlacklistedProcesses.push_back(L"Cheat Engine.exe"); //todo: hide these strings
    this->BlacklistedProcesses.push_back(L"CheatEngine.exe"); 
    this->BlacklistedProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");
    this->BlacklistedProcesses.push_back(L"x64dbg.exe");
    this->BlacklistedProcesses.push_back(L"windbg.exe");
    this->BlacklistedProcesses.push_back(L"DSEFix.exe");
}

/*
    FindBlacklistedProgramsThroughByteScan(DWORD pid) - check process `pid` for specific byte patterns which implicate it of possibly being a bad actor process
    Used in combination with WMI process load callbacks (MonitorProcessCreation), and more checks on a process should be added to ensure its not a false positive
*/
bool Detections::FindBlacklistedProgramsThroughByteScan(DWORD pid)
{
    if (pid <= 4)
        return false;

    struct Pattern 
    {
        BYTE* data;
        size_t size;

        Pattern(BYTE* d, size_t s) : data(d), size(s) {}
    };

    bool foundSignature = false;

    vector<Pattern> BlacklistedPatterns;

    //signature persists even with different optimizations options in compilation
    BYTE signaturePattern_CheatEngine[] = { 0x48, 0x8D, 0x64, 0x24, 0x28, 0xC3, 0x00, 0x48, 0x8D, 0x64, 0x24,0xD8, 0xC6, 0x05 }; //lea rsp,[rsp+28] -> ret -> add [rax-73],cl -> and al,-28

    BlacklistedPatterns.emplace_back(signaturePattern_CheatEngine, sizeof(signaturePattern_CheatEngine));

    for (Pattern pattern : BlacklistedPatterns)
    {
        DWORD patternSize = pattern.size;

        vector<BYTE> textSectionBytes = Process::ReadRemoteTextSection(pid);

        if (!textSectionBytes.empty())
        {
            for (size_t i = 0; i <= textSectionBytes.size() - patternSize; ++i)
            {
                bool found = true;
                for (size_t j = 0; j < patternSize; ++j)
                {
                    if (textSectionBytes[i + j] != pattern.data[j])
                    {
                        found = false;
                        break;
                    }
                }

                if (found)
                {
                    foundSignature = true;
                    Logger::logfw("UltimateAnticheat.log", Detection, L"Found blacklisted byte pattern in process %d at offset %d", pid, i);
                    break;
                }
            }
        }
        else
        {
            Logger::logfw("UltimateAnticheat.log", Warning, L"Failed to read .text section of process %d", pid);
            continue;
        }
    }

    return foundSignature;
}

/*
    Monitors changes to important registry keys related to secure boot, CI, testsigning mode, etc
    Meant to be run in its own thread
*/
void Detections::MonitorImportantRegistryKeys(LPVOID thisPtr)
{
    if (thisPtr == nullptr)
    {
        Logger::logf("UltimateAnticheat.log", Warning, "Detections* was NULL @ MonitorImportantRegistryKeys");
        return;
    }

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    const int KEY_COUNT = 2;

    HKEY hKeys[KEY_COUNT];
    HANDLE hEvents[KEY_COUNT];
    const TCHAR* subKeys[KEY_COUNT] = 
    {
        TEXT("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State\\"),  //secureboot keys being changed at runtime isn't a big deal in this context
        TEXT("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\")  //we'll need to find better keys to monitor which can impact integrity at runtime, however this shows as an example of how we can monitor registry changes
    };

    DWORD filter = REG_NOTIFY_CHANGE_LAST_SET;
    LONG result;

    for (int i = 0; i < KEY_COUNT; i++) 
    {
        result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKeys[i], 0, KEY_NOTIFY, &hKeys[i]);

        if (result != ERROR_SUCCESS) 
        {
            Logger::logf("UltimateAnticheat.log", Warning, "Failed to open key %d. Error: %ld @ MonitorImportantRegistryKeys", i, result);
            return;
        }

        hEvents[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!hEvents[i]) 
        {
            Logger::logf("UltimateAnticheat.log", Warning, "Failed to create event for key %d. Error: %ld\n", i, GetLastError());
            RegCloseKey(hKeys[i]);
            return;
        }

        result = RegNotifyChangeKeyValue(hKeys[i], TRUE, filter, hEvents[i], TRUE);
        if (result != ERROR_SUCCESS) 
        {
            Logger::logf("UltimateAnticheat.log", Warning, "Failed to register notification for key %d. Error: %ld", i, result);
            CloseHandle(hEvents[i]);
            RegCloseKey(hKeys[i]);
            return;
        }
    }

    Logger::logf("UltimateAnticheat.log", Warning, "Monitoring multiple registry keys...");

    bool monitoringKeys = true;

    while (monitoringKeys)
    {        
        DWORD waitResult = WaitForMultipleObjects(KEY_COUNT, hEvents, FALSE, INFINITE); //wait for any of the events to be signaled

        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + KEY_COUNT) 
        {
            int index = waitResult - WAIT_OBJECT_0; //determine which event was signaled

            Logger::logf("UltimateAnticheat.log", Detection, "Key %d value changed!", index);

            Monitor->Flag(DetectionFlags::REGISTRY_KEY_MODIFICATIONS);

            result = RegNotifyChangeKeyValue(hKeys[index], TRUE, filter, hEvents[index], TRUE);   //re register the notification for the key

            if (result != ERROR_SUCCESS) 
            {
                Logger::logf("UltimateAnticheat.log", Warning, "Failed to re-register notification for key %d. Error: %ld", index, result);
            }
        }
        else 
        {
            Logger::logf("UltimateAnticheat.log", Warning, "Unexpected wait result: %ld", waitResult);
            break;
        }
    }

    for (int i = 0; i < KEY_COUNT; i++) 
    {
        if(hEvents[i] != INVALID_HANDLE_VALUE)
            CloseHandle(hEvents[i]);

        RegCloseKey(hKeys[i]);
    }

}