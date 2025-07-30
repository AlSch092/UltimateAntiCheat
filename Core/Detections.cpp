//By AlSch092 @github
#include "Detections.hpp"

Detections::Detections(Settings* s, EvidenceLocker* evidence, shared_ptr<NetClient> client) : Config(s), EvidenceManager(evidence), netClient(client)
{
    this->InitializeBlacklistedProcessesList();

    MonitoringProcessCreation = false; //gets set to true inside `MonitorProcessCreation`

    auto ModuleList = Process::GetLoadedModules();

    try
    {
		auto sections = Process::GetSections(_MAIN_MODULE_NAME);

        if(sections.size() > 0)
            _Proc = make_unique<Process>(sections.size());
        else
            _Proc = make_unique<Process>(6); //.text , .rdata, .data, .pdata, .rsrc, .reloc, .tls, 

        Process::SetNumSections(sections.size());

        for (ProcessData::Section* section : sections)
        {
            if (section != nullptr)
                delete section;
        }

        _Services = make_unique<Services>();

        integrityChecker = make_shared<Integrity>(ModuleList);

        VM = std::make_unique<VirtualMachine>(256);
    }
    catch (const std::bad_alloc& e)
    {
        Logger::logf(Err, "One or more pointers could not be allocated @ Detections::Detections: %s", e.what());
        std::terminate();
    }

    if (!FetchBlacklistedBytePatterns(BlacklisteBytePatternRepository))
    {
        Logger::logf(Warning, "Failed to fetch blacklisted byte patterns from web location!");
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    if (hNtdll != 0) //register DLL notifications callback 
    {
        _LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
        NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)OnDllNotification, this, &DllCallbackRegistrationCookie);
    }
}

Detections::~Detections()
{
    if (DllCallbackRegistrationCookie) //unregister DLL notifications
    {
        typedef NTSTATUS(NTAPI* pfnLdrUnregisterDllNotification)(PVOID Cookie);

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

        if (hNtdll == 0)
            hNtdll = LoadLibraryA("ntdll.dll");

        pfnLdrUnregisterDllNotification pLdrRegisterDllNotification = (pfnLdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");

        NTSTATUS status = pLdrRegisterDllNotification(DllCallbackRegistrationCookie);

        if (!NT_SUCCESS(status))
        {
            Logger::logf(Err, "Failed to unregister DLL notifications: %d", GetLastError());
        }

        DllCallbackRegistrationCookie = nullptr;
    }

    if (MonitorThread != nullptr)
        delete MonitorThread;

    if (RegistryMonitorThread != nullptr)
        delete RegistryMonitorThread;

    if (ProcessCreationMonitorThread != nullptr)
        delete ProcessCreationMonitorThread;
}

/*
    Detections::StartMonitor - use class member MonitorThread to start our main detections loop
	returns `true` on success, `false` if the thread was already created or failed to create
*/
bool Detections::StartMonitor()
{
    if (this->MonitorThread != nullptr) //prevent accidental double calls to this function/double thread creation
        return false;

    this->MonitorThread = new Thread((LPTHREAD_START_ROUTINE)&Monitor, (LPVOID)this, true, false);

    Logger::logf(Info, "Created monitoring thread with ID %d", this->MonitorThread->GetId());
    
    if (this->MonitorThread->GetId() == 0)
    {
        Logger::logf(Err, " Failed to create monitor thread  @ Detections::StartMonitor");
        return false;
    }

    this->ProcessCreationMonitorThread = new Thread((LPTHREAD_START_ROUTINE)&Detections::MonitorProcessCreation, this, true, false);

    this->RegistryMonitorThread = new Thread((LPTHREAD_START_ROUTINE)&MonitorImportantRegistryKeys, (LPVOID)this, true, false);

    return true;
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

        if (Monitor != nullptr && FullDllName != nullptr)
        {
            Logger::logfw(Info, L"[LdrpDllNotification Callback] dll loaded: %s", FullDllName);
            std::lock_guard<std::mutex> lock(Monitor->DLLVerificationQueueMutex);
            Monitor->DLLVerificationQueue.push(wstring(FullDllName));
        }
    }
}

/*
    CheckDLLSignature - checks the signatures of any newly loaded modules
*/
void Detections::CheckDLLSignature()
{
	while (true) //loop until there are no more modules to check
    {
        wstring FullDllName;
     
        {
            std::lock_guard<std::mutex> lock(this->DLLVerificationQueueMutex); //lock only for queue access
            
            if (this->DLLVerificationQueue.empty()) 
            {
                break;
            }

            FullDllName = this->DLLVerificationQueue.front();
            this->DLLVerificationQueue.pop();

        }  //mutex is unlocked here automatically since lock_guard works as a RAII and we create scope with { and }
 
        if (FullDllName.size() > 0) //now do the expensive work without holding the lock
        {
            if (!Authenticode::HasSignature(FullDllName.c_str(), TRUE))
            {
                Logger::logfw(Detection, L"Failed to verify signature of %s", FullDllName.c_str());
                this->EvidenceManager->AddFlagged(DetectionFlags::INJECTED_ILLEGAL_PROGRAM, Utility::ConvertWStringToString(FullDllName), GetCurrentProcessId());
                this->UnsignedModulesLoaded.push_back(FullDllName);
            }
            else
            {
                if(find(this->PassedCertCheckModules.begin(), this->PassedCertCheckModules.end(), FullDllName) == this->PassedCertCheckModules.end())
                    this->PassedCertCheckModules.push_back(FullDllName); //add proper signed module to cache
            }
        }
    }
}

/*
    Detections::Monitor(LPVOID thisPtr)
     Routine which monitors aspects of the process for fragments of cheating, loops continuously until the thread is signalled to shut down
*/
void Detections::Monitor(__in LPVOID thisPtr)
{
    if (thisPtr == NULL)
    {
        Logger::logf(Err, "thisPtr was NULL @ Detections::Monitor. Aborting execution!");
        return;
    }

    Logger::logf(Info, "Starting  Detections::Monitor");

    Detections* Monitor = reinterpret_cast<Detections*>(thisPtr);

    if (Monitor == nullptr)
    {
        Logger::logf(Err, "Monitor Ptr was NULL @ Detections::Monitor. Aborting execution!");
        return;
    }

    UINT64 CachedTextSectionAddress = 0;
    DWORD CachedTextSectionSize = 0;

    UINT64 CachedRDataSectionAddress = 0;
    DWORD CachedRDataSectionSize = 0;

    if (Monitor->Config->bCheckIntegrity) //integrity check setup if option is enabled
    {
        list<ProcessData::Section*> sections = Process::GetSections(_MAIN_MODULE_NAME);
            
        Monitor->SetSectionHash(_MAIN_MODULE_NAME, ".text"); //set our memory hashes of .text
        Monitor->SetSectionHash(_MAIN_MODULE_NAME, ".rdata");

        if (sections.size() == 0)
        {
            Logger::logf(Err, "Sections size was 0 @ Detections::Monitor. Aborting execution!");
            return;
        }

        UINT64 ModuleAddr = (UINT64)GetModuleHandleA(NULL);

        if (ModuleAddr == 0)
        {
            Logger::logf(Err, "Module couldn't be retrieved @ Detections::Monitor. Aborting execution! (%d)\n", GetLastError());
            return;
        }

        for (auto section : sections)
        {
            if (section == nullptr)
                continue;

            if(section->name == ".text")          
            {
                CachedTextSectionAddress = section->address + ModuleAddr;  //cache our .text sections address and memory size, since an attacker could possibly spoof the section name or # of sections in ntheaders to prevent section traversing
                CachedTextSectionSize = section->size;
            }
            else if (section->name == ".rdata")
            {
                CachedRDataSectionAddress = section->address + ModuleAddr;
                CachedRDataSectionSize = section->size;
            }
        }
    }
    
    //Main Monitor Loop, continuous detections go in here. we need access to CachedSectionAddress variables so this loop doesnt get its own function.
    bool Monitoring = true;
    const int MonitorLoopMilliseconds = 5000;

    while (Monitoring)
    {
        if (Monitor == nullptr) //critical error
        {
            Logger::logf(Err, "Monitor ptr was NULL @ Detections::Monitor, shutting down");
            std::terminate();
        }

        if (Monitor->GetMonitorThread()->IsShutdownSignalled()) //end thread if thread shutdown is signalled
        {
            Logger::logf(Info, "STOPPING  Detections::Monitor , ending detections thread");
            return;
        }

        Monitor->CheckDLLSignature(); //check signatures of any newly loaded modules

        if (Monitor->Config->bCheckHypervisor)
        {
            if (Services::IsHypervisorPresent()) //we can either block all hypervisors to try and stop SLAT/EPT manipulation, or only allow certain vendors.
            {
                string vendor = Services::GetHypervisorVendor(); //...however, many custom hypervisors will likely spoof their vendorId to be 'HyperV' or 'VMWare' 

                if (vendor.size() == 0) //custom hypervisors might empty the vendor
                {
                    Logger::logf(Detection, "Hypervisor vendor was empty, some custom hypervisor might be hooking cpuid instruction");
                }
                else if (vendor == "Microsoft Hv" || vendor == "VMwareVMware" || vendor == "XenVMMXenVMM" || vendor == "VBoxVBoxVBox")
                {
                    Logger::logf(Detection, "Hypervisor was present with vendor: %s", vendor.c_str());
                }
                else
                {
                    Logger::logf(Detection, "Hypervisor was present with unknown/non-standard vendor: %s.", vendor.c_str());
                }

                Monitor->EvidenceManager->AddFlagged(DetectionFlags::HYPERVISOR);
            }
        }

        if (Monitor->Config->bCheckIntegrity)
        {
            if (Monitor->GetIntegrityChecker()->IsTLSCallbackStructureModified()) //check various aspects of the TLS callback structure for modifications
            {
                Logger::logf(Detection, "Found modified TLS callback structure section (atleast one aspect of the TLS data directory structure was modified)");
                Monitor->EvidenceManager->AddFlagged(DetectionFlags::CODE_INTEGRITY);
            }

            if (Monitor->IsSectionHashUnmatching(CachedTextSectionAddress, CachedTextSectionSize, ".text")) //compare hashes of .text for modifications
            {
                Logger::logf(Detection, "Found modified .text section (or you're debugging with software breakpoints)!\n");
                Monitor->EvidenceManager->AddFlagged(DetectionFlags::CODE_INTEGRITY);
            }

            if (Monitor->IsSectionHashUnmatching(CachedRDataSectionAddress, CachedRDataSectionSize, ".rdata")) //compare hashes of .text for modifications
            {
                Logger::logf(Detection, "Found modified .rdata section!\n");
                Monitor->EvidenceManager->AddFlagged(DetectionFlags::CODE_INTEGRITY);
            }

            if (!Monitor->GetIntegrityChecker()->CheckFileIntegrityFromDisc()) //check .text of file on disc versus runtime process - this fills the gap of gathering .text hashes at program startup and comparing to that
            {
                Logger::logf(Detection, ".text section of file on disc differs from runtime process!");
                Monitor->EvidenceManager->AddFlagged(DetectionFlags::CODE_INTEGRITY);
            }
        }

        if (Monitor->GetIntegrityChecker()->IsModuleModified(L"WINTRUST.dll")) //check hashes of wintrust.dll for signing-related hooks
        {
            Logger::logf(Detection, "Found modified .text section in WINTRUST.dll!"); //checking .rdata would be helpful too
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::CODE_INTEGRITY);
        }

        vector<uint64_t> mappedRegions = Monitor->DetectManualMapping();

        if (mappedRegions.size() > 0)
        {
            for (uint64_t mappedRegionAddress : mappedRegions)
            {
                Logger::logf(Detection, "Found potentially manually mapped region at: %llX", mappedRegionAddress);
                Monitor->EvidenceManager->AddFlagged(DetectionFlags::MANUAL_MAPPING, std::to_string(mappedRegionAddress), GetCurrentProcessId());
            }        
        }

        if (Monitor->GetConfig() != nullptr && Monitor->GetConfig()->bEnforceDSE) //check for unsigned drivers loaded
        {
            Monitor->SetUnsignedLoadedDriversList(Monitor->GetServiceManager()->GetUnsignedDrivers(Monitor->PassedCertCheckDrivers));

            if (Monitor->GetUnsignedLoadedDriversList().size() > 0) //found one or more unsigned, non-whitelisted drivers loaded
            {
                for (wstring driver : Monitor->GetUnsignedLoadedDriversList())
                {
                    Logger::logfw(Warning, L"Unsigned driver was loaded: %s", driver.c_str());
                }
            }
        }

        if (Monitor->IsBlacklistedProcessRunning()) //external applications running on machine
        {
            Logger::logf(Detection, "Found blacklisted process!");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
        }

        //make sure ws2_32.dll is actually loaded if this gives an error, on my build the dll is not loaded but we'll pretend it is
        if (Monitor->DoesFunctionAppearHooked("ws2_32.dll", "send") || Monitor->DoesFunctionAppearHooked("ws2_32.dll", "recv"))   //ensure you use this routine on functions that don't have jumps or calls as their first byte
        {
            Logger::logf(Detection, "Networking WINAPI (send | recv) was hooked!\n"); //WINAPI hooks doesn't always determine someone is cheating since AV and other software can write the hooks
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::DLL_TAMPERING);
        }

        if (Monitor->GetIntegrityChecker()->IsUnknownModulePresent()) //authenticode call and check against whitelisted module list
        {
            Logger::logf(Detection, "Found at least one unsigned dll loaded : We ideally only want verified, signed dlls in our application!");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::INJECTED_ILLEGAL_PROGRAM);
        }

        if (Services::IsTestsigningEnabled() || Services::IsDebugModeEnabled()) //test signing enabled, self-signed drivers
        {
            Logger::logf(Detection, "Testsigning or debugging mode is enabled! In most cases we don't allow the game/process to continue if testsigning is enabled.");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::UNSIGNED_DRIVERS);
        }

        if (Monitor->Detections::DoesIATContainHooked()) //iat hook check
        {
            Logger::logf(Detection, "IAT was hooked! One or more functions lead to addresses outside their respective modules!\n");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::BAD_IAT);
        }

        if (Detections::IsTextSectionWritable()) //page protections check, can be made more granular or loop over all mem pages
        {
            Logger::logf(Detection, ".text section was writable, which means someone re-re-mapped our memory regions! (or you ran this in DEBUG build)");
            
#ifndef _DEBUG           //in debug build we are not remapping, and software breakpoints in VS may cause page protections to be writable
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::PAGE_PROTECTIONS);
#endif
        }

        if (Detections::CheckOpenHandles()) //open handles to our process check
        {
            Logger::logf(Detection, "Found open process handles to our process from other processes");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::OPEN_PROCESS_HANDLES);
        }

        if (Monitor->IsBlacklistedWindowPresent())
        {
            Logger::logf(Detection, "Found blacklisted window text!");
            Monitor->EvidenceManager->AddFlagged(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
        }

        auto _future = std::async(std::launch::async, &EvidenceLocker::PushAllEvidence, Monitor->EvidenceManager); //push any newly found flags to server
        Sleep(MonitorLoopMilliseconds);
    }
}

/*
    FetchBlacklistedBytePatterns - read file from `url`, add each line of file to our blacklisted byte pattern list
    Each line of the file located at `url` should be a space-seperated hex byte string, eg) 48 8D 05 12 33 CD
    returns `false` on failure
*/
bool Detections::FetchBlacklistedBytePatterns(__in const char* url)
{
    if (url == nullptr)
        return false;

    HttpRequest request;
    request.url = url;
    request.cookie = "";
	request.body = "";
	request.requestHeaders = 
    {
		{"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"},
		{"Accept", "text/plain, */*; q=0.01"},
		{"Accept-Language", "en-US,en;q=0.5"},
		{"Connection", "keep-alive"}
	};

    if (!HttpClient::GetRequest(request))
    {
        return false;
    }

    stringstream ss (request.responseText);

    string bytePattern;

    while (getline(ss, bytePattern))
    {
        vector<uint8_t> bytes;

        if (!bytePattern.empty() && bytePattern.back() == '\r')
        {
            bytePattern.pop_back(); //remove \r
            if (!bytePattern.empty() && bytePattern.back() == ' ')
                bytePattern.pop_back(); //remove space
        }

        stringstream ss2(bytePattern);
        string _byte;
        
        while (getline(ss2, _byte, ' '))
        {
            if (_byte.size() >= 2 && _byte[0] == '/' && _byte[1] == '/') //found comment at end of pattern, don't parse this part
                break;

            uint8_t byte = stoul(_byte, nullptr, 16);
            bytes.push_back(byte);
        }
     
        this->BlacklistedBytePatterns.emplace_back(BytePattern(bytes, bytes.size()));
    }

    return true;
}

/*
SetSectionHash sets the member variable `_TextSectionHashes` or `_RDataSectionHashes` via SetSectionHashList() call after finding the `sectionName` named section (.text in our case)
 Returns a list<Section*>  which we can use in later hashing calls to compare sets of these hashes and detect memory tampering within the section
*/
bool Detections::SetSectionHash(__in const char* moduleName, __in const char* sectionName)
{
    if (moduleName == nullptr || sectionName == nullptr)
    {
        Logger::logf(Err, "one or more parameters were nullptr @ SetSectionHash");
        return false;
    }

    if (GetIntegrityChecker() == nullptr)
    {
		Logger::logf(Err, "IntegrityChecker was nullptr @ SetSectionHash");
		return false;
    }

    bool funcFailed = false;

    UINT64 ModuleAddr = (UINT64)GetModuleHandleA(moduleName);

    if (ModuleAddr == 0)
    {
        Logger::logf(Err, "ModuleAddr was 0 @ SetSectionHash");
        return false;
    }

    list<ProcessData::Section*> sections = Process::GetSections(moduleName);
    
    if (sections.size() == 0)
    {
        Logger::logf(Err, "sections.size() of section %s was 0 @ SetSectionHash", sectionName);
        funcFailed = true;
        goto cleanup;
    }

    for (auto section : sections) 
    {
        if (section == nullptr)
            continue;

		if (section->name == sectionName)
        {
            vector<uint64_t> hashes = GetIntegrityChecker()->GetMemoryHash((uint64_t)section->address + ModuleAddr, section->size);

            if (hashes.size() > 0)
            {
                GetIntegrityChecker()->SetSectionHashList(hashes, sectionName);
                break;
            }
            else
            {
                Logger::logf(Err, "hashes.size() was 0 @ SetSectionHash", sectionName);
                funcFailed = true;
                goto cleanup;
            }
        }
    }

cleanup:
    for (auto section : sections)
    {
        if (section != nullptr)
            delete section;
    }

    return !funcFailed;
}

/*
    IsSectionHashUnmatching  compares our collected hash list from ::SetSectionHash() , we use cached address + size to prevent spoofing (sections can be renamed at runtime by an attacker)
    Returns true if the two sets of hashes do not match, implying memory was modified
*/
bool Detections::IsSectionHashUnmatching(__in const UINT64 cachedAddress, __in const DWORD cachedSize, __in const string section)
{
    if (cachedAddress == 0 || cachedSize == 0)
    {
        Logger::logf(Err, "Parameters were 0 @ Detections::IsSectionHashUnmatching");
        return false;
    }

    Logger::logf(Info, "Checking hashes of address: %llx (%d bytes) for memory integrity\n", cachedAddress, cachedSize);

    if (section == ".text")
    {
        if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetSectionHashList(".text"))) //compares hash to one gathered previously
        {
            Logger::logf(Info, "Hashes match: Program's .text section appears genuine.\n");
            return false;
        }
        else
        {
            Logger::logf(Detection, " .text section of program is modified!\n");
            return true;
        }
    }
    else if (section == ".rdata")
    {
        if (GetIntegrityChecker()->Check((uint64_t)cachedAddress, cachedSize, GetIntegrityChecker()->GetSectionHashList(".rdata"))) //compares hash to one gathered previously
        {
            Logger::logf(Info, "Hashes match: Program's .rdata section appears genuine.\n");
            return false;
        }
        else
        {
            Logger::logf(Detection, " .rdata section of program is modified!\n");
            return true;
        }
    }

    return false;
}

/*
    IsBlacklistedProcessRunning 
    returns TRUE if a blacklisted program is running in the background, blacklisted processes can be found in the class constructor
*/
bool Detections::IsBlacklistedProcessRunning() const
{
    bool foundBlacklistedProcess = false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) 
    {
        Logger::logf(Err, "Failed to create snapshot of processes. Error code: %d @ Detections::IsBlacklistedProcessRunning\n", GetLastError());
        return false;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) 
    {
        Logger::logf(Err, "Failed to get first process. Error code:  %d @ Detections::IsBlacklistedProcessRunning\n", GetLastError());
        CloseHandle(hSnapshot);
        return false;
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
bool Detections::DoesFunctionAppearHooked(__in const char* moduleName, __in const char* functionName)
{
    if (moduleName == nullptr || functionName == nullptr)
    {
        Logger::logf(Err, "moduleName or functionName was NULL @ Detections::DoesFunctionAppearHooked");
        return false;
    }

    bool FunctionPreambleHooked = false;

    HMODULE hMod = GetModuleHandleA(moduleName);

    if (hMod == NULL)
    {
        Logger::logf(Err, " Couldn't fetch module @ Detections::DoesFunctionAppearHooked: %s", moduleName);
        return false;
    }

    UINT64 AddressFunction = (UINT64)GetProcAddress(hMod, functionName);

    if (AddressFunction == NULL)
    {
        Logger::logf(Err, " Couldn't fetch address of function @ Detections::DoesFunctionAppearHooked: %s", functionName);
        return false;
    }

    __try
    {
        if (*(BYTE*)AddressFunction == 0xE8 || *(BYTE*)AddressFunction == 0xE9 || *(BYTE*)AddressFunction == 0xEA || *(BYTE*)AddressFunction == 0xEB) //0xEB = short jump, 0xE8 = call X, 0xE9 = long jump, 0xEA = "jmp oper2:oper1"
            FunctionPreambleHooked = true;
    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        Logger::logf(Warning, " Couldn't read bytes @ Detections::DoesFunctionAppearHooked: %s", functionName);
        return false; //couldn't read memory at function
    }

    return FunctionPreambleHooked;
}

/*
    DoesIATContainHooked - Returns TRUE if any routines in the IAT lead to addresses outside their respective modules
    if the attacker writes their hooks in the dll's address space then they can get around this detection
*/
bool Detections::DoesIATContainHooked()
{
    list<ProcessData::ImportFunction*> IATFunctions = Process::GetIATEntries();
    bool isIATHooked = false;

    auto modules = Process::GetLoadedModules();

    for (ProcessData::ImportFunction* IATEntry : IATFunctions)
    {
        DWORD moduleSize = Process::GetModuleSize(IATEntry->Module);

        bool FoundIATEntryInModule = false;

        if (moduleSize != 0)
        {   //some IAT functions in k32 can point to ntdll (forwarding), thus we have to compare IAT to each other whitelisted DLL range
            for (auto mod : modules)
            {
                UINT64 LowAddr = (UINT64)mod.dllInfo.lpBaseOfDll;
                UINT64 HighAddr = (UINT64)mod.dllInfo.lpBaseOfDll + mod.dllInfo.SizeOfImage;

                if (IATEntry->AddressOfData > LowAddr && IATEntry->AddressOfData < HighAddr) //each IAT entry needs to be checked thru all loaded ranges
                {
                    FoundIATEntryInModule = true;
                }
            }

            if (!FoundIATEntryInModule)
            {
                isIATHooked = true;
                break;
            }
                
        }
        else //error, we shouldnt get here!
        {
            Logger::logf(Err, " Couldn't fetch  module size @ Detections::DoesIATContainHooked");
            return false;
        }
    }

    return isIATHooked;
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
        Logger::logf(Err, "textAddr was NULL @ Detections::IsTextSectionWritable");
        return 0;
    }

    UINT64 max_addr = textAddr + Process::GetTextSectionSize(GetModuleHandle(NULL));

    while ((result = VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) != 0)     //Loop through all pages in .text
    {
        if (address >= max_addr)
            break;

        if (mbi.Protect != PAGE_EXECUTE_READ) //check if its not RX protections
        {
            Logger::logfw(Detection, L"Memory region at address %p is not PAGE_EXECUTE_READ - attacker likely re-re-mapped\n", address);
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
bool Detections::CheckOpenHandles()
{
    bool foundHandle = false;
    vector<Handles::_SYSTEM_HANDLE> handles = Handles::DetectOpenHandlesToProcess();

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

            Logger::logfw(Detection, L"Process %s has open process handle to our process.", procName.c_str());
            foundHandle = true;

        inner_break:
            continue;
        }
    }

    return foundHandle;
}

/*
    IsBlacklistedWindowPresent - Checks if windows with specific title or class names are present.
    *Note* this function should not be used on its own to determine if someone is running a cheat tool, it should be combined with other methods. An opened folder with a blacklisted name will be caught but doesn't imply the actual program is opened, for example
*/
bool Detections::IsBlacklistedWindowPresent()
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
                        Monitor->EvidenceManager->AddFlagged(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
                        Logger::logf(Detection, "Detected a window named 'Cheat Engine' (includes open folder names)");
                        return false;
                    }
                    else if (strstr(windowTitle, (const char*)original_LUAScript))
                    {
                        Monitor->EvidenceManager->AddFlagged(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM);
                        Logger::logf(Detection, "Detected cheat engine's lua script window");
                        return false;
                    }
                }
            }

            return true;
        };

        ENUMWINDOWS pEnumWindows = (ENUMWINDOWS)GetProcAddress(hUser32, "EnumWindows");
        if (pEnumWindows != NULL)
        {
            EnumWindows(WindowCallback, (LPARAM)this);
        }
        else
        {
            Logger::logf(Err, "GetProcAddress failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
            return false;
        }
    }
    else
    {
        Logger::logf(Err, "GetModuleHandle failed @ Detections::IsBlacklistedWindowPresent: %d", GetLastError());
        return false;
    }

    return false;
}

/*
    Detections::MonitorNewProcesses - Monitors process creation events via WMI
    Intended thread function, has no return value as it logs in real-time
*/
void Detections::MonitorProcessCreation(__in LPVOID thisPtr)
{
    if (thisPtr == nullptr)
    {
        Logger::logf(Err, "Monitor Ptr was NULL @ MonitorNewProcesses");
        return;
    }

    Detections* monitor = reinterpret_cast<Detections*>(thisPtr);
    monitor->MonitoringProcessCreation = true;

    HRESULT hres;
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        Logger::logf(Err, "Failed to initialize COM library @ MonitorNewProcesses");
        return;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
    if (FAILED(hres))
    {
        Logger::logf(Err, "Failed to initialize security @ MonitorNewProcesses");
        CoUninitialize();
        return;
    }

    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres))
    {
        Logger::logf(Err, "Failed to create IWbemLocator object @ MonitorProcessCreation");
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres))
    {
        Logger::logf(Err, "Could not connect to WMI namespace @ MonitorProcessCreation");
        pLoc->Release();
        CoUninitialize();
        return;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

    if (FAILED(hres))
    {
        Logger::logf(Err, "Could not set proxy blanket @ MonitorProcessCreation");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecNotificationQuery((wchar_t*)L"WQL", (wchar_t*)L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'", WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

    if (FAILED(hres))
    {
        Logger::logf(Err, "Query for process creation events failed @ MonitorProcessCreation");
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;

    while (pEnumerator && monitor->MonitoringProcessCreation) //keep looping while MonitoringProcessCreation is set to true
    {
        if (monitor != nullptr && monitor->GetProcessCreationMonitorThread() != nullptr)
        {
            if (monitor->GetProcessCreationMonitorThread()->IsShutdownSignalled()) //end execution if signalled
            {
                break;
            }
        }

        HRESULT hr = pEnumerator->Next(WBEM_NO_WAIT, 1, &pclsObj, &uReturn);

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
                VARIANT vtProcId{};
                VARIANT vtName {};
                pClassObj->Get(L"Name", 0, &vtName, 0, 0);
                pClassObj->Get(L"ProcessId", 0, &vtProcId, 0, 0);

                for (wstring blacklistedProcess : monitor->BlacklistedProcesses)
                {
                    if (Utility::wcscmp_insensitive(blacklistedProcess.c_str(), vtName.bstrVal))
                    {
                        Logger::logfw(Detection, L"Blacklisted process was spawned: %s", vtName.bstrVal);
                    }
                }

                Logger::logfw(Info, L"Scanning process for blacklisted patterns: %s", vtName.bstrVal);
          
                if (monitor->FindBlacklistedProgramsThroughByteScan(vtProcId.uintVal))
                {
                    monitor->EvidenceManager->AddFlagged(DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM, Utility::ConvertWStringToString(vtName.bstrVal), GetCurrentProcessId());
                    Logger::logfw(Detection, L"Blacklisted process was found through byte signature: %s", vtName.bstrVal);
                }
                
                VariantClear(&vtName);
                pClassObj->Release();
            }
        }

        VariantClear(&vtProp);
        pclsObj->Release();
        
        if(monitor->GetMonitorThread() != nullptr)
            monitor->GetMonitorThread()->UpdateTick(); //update tick on each loop, then we can check this value from a different thread to see if someone has suspended it

        //this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
    }

    pSvc->Release();
    pLoc->Release();
    pEnumerator->Release();
    CoUninitialize();
}

/*
    InitializeBlacklistedProcessesList - add static list of blacklisted process names to our Detections object
    ...we should also scan for window class names, possible exported functions (in any DLLs running in those programs), etc.
    Most people will of course just rename any common cheat tool names, much better to use byte scanning 
*/
void Detections::InitializeBlacklistedProcessesList()
{
    this->BlacklistedProcesses.push_back(L"Cheat Engine.exe");
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
bool Detections::FindBlacklistedProgramsThroughByteScan(__in const DWORD pid)
{
    if (pid <= 4)
        return false;

    bool foundSignature = false;

    for (BytePattern pattern : this->BlacklistedBytePatterns)
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
                    Logger::logfw(Detection, L"Found blacklisted byte pattern in process %d at offset %d", pid, i);
                    break;
                }
            }
        }
        else
        {
            Logger::logfw(Warning, L"Failed to read .text section of process %d", pid);
            continue;
        }
    }

    return foundSignature;
}

/*
    Monitors changes to important registry keys related to secure boot, CI, testsigning mode, etc
    Meant to be run in its own thread
*/
void Detections::MonitorImportantRegistryKeys(__in LPVOID thisPtr)
{
    if (thisPtr == nullptr)
    {
        Logger::logf(Warning, "Detections* was NULL @ MonitorImportantRegistryKeys");
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
            Logger::logf(Warning, "Failed to open key %d. Error: %ld @ MonitorImportantRegistryKeys", i, result);
            return;
        }

        hEvents[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
        if (!hEvents[i]) 
        {
            Logger::logf(Warning, "Failed to create event for key %d. Error: %ld\n", i, GetLastError());
            RegCloseKey(hKeys[i]);
            return;
        }

        result = RegNotifyChangeKeyValue(hKeys[i], TRUE, filter, hEvents[i], TRUE);
        if (result != ERROR_SUCCESS) 
        {
            Logger::logf(Warning, "Failed to register notification for key %d. Error: %ld", i, result);
            CloseHandle(hEvents[i]);
            RegCloseKey(hKeys[i]);
            return;
        }
    }

    Logger::logf(Info, "Monitoring multiple registry keys...");

    bool monitoringKeys = true;

    while (monitoringKeys)
    {        
        if (Monitor != nullptr && Monitor->GetRegistryMonitorThread() != nullptr && Monitor->GetRegistryMonitorThread()->IsShutdownSignalled()) //end looping if signalled
            break;
        
        DWORD waitResult = WaitForMultipleObjects(KEY_COUNT, hEvents, FALSE, 3000); //wait for any of the events to be signaled

        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + KEY_COUNT) 
        {
            int index = waitResult - WAIT_OBJECT_0; //determine which event was signaled

            Logger::logf(Detection, "Key %d value changed!", index);

            Monitor->EvidenceManager->AddFlagged(DetectionFlags::REGISTRY_KEY_MODIFICATIONS);

            result = RegNotifyChangeKeyValue(hKeys[index], TRUE, filter, hEvents[index], TRUE);   //re register the notification for the key

            if (result != ERROR_SUCCESS) 
            {
                Logger::logf(Warning, "Failed to re-register notification for key %d. Error: %ld", index, result);
            }
        }
        else 
        {
            //Logger::logf(Warning, "Unexpected wait result: %ld", waitResult); //this message will display often, commented out to suppress it
            continue;
        }

        if (Monitor != nullptr && Monitor->GetMonitorThread() != nullptr)
            Monitor->GetMonitorThread()->UpdateTick();

        this_thread::sleep_for(std::chrono::milliseconds(100)); //ease the CPU a bit
    }

    for (int i = 0; i < KEY_COUNT; i++) 
    {
        if(hEvents[i] != 0 && hEvents[i] != INVALID_HANDLE_VALUE)
            CloseHandle(hEvents[i]);

        RegCloseKey(hKeys[i]);
    }
}

/*
    DetectManualMapping - detects if a manually mapped module is injected. also tries to detect PE header erased mapped modules, however this is tricky and possible to throw false positives!
    returns a vector of memory addresses (uint64_t), representing suspicious memory regions not belonging to a loaded module
*/
vector<uint64_t> Detections::DetectManualMapping()
{
    auto modules = Process::GetLoadedModules();

    if (modules.size() == 0)
    {
        Logger::logf(Err, "Failed to fetch list of loaded modules @ DetectManualMapping");
        return {};
    }

    vector<uint64_t> SuspiciousRegions;

    MEMORY_BASIC_INFORMATION mbi;
    uint64_t CurrentRegionAddr = 0;  //starting address to scan from
    uintptr_t userModeLimit = 0x00007FFFFFFFFFFF; 	// 64-bit user-mode memory typically ends around 0x00007FFFFFFFFFFF

    while ((uintptr_t)CurrentRegionAddr < userModeLimit && VirtualQuery((LPCVOID)CurrentRegionAddr, &mbi, sizeof(mbi)) == sizeof(mbi)) //loop through all memory regions in the process
    {
        if (mbi.State != MEM_COMMIT) //skip memory regions that are reserved or free
        {
            CurrentRegionAddr += mbi.RegionSize;
            continue;
        }

        if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY)) //check if the memory region has executable permissions - lazy or unaware cheaters may forget to set their injected code to readonly
        {
            if (Integrity::IsAddressInModule(modules, (uintptr_t)mbi.BaseAddress)) //check if the memory region is part of a known module
            {
                CurrentRegionAddr += mbi.RegionSize; //skip modules which have been loaded properly
                continue;
            }

            unsigned char buffer[512]{ 0 };

            memcpy_s(buffer, sizeof(buffer), (const void*)mbi.BaseAddress, sizeof(buffer));

            if (Integrity::IsPEHeader(buffer)) //if the PE header is deleted, this won't detect it, so tackle that in the "else" block below
            {
                Logger::logf(Detection, "Suspicious PE header found at address %llX", mbi.BaseAddress);
                SuspiciousRegions.push_back((uint64_t)mbi.BaseAddress);
            }
            else //check for erased PE headers. * confirmed working against some manual mappers found on github *
            {
                PSAPI_WORKING_SET_EX_INFORMATION wsInfo;
                wsInfo.VirtualAddress = mbi.BaseAddress;

                bool foundPossibleErasedHeaderModule = true;

                if (QueryWorkingSetEx(GetCurrentProcess(), &wsInfo, sizeof(wsInfo)))
                {
                    if (wsInfo.VirtualAttributes.Valid)
                    {
                        if (!wsInfo.VirtualAttributes.Shared)  // If not shared, it's likely private
                        {
                            bool foundPossibleSection = false; // I may end up introducing capstone in the project, parsing possible instructions would be great for this routine to have
                            unsigned char bufferPossibleMappedSection[128] { 0 };

                            //todo: make some better way than just using a hardcoded offset , since this can be changed via section alignment in compilation

                            uint64_t possibleTextSectionAddress = (uint64_t)(mbi.BaseAddress);

                            //maybe i'll change this to memcpy_s() afterwards - this works fine currently and it's late at night, so maybe next time.
                            if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)possibleTextSectionAddress, bufferPossibleMappedSection, sizeof(bufferPossibleMappedSection), NULL))
                            {
                                for (int i = 0; i < sizeof(bufferPossibleMappedSection) - 4; i++) // many manual mappers erase headers by replacing them with all 00's
                                {
                                    if (bufferPossibleMappedSection[i] != 0 && bufferPossibleMappedSection[i + 1] != 0 && bufferPossibleMappedSection[i + 2] != 0 && bufferPossibleMappedSection[i + 3] != 0)
                                    {
                                        foundPossibleSection = true;
                                        break;
                                    }
                                }
                            }

                            if (foundPossibleSection) //this will be the most likely spot which gives false positives, but its also the trickest to detect
                            {
                                SuspiciousRegions.push_back(possibleTextSectionAddress);
                            }
                        }
                    }
                }
            }
        }

        CurrentRegionAddr += mbi.RegionSize;
    }


    return SuspiciousRegions;
}

/*
    WasProcessNotRemapped - checks if remapping -did not- occur
    returns `true` if program was not remapped
*/
bool Detections::WasProcessNotRemapped()
{
    return false; //this will be finished soon...
}