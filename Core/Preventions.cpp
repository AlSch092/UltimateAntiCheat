//By AlSch092 @github
#include "Preventions.hpp"

/*
  RandomizeModuleName - Changes the program's main module name (in memory) to a random string  
  returns true on success
*/
bool Preventions::RandomizeModuleName()
{
    bool success = false;

    int moduleNameSize = (int)wcslen(_MAIN_MODULE_NAME_W);

    if (moduleNameSize == 0) //this will only hit if _MAIN_MODULE_NAME_W  definition is set to an empty string
    {
        Logger::logf(Err, "string length of definition _MAIN_MODULE_NAME_W was 0 @ Preventions::RandomizeModuleName");
        return false;
    }

    wstring newModuleName = Utility::GenerateRandomWString(moduleNameSize); //intentionally set to -2 to trip up external programs like CE from enumerating dlls & symbols

    if (Process::ChangeModuleName(_MAIN_MODULE_NAME_W, newModuleName)) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
    {
        success = true;

        Process::SetExecutableModuleName(newModuleName);
      
        ProcessData::MODULE_DATA mod = Process::GetModuleInfo(newModuleName.c_str());
        
        if (mod.hModule != 0)
        {
            this->integrityChecker->AddToWhitelist(mod);
        }

        Logger::logfw(Info, L"Changed module name to: %s\n", newModuleName.c_str());
    }

    return success;
}

/*
    DeployBarrier - Launches various attack prevention techniques
    returns Error::OK on success
*/
Error Preventions::DeployBarrier()
{
    Error retError = Error::OK;

    if (!Process::ChangeNumberOfSections(_MAIN_MODULE_NAME, 1)) //change # of sections to 1
    {
        Logger::logf(Err, "Failed to change number of sections @ Preventions::DeployBarrier");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

#ifndef _DEBUG
    if (!RemapProgramSections()) //anti-memory write on .text through sections remapping, thanks to changeofpace
    {
        Logger::logf(Err, " Couldn't remap memory @ DeployBarrier!\n");
        retError = Error::CANT_STARTUP;
    }
#endif

    IsPreventingThreadCreation = true; //used in TLS callback to prevent thread creation (can stop shellcode + module injection)

    if (RandomizeModuleName()) //randomize our main module name at runtime
    {
        Logger::logf(Info, " Randomized our executable's module's name!");
    }
    else
    {
        Logger::logf(Err, " Couldn't change our module's name @ Preventions::DeployBarrier");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    if (!StopAPCInjection()) //patch over ntdll.dll Ordinal8 unnamed function
    {
        Logger::logf(Err, "Couldn't apply anti-APC technique @ Preventions::DeployBarrier");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

#if _WIN32_WINNT >= 0x0602 //minimum windows 8 for SetMitigation routines
    //third parameter (dynamic code) set to true -> prevents VirtualProtect from succeeding on .text sections of loaded/signed modules. while this can be very useful, it breaks our TLS callback protections since we patch over the first byte of new thread's execution addresses
    Preventions::EnableProcessMitigations(true, true, false, true, true); 
#endif

    return retError;
}

/*
    RemapProgramSections - remaps the current module's sections to prevent memory writing/patching
    Thanks to ChangeOfPace @ Github for the RmpRemapImage routines
*/
bool Preventions::RemapProgramSections()
{
    ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(NULL);
    bool remap_succeeded = false;

    if (ImageBase)
    {
        __try
        {
            if (!RmpRemapImage(ImageBase)) //re-mapping of image to stop patching, and of course we can easily detect if someone bypasses this
            {
                Logger::logf(Err, " RmpRemapImage failed @ RemapProgramSections");
            }
            else
            {
                Logger::logf(Info, " Successfully remapped @ RemapProgramSections");
                remap_succeeded = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Logger::logf(Err, " Remapping image failed @ RemapProgramSections");
            return false;
        }
    }
    else
    {
        Logger::logf(Err, " Imagebase was NULL @ RemapAndCheckPages!");
        return false;
    }

    return remap_succeeded;
}

/*
    StopMultipleProcessInstances - Uses shared memory to prevent multiple instances of the process.
    returns true on success
    ... Using a mutex instead may result in attackers closing the mutex handle with popular tools such as Process Hacker
*/
bool Preventions::StopMultipleProcessInstances()
{
    HANDLE hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(int), "UAC");

    if (hSharedMemory == NULL)
    {
        Logger::logf(Err, "Failed to create shared memory. Error code: %lu\n", GetLastError());
        return false;
    }

    int* pIsRunning = (int*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(int));

    if (pIsRunning == NULL)
    {
        Logger::logf(Err, "Failed to map view of file. Error code : % lu\n", GetLastError());
        CloseHandle(hSharedMemory);
        return false;
    }

    if (*pIsRunning == 1337) //duplicate instance found, these instructions can be obfuscated if desired
    {
        UnmapViewOfFile(pIsRunning);
        CloseHandle(hSharedMemory);
        return false;
    }

    *pIsRunning = 1337;

    return true;
}

/*
    StopAPCInjection - prevents APC injection by patching over the first byte of ntdll.Ordinal8. More information about the APC payload can be fetched through hooking
    returns false on failure, true on successful patch
    WARNING: if your program/game relies on usermode APC for functionality then this technique may not be suitable for you
*/
bool Preventions::StopAPCInjection()
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    if (!ntdll)
    {
        Logger::logf(Err, "Failed to fetch ntdll module @ StopAPCInjection. Error code : % lu\n", GetLastError());
        return false;
    }

    const int Ordinal = 8;
    UINT64 Oridinal8 = (UINT64)GetProcAddress(ntdll, MAKEINTRESOURCEA(Ordinal)); //TODO: make sure Ordinal8 exists on other versions of windows and is the same function

    if (!Oridinal8)
    {
        Logger::logf(Err, "Failed to fetch ntdll.Ordinal8 address @ StopAPCInjection");
        return false;
    }

    __try
    {
        DWORD dwOldProt = 0;

        if (!VirtualProtect((LPVOID)Oridinal8, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt))
        {
            Logger::logf(Warning, "Failed to call VirtualProtect on Oridinal8 address @ StopAPCInjection: %llX", Oridinal8);
            return false;
        }
        else
        {
            if (Oridinal8 != 0)
                *(BYTE*)Oridinal8 = 0xC3;

            VirtualProtect((LPVOID)Oridinal8, sizeof(byte), dwOldProt, &dwOldProt);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Logger::logf(Err, "Failed to patch over Ordinal8 address @ StopAPCInjection");
        return false;
    }

    return true;
}

#if _WIN32_WINNT >= 0x0602  //SetProcessMitigationPolicy starts support in Windows 8 
/*
    EnableProcessMitigations - enforces policies which are actioned by the system & loader to prevent dynamic code generation & execution (unsigned code will be rejected by the loader)
*/
void Preventions::EnableProcessMitigations(__in const bool useDEP, __in const bool useASLR, __in const  bool useDynamicCode, __in const bool useStrictHandles, __in const bool useSystemCallDisable)
{
    if (useDEP)
    {
        PROCESS_MITIGATION_DEP_POLICY depPolicy = { 0 };     // DEP Policy
        depPolicy.Enable = 1;
        depPolicy.Permanent = 1;

        if (!SetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
        {
            Logger::logf(Warning, "Failed to set DEP policy @ EnableProcessMitigations: %d", GetLastError());
        }
    }

    if (useASLR)
    {
        PROCESS_MITIGATION_ASLR_POLICY aslrPolicy = { 0 };     //ASLR Policy
        aslrPolicy.EnableBottomUpRandomization = 1;
        aslrPolicy.EnableForceRelocateImages = 1;
        aslrPolicy.EnableHighEntropy = 1;
        aslrPolicy.DisallowStrippedImages = 1;

        if (!SetProcessMitigationPolicy(ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)))
        {
            Logger::logf(Warning, "Failed to set ASLR policy @ EnableProcessMitigations: %d", GetLastError());
        }
    }

    if (useDynamicCode)
    {
        PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = { 0 };     //Dynamic Code Policy -> can prevent VirtualProtect calls on .text sections of loaded modules from working
        dynamicCodePolicy.ProhibitDynamicCode = 1;

        if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy)))
        {
            Logger::logf(Warning, "Failed to set dynamic code policy @ EnableProcessMitigations: %d", GetLastError());
        }
    }

    if (useStrictHandles)
    {
        PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY handlePolicy = { 0 };     // Strict Handle Check Policy
        handlePolicy.RaiseExceptionOnInvalidHandleReference = 1;
        handlePolicy.HandleExceptionsPermanentlyEnabled = 1;

        if (!SetProcessMitigationPolicy(ProcessStrictHandleCheckPolicy, &handlePolicy, sizeof(handlePolicy)))
        {
            Logger::logf(Warning, "Failed to set strict handle check policy @ EnableProcessMitigations: %d", GetLastError());
        }
    }

    if (useSystemCallDisable)
    {
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallPolicy = { 0 };     // System Call Disable Policy
        syscallPolicy.DisallowWin32kSystemCalls = 1;

        if (!SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy, &syscallPolicy, sizeof(syscallPolicy)))
        {
            Logger::logf(Warning, "Failed to set system call disable policy @ EnableProcessMitigations: %d", GetLastError());
        }
    }

    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy = { 0 };     // Binary Signature Policy
    signaturePolicy.MicrosoftSignedOnly = 1;
    SetProcessMitigationPolicy(ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy));

    PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy = { 0 };     //Image Load Policy, a few useful ones in here
    imageLoadPolicy.NoRemoteImages = 1;
    imageLoadPolicy.PreferSystem32Images = 1; //enforce loading from system32 before relative paths for .dlls
    SetProcessMitigationPolicy(ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));
}

#endif


/*
    UnloadBlacklistedDrivers - attempts to unload/stop blacklisted drivers in `driverPaths`
*/
void Preventions::UnloadBlacklistedDrivers(__in const list<wstring> driverPaths)
{
    if (driverPaths.size() > 0)
    {
        for (auto driverPath : driverPaths)
        {
            if (!Services::UnloadDriver(driverPath))
            {
                Logger::logfw(Warning, L"Failed to unload driver %s at UnloadBlacklistedDrivers", driverPath.c_str());
            }
        }
    }
}
