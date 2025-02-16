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

    if (moduleNameSize == 0)
    {
        return false;
    }

    wchar_t* newModuleName = Utility::GenerateRandomWString(moduleNameSize); //intentionally set to -2 to trip up external programs like CE from enumerating dlls & symbols

    if (Process::ChangeModuleName(_MAIN_MODULE_NAME_W, newModuleName)) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
    {
        success = true;
        UnmanagedGlobals::wCurrentModuleName = wstring(newModuleName);
        UnmanagedGlobals::CurrentModuleName = Utility::ConvertWStringToString(UnmanagedGlobals::wCurrentModuleName);
        
        ProcessData::MODULE_DATA* mod = Process::GetModuleInfo(newModuleName);
        
        if (mod != nullptr)
        {
            this->integrityChecker->AddToWhitelist(*mod);
            delete mod;
        }

        Logger::logfw(Info, L"Changed module name to: %s\n", UnmanagedGlobals::wCurrentModuleName.c_str());
    }

    delete[] newModuleName;
    return success;
}

/*
    DeployBarrier - Launches various attack prevention techniques
    returns Error::OK on success
*/
Error Preventions::DeployBarrier()
{
    Error retError = Error::OK;

#ifndef _DEBUG
    IsPreventingThreadCreation = false; //TLS callback anti-dll injection switch var
#endif

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
                Logger::logf(Err, " RmpRemapImage failed.\n");
            }
            else
            {
                Logger::logf(Info, " Successfully remapped\n");
                remap_succeeded = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Logger::logf(Err, " Remapping image failed!");
            return false;
        }
    }
    else
    {
        Logger::logf(Err, " Imagebase was NULL @ RemapAndCheckPages!\n");
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
    HANDLE hSharedMemory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(int), " "); //shared memory with blank name

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
    WARNING: if your program/game relies on APC for functionality then this technique won't be suitable for you
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
void Preventions::EnableProcessMitigations(bool useDEP, bool useASLR, bool useDynamicCode, bool useStrictHandles, bool useSystemCallDisable)
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
}

#endif

/*
    Preventions::PreventDllInjection - changes the export name of specific K32 routines such that an external attacker trying to fetch the address of these is given bad values.
    *Note* : Changing export names for certain important dll routines can result in popup errors for the end-user, thus its not recommended for a live product. Alternatively, routines can have their function preambles 'ret' patched for similar effects  (if you know it wont impact program functionality).
*/
bool Preventions::PreventDllInjection()
{
    bool success = FALSE;

    //Anti-dll injection
    char* RandString1 = Utility::GenerateRandomString(12);
    char* RandString2 = Utility::GenerateRandomString(12);
    char* RandString3 = Utility::GenerateRandomString(14);
    char* RandString4 = Utility::GenerateRandomString(14);

    //prevents DLL injection from any host process relying on calling LoadLibrary in the target process (we are the target in this case) -> can possibly be disruptive to end user
    if (Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryA", RandString1) &&
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryW", RandString2) &&
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExA", RandString3) &&
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExW", RandString4))
    {
        success = TRUE;
    }
    else
    {
        success = FALSE;
    }

    delete[] RandString1; RandString1 = nullptr;
    delete[] RandString2; RandString2 = nullptr;
    delete[] RandString3; RandString3 = nullptr;
    delete[] RandString4; RandString4 = nullptr;

    return success;
}

/*
    PreventShellcodeThreads - changes export routine name of K32's CreateThread such that external attackers cannot look up the functions address.
     *Note* : Changing export names for certain important dll routines can result in popup errors for the end-user, thus its not recommended for a live product. Alternatively, routines can have their function preambles 'ret' patched for similar effects (if you know it wont impact program functionality).
*/
bool Preventions::PreventShellcodeThreads() //using this technique might pop up a warning about missing the function "CreateThread" (Entry Point Not Found)
{
    bool success = FALSE;
    char* RandString1 = Utility::GenerateRandomString(12);

    if (Exports::ChangeFunctionName("KERNEL32.DLL", "CreateThread", RandString1))
        success = TRUE;

    delete[] RandString1;
    RandString1 = nullptr;
    return success;
}

BYTE* Preventions::SpoofPEB() //experimental, don't use this right now as it causes some thread issues
{
    BYTE* newPEBBytes = CopyAndSetPEB();

    if (newPEBBytes == NULL)
    {
        Logger::logf(Err, " Failed to copy PEB @ SpoofPEB!");
        return NULL;
    }

    _MYPEB* ourPEB = (_MYPEB*)&newPEBBytes[0];

    Logger::logf(Info, " Being debugged (PEB Spoofing test): %d. Address of new PEB : %llx\n", ourPEB->BeingDebugged, (UINT64)&newPEBBytes[0]);
    return newPEBBytes;
}
