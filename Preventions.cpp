//By AlSch092 @github
#include "Preventions.hpp"

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
        Logger::logf("UltimateAnticheat.log", Err, " Failed to copy PEB @ SpoofPEB!\n");
        return NULL;
    }

    _MYPEB* ourPEB = (_MYPEB*)&newPEBBytes[0];

    Logger::logf("UltimateAnticheat.log", Info, " Being debugged (PEB Spoofing test): %d. Address of new PEB : %llx\n", ourPEB->BeingDebugged, (UINT64)&newPEBBytes[0]);
    return newPEBBytes;
}

bool Preventions::RandomizeModuleName()
{
    bool success = false;

    int moduleNameSize = (int)wcslen(OriginalModuleName.c_str());

    if (moduleNameSize == 0)
    {
        return false;
    }

    wchar_t* newModuleName = Utility::GenerateRandomWString(moduleNameSize); //intentionally set to -2 to trip up external programs like CE from enumerating dlls & symbols

    if (Process::ChangeModuleName(OriginalModuleName.c_str(), newModuleName)) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
    {
        success = true;
        UnmanagedGlobals::wCurrentModuleName = wstring(newModuleName);
        UnmanagedGlobals::CurrentModuleName = Utility::ConvertWStringToString(UnmanagedGlobals::wCurrentModuleName);
        Logger::logfw("UltimateAnticheat.log", Info, L"Changed module name to: %s\n", UnmanagedGlobals::wCurrentModuleName.c_str());
    }

    delete[] newModuleName;
    return success;
}

Error Preventions::DeployBarrier() 
{
    Error retError = Error::OK;

#ifndef _DEBUG
    IsPreventingThreadCreation = false; //TLS callback anti-dll injection switch var
#endif

#ifndef _DEBUG
    if (!RemapProgramSections()) //anti-memory write through sections remapping, thanks changeofpace
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't remap memory @ DeployBarrier!\n");
        retError = Error::CANT_STARTUP;
    }
#endif

    IsPreventingThreadCreation = true; //used in TLS callback to prevent thread creation (can stop shellcode + module injection)

    if (RandomizeModuleName()) //randomize our main module name at runtime
    {
        Logger::logf("UltimateAnticheat.log", Info, " Randomized our executable's module's name!");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't change our module's name @ Preventions::ChangeModuleName");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    if (!StopAPCInjection()) //patch over ntdll.dll Ordinal8 unnamed function
    {
        Logger::logf("UltimateAnticheat.log", Err, "Couldn't apply anti-APC technique @ Preventions::ChangeModuleName");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    //anything commented out below means it needs further testing to ensure no side effects occur, 

    //if (PreventDllInjection()) //anti-injection by renaming exports of LoadLibrary
    //{
    //    Logger::logf("UltimateAnticheat.log", Info, " Wrote over LoadLibrary (kernel32) export names successfully!\n");
    //}
    //else
    //{
    //    Logger::logf("UltimateAnticheat.log", Err, " Couldn't write over export names @ Preventions::ChangeExportNames\n");
    //    retError = Error::CANT_APPLY_TECHNIQUE;
    //}

    //if (PreventShellcodeThreads()) //prevent lookups to CreateThread symbol from injected code by renaming the export name in memory, but can throw errors to the end user
    //{
    //    Logger::logf("UltimateAnticheat.log", Info, " Wrote over CreateThread (kernel32) export name successfully!\n");
    //}
    //else
    //{
    //    Logger::logf("UltimateAnticheat.log", Err, " Couldn't write over export names @ Preventions::ChangeExportNames\n");
    //    retError = Error::CANT_APPLY_TECHNIQUE;
    //}

    //BYTE* newPEB = SpoofPEB(); //memory should be free'd at end of program  -> CURRENTLY CAUSES ISSUES WITH THREADING, need to look at it deeper

    //if (newPEB != NULL)
    //{
    //    Logger::logf("UltimateAnticheat.log", Info, " Spoofed PEB successfully!\n");
    //}
    //else
    //{
    //    Logger::logf("UltimateAnticheat.log", Err, " Couldn't spoof PEB @ Preventions::ChangeExportNames\n");
    //    retError = Error::CANT_APPLY_TECHNIQUE;
    //}

    return retError;
}

//this function re-maps the process memory and then checks if someone else has re-re-mapped it by querying page protections
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
                Logger::logf("UltimateAnticheat.log", Err, " RmpRemapImage failed.\n");
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Info, " Successfully remapped\n");
                remap_succeeded = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Logger::logf("UltimateAnticheat.log", Err, " Remapping image failed, please ensure optimization is set to /O2\n");
            return false;
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Imagebase was NULL @ RemapAndCheckPages!\n");
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to create shared memory. Error code: %lu\n", GetLastError());
        return false;
    }

    int* pIsRunning = (int*)MapViewOfFile(hSharedMemory, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(int));
    
    if (pIsRunning == NULL) 
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to map view of file. Error code : % lu\n", GetLastError());
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
        Logger::logf("UltimateAnticheat.log", Err, "Failed to fetch ntdll module @ StopAPCInjection. Error code : % lu\n", GetLastError());
        return false;
    }

    const int Ordinal = 8;
    UINT64 Oridinal8 = (UINT64)GetProcAddress(ntdll, MAKEINTRESOURCEA(Ordinal)); //TODO: make sure Ordinal8 exists on other versions of windows and is the same function

    if (!Oridinal8)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to fetch ntdll.Ordinal8 address @ StopAPCInjection");
        return false;
    }

    __try
    {
        DWORD dwOldProt = 0;

        if (!VirtualProtect((LPVOID)Oridinal8, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt))
        {
            Logger::logf("UltimateAnticheat.log", Warning, "Failed to call VirtualProtect on Oridinal8 address @ StopAPCInjection: %llX", Oridinal8);
            return false;
        }
        else
        {
            if (Oridinal8 != 0)
                *(BYTE*)Oridinal8 = 0xC3;

            VirtualProtect((LPVOID)Oridinal8, sizeof(byte), dwOldProt, &dwOldProt);
        }

    }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Failed to patch over Ordinal8 address @ StopAPCInjection");
        return false;
    }

    return true;
}
