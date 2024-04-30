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

    delete[] RandString1;
    delete[] RandString2;
    delete[] RandString3;
    delete[] RandString4;

    return success;
}

bool Preventions::PreventShellcodeThreads() //using this technique might pop up a warning about missing the function "CreateThread" (Entry Point Not Found)
{
    bool success = FALSE;
    char* RandString1 = Utility::GenerateRandomString(12);

    if (Exports::ChangeFunctionName("KERNEL32.DLL", "CreateThread", RandString1))
        success = TRUE;

    delete[] RandString1;
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
        wprintf(L"Changed module name to: %s\n", UnmanagedGlobals::wCurrentModuleName.c_str());
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
    if (!RemapProgramSections()) //anti-memory write
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't remap memory @ DeployBarrier!\n");
        retError = Error::CANT_STARTUP;
    }
#endif

    IsPreventingThreadCreation = true;

    //if (PreventDllInjection()) //anti-injection
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

    //BYTE* newPEB = SpoofPEB(); //memory should be free'd at end of program  -> CURRENTLY CAUSES ISSUES WITH THREADING, DO NOT USE! 

    //if (newPEB != NULL)
    //{
    //    Logger::logf("UltimateAnticheat.log", Info, " Spoofed PEB successfully!\n");
    //}
    //else
    //{
    //    Logger::logf("UltimateAnticheat.log", Err, " Couldn't spoof PEB @ Preventions::ChangeExportNames\n");
    //    retError = Error::CANT_APPLY_TECHNIQUE;
    //}

    if (RandomizeModuleName()) 
    {
        Logger::logf("UltimateAnticheat.log", Info, " Randomized our executable's module's name!\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't change our module's name @ Preventions::ChangeModuleName\n");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

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
        exit(Error::NULL_MEMORY_REFERENCE);
    }

    return remap_succeeded;
}

