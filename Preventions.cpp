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

    //prevents DLL injection from any host process relying on calling LoadLibrary in the target process (we are the target in this case)
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

BYTE* Preventions::SpoofPEB()
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

bool Preventions::ChangeModuleName()
{
    bool success = false;

    int moduleNameSize = (int)wcslen(OriginalModuleName.c_str());

    if (moduleNameSize <= 2) //prevent underflow on next statements
    {
        return false;
    }

    wchar_t* newModuleName = Utility::GenerateRandomWString(moduleNameSize - 2); //intentionally set to -2 to trip up external programs like CE from enumerating dlls & symbols

    if (Process::ChangeModuleName(OriginalModuleName.c_str(), newModuleName)) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
    {
        wprintf(L"Changed module name to %s!\n", newModuleName);
        success = true;
    }

    delete[] newModuleName;
    return success;
}

Error Preventions::DeployBarrier() 
{
    Error retError = Error::OK;

    IsPreventingThreadCreation = true; //TLS callback anti-dll injection switch var

#ifndef _DEBUG
    if (!RemapAndCheckPages()) //anti-memory write
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't remap memory @ DeployBarrier!\n");
        retError = Error::CANT_STARTUP;
    }
#endif
    if (PreventDllInjection()) //anti-injection
    {
        Logger::logf("UltimateAnticheat.log", Info, " Wrote over LoadLibrary (kernel32) export names successfully!\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't write over export names @ Preventions::ChangeExportNames\n");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    BYTE* newPEB = SpoofPEB(); //memory should be free'd at end of program

    if (newPEB != NULL)
    {
        Logger::logf("UltimateAnticheat.log", Info, " Spoofed PEB successfully!\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't spoof PEB @ Preventions::ChangeExportNames\n");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    if (ChangeModuleName()) //should block calls to GetModuleHandle from working unless the cheater keeps up with our new module's name
    {
        Logger::logf("UltimateAnticheat.log", Info, " Randomized our module's name!\n");
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Couldn't change our module's name @ Preventions::ChangeModuleName\n");
        retError = Error::CANT_APPLY_TECHNIQUE;
    }

    return retError;
}

//this function re-maps the process memory and then checks if someone else has re-re-mapped it by querying page protections
bool Preventions::RemapAndCheckPages()
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
            Logger::logf("UltimateAnticheat.log", Err, " Remapping image failed with an exception, you might need to place this at the top of your code before other security mechanisms are in place\n");
            return false;
        }

        //remapping protects mainly the .text section from writes, which means we should query this section to see if it was changed to writable (re-re-mapping check)
        UINT64 textSection = Process::GetSectionAddress(NULL, ".text");

        //check page protections, if they're writable then some cheater has re-re-mapped our image to make it write-friendly
        MEMORY_BASIC_INFORMATION mbi = {};

        if (remap_succeeded)
        {
            if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)textSection, &mbi, sizeof(mbi))) //check if someone else re-mapped our process with writable permissions after we remapped it
            {
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_COMMIT && mbi.Type == MEM_MAPPED) //after remapping, mbi.Type will be MEM_MAPPED instead of MEM_IMAGE, and memState will be COMMIT instead of RESERVE
                {
                    Logger::logf("UltimateAnticheat.log", Detection, " re-re-mapping occured : Cheater! Change back the page protections NOW! \n");
                    exit(Error::PAGE_PROTECTIONS_MISMATCH);
                }
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Err, " VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
        else //remapping failed for us - check if pages are writable anyway
        {
            if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)textSection, &mbi, sizeof(mbi))) //case where remapping fails but page protections are still tampered (PAGE_EXECUTE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_READONLY
            {
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_RESERVE && mbi.Type == MEM_IMAGE) //if remapping failed, it will still be MEM_IMAGE
                {
                    Logger::logf("UltimateAnticheat.log", Detection, " page protections were writable! \n");
                }
            }
            else
            {
                Logger::logf("UltimateAnticheat.log", Err, " VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
    }
    else
    {
        Logger::logf("UltimateAnticheat.log", Err, " Imagebase was NULL @ RemapAndCheckPages!\n");
        exit(Error::NULL_MEMORY_REFERENCE);
    }

    return remap_succeeded;
}

