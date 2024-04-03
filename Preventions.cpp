//By AlSch092 @github
#include "Preventions.hpp"

Error Preventions::DeployBarrier() 
{
    Error retError = Error::OK;

    IsPreventingThreadCreation = true; //TLS anti-dll injection

    if (!RemapAndCheckPages()) //anti-memory write
    {
        printf("[ERROR] Couldn't remap memory @ DeployBarrier!\n");
        retError = Error::CANT_STARTUP;
    }

    //Anti-dll injection
    char* RandString1 = Utility::GenerateRandomString(10);
    char* RandString2 = Utility::GenerateRandomString(10);
    char* RandString3 = Utility::GenerateRandomString(10);
    char* RandString4 = Utility::GenerateRandomString(10);

    if (Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryA", RandString1) &&   ///prevents DLL injection from any method relying on calling LoadLibrary in the host process.
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryW", RandString2) &&
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExA", RandString3) &&
        Exports::ChangeFunctionName("KERNEL32.DLL", "LoadLibraryExW", RandString4))
            printf("[INFO] Wrote over LoadLibrary export names successfully!\n");

    delete[] RandString1;
    delete[] RandString2;
    delete[] RandString3;
    delete[] RandString4;

    //PEB spoofing
    BYTE* newPEBBytes = CopyAndSetPEB();

    if (newPEBBytes == NULL)
    {
        printf("Failed to copy PEB!\n");
        exit(0);
    }

    _MYPEB* ourPEB = (_MYPEB*)&newPEBBytes[0];

    printf("Being debugged (PEB Spoofing test): %d. Address of new PEB : %llx\n", ourPEB->BeingDebugged, (UINT64)&newPEBBytes[0]);

    std::wstring newModuleName = L"new_name";

    if (Process::ChangeModuleName(L"UltimateAnticheat.exe", (wchar_t*)newModuleName.c_str())) //in addition to changing export function names, we can also modify the names of loaded modules/libraries.
    {
        wprintf(L"Changed module name to %s!\n", newModuleName.c_str());
    }
    else
    {
        printf("[ERROR] Couldn't change module name @ DeployBarrier!\n");
        retError = Error::GENERIC_FAIL;
    }

    //AC->InternalModuleName = newModuleName; //need to expose Anticheat* class member in Preventions class

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
                printf("RmpRemapImage failed.\n");
            }
            else
            {
                printf("Successfully remapped\n");
                remap_succeeded = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            printf("Remapping image failed with an exception, you might need to place this at the top of your code before other security mechanisms are in place\n");
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
                    printf("Cheater! Change back the protections NOW!\n");
                    exit(Error::PAGE_PROTECTIONS_MISMATCH);
                }
            }
            else
            {
                printf("VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
        else //remapping failed for us - check if pages are writable anyway
        {
            if (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)textSection, &mbi, sizeof(mbi))) //case where remapping fails but page protections are still tampered (PAGE_EXECUTE_READWRITE instead of PAGE_EXECUTE_READ/PAGE_READONLY
            {
                if (mbi.AllocationProtect == PAGE_EXECUTE_READWRITE && mbi.State == MEM_RESERVE && mbi.Type == MEM_IMAGE) //if remapping failed, it will still be MEM_IMAGE
                {
                    printf("Cheater! Change back the protections NOW!\n");
                    exit(Error::PAGE_PROTECTIONS_MISMATCH);
                }
            }
            else
            {
                printf("VirtualQuery failed at RemapAndCheckPages .. we aren't supposed to reach this block: %d\n", GetLastError());
                return false;
            }
        }
    }
    else
    {
        printf("Imagebase was NULL!\n");
        exit(Error::NULL_MEMORY_REFERENCE);
    }

    return remap_succeeded;
}

