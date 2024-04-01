//By AlSch092 @github
#include "Preventions.hpp"

int Preventions::DeployBarrier() 
{
    IsPreventingThreadCreation = true;

    if (!RemapAndCheckPages()) //TODO: finish this
    {
        return 0;
    }
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

