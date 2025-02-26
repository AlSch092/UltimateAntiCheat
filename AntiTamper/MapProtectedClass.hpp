//By AlSch092 @github, ProtectedMemory class originally from my project found at https://github.com/AlSch092/RemapProtectedClass

#pragma once
#include "../Process/Memory/ntdll.h"
#include <stdexcept>

using namespace std;

/*
    ProtectedMemory - Protects the memory of a class object by memory mapping it, then remapping it with SEC_NO_CHANGE
    should be used as follows:

    ```
    ProtectedMemory your_class(sizeof(YourClass));
    YourClass* ProtectedMemoryStaticClass = your_class.Construct<YourClass>(your_args_1, your_args_2);

    try
    {
        your_class.Protect();
    }
    catch (const std::runtime_error& ex)
    {
        Logger::UserLogF(Err, "Settings could not be initialized. Now closing application.");
        return;
    }
    ```
*/
class ProtectedMemory   //RAII class to handle memory mapping
{
private:
    HANDLE hSection;
    PVOID pViewBase;
    SIZE_T size;

public:
    ProtectedMemory(SIZE_T sectionSize) : hSection(nullptr), pViewBase(nullptr), size(sectionSize)
    {
        LARGE_INTEGER sectionSizeLi = {};
        sectionSizeLi.QuadPart = sectionSize;

        NTSTATUS ntstatus = NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &sectionSizeLi, PAGE_EXECUTE_READWRITE, SEC_COMMIT | SEC_NO_CHANGE, NULL);
        if (!NT_SUCCESS(ntstatus))
        {
            throw std::runtime_error("NtCreateSection failed");
        }

        SIZE_T viewSize = 0;
        LARGE_INTEGER sectionOffset = {};

        ntstatus = NtMapViewOfSection(hSection, NtCurrentProcess(), &pViewBase, 0, PAGE_SIZE, &sectionOffset, &viewSize, ViewUnmap, 0, PAGE_READWRITE);
        if (!NT_SUCCESS(ntstatus))
        {
            CloseHandle(hSection);
            throw std::runtime_error("NtMapViewOfSection failed");
        }
    }

    /*
        Protect - protect the memory view at `pViewBase` class member to make it non-writable by re-mapping with SEC_NO_CHANGE
        throws `runtime_error` on failure
    */
    void Protect() 
    {
        SIZE_T viewSize = 0;
        LARGE_INTEGER sectionOffset = {};
        NTSTATUS ntstatus = NtUnmapViewOfSection(NtCurrentProcess(), pViewBase); // unmap original view

        ntstatus = NtMapViewOfSection(hSection, NtCurrentProcess(), &pViewBase, 0, 0, &sectionOffset, &viewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ); //map with SEC_NO_CHANGE and use PAGE_EXECUTE_READ
        if (!NT_SUCCESS(ntstatus))
        {
            throw std::runtime_error("Failed to remap view as protected");
        }
    }

    ~ProtectedMemory() //RAII destructor - unmap view of section
    {
        if (hSection && hSection != INVALID_HANDLE_VALUE)
        {
            CloseHandle(hSection);
            hSection = INVALID_HANDLE_VALUE; //since we call the destructor explicitly if modifying the protected classes values, make sure a "double closehandle" doesnt occur
        }

        if (pViewBase)
        {
            NtUnmapViewOfSection(NtCurrentProcess(), pViewBase);
        }
    }

    PVOID GetBaseAddress() const { return pViewBase; }

    template<typename T, typename... Args>      //"placement new" concept using variadic template
    T* Construct(Args&&... args)
    {
        return new (pViewBase) T(std::forward<Args>(args)...);
    }
};
