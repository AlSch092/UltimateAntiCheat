//Thank you to @changeofpace for this
#include "remap.hpp"
#include "../Process/Memory/ntdll.h"

//=============================================================================
// Private Types
//=============================================================================
typedef BOOL(NTAPI* REMAP_ROUTINE)(
    _In_ PVOID pRemapRegion
    );


//=============================================================================
// Module Globals
//=============================================================================
static ULONG g_CharacteristicsProtectionMap[2][2][2] =
{
    {
        { PAGE_NOACCESS, PAGE_WRITECOPY },
        { PAGE_READONLY, PAGE_READWRITE }

    },
    {
        { PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY },
        { PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE }
    },
};


//=============================================================================
// Private Prototypes
//=============================================================================
_Check_return_
static
BOOL
RmppVerifyPeSectionAlignment(
    _In_ PIMAGE_NT_HEADERS pNtHeaders
);

static
VOID
RmppCopyPeSections(
    _In_ PIMAGE_NT_HEADERS pNtHeaders,
    _In_ ULONG_PTR DestinationBase
);

_Check_return_
static
BOOL
RmppRemapImageRoutine(
    _In_ PVOID pRemapRegion
);

_Check_return_
static
ULONG
RmppConvertSectionCharacteristicsToPageProtection(
    _In_ ULONG Characteristics
);

_Check_return_
static
BOOL
RmppMapProtectedView(
    _In_ HANDLE hSection,
    _In_ ULONG_PTR BaseAddress,
    _In_ SIZE_T cbSize,
    _In_ SIZE_T cbOffset,
    _In_ ULONG Protection
);

_Check_return_
static
BOOL
RmppValidateRemappedImageProtection(
    _In_ ULONG_PTR ImageBase
);

_Check_return_
static
BOOL
RmppValidateRemappedPeSectionProtection(
    _In_ PVOID pSectionBase
);


//=============================================================================
// Public Interface
//=============================================================================

//
// RmpRemapImage
//
// This function remaps the pe image at 'ImageBase' so that the page protection
//  of all pages contained in the image cannot be changed.
//
// The remapping process uses the following strategy:
//
//  1. The image is copied to an executable buffer referred to as the 'remap
//      region'.
//
//  2. The remap routine inside the remap region is located and invoked.
//
//  3. The remap routine creates a page-file-backed section to store the
//      remapped image.
//
//  4. The remap routine maps a view of the entire section and copies the
//      contents of the image to the view. This view is then unmapped.
//
//  5. The remap routine maps a view for each pe section in the image using the
//      relative virtual address of the pe section as the section offset for
//      the view. Each view is mapped using the 'SEC_NO_CHANGE' allocation
//      type to prevent page protection changes.
//
//  6. The remap routine completes and execution returns to the remapped image.
//
// NOTE This strategy requires each pe section in the image to be aligned to
//  the system allocation granularity. See the documentation for
//  'ZwMapViewOfSection' for details.
//
// NOTE This function currently only supports x64 images.
//
_Use_decl_annotations_
BOOL
RmpRemapImage(
    ULONG_PTR ImageBase
)
{
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PVOID pRemapRegion = NULL;
    REMAP_ROUTINE fpRemapRoutine = NULL;
    BOOL status = TRUE;

    printf("Remapping image at 0x%IX\n", ImageBase);

    pNtHeaders = RtlImageNtHeader((PVOID)ImageBase);
    if (!pNtHeaders)
    {
        printf("RtlImageNtHeader failed. (BaseAddress = 0x%IX)\n",
            ImageBase);
        status = FALSE;
        goto exit;
    }

    status = RmppVerifyPeSectionAlignment(pNtHeaders);
    if (!status)
    {
        printf("RmppVerifyPeSectionAlignment failed.\n");
        goto exit;
    }

    //
    // Allocate an executable and writable buffer where the remap routine will
    //  execute.
    //
    pRemapRegion = VirtualAlloc(
        NULL,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    if (!pRemapRegion)
    {
        printf("VirtualAlloc failed: %u\n", GetLastError());
        status = FALSE;
        goto exit;
    }

    //printf("RemapRegion:    0x%IX\n", (ULONG_PTR)pRemapRegion);

    //
    // Copy the image to the remap region.
    //
    RmppCopyPeSections(pNtHeaders, (ULONG_PTR)pRemapRegion);

    //
    // Locate the address of the remap routine inside the remap region.
    //
    fpRemapRoutine = (REMAP_ROUTINE)(
        (ULONG_PTR)pRemapRegion +
        (ULONG_PTR)RmppRemapImageRoutine -
        ImageBase);

    //printf("RemapRoutine:   0x%IX\n", (ULONG_PTR)fpRemapRoutine);

    //
    // Invoke the remap routine inside the remap region.
    //
    status = fpRemapRoutine(pRemapRegion);
    if (!status)
    {
        printf("RmppRemapImageRoutine failed.\n");
        goto exit;
    }

    //
    // Verify that each pe section in the remapped image is protected.
    //
    status = RmppValidateRemappedImageProtection(ImageBase);
    if (!status)
    {
        printf("RmppValidateRemappedImageProtection failed.\n");
        goto exit;
    }

exit:
    if (pRemapRegion)
    {
        if (!VirtualFree(pRemapRegion, 0, MEM_RELEASE))
        {
            printf("VirtualFree failed: %u\n", GetLastError());
        }
    }

    return status;
}


//=============================================================================
// Private Interface
//=============================================================================

//
// RmppVerifyPeSectionAlignment
//
// Verify that each pe section is aligned to the system allocation granularity.
//
_Use_decl_annotations_
static
BOOL
RmppVerifyPeSectionAlignment(
    PIMAGE_NT_HEADERS pNtHeaders
)
{
    SYSTEM_INFO SystemInfo = {};
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    ULONG_PTR SectionBase = 0;
    BOOL status = TRUE;

    //printf("Verifying pe section alignment:\n");

    //
    // Query the system allocation granularity.
    //
    GetSystemInfo(&SystemInfo);

    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
    {
        SectionBase =
            pNtHeaders->OptionalHeader.ImageBase +
            pSectionHeader[i].VirtualAddress;

        printf("    %-8.8s    0x%IX - 0x%IX,  0x%08X\n",
            pSectionHeader[i].Name,
            SectionBase,
            SectionBase + pSectionHeader[i].Misc.VirtualSize,
            pSectionHeader[i].Misc.VirtualSize);

        status = POINTER_IS_ALIGNED(
            SectionBase,
            SystemInfo.dwAllocationGranularity);
        if (!status)
        {
            printf("Unexpected section alignment. (SectionBase = 0x%IX)\n",
                SectionBase);
            goto exit;
        }
    }

    //
    // Verify pe header alignment.
    //
    status = POINTER_IS_ALIGNED(
        pNtHeaders->OptionalHeader.ImageBase,
        SystemInfo.dwAllocationGranularity);
    if (!status)
    {
        printf("Unexpected section alignment. (SectionBase = 0x%IX)\n",
            SectionBase);
        goto exit;
    }

exit:
    return status;
}


//
// RmppCopyPeSections
//
_Use_decl_annotations_
static
VOID
RmppCopyPeSections(
    PIMAGE_NT_HEADERS pNtHeaders,
    ULONG_PTR DestinationBase
)
{
    ULONG_PTR SourceBase = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    SourceBase = pNtHeaders->OptionalHeader.ImageBase;

    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    //
    // We copy each pe section individually because images compiled with the
    //  '/ALIGN' linker option will have reserved memory padding.
    //
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
    {
        //printf("Copying %-8.8s from 0x%IX to 0x%IX,  0x%08X\n",
           // pSectionHeader[i].Name,
            //SourceBase + pSectionHeader[i].VirtualAddress,
            //DestinationBase + pSectionHeader[i].VirtualAddress,
            //pSectionHeader[i].Misc.VirtualSize);

        RtlCopyMemory(
            (PVOID)(DestinationBase + pSectionHeader[i].VirtualAddress),
            (PVOID)(SourceBase + pSectionHeader[i].VirtualAddress),
            pSectionHeader[i].Misc.VirtualSize);
    }

    //
    // Copy the pe header.
    //
    RtlCopyMemory((PVOID)DestinationBase, (PVOID)SourceBase, PAGE_SIZE);
}


//
// RmppRemapImageRoutine
//
// This routine unmaps the original image then reconstructs it as contiguous
//  memory mapped views.
//
_Use_decl_annotations_
static
BOOL
RmppRemapImageRoutine(
    PVOID pRemapRegion
)
{
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    HANDLE hSection = NULL;
    LARGE_INTEGER cbSectionSize = {};
    PVOID pViewBase = NULL;
    ULONG_PTR ImageBase = 0;
    LARGE_INTEGER cbSectionOffset = {};
    SIZE_T cbViewSize = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    ULONG Protection = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    pNtHeaders = RtlImageNtHeader(pRemapRegion);
    if (!pNtHeaders)
    {
        printf("RtlImageNtHeader failed. (BaseAddress = 0x%IX)\n",
            pRemapRegion);
        status = FALSE;
        goto exit;
    }

    cbSectionSize.QuadPart = pNtHeaders->OptionalHeader.SizeOfImage;

    //
    // Create a page-file-backed section to store the remapped image.
    //
    ntstatus = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &cbSectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT | SEC_NO_CHANGE,
        NULL);
    if (!NT_SUCCESS(ntstatus))
    {
        printf("NtCreateSection failed: 0x%X\n", ntstatus);
        status = FALSE;
        goto exit;
    }

    //
    // Map a view of the entire section.
    //
    ntstatus = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &pViewBase,
        0,
        pNtHeaders->OptionalHeader.SizeOfImage,
        &cbSectionOffset,
        &cbViewSize,
        ViewUnmap,
        0,
        PAGE_READWRITE);
    if (!NT_SUCCESS(ntstatus))
    {
        printf("NtMapViewOfSection failed: 0x%X\n", ntstatus);
        status = FALSE;
        goto exit;
    }

    //
    // Copy the image to our view.
    //
    RmppCopyPeSections(pNtHeaders, (ULONG_PTR)pViewBase);

    //
    // Unmap the copy-view because we no longer need it.
    //
    ntstatus = NtUnmapViewOfSection(NtCurrentProcess(), pViewBase);
    if (!NT_SUCCESS(ntstatus))
    {
        printf("NtUnmapViewOfSection failed: 0x%X\n", ntstatus);
        status = FALSE;
        goto exit;
    }

    //
    // Unmap the original image.
    //
    ImageBase = pNtHeaders->OptionalHeader.ImageBase;

    ntstatus = NtUnmapViewOfSection(NtCurrentProcess(), (PVOID)ImageBase);
    if (!NT_SUCCESS(ntstatus))
    {
        printf("NtUnmapViewOfSection failed: 0x%X\n", ntstatus);
        status = FALSE;
        goto exit;
    }

    //
    // Reconstruct the image by mapping a view of the section for each pe
    //  section in the image.
    //
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
    {
        Protection = RmppConvertSectionCharacteristicsToPageProtection(
            pSectionHeader[i].Characteristics);

        status = RmppMapProtectedView(
            hSection,
            ImageBase + pSectionHeader[i].VirtualAddress,
            pSectionHeader[i].Misc.VirtualSize,
            pSectionHeader[i].VirtualAddress,
            Protection);
        if (!status)
        {
            printf("RmppMapProtectedView failed.\n");
            goto exit;
        }

        printf("Mapped protected view at: %llx\n", ImageBase + pSectionHeader[i].VirtualAddress);
    }

    //
    // Map a view for the pe header.
    //
    status = RmppMapProtectedView(
        hSection,
        ImageBase,
        PAGE_SIZE,
        0,
        PAGE_READONLY);
    if (!status)
    {
        printf("RmppMapProtectedView failed.\n");
        goto exit;
    }

exit:
    if (hSection)
    {
        ntstatus = NtClose(hSection);
        if (!NT_SUCCESS(ntstatus))
        {
            printf("NtClose failed: 0x%X\n", ntstatus);
        }
    }

    return status;
}


//
// RmppConvertSectionCharacteristicsToPageProtection
//
_Use_decl_annotations_
static
ULONG
RmppConvertSectionCharacteristicsToPageProtection(
    ULONG Characteristics
)
{
    BOOL fExecutable = FALSE;
    BOOL fReadable = FALSE;
    BOOL fWritable = FALSE;
    ULONG Protection = 0;

    if (0 != (IMAGE_SCN_MEM_EXECUTE & Characteristics))
    {
        fExecutable = TRUE;
    }

    if (0 != (IMAGE_SCN_MEM_READ & Characteristics))
    {
        fReadable = TRUE;
    }

    if (0 != (IMAGE_SCN_MEM_WRITE & Characteristics))
    {
        fWritable = TRUE;
    }

    Protection =
        g_CharacteristicsProtectionMap[fExecutable][fReadable][fWritable];

    if (0 != (IMAGE_SCN_MEM_NOT_CACHED & Characteristics))
    {
        Protection |= PAGE_NOCACHE;
    }

    return Protection;
}


//
// RmppMapProtectedView
//
_Use_decl_annotations_
static
BOOL
RmppMapProtectedView(
    HANDLE hSection,
    ULONG_PTR BaseAddress,
    SIZE_T cbSize,
    SIZE_T cbOffset,
    ULONG Protection
)
{
    LARGE_INTEGER cbSectionOffset = {};
    PVOID pViewBase = NULL;
    SIZE_T cbViewSize = 0;
    NTSTATUS ntstatus = STATUS_SUCCESS;
    BOOL status = TRUE;

    pViewBase = (PVOID)BaseAddress;
    cbViewSize = cbSize;
    cbSectionOffset.QuadPart = cbOffset;

    ntstatus = NtMapViewOfSection(
        hSection,
        NtCurrentProcess(),
        &pViewBase,
        0,
        0,
        &cbSectionOffset,
        &cbViewSize,
        ViewUnmap,
        SEC_NO_CHANGE,
        Protection);
    if (!NT_SUCCESS(ntstatus))
    {
        printf(
            "NtMapViewOfSection failed: 0x%X (Base = 0x%IX, Offset = 0x%IX, Size = 0x%IX)\n",
            ntstatus,
            pViewBase,
            cbSectionOffset.QuadPart,
            cbViewSize);
        status = FALSE;
        goto exit;
    }

exit:
    return status;
}


//
// RmppValidateRemappedImageProtection
//
_Use_decl_annotations_
static
BOOL
RmppValidateRemappedImageProtection(
    ULONG_PTR ImageBase
)
{
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    BOOL status = TRUE;

    printf("Validating remapped image protection.\n");

    pNtHeaders = RtlImageNtHeader((PVOID)ImageBase);
    if (!pNtHeaders)
    {
        printf("RtlImageNtHeader failed. (BaseAddress = 0x%IX)\n",
            ImageBase);
        status = FALSE;
        goto exit;
    }

    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i)
    {
        status = RmppValidateRemappedPeSectionProtection(
            (PVOID)(ImageBase + pSectionHeader[i].VirtualAddress));
        if (!status)
        {
            printf("RmppValidateRemappedPeSectionProtection failed.\n");
            goto exit;
        }
    }

    //
    // Validate the pe header.
    //
    status = RmppValidateRemappedPeSectionProtection((PVOID)ImageBase);
    if (!status)
    {
        printf("RmppValidateRemappedPeSectionProtection failed.\n");
        goto exit;
    }

exit:
    return status;
}


//
// RmppValidateRemappedPeSectionProtection
//
_Use_decl_annotations_
static
BOOL
RmppValidateRemappedPeSectionProtection(
    PVOID pSectionBase
)
{
    MEMORY_BASIC_INFORMATION MemoryBasicInfo = {};
    ULONG TestProtect = 0;
    ULONG PreviousProtect = 0;
    BOOL status = TRUE;

    //
    // Query the current page protection.
    //
    if (!VirtualQuery(pSectionBase, &MemoryBasicInfo, sizeof(MemoryBasicInfo)))
    {
        printf("VirtualQuery failed: %u (BaseAddress = 0x%IX)\n",
            GetLastError(),
            pSectionBase);
        status = FALSE;
        goto exit;
    }

    //
    // We use PAGE_EXECUTE_READWRITE as our test protection value because it is
    //  the most permissive page protection.
    //
    if (PAGE_EXECUTE_READWRITE != MemoryBasicInfo.Protect)
    {
        TestProtect = PAGE_EXECUTE_READWRITE;
    }
    else
    {
        TestProtect = PAGE_NOACCESS;
    }

    //
    // Attempt to modify the page protection of every page contained in the
    //  memory region. This should fail because each view was mapped with the
    //  SEC_NO_CHANGE allocation type.
    //
    status = VirtualProtect(
        pSectionBase,
        MemoryBasicInfo.RegionSize,
        TestProtect,
        &PreviousProtect);
    if (status)
    {
        printf(
            "Section is not protected. (BaseAddress = 0x%IX, Protect = 0x%X)\n",
            pSectionBase,
            PreviousProtect);
        status = FALSE;
        goto exit;
    }

    // Reset the status code to indicate success.
    status = TRUE;

exit:
    return status;
}
