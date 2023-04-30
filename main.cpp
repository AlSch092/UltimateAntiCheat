// UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there.
// an 'in-development' anti-tamper + anti-debug + anti-load for x86, x64
// Author: Alsch092,  github: alsch092)

#pragma comment(linker, "/ALIGN:0x10000") //for remapping code

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3

#include "AntiCheat.hpp"
#include "Process/Memory/remap.hpp"

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved);

#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif

PIMAGE_TLS_CALLBACK _tls_callback = TLSCallback;
#pragma data_seg ()
#pragma const_seg ()

using namespace std;

void NTAPI __stdcall TLSCallback(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
    printf("DllHandle: %llX, dwReason: %d, Reserved: %llX\n", DllHandle, dwReason, Reserved);

    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        printf("New process attached\n");
        break;

    case DLL_THREAD_ATTACH:
        //ExitThread(0); //we can stop DLL injecting + DLL debuggers this way, but make sure you're handling your threads carefully..
        printf("New thread spawned!\n");
        break;

    case DLL_THREAD_DETACH:
        printf("Thread detached!\n");
        break;
    };
}

void TestFunction() //called by our 'rogue'/SymLink CreateThread. WINAPI is not called for this!
{
    printf("Hello! this thread was made without calling CreateThread directly!\n");
}

bool TestProgramHash(AntiCheat* AC)
{
    uint64_t module = (uint64_t)GetModuleHandleW(L"UltimateAnticheat.exe");

    if (!module)
    {
        printf("Failed to get current module! %d\n", GetLastError());
        return false;
    }

    DWORD moduleSize = AC->GetProcessObject()->GetMemorySize();

    AC->GetProcessObject()->SetModuleHashList(AC->GetIntegrityChecker()->GetHash((uint64_t)module, 0x1000)); //cache the list of hashes we get from the process .text section

    MessageBoxA(0, "Write over '.text' section memory here to test integrity checking!", 0, 0);

    if (AC->GetIntegrityChecker()->Check((uint64_t)module, 0x1000, AC->GetProcessObject()->GetModuleHashList()))
    {
        printf("Hashes match! Program appears genuine! Remember to put this inside a TLS callback (and then make sure TLS callback isn't hooked) to ensure we get hashes before memory is tampered.\n");
    }
    else
    {
        printf("Program is modified!\n");
        return true;
    }

    return false;
}

void TestFunctionalities()
{
    AntiCheat* AC = new AntiCheat();

    AC->GetProcessObject()->SetElevated(Process::IsProcessElevated());

    AC->GetProcessObject()->GetProgramSections("UltimateAnticheat.exe"); //we can stop a routine like this from working if we patch NumberOfSections to 0

    if (!Process::CheckParentProcess(L"explorer.exe"))
    {
        printf("Parent process was not explorer.exe! hekker detected!\n"); //sometimes people will launch a game from their own process, which we can easily detect if they haven't spoofed it
    }

    TestProgramHash(AC);

    SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //works -> shows how we can call CreateThread without directly calling winapi, we call our pointer instead which then invokes createthread

    AC->GetAntiDebugger()->StartAntiDebugThread();

    std::wstring newModuleName = L"new_name";

    if (Process::ChangeModuleName((wchar_t*)L"UltimateAnticheat.exe", (wchar_t*)newModuleName.c_str()))
    {
        wprintf(L"Changed module name to %s!\n", newModuleName.c_str());
    }

    if (AC->GetAntiDebugger()->_IsHardwareDebuggerPresent())
    {
        printf("Found hardware debugger!\n");
    }

    if (Utility::IsVTableHijacked((void*)AC))
    {
        printf("VTable of Anticheat has been compromised/hooked.\n");
    }

    if (!AC->GetProcessObject()->ProtectProcess())
    {
        printf("Could not protect process.\n");
    }

    ULONG_PTR ImageBase = (ULONG_PTR)GetModuleHandle(NULL);

    if (ImageBase)
    {
        if (!RmpRemapImage(ImageBase))
        {
            printf("RmpRemapImage failed.\n");
        }
    }
    else
    {
        printf("Imagebase was NULL!\n");
    }

    delete AC;
}

int main(int argc, char** argv)
{
    //  _MessageBox();
    TestFunctionalities();
}
