// UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there.
// an 'in-development' anti-tamper + anti-debug + anti-load for x86, x64
// Author: Alsch092,  github: alsch092)
// Credits to changeofpace for file re-mapping code

#pragma comment(linker, "/ALIGN:0x10000")

#define DLL_PROCESS_DETACH 0
#define DLL_PROCESS_ATTACH 1
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3

#include "AntiCheat.hpp"
#include "Process/Memory/remap.hpp"

//
// This linker option forces every pe section to be loaded at an address which
//  is aligned to the system allocation granularity. At runtime, each section
//  is padded with pages of reserved memory.
// NOTE This option does not affect file size.


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
        ExitThread(0); //we can stop DLL injecting + DLL debuggers this way
        printf("New thread spawned!\n");
        break;


    case DLL_THREAD_DETACH:
        printf("Thread detached!\n");
        break;
    };
}

void GetUserInput()
{
    bool readingCmd = true;

    while (readingCmd)
    {
        cout << "Select your poison.\n";

        cout << "[1] Start anti-tamper.\n";
        cout << "[2] Start anti-debug.\n";
        cout << "[3] Activate process hiding\n";
        cout << "[4] Reject new modules + scan current modules for proxies.\n";
        cout << "[5] Start all detections\n";

        wchar_t userIn[20];
        wscanf_s(L"%s", userIn, 20);

        switch (userIn[0]) //Todo: finish implementing this!
        {
        case L'1':
            cout << "Selected 1.";
            break;

        case L'2':
            cout << "Selected 2.";
            break;

        case L'3':
            cout << "Selected 3.";
            break;

        case L'4':
            cout << "Selected 4.";
            break;

        case L'5':
            cout << "Selected 5.";
            break;

        case L'0':
            cout << "Done!.";
            return;

        default:
            cout << "Input not recognized as an option. Try again.";
            break;
        }

    }
}

void TestFunction() //called by our 'rogue'/SymLink CreateThread. WINAPI is not called for this!
{
    printf("Hello!\n");
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

    MessageBoxA(0, "Write '.text' section memory here!", 0, 0);

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

void TestAllFunctionalities()
{
    AntiCheat* AC = new AntiCheat();
    TestProgramHash(AC);

    BOOL bElevated = Process::IsProcessElevated();
    AC->GetProcessObject()->SetElevated(bElevated);

    if (bElevated)
    {
        printf("Process is elevated!\n");

        //Services* s = new Services();
       // s->StopEventLog();  //this works but its not neccesary as this is not malware! if we want to get savvy there's most likely a way to push our own custom/spoofed event logs by finding the function in the eventlog module which does this and calling it ourselves.
        //todo: write generic function which stops a service instead of just targeting event log
    }

    //AC->ShellcodeTests();

    SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //works

    AC->GetAntiDebugger()->StartAntiDebugThread();

    std::wstring newModuleName = L"new.blah";

    if (ChangeModuleName((wchar_t*)L"UltimateAnticheat.exe", (wchar_t*)newModuleName.c_str()))
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
}

int main()
{
    TestAllFunctionalities();
    GetUserInput();
}
