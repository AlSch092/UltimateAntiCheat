// UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there.
// an 'in-development' anti-tamper + anti-debug + anti-load for x86, x64
// !not for commercial use! please contact the author if you wish to use examples from this in your commercial project.
// Author: Alex Schwarz (aschwarz92@outlook.com, github: alsch092)

#include <iostream>
#include "AntiCheat.hpp"

using namespace std;

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

void TestFunction() //called by our 'rogue'/SymLink CreateThread
{
    printf("Hello!\n");
}

void TestAllFunctionalities()
{
    AntiCheat* AC = new AntiCheat();
    bool isCompromised;

   // AC->ShellcodeTests();

    SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //works

    AC->GetAntiDebugger()->StartAntiDebugThread();

    uint64_t thisModule = (uint64_t)GetModuleHandleA(NULL);

    if (!thisModule)
    {
        printf("Failed to get current module! %d\n", GetLastError());
    }

    DWORD moduleSize = AC->GetProcessObject()->GetMemorySize();
 
    AC->GetProcessObject()->SetModuleHashList(AC->GetIntegrityChecker()->GetHash((uint64_t)thisModule, moduleSize));

    MessageBoxA(0, "Write process memory here, Check() below should detect if the program is tampered", 0, 0);

    if (AC->GetIntegrityChecker()->Check((uint64_t)thisModule, moduleSize, AC->GetProcessObject()->GetModuleHashList()))
    {
        printf("Hashes match! Program is genuine! Remember to put this inside a TLS callback (and then make sure TLS callback isn't hooked) to ensure we get hashes before memory is tampered.\n");
        isCompromised = false;
    }
    else
    {
        printf("Program is MODIFIED!\n");
        isCompromised = true;
    }

    std::wstring newModuleName = L"new_module_name_any_extension.blah";

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

    AC->GetProcessObject()->SetElevated(Process::IsProcessElevated());

    if (AC->GetProcessObject()->GetElevated())
    {
        printf("Process is elevated!\n");

        Services* s = new Services();
        s->StopEventLog();  //this works but its not neccesary as this is not malware! if we want to get savvy there's most likely a way to push our own custom/spoofed event logs by finding the function in the eventlog module which does this and calling it ourselves.
        //todo: write generic function which stops a service instead of just targeting event log
    }
}

int main()
{
    TestAllFunctionalities();
    GetUserInput();
}
