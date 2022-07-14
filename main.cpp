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

        switch (userIn[0])
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

void TestFunction() //called by our 'rogue' CreateThread
{
    printf("Hello!\n");
}

void TestAllFunctionalities()
{
    AntiCheat* AC = new AntiCheat();

    ChangeModuleName((wchar_t*)L"UltimateAnticheat.exe", (wchar_t*)L"ABC123");

   // AC->ShellcodeTests();

    SymbolicHash::CreateThread_Hash(0, 0, (LPTHREAD_START_ROUTINE)&TestFunction, 0, 0, 0); //works

    AC->GetAntiDebugger()->StartAntiDebugThread();

    AC->GetIntegrityChecker()->Check((uint64_t)GetModuleHandleA(NULL), 5, (byte*)"\x4D\x5A\x90\x00\x03");

    uint64_t k32DLL = (uint64_t)GetModuleHandleA("kernel32.dll");
    AC->GetIntegrityChecker()->GetHash((uint64_t)k32DLL, 8); //make some hash of kernel32.dll's bytes, ideally we want to make some heartbeat that hashes memory of the game or process and checks with server, this would get rid of 95% of cheaters
    
    AC->GetAntiDebugger()->_IsHardwareDebuggerPresent();

    if (Utility::IsVTableHijacked((void*)AC))
    {
        printf("VTable of Anticheat has been compromised/hooked.\n");
    }

    if (!AC->GetProcessObject()->ProtectProcess())
    {
        printf("Could not protect process.\n");
    }

    Services* s = new Services();
    // s->StopEventLog();  //this works but its not neccesary as this is not malware! if we want to get savvy there's most likely a way to push our own custom/spoofed event logs by finding the function in the eventlog module which does this and calling it ourselves.

    if (!s->GetServiceModules("Dhcp")) //we can actually open the service process modules and suspend threads or kill the process to stop windows reporting and functionalities. 
    {
        printf("Could not get running services!\n");
    }


}

int main()
{
    TestAllFunctionalities();

    GetUserInput();
}
