// UltimateAnticheat.cpp : This file contains the 'main' function. Program execution begins and ends there.
// an 'in-development' anti-tamper + anti-debug + anti-load for x86, x64
// !not for commercial use! please contact the author if you wish to use examples from this in your commercial project.

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

int main()
{
    AntiCheat* AC = new AntiCheat();
    
    AC->GetAntiDebugger()->StartAntiDebugThread(); //some quick tests
    
    if(AC->GetIntegrityChecker()->Check((uint64_t)GetModuleHandleA(NULL), 5, "\xFF\xFF\xFF\xFF\xFF"))
    {
        printf("Hash of memory: %X\n", AC->GetIntegrityChecker()->GetHash((uint64_t)GetModuleHandleA(NULL), 5));
    }

    GetUserInput();
}
