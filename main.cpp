/*  
    U.A.C. is a non-invasive usermode anticheat for x64 Windows, tested on Windows 10 & 11. Usermode is used to ensure an optimal end user experience. It also provides insight into how many kernelmode attack methods can be prevented from usermode, through concepts such as secure boot enforcement and DSE checking.
    
    Please view the readme for more information regarding program features. If you'd like to use this project in your game/software, please contact the author.

    License: GNU Affero general public license, please be aware of what and what not can be done with this license.. ** you do not have the right to copy this project into your closed-source, for-profit project **

    Author: AlSch092 @ Github
*/
#include <map>
#include <conio.h>
#include "AntiCheat.hpp"
#include "SplashScreen.hpp"


shared_ptr<Settings> Settings::Instance = nullptr; //we only want a single instance of this object throughout the program (some classes might use raw pointers to this object)

void checkAntiCheatThreads(unique_ptr<AntiCheat> &Anti_Cheat);
void showSplash(shared_ptr<Settings> c);
void PrintCheatingReasonExplanation(list<DetectionFlags> &flags, list<DetectionFlags> &previousFlags);


int main(int argc, char** argv)
{
    // Set default options
#ifdef _DEBUG //in debug compilation, we are more lax with our protections for easier testing purposes
    bool bEnableNetworking = false;  //change this to false if you don't want to use the server
    bool bEnforceSecureBoot = false;
    bool bEnforceDSE = true;
    bool bEnforceNoKDBG = true;
    bool bUseAntiDebugging = false;
    bool bUseIntegrityChecking = true;
    bool bCheckThreadIntegrity = true;
    bool bCheckHypervisor = true;
    bool bRequireRunAsAdministrator = true;
    bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
    bool bEnableLogging = true;

    const list<wstring> allowedParents = {L"VsDebugConsole.exe", L"vsdbg.exe", L"powershell.exe", L"bash.exe", L"zsh.exe", L"explorer.exe"};
    const string logFileName = "UltimateAnticheat.log";

#else
    bool bEnableNetworking = false; //change this to false if you don't want to use the server
    bool bEnforceSecureBoot = false; //secure boot is recommended in distribution builds
    bool bEnforceDSE = true;
    bool bEnforceNoKDBG = true;
    bool bUseAntiDebugging = true;
    bool bUseIntegrityChecking = true;
    bool bCheckThreadIntegrity = true;
    bool bCheckHypervisor = true;
    bool bRequireRunAsAdministrator = true;
    bool bEnableLogging = true; // set to false to not create a detailed AntiCheat log file on the user's system
    bool bUsingDriver = false; //signed driver for hybrid KM + UM anticheat. the KM driver will not be public, so make one yourself if you want to use this option
    
    const list<wstring> allowedParents = {L"explorer.exe", L"steam.exe"}; //add your launcher here
    const string logFileName = ""; //empty : does not log to file
#endif

    shared_ptr<Settings> ConfigInstance = Settings::CreateInstance(bEnableNetworking, bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor, bRequireRunAsAdministrator, bUsingDriver, allowedParents, bEnableLogging, logFileName);
    showSplash(ConfigInstance); //optional, show settings configuration credits and splash

    unique_ptr<AntiCheat> Anti_Cheat = nullptr;

    try
    {
        Anti_Cheat = make_unique<AntiCheat>(ConfigInstance);   //create the AntiCheat object
    }
    catch (const bad_alloc& e)
    {
        Logger::logf(Err, "Anticheat pointer could not be allocated @ main(): %s", e.what());
        return 1;
    }
    catch (const AntiCheatInitFail& e)
    {
        Logger::logf(Err, "Anticheat init error: %d %s", e.reasonEnum, e.what());
        return 1;
    }

    cout << "\n----------------------------------------------------------------------------------------------------------\n";
    cout << "All protections have been deployed, the program will now loop using its detection methods. Thanks for your interest in the project!\n\n";
    cout << "press any key to exit the program\n\n";

    //example "game loop"
    list<DetectionFlags> previousFlags = {};
    bool cheaterDetected = false;
    while (true) {
        // todo: move to own thread as a functionality of antiCheat
        checkAntiCheatThreads(Anti_Cheat);

        list<DetectionFlags> flags = Anti_Cheat->GetMonitor()->GetDetectedFlags();

        if (!cheaterDetected && Anti_Cheat->GetMonitor()->IsUserCheater())
        {
            cheaterDetected = true;
            Logger::logf(Info, "Detected a possible cheater");
        }

        #ifdef _DEBUG
            PrintCheatingReasonExplanation(flags, previousFlags);
        #endif

        if (_kbhit())
            break;
        previousFlags = flags;
        Sleep(1000); //let the other threads run to display monitoring
    }
    cout << "process ending, please wait for threads to cleanup\n\n";
    return 0;
}

void checkAntiCheatThreads(unique_ptr<AntiCheat> &Anti_Cheat)
{
    if (Anti_Cheat->GetConfig()->bCheckThreads)
    {   //typically thread should cross-check eachother to ensure nothing is suspended, in this version of the program we only check thread suspends here
        if (Anti_Cheat->IsAnyThreadSuspended()) //make sure that all our necessary threads aren't suspended by an attacker
        {
            Logger::logf(Detection, "Atleast one of our threads was found suspended! All threads must be running for proper module functionality.");
            Anti_Cheat->GetMonitor()->Flag(DetectionFlags::SUSPENDED_THREAD);
        }
    }
}


void showSplash(shared_ptr<Settings> c)
{
    #ifdef _DEBUG
        cout << "\tEnable logging :\t\t" << boolalpha << c->enableLogging << endl;
        cout << "Settings for this instance:\n";
        cout << "\tEnable Networking:\t" << boolalpha << c->bNetworkingEnabled << endl;
        cout << "\tEnforce Secure Boot: \t" << boolalpha << c->bEnforceSecureBoot << endl;
        cout << "\tEnforce DSE:\t\t" << boolalpha << c->bEnforceDSE << endl;
        cout << "\tEnforce No KDBG:\t" << boolalpha << c->bEnforceNoKDbg << endl;
        cout << "\tUse Anti-Debugging:\t" << boolalpha << c->bUseAntiDebugging << endl;
        cout << "\tUse Integrity Checking:\t" << boolalpha << c->bCheckIntegrity << endl;
        cout << "\tCheck Thread Integrity:\t" << boolalpha << c->bCheckThreads << endl;
        cout << "\tCheck Hypervisor:\t" << boolalpha << c->bCheckHypervisor << endl;
        cout << "\tRequire Admin:\t\t" << boolalpha << c->bRequireRunAsAdministrator << endl;
        cout << "\tAllowed parent processes: \t\t" << endl;

        for (auto parent: c->allowedParents)
        {
            wcout << parent << " ";
        }

        cout << endl;
    #endif

    SetConsoleTitle(L"Ultimate Anti-Cheat");

    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Splash::InitializeSplash, 0, 0, 0); //open splash window

    cout << "------------------------------------------------------------------------------------------\n";
    cout << "|                            Welcome to Ultimate Anti-Cheat!                             |\n";
    cout << "|  An in-development, non-commercial AC made to help teach concepts in game security     |\n";
    cout << "|                              Made by AlSch092 @Github                                  |\n";
    cout << "|         ...With special thanks to:                                                     |\n";
    cout << "|           changeofpace@github (remapping method)                                       |\n";
    cout << "|           discriminating@github (dll load notifcations, catalog verification)          |\n";
    cout << "------------------------------------------------------------------------------------------\n";
}

void PrintCheatingReasonExplanation(list<DetectionFlags> &flags, list<DetectionFlags> &previousFlags) {
    map<DetectionFlags, const char*> explanations = 
    {
        { DetectionFlags::DEBUGGER, "Debugger detected" },
        { DetectionFlags::PAGE_PROTECTIONS, ".text section is writable, memory was re-mapped" },
        { DetectionFlags::CODE_INTEGRITY, "process patched" },
        { DetectionFlags::DLL_TAMPERING, "Networking WINAPI hooked" },
        { DetectionFlags::BAD_IAT, "DLL hooking via Import Adress Table modification" },
        { DetectionFlags::OPEN_PROCESS_HANDLES, "A process has handles on our process" },
        { DetectionFlags::UNSIGNED_DRIVERS, "unsigned drivers on machine" },
        { DetectionFlags::INJECTED_ILLEGAL_PROGRAM, "unsigned DLL injected on the process" },
        { DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM, "blacklisted program name running on machine" },
        { DetectionFlags::REGISTRY_KEY_MODIFICATIONS, "changes to registry keys related to secure boot, CI, testsigning mode, etc..." },
        { DetectionFlags::MANUAL_MAPPING, "manually mapped module injected" },
        { DetectionFlags::SUSPENDED_THREAD, "an anti-cheat thread has been suspended" },
        { DetectionFlags::HYPERVISOR, "an hypervisor is running on the machine" }
    };
    for (DetectionFlags flag : flags)
    {
        if (find(previousFlags.begin(), previousFlags.end(), flag) == previousFlags.end()) {
            Logger::logf(LogType::Detection, explanations[flag]);
        }
    }
}
