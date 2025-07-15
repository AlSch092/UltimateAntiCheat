
### setting up

#todo
### usage example

#todo
see main.cpp

```cpp
#include "API/API.hpp"
#include "AntiCheat.hpp"


    shared_ptr<Settings> ConfigInstance = Settings::CreateInstance(bEnableNetworking, bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDBG, bUseAntiDebugging, bUseIntegrityChecking, bCheckThreadIntegrity, bCheckHypervisor, bRequireRunAsAdministrator, bUsingDriver, allowedParents, logToFile);

    unique_ptr<AntiCheat> Anti_Cheat = nullptr;

    try
    {
        Anti_Cheat = make_unique<AntiCheat>(ConfigInstance, Services::GetWindowsVersion());   //after all environmental checks (secure boot, DSE, adminmode) are performed, create the AntiCheat object
    }
    catch (const std::bad_alloc& e)
    {
        Logger::logf("UltimateAnticheat.log", Err, "Anticheat pointer could not be allocated @ main(): %s", e.what());
        std::terminate();
    }

    if (API::Dispatch(Anti_Cheat.get(), API::DispatchCode::INITIALIZE) != Error::OK) //initialize AC , this will start all detections + preventions
    {
        Logger::logf("UltimateAnticheat.log", Err, "Could not initialize program: API::Dispatch failed. Shutting down.");
        return 1;
    }

	while (true) { //game loop
	    if (Anti_Cheat->GetMonitor()->IsUserCheater())
	    {
	        std::cout << "Detected a possible cheater " << std::endl;
	    }
	
	    list<DetectionFlags> flags = Anti_Cheat->GetMonitor()->GetDetectedFlags();
		//do stuff to read the detailed anti cheat flags;
		std::map<DetectionFlags, const char*> explanations = {...};
	    for (DetectionFlags flag : flags) {
	            std::cout << explanations[flag] << std::endl;
	    }
    }

```
### Settings

| type                          | variable                   | explanation                                                                | rationale                                                                                    |
| ----------------------------- | -------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| bool                          | bNetworkingEnabled         | calls your server when cheat is detected                                   |                                                                                              |
| bool                          | bEnforceSecureBoot         | force player to enable secure boot                                         | prevents kernel-level cheats                                                                 |
| bool                          | bEnforceDSE                | force player to enable Driver Signature Enforcement                        | prevents custom unsigned driver cheats.                                                      |
| bool                          | bEnforceNoKDbg             |                                                                            | unused for now                                                                               |
| bool                          | bUseAntiDebugging          | prevents debugging the process                                             |                                                                                              |
| bool                          | bCheckIntegrity            | check process is not patched                                               |                                                                                              |
| bool                          | bCheckThreads              | ensure threads launched by the anti-cheat are not suspended by an attacker |                                                                                              |
| bool                          | bCheckHypervisor           | check if user is running an hypervisor                                     | detects if running in VM.                                                                    |
| bool                          | bRequireRunAsAdministrator | force player to launch as administrator                                    | prevents elevated cheats.                                                                    |
| bool                          | bUsingDriver               | use your own custom kernel driver                                          | TODO: documentation on how to create your driver to be done.                                 |
| const std::list<std::wstring> | allowedParents             | allowed parent processes for the executable                                | prevents launching from debugger.                                                            |
| bool                          | logToFile                  | write logs to console and file.                                            | disable in production to prevent cheaters understanding what exactly triggers the AntiCheat. |


### DetectionFlags


| name                       | explanation                                                                                                                                                   | Severity | False positive potential                                                                      | implementation details                                                                      |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| DEBUGGER                   | debugger is detected                                                                                                                                          | High     |                                                                                               | check the Debugger section                                                                  |
| PAGE_PROTECTIONS           | read-only process pages become writable                                                                                                                       | High     |                                                                                               | .text section was writable                                                                  |
| CODE_INTEGRITY             | process patched                                                                                                                                               | High     |                                                                                               | check changes in .text, .rdata sections, wintrust dll and custom network callback structure |
| DLL_TAMPERING              | Detects hooking of DLLs                                                                                                                                       | High     |                                                                                               | for now checks only the Networking WINAPI DLL                                               |
| MANUAL_MAPPING             | [manually mapped](https://youtu.be/qzZTXcBu3cE?si=AtLgNzhbRC6qhQfj&t=96) module injected in process                                                           | High     |                                                                                               |                                                                                             |
| BAD_IAT                    | DLL hooking via [Import Adress Table modification](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking) | High     |                                                                                               | Check if adresses in the table are coherent                                                 |
| INJECTED_ILLEGAL_PROGRAM   | unsigned DLL injected on the process                                                                                                                          | High     |                                                                                               |                                                                                             |
| EXTERNAL_ILLEGAL_PROGRAM   | blacklisted program name running on machine                                                                                                                   | High     | Low, but detects debuggers windows not interacting on our process.                            | Detects windows named like "CheatEngine" and processes with blacklisted byte patterns       |
| REGISTRY_KEY_MODIFICATIONS | changes to important registry keys                                                                                                                            | Medium   |                                                                                               | keys related to secure boot, CI, testsigning mode, etc...                                   |
| UNSIGNED_DRIVERS           | unsigned drivers on machine                                                                                                                                   | Medium   | Medium, could happen if user installs strange drivers.                                        | lists currently loaded drivers and check their signature                                    |
| OPEN_PROCESS_HANDLES       | A process has handles on our process                                                                                                                          | Low      | Medium, some false positives have been found.                                                 |                                                                                             |
| HYPERVISOR                 | an hypervisor is running on the machine                                                                                                                       | Low      | High, often hypervisor are running by default.<br>Manual check of the vendor name is advised. |                                                                                             |
| SUSPENDED_THREAD           | not implemented for now                                                                                                                                       | None yet |                                                                                               |                                                                                             |

### Debugger

#todo

| Name                | rationale |
| ------------------- | --------- |
| WINAPI_DEBUGGER     |           |
| PEB                 |           |
| HARDWARE_REGISTERS  |           |
| HEAP_FLAG           |           |
| INT3                |           |
| INT2C               |           |
| INT2D               |           |
| CLOSEHANDLE         |           |
| DEBUG_OBJECT        |           |
| VEH_DEBUGGER        |           |
| KERNEL_DEBUGGER     |           |
| TRAP_FLAG           |           |
| DEBUG_PORT          |           |
| PROCESS_DEBUG_FLAGS |           |
| REMOTE_DEBUGGER     |           |
| DBG_BREAK           |           |
