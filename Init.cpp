#include "Init.hpp"
#include "Preventions.hpp"
#include "Common/Globals.hpp"

/*
The TLS callback triggers on process + thread attachment & detachment, which means we can catch any threads made by an attacker in our process space.
We can end attacker threads using ExitThread(), and let in our threads which are managed.
...An attacker can circumvent this by modifying the pointers to TLS callbacks which the program usually keeps track of, which requires re-remapping
*/
void NTAPI __stdcall TLSCallback(PVOID pHandle, DWORD dwReason, PVOID Reserved)
{
    const UINT ThreadExecutionAddressStackOffset = 0x378; //** this might change on different version of window, Windows 10 is all I have access to currently

    switch (dwReason)
    {
        case DLL_PROCESS_ATTACH:
        {
            if (!Preventions::StopMultipleProcessInstances()) //prevent multi-clients by using shared memory-mapped region
            {
                Logger::logf(Err, "Could not initialize program: shared memory check failed, make sure only one instance of the program is open. Shutting down.");
                terminate();
            }

            Logger::logf(Info, " New process attached, current thread %d\n", GetCurrentThreadId());

            if (UnmanagedGlobals::FirstProcessAttach) //process creation will trigger PROCESS_ATTACH, so we can put some initialize stuff in here incase main() is hooked or statically modified by the attacker
            {
                if (!UnmanagedGlobals::SetExceptionHandler)
                {
                    SetUnhandledExceptionFilter(UnmanagedGlobals::ExceptionHandler);

                    if (!AddVectoredExceptionHandler(1, UnmanagedGlobals::ExceptionHandler))
                    {
                        Logger::logf(Err, " Failed to register Vectored Exception Handler @ TLSCallback: %d\n", GetLastError());
                    }

                    UnmanagedGlobals::SetExceptionHandler = true;
                }

                UnmanagedGlobals::FirstProcessAttach = false;
            }
            else
            {
                Logger::logf(Detection, " Some unknown process attached @ TLSCallback "); //this should generally never be triggered in this example
            }
        }break;

        case DLL_PROCESS_DETACH: //program exit, clean up any memory allocated
        {
            UnmanagedGlobals::ThreadList->clear();
            delete UnmanagedGlobals::ThreadList;
        }break;

        case DLL_THREAD_ATTACH: //add to our thread list, or if thread is not executing valid address range, patch over execution address
        {         
#ifndef _DEBUG
            if (!Debugger::AntiDebug::HideThreadFromDebugger(GetCurrentThread())) //hide thread from debuggers, placing this in the TLS callback allows all threads to be hidden
            {
                Logger::logf(Warning, " Failed to hide thread from debugger @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }
#endif
            if (!UnmanagedGlobals::AddThread(GetCurrentThreadId()))
            {
                Logger::logf(Err, " Failed to add thread to ThreadList @ TLSCallback: thread id %d\n", GetCurrentThreadId());
            }

            if (UnmanagedGlobals::SupressingNewThreads)
            {
                if (Services::GetWindowsVersion() == Windows11) //Windows 11 no longer has the thread's start address on the its stack, bummer
                    return;

                UINT64 ThreadExecutionAddress = *(UINT64*)((UINT64)_AddressOfReturnAddress() + ThreadExecutionAddressStackOffset); //check down the stack for the thread execution address, compare it to good module range, and if not in range then we've detected a rogue thread
                
                if (ThreadExecutionAddress == 0) //this generally should never be 0, but we'll add a check for good measure incase the offset changes on different W10 builds
                    return;

                auto modules = Process::GetLoadedModules();

                for (auto module : modules)
                {
                    UINT64 LowAddr = (UINT64)module.dllInfo.lpBaseOfDll;
                    UINT64 HighAddr = (UINT64)module.dllInfo.lpBaseOfDll + module.dllInfo.SizeOfImage;

                    if (ThreadExecutionAddress > LowAddr && ThreadExecutionAddress < HighAddr) //a properly loaded DLL is making the thread, so allow it to execute
                    {
                        //if any unsigned .dll is loaded, it will be caught in the DLL load callback/notifications, so we shouldnt need to cert check in this routine (this will cause slowdowns in execution, also cert checking inside the TLS callback doesn't seem to work properly here)
                        return; //any manually mapped modules' threads will be stopped since they arent using the loader and thus won't be in the loaded modules list
                    }
                }

                Logger::logf(Info, " Stopping unknown thread from being created  @ TLSCallback: thread id %d", GetCurrentThreadId());
                Logger::logf(Info, " Thread id %d wants to execute function @ %llX. Patching over this address.", GetCurrentThreadId(), ThreadExecutionAddress);

                DWORD dwOldProt = 0;

                if(!VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_EXECUTE_READWRITE, &dwOldProt)) //make thread start address writable
                {
                    Logger::logf(Warning, "Failed to call VirtualProtect on ThreadStart address @ TLSCallback: %llX", ThreadExecutionAddress);
                }
                else
                {
                    if (ThreadExecutionAddress != 0)
                    {
                        *(BYTE*)ThreadExecutionAddress = 0xC3; //write over any functions which are scheduled to execute next by this thread and not inside our whitelisted address range
                        VirtualProtect((LPVOID)ThreadExecutionAddress, sizeof(byte), PAGE_READONLY, &dwOldProt); // (optional) take away executable protections for the rogue thread's start address
                    }
                }
            }

        }break;

        case DLL_THREAD_DETACH:
        {
            UnmanagedGlobals::RemoveThread(GetCurrentThreadId());
        }break;
    };
}
