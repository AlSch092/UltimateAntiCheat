#pragma once
#include "../Process/Process.hpp"
#include <stdio.h> //for printing info
#include <tlhelp32.h> //process watching
#include <Psapi.h> //process watching
#include <stdexcept>

#define MAX_DLLS 128 
#define MAX_FILE_PATH_LENGTH 256

namespace Debugger
{
    //see bottom of file for list of windows structures related to debugging
    enum Detections
    {
        WINAPI_DEBUGGER = 1,
        PEB_FLAG,
        HARDWARE_REGISTERS,
        HEAP,
        INT3, //same as DebugBreak()
        INT2C,
        INT2D, //
        MULTIBYTE_INT3, //extended int3
        INTO,
        CLOSEHANDLE,
        DEBUG_EVENT,
        DEBUG_OBJECT,
        KNOWN_DEBUGGER, //for commonly used tools such as IDA, olly, etc
        VEH_DEBUGGER, //https://github.com/cheat-engine/cheat-engine/blob/66d2ad3ba7f4de6726f61437300b24fa00c425f5/Cheat%20Engine/VEHDebugger.pas -> calls CreateFileMapping, MapViewOfFile, CreateEvent, DuplicateHandle, then injects a DLL (vehdebug_x86/64.dll) -> calls "vehdebug.InitializeVEH' export, thus we can likely detect this by a simple module enum
        TRAP_FLAG, //There is a Trap Flag in the Flags register. Bit number 8 of the EFLAGS register is the trap flag. When the Trap Flag is set, a SINGLE_STEP exception is generated.
        ICE_0xF1, //ICEBP is an undocumented instruction that serves as a single byte interrupt 1, generating a single step exception. It can be used to detect if the program is traced.
        SINGLE_STEP,
        OVERFLOW_FLAG, 
        EXPORTED_FUNCTIONS,
        PARENT,
        ILLEGAL_INSTRUCTION,
        PRIVILEGED_INSTRUCTION,

        ALL = -1
    };

    class AntiDebug
    {
    public:
        
        AntiDebug()
        {
            this->DetectionThread = NULL;
            this->DebuggerMethodsDetected = 0;
        }
        
        inline int GetDebuggerMethodsDetected() { return DebuggerMethodsDetected; }
    
        inline HANDLE GetDetectionThread() { return this->DetectionThread; }

        inline bool _IsDebuggerPresent();
        inline bool _IsDebuggerPresentHeapFlags();
        inline bool _IsKernelDebuggerPresent();
        inline bool _IsHardwareDebuggerPresent();
        inline bool _IsDebuggerPresentCloseHandle();
        inline bool _IsDebuggerPresent_RemoteDebugger();
        inline bool _IsDebuggerPresent_IllegalInstruction();
        inline bool _IsDebuggerPresent_Int2c();
        inline bool _IsDebuggerPresent_Int2d();
        inline bool _IsDebuggerPresent_VEH();
        inline bool _IsDebuggerPresent_DbgBreak();
        inline bool _IsDebuggerPresent_WaitDebugEvent();
        inline bool _IsDebuggerPresent_PEB();

       // bool CheckForDebugger();
        static void CheckForDebugger(LPVOID AD);
        void StartAntiDebugThread();


#ifdef ENVIRONMENT32 //we will try to make x64 versions for these a bit later
        bool _IsDebuggerPresent_TrapFlag();
        //bool _IsDebuggerPresent_INT2D();
#endif

    private:
        
        int DebuggerMethodsDetected = 0;          
        HANDLE DetectionThread;
    };
}

//The following structures are used with debugging :
//
//CONTEXT
//CREATE_PROCESS_DEBUG_INFO
//CREATE_THREAD_DEBUG_INFO
//DEBUG_EVENT
//EXCEPTION_DEBUG_INFO
//EXIT_PROCESS_DEBUG_INFO
//EXIT_THREAD_DEBUG_INFO
//LDT_ENTRY
//LOAD_DLL_DEBUG_INFO
//OUTPUT_DEBUG_STRING_INFO
//RIP_INFO
//UNLOAD_DLL_DEBUG_INFO
//WOW64_CONTEXT
//WOW64_FLOATING_SAVE_AREA
//WOW64_LDT_ENTRY
//
