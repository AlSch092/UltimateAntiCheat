//By AlSch092 @github
#pragma once
#include "../Process/Process.hpp"

#define MAX_DLLS 256 
#define MAX_FILE_PATH_LENGTH 256

namespace Debugger
{
    //see bottom of file for list of windows structures related to debugging
    enum Detections
    {
        WINAPI_DEBUGGER = 1,
        PEB_FLAG,
        HARDWARE_REGISTERS,
        HEAP_FLAG,
        INT3, //same as DebugBreak()
        INT2C,
        INT2D, //
        MULTIBYTE_INT3, //extended int3
        CLOSEHANDLE,
        DEBUG_EVENT,
        DEBUG_OBJECT,
        VEH_DEBUGGER, //https://github.com/cheat-engine/cheat-engine/blob/66d2ad3ba7f4de6726f61437300b24fa00c425f5/Cheat%20Engine/VEHDebugger.pas -> calls CreateFileMapping, MapViewOfFile, CreateEvent, DuplicateHandle, then injects a DLL (vehdebug_x86/64.dll) -> calls "vehdebug.InitializeVEH' export, thus we can likely detect this by a simple module enum
        KERNEL_DEBUGGER,
        TRAP_FLAG, //There is a Trap Flag in the Flags register. Bit number 8 of the EFLAGS register is the trap flag. When the Trap Flag is set, a SINGLE_STEP exception is generated.
        ICE_0xF1, //ICEBP is an undocumented instruction that serves as a single byte interrupt 1, generating a single step exception. It can be used to detect if the program is traced.
        DEBUG_PORT,
        PROCESS_DEBUG_FLAGS,
        PARENT,   //parent is ollydbg.exe or whatever else known debugger
    };

    class AntiDebug
    {
    public:
        
        AntiDebug()
        {
            this->DetectionThread = NULL;
        }
        
        list<Detections> GetDebuggerMethodsDetected() { return DebuggerMethodsDetected; }
    
        HANDLE GetDetectionThread() { return this->DetectionThread; }
        void SetDetectionThread(HANDLE h) { this->DetectionThread = h; }

        inline bool _IsDebuggerPresent() { return IsDebuggerPresent(); }
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
        inline bool _IsDebuggerPresent_DebugPort();
        inline bool _IsDebuggerPresent_ProcessDebugFlags();

        static void CheckForDebugger(LPVOID AD);
        void StartAntiDebugThread();

#ifdef ENVIRONMENT32 //ununsed for now,
        bool _IsDebuggerPresent_TrapFlag();
        //bool _IsDebuggerPresent_INT2D();
#endif

    private:       
        list<Detections> DebuggerMethodsDetected;
        HANDLE DetectionThread;

        Thread* _DetectionThread = NULL;
    };
}