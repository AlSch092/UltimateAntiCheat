#pragma once
#include <Winternl.h>
#include <Windows.h>
#include <stdio.h> //for printing info
#include <tlhelp32.h> //process watching
#include <Psapi.h> //process watching
#include "../Process/PEB.hpp"


#define MAX_DLLS 128 
#define MAX_FILE_PATH_LENGTH 256

namespace Debugger
{
    //Todo: Get all methods from scyllahide
    //see bottom of file for list of windows structures related to debugging
    enum Detections
    {
        WINAPI_DEBUGGER,
        PEB_FLAG,
        HARDWARE_REGISTERS,
        HEAP,
        INTC,
        INT2C,
        DEBUG_EVENT, 
        DEBUG_OBJECT,
        KNOWN_DEBUGGER, //for commonly used tools such as IDA, olly, etc
        VEH_DEBUGGER, //https://github.com/cheat-engine/cheat-engine/blob/66d2ad3ba7f4de6726f61437300b24fa00c425f5/Cheat%20Engine/VEHDebugger.pas -> calls CreateFileMapping, MapViewOfFile, CreateEvent, DuplicateHandle, then injects a DLL (vehdebug_x86/64.dll) -> calls "vehdebug.InitializeVEH' export, thus we can likely detect this by a simple module enum

        ALL = -1
    };

    class AntiDebug
    {
    public:
        
        AntiDebug()
        {
            this->DebuggerMethodsDetected = 0;
            this->DebuggerDetectionMethods = WINAPI_DEBUGGER;
        }
        
        inline int GetDebuggerMethodsDetected() { return DebuggerMethodsDetected; }
    
        inline HANDLE GetDetectionThread() { return this->DetectionThread; }

        inline bool _IsDebuggerPresent();
        inline bool _IsDebuggerPresentHeapFlags();
        inline bool _IsKernelDebuggerPresent();
        inline bool _IsHardwareDebuggerPresent();

       // bool CheckForDebugger();
        static void CheckForDebugger(LPVOID AD);
        void StartAntiDebugThread();

    private:
        
        int DebuggerMethodsDetected = 0;
        int DebuggerDetectionMethods = 0;
    
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
