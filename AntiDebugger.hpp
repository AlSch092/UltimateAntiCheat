#pragma once
#include <Winternl.h>
#include <Windows.h>
#include <stdio.h> //for printing info
#include <tlhelp32.h> //process watching
#include <Psapi.h> //process watching

#define MAX_DLLS 128 
#define MAX_FILE_PATH_LENGTH 256

namespace Debugger
{
    enum Detections //a few basic methods for now just as example
    {
        WINAPI_DEBUGGER = 0,
        PEB_FLAG,
        HARDWARE_REGISTERS,
        KNOWN_DEBUGGER, //for commonly used tools such as IDA, olly, etc
        VEH_DEBUGGER, //https://github.com/cheat-engine/cheat-engine/blob/66d2ad3ba7f4de6726f61437300b24fa00c425f5/Cheat%20Engine/VEHDebugger.pas -> calls CreateFileMapping, MapViewOfFile, CreateEvent, DuplicateHandle, then injects a DLL (vehdebug_x86/64.dll) -> calls "vehdebug.InitializeVEH' export, thus we can likely detect this by a simple module enum
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

        bool IsBeingDebugged() //if atleast one method is detected, return true -> go through all methods
        {
            bool _isDebugged = false;
          
            if (IsDebuggerPresent()) //winapi
            {
                DebuggerMethodsDetected = DebuggerMethodsDetected | WINAPI_DEBUGGER;
                _isDebugged = true;
            }
          
            //PEB flag, well documented
            if (PEB_IsDebugged()) 
            {
                 DebuggerMethodsDetected = DebuggerMethodsDetected | PEB_FLAG;
                 _isDebugged = true;
            }
          
            //...and so on
            //todo -> switch this into .cpp file, then see if we can remove this function and replace it with a shell version of it
            return _isDebugged;
        }
    
        static void CheckForDebugger(LPVOID AD); //threaded method
        void StartAntiDebugThread();

    private:
        
        int DebuggerMethodsDetected;
        int DebuggerDetectionMethods;
    
        HANDLE DetectionThread;
    };
}
