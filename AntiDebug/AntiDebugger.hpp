//By AlSch092 @github
#pragma once
#include "../Process/Process.hpp"

#define MAX_DLLS 256 
#define MAX_FILE_PATH_LENGTH 256
#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)

namespace Debugger
{
    enum Detections
    {
        WINAPI_DEBUGGER = 1,
        PEB_FLAG,
        HARDWARE_REGISTERS,
        HEAP_FLAG,
        INT3,
        INT2C,
        INT2D,
        CLOSEHANDLE,
        DEBUG_EVENT,
        DEBUG_OBJECT,
        VEH_DEBUGGER,
        KERNEL_DEBUGGER,
        TRAP_FLAG,
        DEBUG_PORT,
        PROCESS_DEBUG_FLAGS,
        PARENT,
    };

    class AntiDebug
    {
    public:
        
        AntiDebug()
        {
        }

        ~AntiDebug()
        {
            delete this->DetectionThread;
        }
        
        list<Detections> GetDebuggerMethodsDetected() { return DebuggerMethodsDetected; }
    
        Thread* GetDetectionThread() { return this->DetectionThread; }
        HANDLE GetDetectionThreadHandle() { if (this->DetectionThread != NULL) return this->DetectionThread->handle; else return INVALID_HANDLE_VALUE; }
        void SetDetectionThread(HANDLE h) { this->DetectionThread->handle = h; }

        inline bool _IsDebuggerPresent() { return IsDebuggerPresent(); }
        inline bool _IsDebuggerPresent_HeapFlags();
        inline bool _IsDebuggerPresent_CloseHandle();
        inline bool _IsDebuggerPresent_RemoteDebugger();
        inline bool _IsDebuggerPresent_Int2c();
        inline bool _IsDebuggerPresent_Int2d();
        inline bool _IsDebuggerPresent_VEH();
        inline bool _IsDebuggerPresent_DbgBreak();
        inline bool _IsDebuggerPresent_WaitDebugEvent();
        inline bool _IsDebuggerPresent_PEB();
        inline bool _IsDebuggerPresent_DebugPort();
        inline bool _IsDebuggerPresent_ProcessDebugFlags();
        inline bool _IsKernelDebuggerPresent();
        inline bool _IsKernelDebuggerPresent_SharedKData();
        inline bool _IsHardwareDebuggerPresent();

        static void CheckForDebugger(LPVOID AD);
        void StartAntiDebugThread();

    private:       
        list<Detections> DebuggerMethodsDetected;

        Thread* DetectionThread = NULL;
    };
}

typedef struct _KUSER_SHARED_DATA
{
    ULONG TickCountLowDeprecated;
    ULONG TickCountMultiplier;
    volatile LARGE_INTEGER InterruptTime;
    volatile LARGE_INTEGER SystemTime;
    volatile LARGE_INTEGER TimeZoneBias;
    USHORT ImageNumberLow;
    USHORT ImageNumberHigh;
    WCHAR NtSystemRoot[260];
    ULONG MaxStackTraceDepth;
    ULONG CryptoExponent;
    ULONG TimeZoneId;
    ULONG LargePageMinimum;
    ULONG Reserved2[7];
    ULONG NtProductType;
    BOOLEAN ProductTypeIsValid;
    BOOLEAN Reserved1[1];
    USHORT NativeProcessorArchitecture;
    ULONG NtMajorVersion;
    ULONG NtMinorVersion;
    BOOLEAN ProcessorFeatures[64];
    ULONG Reserved3;
    ULONG Reserved4;
    ULONG Reserved5;
    ULONG Reserved6;
    ULONG Reserved7;
    ULONG Reserved8;
    ULONG Reserved9;
    ULONG ActiveConsoleId;
    ULONG DismountCount;
    ULONG ComPlusPackage;
    ULONG LastSystemRITEventTickCount;
    ULONG NumberOfPhysicalPages;
    BOOLEAN SafeBootMode;
    ULONG SharedDataFlags;
    ULONG DbgErrorPortPresent;
    ULONG DbgElevationEnabled;
    ULONG DbgVirtEnabled;
    ULONG DbgInstallerDetectEnabled;
    ULONG DbgSystemDllRelocated;
    ULONG DbgDynProcessorEnabled;
    ULONG DbgSEHValidationEnabled;
    ULONG KernelReserved[2];
    ULONG DbgUmsEnabled;
    ULONG DbgKdEnabled; // This field indicates if kernel debugging is enabled.
    ULONG Reserved10[1];
    ULONG SystemCall[2];
    ULONG SystemCallReturn[2];
    ULONG SystemCallPad[3];
    union {
        volatile LARGE_INTEGER TickCount;
        volatile ULONG64 TickCountQuad;
    };
    ULONG Cookie;
    ULONG Wow64SharedInformation[16];
    USHORT UserModeGlobalLogger[8];
    ULONG64 TimeSlip;
    ULONG64 SystemReserved[1];
    ULONG64 TestRetInstruction;
    ULONG64 QpcFrequency;
    ULONG64 SystemCallPad2[3];
    ULONG64 SystemCallPad3[3];
    ULONG64 TickCountPad[1];
    ULONG DbgSystemDllRelocated32;
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;