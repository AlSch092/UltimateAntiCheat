//By AlSch092 @github
#pragma once
#include "../Network/NetClient.hpp" //to flag users to server
#include "../Common/Settings.hpp"
#include <functional>

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)

namespace Debugger
{
    enum Detections
    {
        WINAPI_DEBUGGER = 1,
        PEB,
        HARDWARE_REGISTERS,
        HEAP_FLAG,
        INT3,
        INT2C,
        INT2D,
        CLOSEHANDLE,
        DEBUG_OBJECT,
        VEH_DEBUGGER,
        DBK64_DRIVER,
        KERNEL_DEBUGGER,
        TRAP_FLAG,
        DEBUG_PORT,
        PROCESS_DEBUG_FLAGS,
        REMOTE_DEBUGGER,
        DBG_BREAK,
    };

    /*
        AntiDebug - The AntiDebug class provides Anti-debugging methods, and should be inherited by a "detections" class which implements a set of monitoring routines.
        In this case, we're using the `DebuggerDetections` class to store our detection routines. The routines are stored in `DetectionFunctionList`, where each of them is called on each monitor iteration in `CheckForDebugger()`
    */
    class AntiDebug
    {
    public:
        
        AntiDebug(Settings* s, shared_ptr<NetClient> netClient) : netClient(netClient), Config(s)
        {
            if (s == nullptr)
            {
                Logger::logf(Warning, "Settings object pointer was somehow nullptr, unknown behavior may take place @ AntiDebug::AntiDebug()");
            }

            if (!PreventWindowsDebuggers()) //patch over some routine preambles, this may be phased out in future
            {
                Logger::logf(Warning, "Routine PreventWindowsDebuggers failed @ AntiDebug::AntiDebug()");
            }

            CommonDebuggerProcesses.push_back(L"x64dbg.exe"); //strings should be encrypted in a live environment
            CommonDebuggerProcesses.push_back(L"CheatEngine.exe");
            CommonDebuggerProcesses.push_back(L"idaq64.exe");
            CommonDebuggerProcesses.push_back(L"cheatengine-x86_64-SSE4-AVX2.exe");
            CommonDebuggerProcesses.push_back(L"kd.exe");
            CommonDebuggerProcesses.push_back(L"DbgX.Shell.exe");
        }

		~AntiDebug() = default; //any smart pointers will be cleaned up automatically

        AntiDebug operator+(AntiDebug& other) = delete; //delete all arithmetic operators, unnecessary for context
        AntiDebug operator-(AntiDebug& other) = delete;
        AntiDebug operator*(AntiDebug& other) = delete;
        AntiDebug operator/(AntiDebug& other) = delete;
        
		list<Detections> GetDebuggerMethodsDetected() const { return DebuggerMethodsDetected; } //we could always turn this into an integer that uses powers of 2
    
        Thread* GetDetectionThread() const  { return this->DetectionThread.get(); }
        NetClient* GetNetClient() const { return this->netClient.get(); }
        Settings* GetSettings() const { return this->Config; }

        void StartAntiDebugThread();

        static void CheckForDebugger(LPVOID AD); //thread looping function to monitor, pass AntiDebug* member as `AD`

        static bool PreventWindowsDebuggers(); //experimental method, patch DbgBreakpoint + DbgUiRemoteBreakin

        static bool HideThreadFromDebugger(HANDLE hThread);

        bool AddDetectedFlag(Detections f);
        bool Flag(Detections flag); //notify server 

        template<typename Func>
        void AddDetectionFunction(Func func) //define detection functions in the subclass, `DebuggerDetections`, then add them to the list using this func
        {
            DetectionFunctionList.emplace_back(func);
        }

        bool RunDetectionFunctions()  //run all detection functions
        {
            bool DetectedDebugger = false;

            for (auto& func : DetectionFunctionList)
            {
                if (DetectedDebugger = func()) //call the debugger detection method
                { //...if debugger was found, optionally take further action below (detected flags are already set in each routine, so this block is empty)
                }
            }

            return DetectedDebugger;
        }

        static void _IsHardwareDebuggerPresent(LPVOID AD); //this func needs to run in its own thread, since it suspends all other threads and checks their contexts for DR's with values. its placed in this class since it doesn't fit the correct definition type for our detection function list

        bool IsDBK64DriverLoaded();

    protected:
        vector<function<bool()>> DetectionFunctionList; //list of debugger detection methods, which are contained in the subclass `DebuggerDetections`
        
        list<wstring> CommonDebuggerProcesses;

    private:       
        list<Detections> DebuggerMethodsDetected;

        unique_ptr<Thread> DetectionThread = nullptr; //set in `StartAntiDebugThread`

        shared_ptr<NetClient> netClient = nullptr; //set in constructor

        Settings* Config = nullptr;

        const wstring DBK64Driver = L"DBK64.sys"; //DBVM debugger, this driver loaded and in a running state may likely indicate the presence of dark byte's VM debugger *todo -> add check on this driver*
    };
}

typedef struct _KSYSTEM_TIME
{
    ULONG LowPart;
    LONG High1Time;
    LONG High2Time;
} KSYSTEM_TIME, * PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
    NtProductWinNt = 1,
    NtProductLanManNt = 2,
    NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
    StandardDesign = 0,
    NEC98x86 = 1,
    EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA  //https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data
{
    ULONG                         TickCountLowDeprecated;
    ULONG                         TickCountMultiplier;
    KSYSTEM_TIME                  InterruptTime;
    KSYSTEM_TIME                  SystemTime;
    KSYSTEM_TIME                  TimeZoneBias;
    USHORT                        ImageNumberLow;
    USHORT                        ImageNumberHigh;
    WCHAR                         NtSystemRoot[260];
    ULONG                         MaxStackTraceDepth;
    ULONG                         CryptoExponent;
    ULONG                         TimeZoneId;
    ULONG                         LargePageMinimum;
    ULONG                         AitSamplingValue;
    ULONG                         AppCompatFlag;
    ULONGLONG                     RNGSeedVersion;
    ULONG                         GlobalValidationRunlevel;
    LONG                          TimeZoneBiasStamp;
    ULONG                         NtBuildNumber;
    NT_PRODUCT_TYPE               NtProductType;
    BOOLEAN                       ProductTypeIsValid;
    BOOLEAN                       Reserved0[1];
    USHORT                        NativeProcessorArchitecture;
    ULONG                         NtMajorVersion;
    ULONG                         NtMinorVersion;
    BOOLEAN                       ProcessorFeatures[64];
    ULONG                         Reserved1;
    ULONG                         Reserved3;
    ULONG                         TimeSlip;
    ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
    ULONG                         BootId;
    LARGE_INTEGER                 SystemExpirationDate;
    ULONG                         SuiteMask;
    BOOLEAN                       KdDebuggerEnabled;
    union {
        UCHAR MitigationPolicies;
        struct {
            UCHAR NXSupportPolicy : 2;
            UCHAR SEHValidationPolicy : 2;
            UCHAR CurDirDevicesSkippedForDlls : 2;
            UCHAR Reserved : 2;
        };
    };
    USHORT                        CyclesPerYield;
    ULONG                         ActiveConsoleId;
    ULONG                         DismountCount;
    ULONG                         ComPlusPackage;
    ULONG                         LastSystemRITEventTickCount;
    ULONG                         NumberOfPhysicalPages;
    BOOLEAN                       SafeBootMode;
    union {
        UCHAR VirtualizationFlags;
        struct {
            UCHAR ArchStartedInEl2 : 1;
            UCHAR QcSlIsSupported : 1;
        };
    };
    UCHAR                         Reserved12[2];
    union 
    {
        ULONG SharedDataFlags;
        struct 
        {
            ULONG DbgErrorPortPresent : 1;
            ULONG DbgElevationEnabled : 1;
            ULONG DbgVirtEnabled : 1;
            ULONG DbgInstallerDetectEnabled : 1;
            ULONG DbgLkgEnabled : 1;
            ULONG DbgDynProcessorEnabled : 1;
            ULONG DbgConsoleBrokerEnabled : 1;
            ULONG DbgSecureBootEnabled : 1;
            ULONG DbgMultiSessionSku : 1;
            ULONG DbgMultiUsersInSessionSku : 1;
            ULONG DbgStateSeparationEnabled : 1;
            ULONG SpareBits : 21;
        } Dbg;
    } DbgUnion;
    ULONG                         DataFlagsPad[1];
    ULONGLONG                     TestRetInstruction;
    LONGLONG                      QpcFrequency;
    ULONG                         SystemCall;
    ULONG                         Reserved2;
    ULONGLONG                     FullNumberOfPhysicalPages;
    ULONGLONG                     SystemCallPad[1];
    union 
    {
        KSYSTEM_TIME TickCount;
        ULONG64      TickCountQuad;
        struct 
        {
            ULONG ReservedTickCountOverlay[3];
            ULONG TickCountPad[1];
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME3;
    ULONG                         Cookie;
    ULONG                         CookiePad[1];
    LONGLONG                      ConsoleSessionForegroundProcessId;
    ULONGLONG                     TimeUpdateLock;
    ULONGLONG                     BaselineSystemTimeQpc;
    ULONGLONG                     BaselineInterruptTimeQpc;
    ULONGLONG                     QpcSystemTimeIncrement;
    ULONGLONG                     QpcInterruptTimeIncrement;
    UCHAR                         QpcSystemTimeIncrementShift;
    UCHAR                         QpcInterruptTimeIncrementShift;
    USHORT                        UnparkedProcessorCount;
    ULONG                         EnclaveFeatureMask[4];
    ULONG                         TelemetryCoverageRound;
    USHORT                        UserModeGlobalLogger[16];
    ULONG                         ImageFileExecutionOptions;
    ULONG                         LangGenerationCount;
    ULONGLONG                     Reserved4;
    ULONGLONG                     InterruptTimeBias;
    ULONGLONG                     QpcBias;
    ULONG                         ActiveProcessorCount;
    UCHAR                         ActiveGroupCount;
    UCHAR                         Reserved9;
    union 
    {
        USHORT QpcData;
        struct 
        {
            UCHAR QpcBypassEnabled;
            UCHAR QpcReserved;
        };
    };
    LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
    LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
    XSTATE_CONFIGURATION          XState;
    KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
    ULONG                         Spare;
    ULONG64                       UserPointerAuthMask;
    XSTATE_CONFIGURATION          XStateArm64;
    ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, * PKUSER_SHARED_DATA;
