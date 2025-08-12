//By AlSch092 @github
#pragma once
#include "../Network/NetClient.hpp" //to flag users to server
#include "../Common/Settings.hpp"
#include "../Common/EvidenceLocker.hpp"
#include <functional>

#define USER_SHARED_DATA ((KUSER_SHARED_DATA * const)0x7FFE0000)

namespace Debugger
{
    /*
        AntiDebug - The AntiDebug class provides Anti-debugging methods, and should be inherited by a "detections" class which implements a set of monitoring routines.
        In this case, we're using the `DebuggerDetections` class to store our detection routines. The routines are stored in `DetectionFunctionList`, where each of them is called on each monitor iteration in `CheckForDebugger()`
    */
    class AntiDebug
    {
    public:
        
        AntiDebug(Settings* s, EvidenceLocker* evidence) :  Config(s), EvidenceManager(evidence)
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

        ~AntiDebug()
        {
			if (DetectionThread != nullptr)
			{
				DetectionThread->SignalShutdown(TRUE);
                DetectionThread->JoinThread();
				DetectionThread.reset();
			}
        } 

        AntiDebug operator+(AntiDebug& other) = delete; //delete all arithmetic operators, unnecessary for context
        AntiDebug operator-(AntiDebug& other) = delete;
        AntiDebug operator*(AntiDebug& other) = delete;
        AntiDebug operator/(AntiDebug& other) = delete;
        
        Thread* GetDetectionThread() const  { return this->DetectionThread.get(); }
        Settings* GetSettings() const { return this->Config; }

        void StartAntiDebugThread();

        static void CheckForDebugger(LPVOID AD); //thread looping function to monitor, pass AntiDebug* member as `AD`

        static bool PreventWindowsDebuggers(); //experimental method, patch DbgBreakpoint + DbgUiRemoteBreakin

        static bool HideThreadFromDebugger(HANDLE hThread);

        template<typename Func>
        void AddDetectionFunction(Func func) //define detection functions in the subclass, `DebuggerDetections`, then add them to the list using this func
        {
            std::lock_guard<std::mutex> lock(this->DetectionRoutineMutex);
            DetectionFunctionList.emplace_back(func);
        }

        void RunDetectionFunctions()  //run all detection functions
        {
            std::lock_guard<std::mutex> lock(this->DetectionRoutineMutex);
            
            for (const auto& func : this->DetectionFunctionList)
            {
                DetectionFlags DetectedMethod = NONE;

                if (DetectedMethod = func()) //call the debugger detection method
                {
                    if (DetectedMethod > EXECUTION_ERROR)
                    {
                        this->AddFlagged(DetectedMethod);

                        if (this->EvidenceManager != nullptr)
                            this->EvidenceManager->AddFlagged(DetectedMethod);

                        Logger::logf(Info, "Debugger flag detected: %d", DetectedMethod); //optionally, iterate over DetectedMethods list if you want a more granular logging 
                    }    
                }
            }
        }

        static void _IsHardwareDebuggerPresent(LPVOID AD); //this func needs to run in its own thread, since it suspends all other threads and checks their contexts for DR's with values. its placed in this class since it doesn't fit the correct definition type for our detection function list

        bool IsDBK64DriverLoaded();

        static void HideAllThreadsFromDebugger();

    protected:
        vector<std::function<DetectionFlags()>> DetectionFunctionList; //list of debugger detection methods, which are contained in the subclass `DebuggerDetections`      
        
        list<wstring> CommonDebuggerProcesses;
        
        EvidenceLocker* EvidenceManager = nullptr;

    private:      

        unique_ptr<Thread> DetectionThread = nullptr; //set in `StartAntiDebugThread`

        list<DetectionFlags> DetectedMethods;

        Settings* Config = nullptr;

        const wstring DBK64Driver = L"DBK64.sys"; //DBVM debugger, this driver loaded and in a running state may likely indicate the presence of dark byte's VM debugger *todo -> add check on this driver*

        std::mutex DetectionRoutineMutex;
        std::mutex FlggedListMutex;

        void AddFlagged(const DetectionFlags& method)
        {
            std::lock_guard<std::mutex> lock(FlggedListMutex);
            if (std::find(this->DetectedMethods.begin(), this->DetectedMethods.end(), method) == this->DetectedMethods.end())
                this->DetectedMethods.push_back(method);
        }
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
