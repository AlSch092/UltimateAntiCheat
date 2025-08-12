#pragma once
#include "AntiDebugger.hpp"

class DebuggerDetections final  : public Debugger::AntiDebug
{
public:
    DebuggerDetections(Settings* s, EvidenceLocker* evidence) : Debugger::AntiDebug(s, evidence)
    {
#ifndef _DEBUG //VS debugger messes up if threads get hidden from it
        this->HideAllThreadsFromDebugger();
#endif

        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_HeapFlags(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_CloseHandle(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_RemoteDebugger(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_VEH(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_PEB(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_DebugPort(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsDebuggerPresent_ProcessDebugFlags(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsKernelDebuggerPresent(); });
        AddDetectionFunction([this]() -> DetectionFlags { return _IsKernelDebuggerPresent_SharedKData(); });
        //AddDetectionFunction([this]() -> DetectionFlags { return _ExitCommonDebuggers(); });
    }

    DetectionFlags _IsDebuggerPresent();
    DetectionFlags _IsDebuggerPresent_HeapFlags();
    DetectionFlags _IsDebuggerPresent_CloseHandle();
    DetectionFlags _IsDebuggerPresent_RemoteDebugger();
    DetectionFlags _IsDebuggerPresent_VEH();
    DetectionFlags _IsDebuggerPresent_PEB();
    DetectionFlags _IsDebuggerPresent_DebugPort();
    DetectionFlags _IsDebuggerPresent_ProcessDebugFlags();
    DetectionFlags _IsKernelDebuggerPresent();
    DetectionFlags _IsKernelDebuggerPresent_SharedKData();
    DetectionFlags _ExitCommonDebuggers(); //call ExitProcess in a remote thread on common debuggers
};