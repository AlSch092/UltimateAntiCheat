//By AlSch092 @github
#pragma once
#include "DetectionFlags.hpp"
#include <unordered_map>

enum class DetectionSeverity
{
    INFO,       // Log only, no action taken
    WARNING,    // Log and report to API
    CRITICAL    // Log, report to API, and terminate target process
};

/*
    DetectionSeverityConfig manages the severity levels for different detection types
    Allows configuration of which detections should shutdown vs just log
*/
class DetectionSeverityConfig final
{
public:
    DetectionSeverityConfig()
    {
        // Initialize default severity levels
        InitializeDefaultSeverities();
    }

    DetectionSeverity GetSeverity(DetectionFlags flag) const
    {
        auto it = severityMap.find(flag);
        if (it != severityMap.end())
        {
            return it->second;
        }
        return DetectionSeverity::WARNING; // Default to warning if not found
    }

    void SetSeverity(DetectionFlags flag, DetectionSeverity severity)
    {
        severityMap[flag] = severity;
    }

    bool ShouldTerminateProcess(DetectionFlags flag) const
    {
        return GetSeverity(flag) == DetectionSeverity::CRITICAL;
    }

    bool ShouldReportToAPI(DetectionFlags flag) const
    {
        DetectionSeverity severity = GetSeverity(flag);
        return severity == DetectionSeverity::WARNING || severity == DetectionSeverity::CRITICAL;
    }

private:
    std::unordered_map<DetectionFlags, DetectionSeverity> severityMap;

    void InitializeDefaultSeverities()
    {
        // Memory tampering & integrity - CRITICAL (terminate process)
        severityMap[DetectionFlags::PAGE_PROTECTIONS] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::CODE_INTEGRITY] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::MANUAL_MAPPING] = DetectionSeverity::CRITICAL;

        // DLL/IAT tampering - WARNING (log & report, may be runtime injection)
        severityMap[DetectionFlags::DLL_TAMPERING] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::BAD_IAT] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::INJECTED_ILLEGAL_PROGRAM] = DetectionSeverity::WARNING;

        // External monitoring - WARNING (informational)
        severityMap[DetectionFlags::OPEN_PROCESS_HANDLES] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::EXTERNAL_ILLEGAL_PROGRAM] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::UNSIGNED_DRIVERS] = DetectionSeverity::WARNING;

        // System modifications - WARNING
        severityMap[DetectionFlags::REGISTRY_KEY_MODIFICATIONS] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::SUSPENDED_THREAD] = DetectionSeverity::WARNING;
        severityMap[DetectionFlags::HYPERVISOR] = DetectionSeverity::INFO;

        // Debugger detections - CRITICAL (terminate immediately)
        severityMap[DetectionFlags::DEBUG_WINAPI_DEBUGGER] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_PEB] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_HARDWARE_REGISTERS] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_HEAP_FLAG] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_INT3] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_INT2C] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_CLOSEHANDLE] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_DEBUG_OBJECT] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_VEH_DEBUGGER] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_DBK64_DRIVER] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_KERNEL_DEBUGGER] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_TRAP_FLAG] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_DEBUG_PORT] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_PROCESS_DEBUG_FLAGS] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_REMOTE_DEBUGGER] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_DBG_BREAK] = DetectionSeverity::CRITICAL;
        severityMap[DetectionFlags::DEBUG_KNOWN_DEBUGGER_PROCESS] = DetectionSeverity::CRITICAL;
    }
};
