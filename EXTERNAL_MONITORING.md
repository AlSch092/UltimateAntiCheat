# External Process Monitoring Mode

## Overview

UltimateAntiCheat now supports **external process monitoring mode**, allowing it to monitor a target process from outside rather than being compiled into the game binary itself.

## Usage

### Command Line Arguments

```bash
UltimateAntiCheat.exe --pid <process_id> --api-domain <domain>
```

**Arguments:**
- `--pid <process_id>` - Target process ID to monitor (required for external mode)
- `--api-domain <domain>` - API domain for event logging (e.g., https://api.yourgame.com)
- `--help, -h` - Show help message

**Example:**
```bash
UltimateAntiCheat.exe --pid 1234 --api-domain https://api.yourgame.com
```

## API Event Logging

When detections occur, the anti-cheat will send POST requests to:
```
{API_DOMAIN}/events/log
```

### Event Payload Format

```json
{
  "detection_type": 1000,
  "detection_name": "Code Integrity Violation",
  "detection_details": "Memory modification detected in .text section",
  "process_id": 1234,
  "timestamp": 1234567890,
  "mac_addresses": [
    "00:11:22:33:44:55",
    "AA:BB:CC:DD:EE:FF"
  ],
  "platform": "Windows",
  "architecture": "x64"
}
```

## Detection Severity Levels

Detections are classified into three severity levels:

### INFO
- Only logged locally
- No API notification sent
- No action taken
- Example: Hypervisor detection

### WARNING
- Logged locally
- Sent to API (if enabled)
- No termination
- **Suitable for runtime injections that may be legitimate game features**
- Examples:
  - DLL tampering/hooking
  - IAT modifications
  - Injected unsigned programs
  - External process handles
  - Registry modifications

### CRITICAL
- Logged locally
- Sent to API (if enabled)
- **Target process terminated**
- Examples:
  - Memory protection changes (re-remapping)
  - Code integrity violations
  - Manual mapping
  - All debugger detections

## Important Limitations

### ⚠️ External Monitoring Constraints

When monitoring an **external process** (not self), many detection techniques have significant limitations:

#### 1. **Memory Integrity Checks**
- ❌ Cannot verify code integrity without reading remote process memory
- ❌ Requires `PROCESS_VM_READ` access
- ❌ Can be blocked by security software or PPL/PPS protected processes
- ⚠️ Many integrity checks are **disabled** in external mode

#### 2. **Debugger Detection**
- ✅ Some debugger checks work externally (e.g., checking debug port via NtQueryInformationProcess)
- ❌ Many usermode debugger checks require being inside the process
- ❌ Cannot use PEB flags, heap flags, or exception-based checks externally
- ⚠️ **Significantly reduced effectiveness**

#### 3. **DLL Monitoring**
- ❌ DLL load notifications (`LdrRegisterDllNotification`) only work for the current process
- ❌ Cannot monitor DLL injections in real-time from external process
- ⚠️ Must use polling via `EnumProcessModulesEx` (slower, less reliable)

#### 4. **Thread Monitoring**
- ❌ Cannot prevent thread creation in external process
- ❌ TLS callbacks don't work for external processes
- ⚠️ Limited to enumeration via `CreateToolhelp32Snapshot`

#### 5. **IAT/Hook Detection**
- ❌ Requires reading remote process memory
- ❌ High overhead for continuous monitoring
- ⚠️ Detections will be delayed

#### 6. **Privileges Required**
- ✅ Must run as **Administrator**
- ✅ Needs `PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`, `PROCESS_TERMINATE`
- ❌ Won't work against PPL (Protected Process Light) processes
- ❌ Won't work against anti-virus or system processes

### Recommended Use Cases

#### ✅ Good for External Monitoring:
- Basic process enumeration (blacklisted processes)
- Driver signature checking (system-wide)
- Registry monitoring (system-wide)
- External handle detection (from other processes)
- Service enumeration
- Hypervisor detection

#### ❌ Poor for External Monitoring (requires being inside process):
- Real-time code integrity checks
- Comprehensive debugger detection
- DLL injection prevention
- Hook/IAT tampering detection
- Memory protection verification
- Thread creation prevention

## Configuration

### Default Severity Configuration

The severity levels are configured in `Common/DetectionSeverity.hpp`. You can modify these based on your needs:

```cpp
// Memory tampering - CRITICAL
severityMap[DetectionFlags::PAGE_PROTECTIONS] = DetectionSeverity::CRITICAL;
severityMap[DetectionFlags::CODE_INTEGRITY] = DetectionSeverity::CRITICAL;

// DLL tampering - WARNING (may be runtime game injections)
severityMap[DetectionFlags::DLL_TAMPERING] = DetectionSeverity::WARNING;
severityMap[DetectionFlags::INJECTED_ILLEGAL_PROGRAM] = DetectionSeverity::WARNING;
```

### Modifying Severities at Runtime

```cpp
Detections* monitor = antiCheat->GetMonitor();
monitor->SetDetectionSeverity(DetectionFlags::DLL_TAMPERING, DetectionSeverity::INFO);
```

## Architecture Changes

### New Files
- `GameEvents/EventReporter.hpp/cpp` - API event reporting
- `Common/DetectionSeverity.hpp` - Severity configuration
- `EXTERNAL_MONITORING.md` - This documentation

### Modified Files
- `Common/Settings.hpp` - Added API and external mode configuration
- `Common/Utility.hpp/cpp` - Added MAC address collection
- `main.cpp` - Added command-line argument parsing
- `Core/Detections.hpp/cpp` - Added centralized detection handler with API reporting

## Security Considerations

### Bypassing External Monitoring

⚠️ **As you mentioned, external monitoring is bypassable.** Here's why:

1. **Process can be killed** - The monitoring process can be terminated
2. **API can be spoofed** - Network traffic can be intercepted/modified
3. **Memory can be manipulated** - Before the monitor reads it
4. **Detection lag** - External monitoring is inherently slower
5. **Privilege escalation** - Attackers can gain higher privileges

### Recommended Security Measures

1. **Run as System Service** - Use Windows Service with protection
2. **Kernel Driver** - Combine with kernel-mode driver for better protection
3. **Server-Side Validation** - Don't trust client-only checks
4. **Redundancy** - Multiple monitoring processes
5. **Obfuscation** - Obfuscate the monitoring binary
6. **Heartbeat** - Require regular heartbeats to server
7. **Hybrid Approach** - Use both internal (in-game) and external monitoring

## Traditional Mode (Self-Monitoring)

To use the traditional mode where the anti-cheat is compiled into your game:

1. **Don't** pass `--pid` argument
2. Link `UltimateAntiCheat` as a static library (`.lib`) into your game
3. Initialize AntiCheat object in your game's startup code
4. This provides much better protection as it's inside the protected process

## Building

The project can be built in two configurations:

1. **Standalone EXE** - For external monitoring mode
2. **Static LIB** - For integration into game binary (recommended for security)

```cmake
# Build as standalone executable
cmake -DBUILD_TYPE=Standalone ..

# Build as static library
cmake -DBUILD_TYPE=Library ..
```

## Future Improvements

Potential enhancements for external monitoring:

- [ ] Kernel driver integration for better external monitoring
- [ ] Multiple target process support
- [ ] Process event monitoring via WMI/ETW
- [ ] Memory scanning at intervals
- [ ] Configurable severity levels via config file
- [ ] Encrypted communication with API
- [ ] Certificate pinning for API requests
- [ ] Process protection using PPL
