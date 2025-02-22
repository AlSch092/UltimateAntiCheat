//UltimateAnticheat Server - By AlSch092 @ Github

namespace UACServer
{
    enum DetectionFlags //used in client-server comms to flag cheaters
    {
	DEBUGGER,
	PAGE_PROTECTIONS, //re-remapping
	CODE_INTEGRITY,   //.text section changes
	DLL_TAMPERING, //hooking or modifying loaded DLLs
	BAD_IAT, //IAT hooking
	OPEN_PROCESS_HANDLES,
	UNSIGNED_DRIVERS,
	INJECTED_ILLEGAL_PROGRAM,
	EXTERNAL_ILLEGAL_PROGRAM,
	REGISTRY_KEY_MODIFICATIONS,
	MANUAL_MAPPING,
	SUSPENDED_THREAD,
	HYPERVISOR,
    };
}
