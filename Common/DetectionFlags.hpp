#pragma once

enum DetectionFlags //used in client-server comms to flag cheaters. needs to be visible to NetClient thus not inside the Detections class since we don't want to #include Detections.hpp from NetClient.hpp
{
    NONE = 0,
    EXECUTION_ERROR,

	PAGE_PROTECTIONS = 1000, //re-remapping
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

    //DEBUGGER DETECTIONS ----------------
    DEBUG_WINAPI_DEBUGGER = 10000,
    DEBUG_PEB,
    DEBUG_HARDWARE_REGISTERS,
    DEBUG_HEAP_FLAG,
    DEBUG_INT3,
    DEBUG_INT2C,
    DEBUG_CLOSEHANDLE,
    DEBUG_DEBUG_OBJECT,
    DEBUG_VEH_DEBUGGER,
    DEBUG_DBK64_DRIVER,
    DEBUG_KERNEL_DEBUGGER,
    DEBUG_TRAP_FLAG,
    DEBUG_DEBUG_PORT,
    DEBUG_PROCESS_DEBUG_FLAGS,
    DEBUG_REMOTE_DEBUGGER,
    DEBUG_DBG_BREAK,
    DEBUG_KNOWN_DEBUGGER_PROCESS,
    ///DEBUGGER DETECTIONS ----------------
};