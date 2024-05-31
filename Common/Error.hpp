//By Alsch092 @ github
#pragma once
enum Error
{
	OK,
	CANT_STARTUP,
	CANT_APPLY_TECHNIQUE,
	CANT_CONNECT,
	CANT_RECIEVE,
	CANT_SEND,
	LOST_CONNECTION,
	SERVER_KICKED,
	INCOMPLETE_SEND,
	INCOMPLETE_RECV,
	NO_RECV_THREAD,
	BAD_HEARTBEAT,
	BAD_OPCODE,
	BAD_SOCKET,
	DATA_LENGTH_MISMATCH,
	NULL_MEMORY_REFERENCE,
	PARENT_PROCESS_MISMATCH,
	PAGE_PROTECTIONS_MISMATCH,
	LICENSE_UNKNOWN,
	BAD_MODULE,
	GENERIC_FAIL,
};

enum DetectionFlags //used in client-server comms to flag cheaters. needs to be visible to NetClient thus not inside the Detections class since we don't want to #include Detections.hpp from NetClient.hpp
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
};