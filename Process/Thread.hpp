//By AlSch092 @ Github
#pragma once
#include <windows.h>
#include "../Common/Logger.hpp"


/*
	Thread class represents a process thread, we aim to track threads in our process such that we can determine possible rogue threads
	Any helper functions related to threads are also defined in this class
*/
class Thread
{
public:
	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD Id = 0;
	DWORD ContextFlags = 0;

	bool ShutdownSignalled = false;
	bool CurrentlyRunning = false;

	static bool IsThreadRunning(HANDLE threadHandle);
	static bool IsThreadSuspended(HANDLE threadHandle);
};

