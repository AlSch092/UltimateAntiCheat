//By AlSch092 @ Github
#pragma once
#include <windows.h>
#include <stdio.h>

class Thread
{
public:
	HANDLE handle;
	DWORD Id;
	DWORD ContextFlags;

	bool ShutdownSignalled; //send a signal here to make the thread close naturally

	static bool IsThreadRunning(HANDLE threadHandle);
	static bool IsThreadSuspended(HANDLE threadHandle);
};

