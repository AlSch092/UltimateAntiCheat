//By AlSch092 @ Github
#pragma once
#include <windows.h>
#include <stdio.h>

class Thread
{
public:
	DWORD Id;
	DWORD ContextFlags;

	static bool IsThreadRunning(HANDLE threadHandle);
	static bool IsThreadSuspended(HANDLE threadHandle);
};

