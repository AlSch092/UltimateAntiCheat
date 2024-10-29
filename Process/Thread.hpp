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

	Thread()
	{
	}

	Thread(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam)
	{
		this->handle = CreateThread(0, 0, toExecute, lpOptionalParam, 0, &this->Id);

		if (this->handle == INVALID_HANDLE_VALUE)
		{
			Logger::logf("UltimateAnticheat.log", Err, "Failed to create new thread @ Thread::Thread - address %llX", (UINT_PTR)toExecute);
			this->CurrentlyRunning = false;
			return;
		}

		this->ExecutionAddress = (UINT_PTR)toExecute;
		this->OptionalParam = lpOptionalParam;
		this->ShutdownSignalled = false;
		this->CurrentlyRunning = true;
	}

	~Thread()
	{
		Logger::logf("UltimateAnticheat.log", Info, "Ending thread which originally executed at: %llX", this->ExecutionAddress);

		if (this->handle != INVALID_HANDLE_VALUE)
		{
			this->ShutdownSignalled = true;

			if (!TerminateThread(this->handle, 0))
			{
				Logger::logf("UltimateAnticheat.log", Warning, "TerminateThread failed @ ~Thread");
			}
		}
	}

	HANDLE handle = INVALID_HANDLE_VALUE;
	DWORD Id = 0;
	DWORD ContextFlags = 0;

	UINT_PTR ExecutionAddress = 0;
	LPVOID OptionalParam = nullptr;

	bool ShutdownSignalled = false;
	bool CurrentlyRunning = false;

	static bool IsThreadRunning(HANDLE threadHandle); //these could potentially go into Process.hpp/cpp, since we have one Thread class for each thread, thus a static function is not as well suited to be here
	static bool IsThreadSuspended(HANDLE threadHandle);
};
