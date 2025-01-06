//By AlSch092 @ Github
#include "Thread.hpp"

/*
    Thread::BeginExecution - Managed thread creation & start. this overloaded routine is used when thread data members are already set from other places of code
    return `true` on success, `false` on failure
*/
BOOL Thread::BeginExecution()
{
	if (this->ExecutionAddress != NULL)
	{
		this->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&this->ExecutionAddress, this->OptionalParam, 0, &this->Id);

		if (this->handle == INVALID_HANDLE_VALUE)
		{
            Logger::logf("UltimateAnticheat.log", Err, " CreateThread failed @ BeginExecution: %d\n", GetLastError());
			this->Id = NULL;
			return FALSE;
		}
	}

	return TRUE;
}

/*
    Thread::BeginExecution - Managed thread creation & start
    return `true` on success, `false` on failure
*/
BOOL Thread::BeginExecution(DWORD_PTR toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever)
{
	if (ExecutionAddress != NULL)
	{
		this->ExecutionAddress = toExecute;
		this->OptionalParam = lpOptionalParam;
		this->ShouldRunForever = shouldRunForever;

		this->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&ExecutionAddress, OptionalParam, 0, &this->Id);

		if (this->handle == INVALID_HANDLE_VALUE)
		{
            Logger::logf("UltimateAnticheat.log", Err, " CreateThread failed @ BeginExecution: %d\n", GetLastError());
			this->Id = NULL;
			return FALSE;
		}

        Tick = std::chrono::steady_clock::now();

		return TRUE;
	}
	else
		return FALSE;
}

bool Thread::IsThreadRunning(HANDLE threadHandle)
{
    if (threadHandle == NULL)
        return false;

    DWORD exitCode;

    if (GetExitCodeThread(threadHandle, &exitCode) != 0)
    {
        return (exitCode == STILL_ACTIVE);
    }

    Logger::logf("UltimateAnticheat.log", Err, " GetExitCodeThread failed @ IsThreadRunning: %d\n", GetLastError());
    return false;
}

/*
    IsThreadSuspended - checks if a thread is currently suspended by suspending it
    has its drawbacks since it suspends threads very briefly, but it works fine
*/
bool Thread::IsThreadSuspended(HANDLE threadHandle)
{
    if (threadHandle == INVALID_HANDLE_VALUE || threadHandle == NULL)
        return false;

    bool suspended = false;

    DWORD suspendCount = SuspendThread(threadHandle);

    if (suspendCount == (DWORD)-1)
    {
        return false;
    }
    else if (suspendCount > 0) //already suspended by someone else
    {
        ResumeThread(threadHandle);
        suspended = true;
    }
    else
    {
        ResumeThread(threadHandle);
    }  

    return suspended;
}