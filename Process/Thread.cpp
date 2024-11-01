//By AlSch092 @ Github
#include "Thread.hpp"

BOOL Thread::BeginExecution()
{
	if (ExecutionAddress != NULL)
	{
		this->handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&ExecutionAddress, OptionalParam, 0, &this->Id);

		if (this->handle == INVALID_HANDLE_VALUE)
		{
			this->Id = NULL;
			return FALSE;
		}
	}

	return TRUE;
}

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
			this->Id = NULL;
			return FALSE;
		}

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
    IsThreadSuspended - checks if a thread is suspending it by attempting to suspend it
    has its drawbacks since it suspends threads, but it works fine
*/
bool Thread::IsThreadSuspended(HANDLE threadHandle)
{
    DWORD suspendCount = SuspendThread(threadHandle); //OS handles suspend count so we can't fetch this from memory in the current process

    if (suspendCount == (DWORD)-1)
    {
        return false;
    }
    else if (suspendCount > 0)
    {
        ResumeThread(threadHandle);
        return true;
    }
    else
    {
        ResumeThread(threadHandle);
        return false;
    }  
}