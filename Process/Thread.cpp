//By AlSch092 @ Github
#include "Thread.hpp"

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