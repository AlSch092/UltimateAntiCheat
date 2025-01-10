//By AlSch092 @ Github
#include "Thread.hpp"

/*
    Thread::BeginExecution - Managed thread creation & start
    return `true` on success, `false` on failure
*/
BOOL Thread::BeginExecution(LPTHREAD_START_ROUTINE toExecute, LPVOID lpOptionalParam, BOOL shouldRunForever)
{
    if (toExecute != NULL)
    {
        this->ExecutionAddress = (UINT64)toExecute;
        this->OptionalParam = lpOptionalParam;
        this->ShouldRunForever = shouldRunForever;

        try
        {
            // Use a lambda to wrap the LPTHREAD_START_ROUTINE for std::thread
            this->t = std::thread([toExecute, lpOptionalParam]() { toExecute(lpOptionalParam); });

            this->handle = t.native_handle(); // Get the native handle
            this->Id = GetThreadId(this->handle);

            t.detach();

            Tick = std::chrono::steady_clock::now();

            return TRUE;
        }
        catch (const std::system_error& e)
        {
            Logger::logf("UltimateAnticheat.log", Err, "std::thread failed @ BeginExecution: %s\n", e.what());
            this->Id = NULL;
            return FALSE;
        }
    }
    else
    {
        return FALSE;
    }
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