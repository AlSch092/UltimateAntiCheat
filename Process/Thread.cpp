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

bool Thread::IsThreadSuspended(HANDLE threadHandle)
{
    if (threadHandle == NULL)
        return false;

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;
    if (GetThreadContext(threadHandle, &context))
    {
        return (context.ContextFlags == CONTEXT_CONTROL && context.ContextFlags != 0);
    }

    Logger::logf("UltimateAnticheat.log", Err, "GetExitCodeThread failed @ IsThreadSuspended: %d\n", GetLastError());
    return false;
}