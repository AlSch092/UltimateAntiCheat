//By AlSch092 @ github
#pragma once
#include <string>

namespace UnmanagedGlobals
{
    static std::wstring wCurrentModuleName;
    static std::string CurrentModuleName;

    static std::list<Thread*>* ThreadList = new std::list<Thread*>();
    static bool AddThread(DWORD id);
    static void RemoveThread(DWORD tid);

    static LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

    static bool SupressingNewThreads = false;
    static bool SetExceptionHandler = false;
    static bool FirstProcessAttach = true;
}
