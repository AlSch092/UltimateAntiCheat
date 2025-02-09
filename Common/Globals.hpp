//By AlSch092 @ github
#pragma once
#include <string>
#include <vector>
#include "../Process/Process.hpp"
/*
    This namespace contains variables which would otherwise be global. In this project, variables are only global if visibility between managed and unmanaged code is required.
    For example, our TLS callback has a switch to supress thread creation, which is based on a member of the `Preventions` class. Since there's no global `Preventions` variable, our TLS callback needs access to this variable somehow
*/
namespace UnmanagedGlobals
{
	static std::wstring wCurrentModuleName;
    static std::string CurrentModuleName;

    static std::list<Thread*>* ThreadList = new std::list<Thread*>();
    static bool AddThread(DWORD id);
    static void RemoveThread(DWORD tid);

    static LONG WINAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);

    static bool SupressingNewThreads = true; //this member is usually set to true after initialization is complete
    static bool SetExceptionHandler = false;
    static bool FirstProcessAttach = true;
}
