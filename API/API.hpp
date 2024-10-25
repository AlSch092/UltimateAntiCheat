//By AlSch092 @ Github
#pragma once
#include "../AntiCheat.hpp"
#include "../Common/Error.hpp"

using namespace std;

//API namespace is the interface to work with the AntiCheat class, to intialize it and clean up. also contains some important variables for the AC's runtime environment
namespace API
{
	enum DispatchCode
	{
		INITIALIZE,
		CLIENT_EXIT,
	};

	static const char* ServerEndpoint = "127.0.0.1";
	static unsigned short ServerPort = 5445;
#ifdef _DEBUG
	static const wchar_t* whitelistedParentProcess = L"VsDebugConsole.exe"; //if debugging in VS, otherwise change to explorer.exe
#else
	static const wchar_t* whitelistedParentProcess = L"explorer.exe";
#endif

	Error Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerConnected);
	Error LaunchDefenses(AntiCheat* AC); //these routines are usually called by Dispatch with `INITIALIZE` dispatch code

        Error Cleanup(AntiCheat* AC);
	
	Error Dispatch(AntiCheat* AC, DispatchCode code); //if you insist on using this project as a standalone .dll, you can change this function to dllexport
}


