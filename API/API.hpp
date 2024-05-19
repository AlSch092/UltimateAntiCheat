//By AlSch092 @ Github
#pragma once
#include "../AntiCheat.hpp"

using namespace std;

//API is exported dispatch routine needed for a game to initialize this anti-cheat class
namespace API
{
	enum DispatchCode
	{
		INITIALIZE,
		CLIENT_EXIT,
	};

	static bool serverAvailable = false; //change this to false if you don't want to use networking

	static bool isPostInitialization = false;

	static const char* ServerEndpoint = "127.0.0.1";
	static unsigned short ServerPort = 5445;
#ifdef _DEBUG
	static const wchar_t* whitelistedParentProcess = L"VsDebugConsole.exe"; //if debugging in VS, otherwise change to explorer.exe
#else
	static const wchar_t* whitelistedParentProcess = L"explorer.exe";
#endif

	Error Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerConnected);
	Error Cleanup(AntiCheat* AC);
	Error LaunchDefenses(AntiCheat* AC);
	
	Error __declspec(dllexport) Dispatch(AntiCheat* AC, DispatchCode code);
}


