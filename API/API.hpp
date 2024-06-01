//By AlSch092 @ Github
#pragma once
#include "../AntiCheat.hpp"

using namespace std;

//API class is the interface to work with the AntiCheat class from the game code
namespace API
{
	enum DispatchCode
	{
		INITIALIZE,
		CLIENT_EXIT,
	};

	static bool serverAvailable = true; //networking on/off switch

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
	
	Error __declspec(dllexport) Dispatch(AntiCheat* AC, DispatchCode code); //incase the user wants to build as a .dll, we export this routine to expose the AntiCheat class to a host game process
}


