#pragma once
#include "../AntiCheat.hpp"

using namespace std;

//API is exported dispatch routine needed for a game to initialize this anti-cheat program
namespace API
{
	enum DispatchCode
	{
		INITIALIZE,
		FAILED_INITIALIZE,
		CLIENT_EXIT,
		CLIENT_DISCONNECT,
		HEARTBEAT,
	};

	static bool isPostInitialization = false;

	static const char* ServerEndpoint = "127.0.0.1";
	static unsigned short ServerPort = 5445;
	
	static const wchar_t* whitelistedParentProcess = L"explorer.exe"; //change to VsDebugConsole.exe if you're debugging in VS

	int Initialize(AntiCheat* AC, string licenseKey, wstring parentProcessName, bool isServerConnected);
	int LaunchBasicTests(AntiCheat* AC);
	
	int SendHeartbeat(AntiCheat* AC);
	
	int __declspec(dllexport) Dispatch(AntiCheat* AC, DispatchCode code);
}


