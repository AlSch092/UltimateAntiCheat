#pragma once
#include "AntiCheat.hpp"
//API is exported routines needed for a game to initialize this anti-cheat program

using namespace std;

extern AntiCheat* g_AC;

namespace API
{
	enum DispatchCode //Codes which the game/process might send to us. communication is one-way
	{
		FAILED_INITIALIZE,
		CLIENT_EXIT,
		CLIENT_DISCONNECT,
		HEARTBEAT,
	};

	int __declspec(dllexport) Initialize(string licenseKey);
	int __declspec(dllexport) Dispatch(DispatchCode code, int reason);
}
