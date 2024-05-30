//By AlSch092 @github
#pragma once

#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#include "Detections.hpp"
#include "Preventions.hpp"
#include "Logger.hpp"

/*
	The `AntiCheat` class is a container for the necessary classes of our program, including the monitor, barrier, netclient, and anti-debugger
*/
class AntiCheat
{
public:

	AntiCheat()
	{	
		_AntiDebugger = new Debugger::AntiDebug();
		
		Client = new NetClient();

		Monitor = new Detections(false, Client);
		
		Barrier = new Preventions(true); //true = prevent new threads from being made
	}

	~AntiCheat()
	{
		delete Monitor;
		delete Barrier;
		delete _AntiDebugger;
		delete Client;

		Monitor = nullptr;
		Barrier = nullptr;
		_AntiDebugger = nullptr;
		Client = nullptr;
	}

	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }
	NetClient* GetNetworkClient() { return this->Client; }
	Preventions* GetBarrier() { return this->Barrier;  }
	Detections* GetMonitor() { return this->Monitor; }

	/*
		IsAnyThreadSuspended - Checks the looping threads of class members to ensure the program is running as normal. An attacker may try to suspend threads to either remap or disable functionalities
		returns true if any thread is found suspended
	*/
	__forceinline bool IsAnyThreadSuspended()
	{
		if (Thread::IsThreadSuspended(Monitor->GetMonitorThread()->handle))
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Monitor was found suspended! Abnormal program execution.");
			return true;
		}
		else if (Thread::IsThreadSuspended(_AntiDebugger->GetDetectionThreadHandle()))
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Anti-debugger was found suspended! Abnormal program execution.");
			return true;
		}
		else if (Thread::IsThreadSuspended(Client->GetRecvThread()->handle))
		{
			Logger::logf("UltimateAnticheat.log", Detection, "Netclient comms thread was found suspended! Abnormal program execution.");
			return true;
		}

		return false;
	}

private:

	Detections* Monitor = nullptr; //cheat detections
	Preventions* Barrier = nullptr; //cheat preventions
	Debugger::AntiDebug* _AntiDebugger = nullptr;
	NetClient* Client = nullptr; //for client-server comms
};