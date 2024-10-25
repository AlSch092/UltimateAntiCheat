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
#include "Common/Logger.hpp"
#include "Common/Settings.hpp"
#include <memory>

/*
	The `AntiCheat` class is a container for the necessary classes of our program, including the monitor, barrier, netclient, and anti-debugger
*/
class AntiCheat
{
public:

	AntiCheat(Settings* config)
	{		
		if (config != nullptr)
		{
			this->Config = config;
		}
		else
		{
			Logger::logf("UltimateAnticheat.log", Err, "Settings pointer was NULL @ AntiCheat::AntiCheat");
			return;
		}

		this->NetworkClient = std::make_shared<NetClient>();

		this->_AntiDebugger = std::make_unique<Debugger::AntiDebug>(config, NetworkClient); //any detection methods need the netclient for comms

		this->Monitor = std::make_unique<Detections>(config, false, NetworkClient, UnmanagedGlobals::ModulesAtStartup);
		
		this->Barrier = std::make_unique<Preventions>(config, true, Monitor.get()->GetIntegrityChecker()); //true = prevent new threads from being made
	}

	~AntiCheat() //the destructor is now empty since all pointers of this class were recently switched to unique_ptrs
	{
	}

	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger.get(); }
	
	NetClient* GetNetworkClient() { return this->NetworkClient.get(); }
	
	Preventions* GetBarrier() { return this->Barrier.get();  }
	
	Detections* GetMonitor() { return this->Monitor.get(); }

	Settings* GetConfiguration() { return this->Config; }

	__forceinline bool IsAnyThreadSuspended();

private:

	std::unique_ptr<Detections> Monitor;  //cheat detections

	std::unique_ptr<Preventions> Barrier;  //cheat preventions

	std::unique_ptr<Debugger::AntiDebug> _AntiDebugger;

	std::shared_ptr <NetClient> NetworkClient; //for client-server comms, our other classes need access to this to send detected flags to the server
	
	Settings* Config = nullptr; //the unique_ptr for this is made in main.cpp
};

/*
	IsAnyThreadSuspended - Checks the looping threads of class members to ensure the program is running as normal. An attacker may try to suspend threads to either remap or disable functionalities
	returns true if any thread is found suspended
*/
__forceinline bool AntiCheat::IsAnyThreadSuspended()
{
	if (Thread::IsThreadSuspended(Monitor->GetMonitorThread()->handle))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Monitor was found suspended! Abnormal program execution.");
		return true;
	}
	else if (Thread::IsThreadSuspended(_AntiDebugger->GetDetectionThreadHandle()) && Config->bUseAntiDebugging)
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Anti-debugger was found suspended! Abnormal program execution.");
		return true;
	}
	else if (Thread::IsThreadSuspended(NetworkClient->GetRecvThread()->handle))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Netclient comms thread was found suspended! Abnormal program execution.");
		return true;
	}

	return false;
}
