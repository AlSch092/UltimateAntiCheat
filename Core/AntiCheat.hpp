//By AlSch092 @github
#pragma once

#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifndef _LIB_

#include "AntiCheatInitFail.hpp"
#include "Detections.hpp"
#include "Preventions.hpp"
#include "../Common/Logger.hpp"
#include "../Common/Settings.hpp"
#include "../AntiDebug/DebuggerDetections.hpp"

/*
	The `AntiCheat` class is a container for the necessary classes of our program, including the monitor, barrier, netclient, and anti-debugger
*/
class AntiCheat final
{
public:

	AntiCheat(__in Settings* config);
	~AntiCheat();

	Error Cleanup();
	Error FastCleanup(); //cleanup function for when we need to exit the program quickly

	Error Initialize(std::string licenseKey, bool isServerAvailable);
	bool DoPreInitializeChecks();
	Error LaunchDefenses();

	AntiCheat& operator=(AntiCheat&& other) = delete; //delete move assignments

	AntiCheat operator+(AntiCheat& other) = delete; //delete all arithmetic operators, unnecessary for context
	AntiCheat operator-(AntiCheat& other) = delete;
	AntiCheat operator*(AntiCheat& other) = delete;
	AntiCheat operator/(AntiCheat& other) = delete;

	DebuggerDetections* GetAntiDebugger() const { return this->AntiDebugger.get(); }
	
	weak_ptr<NetClient> GetNetworkClient() const  { return this->NetworkClient; }
	
	Preventions* GetBarrier() const  { return this->Barrier.get(); }  //pointer lifetime stays within the Anticheat class, these 'Get' functions should only be used to call functions of these classes
	
	Detections* GetMonitor() const { return this->Monitor.get(); }

	Settings* GetConfig() const { return this->Config; }

	bool IsAnyThreadSuspended();

private:

	unique_ptr<Detections> Monitor = nullptr;  //cheat detections

	unique_ptr<Preventions> Barrier = nullptr;  //cheat preventions

	unique_ptr<DebuggerDetections> AntiDebugger = nullptr;

	shared_ptr <NetClient> NetworkClient = nullptr; //for client-server comms, our other classes need access to this to send detected flags to the server
	
	Settings* Config = nullptr; //the unique_ptr for this is made in main.cpp

	WindowsVersion WinVersion = WindowsVersion::ErrorUnknown;
	
	EvidenceLocker* Evidence = nullptr;
};


#endif //_LIB_