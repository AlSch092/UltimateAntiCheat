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
#include "AntiCheatInitFail.hpp"
#include "AntiDebug/DebuggerDetections.hpp"
#include "API/API.hpp"

/*
	The `AntiCheat` class is a container for the necessary classes of our program, including the monitor, barrier, netclient, and anti-debugger
*/
class AntiCheat final
{
public:

	AntiCheat(__in Settings* config, __in const WindowsVersion WinVersion);
	~AntiCheat();

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

	bool DoPreInitializeChecks();

private:

	unique_ptr<Detections> Monitor;  //cheat detections

	unique_ptr<Preventions> Barrier;  //cheat preventions

	unique_ptr<DebuggerDetections> AntiDebugger;

	shared_ptr <NetClient> NetworkClient; //for client-server comms, our other classes need access to this to send detected flags to the server
	
	Settings* Config = nullptr; //the unique_ptr for this is made in main.cpp

	WindowsVersion WinVersion;

	const wstring DriverSignerSubject = L"YourCoolCompany";  //this refers to the company/party who initiated the file signing, for example "Valve Corp.". If you have an EV certificate, you can change this to your own company

	EvidenceLocker* Evidence = nullptr;
};
