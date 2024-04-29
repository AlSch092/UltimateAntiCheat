//By AlSch092 @github
#pragma once

#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#include "Network/NetClient.hpp"
#include "Detections.hpp"
#include "Preventions.hpp"
#include "Logger.hpp"

class AntiCheat
{
public:

	AntiCheat()
	{	
		_AntiDebugger = new Debugger::AntiDebug();
		Monitor = new Detections(false);
		Barrier = new Preventions();
		Client = new NetClient();
	}

	~AntiCheat()
	{
		delete Monitor;
		delete Barrier;
		delete _AntiDebugger;
		delete Client;
	}

	Debugger::AntiDebug* GetAntiDebugger() { return this->_AntiDebugger; }
	NetClient* GetNetworkClient() { return this->Client; }
	Preventions* GetBarrier() { return this->Barrier;  }
	Detections* GetMonitor() { return this->Monitor; }

private:

	Detections* Monitor = NULL;
	Preventions* Barrier = NULL;
	Debugger::AntiDebug* _AntiDebugger = NULL;

	NetClient* Client = NULL;
};