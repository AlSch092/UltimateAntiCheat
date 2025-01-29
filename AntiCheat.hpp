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

/*
	The `AntiCheat` class is a container for the necessary classes of our program, including the monitor, barrier, netclient, and anti-debugger
*/
class AntiCheat final
{
public:

	AntiCheat(shared_ptr<Settings> config, WindowsVersion WinVersion) : Config(config), WinVersion(WinVersion)
	{		
		if (config == nullptr)
		{
			Logger::logf("UltimateAnticheat.log", Err, "Settings pointer was NULL @ AntiCheat::AntiCheat");
			return;
		}
		
		try
		{
			this->NetworkClient = make_shared<NetClient>();

			this->AntiDebugger = make_unique<DebuggerDetections>(config, NetworkClient); //any detection methods need the netclient for comms

			this->Monitor = make_unique<Detections>(config, false, NetworkClient, UnmanagedGlobals::ModulesAtStartup);

			this->Barrier = make_unique<Preventions>(config, true, Monitor.get()->GetIntegrityChecker()); //true = prevent new threads from being made
		}
		catch (const std::bad_alloc& e)
		{
			Logger::logf("UltimateAnticheat.log", Err, "Critical allocation failure in AntiCheat::AntiCheat: %s", e.what());
			std::terminate();  //do not allow proceed if any pointers fail to alloc
		}

		if (config->bUsingDriver) //register + load the driver using the "sc" command, unload it when the program exits
		{
			//additionally, we need to check the signature on our driver to make sure someone isn't spoofing it. this will be added soon after initial testing is done

			wchar_t absolutePath[MAX_PATH] = { 0 };
			
			if (!GetFullPathName(Config->GetKMDriverPath().c_str(), MAX_PATH, absolutePath, nullptr))
			{
				Logger::logf("UltimateAnticheat.log", Err, "Could not get absolute path from driver relative path, shutting down.");
				std::terminate();  //do not allow proceed since config is set to using driver
			}
				
			if (!Services::LoadDriver(Config->GetKMDriverName().c_str(), absolutePath))
			{
				Logger::logf("UltimateAnticheat.log", Err, "Could not get load the driver, shutting down.");
				std::terminate();  //do not allow to proceed since config is set to using driver
			}

			Logger::logfw("UltimateAnticheat.log", Info, L"Loaded driver: %s from path %s", Config->GetKMDriverName().c_str(), absolutePath);
		}

	}

	~AntiCheat() //the destructor is now empty since all pointers of this class were recently switched to unique_ptrs
	{
		if (Config != nullptr && Config->bUsingDriver) //unload the KM driver
		{
			if (!Services::UnloadDriver(Config->GetKMDriverName()))
			{
				Logger::logf("UltimateAnticheat.log", Warning, "Failed to unload kernelmode driver!");
			}
		}	
	}

	AntiCheat& operator=(AntiCheat&& other) = delete; //delete move assignments

	AntiCheat operator+(AntiCheat& other) = delete; //delete all arithmetic operators, unnecessary for context
	AntiCheat operator-(AntiCheat& other) = delete;
	AntiCheat operator*(AntiCheat& other) = delete;
	AntiCheat operator/(AntiCheat& other) = delete;

	DebuggerDetections* GetAntiDebugger() const { return this->AntiDebugger.get(); }
	
	weak_ptr<NetClient> GetNetworkClient() const  { return this->NetworkClient; }
	
	Preventions* GetBarrier() const  { return this->Barrier.get(); }  //pointer lifetime stays within the Anticheat class, these 'Get' functions should only be used to call functions of these classes
	
	Detections* GetMonitor() const { return this->Monitor.get(); }

	Settings* GetConfig() const { return this->Config.get(); }

	__forceinline bool IsAnyThreadSuspended();

private:

	unique_ptr<Detections> Monitor;  //cheat detections

	unique_ptr<Preventions> Barrier;  //cheat preventions

	unique_ptr<DebuggerDetections> AntiDebugger;

	shared_ptr <NetClient> NetworkClient; //for client-server comms, our other classes need access to this to send detected flags to the server
	
	shared_ptr<Settings> Config; //the unique_ptr for this is made in main.cpp

	WindowsVersion WinVersion;
};

/*
	IsAnyThreadSuspended - Checks the looping threads of class members to ensure the program is running as normal. An attacker may try to suspend threads to either remap or disable functionalities
	returns true if any thread is found suspended
*/
__forceinline bool AntiCheat::IsAnyThreadSuspended()
{
	if (Monitor->GetMonitorThread()!= nullptr && Thread::IsThreadSuspended(Monitor->GetMonitorThread()->GetId()))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Monitor was found suspended! Abnormal program execution.");
		return true;
	}
	else if (Monitor->GetProcessCreationMonitorThread() != nullptr && Thread::IsThreadSuspended(Monitor->GetProcessCreationMonitorThread()->GetId()))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Monitor's process creation thread was found suspended! Abnormal program execution.");
		return true;
	}
	else if (Config->bUseAntiDebugging && AntiDebugger->GetDetectionThread() != nullptr && Thread::IsThreadSuspended(AntiDebugger->GetDetectionThread()->GetId()))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Anti-debugger was found suspended! Abnormal program execution.");
		return true;
	}
	else if (NetworkClient->GetRecvThread() != nullptr && Thread::IsThreadSuspended(NetworkClient->GetRecvThread()->GetId()))
	{
		Logger::logf("UltimateAnticheat.log", Detection, "Netclient comms thread was found suspended! Abnormal program execution.");
		return true;
	}

	return false;
}