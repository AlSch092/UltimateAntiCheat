//By AlSch092 @github
#pragma once
#include "Network/NetClient.hpp" //Net Comms
#include "AntiDebug/DebuggerDetections.hpp"
#include "AntiTamper/Integrity.hpp" //Code Integrity
#include "Environment/Services.hpp" //`Services` class
#include "Obscure/Obfuscation.hpp" //`ObfuscatedData` class
#include "Common/Globals.hpp" //`UnmanagedGlobals` namespace
#include "Obscure/ntldr.hpp" //dll notification structures
#include <Wbemidl.h> //for process event creation (WMI)
#include <comdef.h>  //for process event creation (WMI)

#pragma comment(lib, "wbemuuid.lib")  //for process event creation (WMI)

/*
	The detections class contains a set of static functions to help detect fragments of cheating, along with a thread for looping detections and a thread for process creation events
*/
class Detections final
{
public:

	Detections(Settings* s, BOOL StartMonitor, shared_ptr<NetClient> client, vector<ProcessData::MODULE_DATA>* currentModules) : Config(s), netClient(client)
	{
		this->InitializeBlacklistedProcessesList();

		MonitoringProcessCreation = false; //gets set to true inside `MonitorProcessCreation`

		try 
		{
			_Proc = make_unique<Process>(EXPECTED_SECTIONS);
			_Services = make_unique<Services>(false);
			integrityChecker = make_shared<Integrity>(currentModules);
		}
		catch (const std::bad_alloc& e) 
		{
			Logger::logf("UltimateAnticheat.log", Err, "One or more pointers could not be allocated @ Detections::Detections: %s", e.what());
			std::terminate();
		}
	
		this->CheaterWasDetected = new ObfuscatedData<uint8_t>((bool)false); //using 'bool' as the templated type will force values to 0/1 by the compiler when we need to xor them to other values

		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

		if (hNtdll != 0) //register DLL notifications callback 
		{
			_LdrRegisterDllNotification pLdrRegisterDllNotification = (_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
			PVOID cookie;
			NTSTATUS status = pLdrRegisterDllNotification(0, (PLDR_DLL_NOTIFICATION_FUNCTION)OnDllNotification, this, &cookie);
		}

		if (StartMonitor)
			this->StartMonitor();

		ProcessCreationMonitorThread = new Thread((LPTHREAD_START_ROUTINE)Detections::MonitorProcessCreation, this, true);
	}

	~Detections()
	{
		if (MonitorThread != NULL)
			delete MonitorThread;
	}

	Detections(Detections&&) = delete;  //delete move constructr
	Detections& operator=(Detections&&) noexcept = default; //delete move assignment operator

	Detections(const Detections&) = delete; //delete copy constructor 
	Detections& operator=(const Detections&) = delete; //delete assignment operator

	Detections operator+(Detections& other) = delete; //delete all arithmetic operators, unnecessary for context
	Detections operator-(Detections& other) = delete;
	Detections operator*(Detections& other) = delete;
	Detections operator/(Detections& other) = delete;

	NetClient* GetNetClient() { return this->netClient.get(); }

	Settings* GetSettings() const { return this->Config; }

	Services* GetServiceManager() const { return this->_Services.get(); }

	shared_ptr<Integrity> GetIntegrityChecker() const { return this->integrityChecker; }

	void SetCheater(BOOL cheating) { this->CheaterWasDetected->SetData((uint8_t)cheating); } //obfuscated bool/int variable. cast to uint8 to avoid getting stuck as 0/1 by compilers bool interpretation
	BOOL IsUserCheater() const  { return this->CheaterWasDetected->GetData(); }

	list<ProcessData::Section*>* SetSectionHash(const char* module, const char* sectionName);
	BOOL CheckSectionHash(UINT64 cachedAddress, DWORD cachedSize);

	Thread* GetMonitorThread() const { return this->MonitorThread; }

	Process* GetProcessObj() const { return this->_Proc.get(); }  //other classes should not be able to set the process object, it is created by default in the constructor

	BOOL IsBlacklistedProcessRunning() const;

	static BOOL DoesFunctionAppearHooked(const char* moduleName, const char* functionName); //checks for jumps or calls as the first byte on a function
	
	static BOOL DoesIATContainHooked(); //check IAT for hooks
	
	static UINT64 IsTextSectionWritable(); //check all pages in .text section of image module for writable pages (after remapping, our .text section should only have RX protected pages)
	
	static BOOL CheckOpenHandles(); //detect any open handles to our process, very useful since this will detect most external cheats
	
	BOOL IsBlacklistedWindowPresent();

	bool AddDetectedFlag(DetectionFlags f); //add to DetectedFlags without duplicates
	bool Flag(DetectionFlags flag); //sets `IsCheater` to true, notifies server component of detected flag

	static VOID OnDllNotification(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context);

	BOOL StartMonitor(); //begin threading
	static void Monitor(LPVOID thisPtr); //loop detections/monitor -> thread function

private:

	void InitializeBlacklistedProcessesList();

	static void MonitorProcessCreation(LPVOID thisPtr);

	bool MonitoringProcessCreation;

	ObfuscatedData<uint8_t>* CheaterWasDetected = NULL; //using bool as the type does not work properly with obfuscation since the compiler uses true/false, so use uint8_t instead and cast to BOOL when needed

	unique_ptr<Services> _Services = NULL; 
	shared_ptr<Integrity> integrityChecker = NULL;
	shared_ptr<NetClient> netClient; //send any detections to the server

	Thread* MonitorThread = NULL; //these should ideally be unique_ptrs which end the thread when the pointers go out of scope, will make these changes soon
	Thread* ProcessCreationMonitorThread = NULL;

	list<wstring> BlacklistedProcesses;

	unique_ptr<Process> _Proc = nullptr; //keep track of our sections, loaded modules, etc using a managed class

	Settings* Config; //non-owning pointer to the original unique_ptr<Settings> in main.cpp

	list<DetectionFlags> DetectedFlags;
};