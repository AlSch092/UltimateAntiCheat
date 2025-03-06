//By AlSch092 @github
#pragma once
#include "Network/NetClient.hpp" //Net Comms
#include "Network/HttpClient.hpp"
#include "AntiDebug/DebuggerDetections.hpp"
#include "AntiTamper/Integrity.hpp" //Code Integrity
#include "Environment/Services.hpp" //`Services` class
#include "Obscure/Obfuscation.hpp" //`ObfuscatedData` class
#include "Common/DetectionFlags.hpp"
#include "Obscure/ntldr.hpp" //dll notification structures
#include <Wbemidl.h> //for process event creation (WMI)
#include <comdef.h>  //for process event creation (WMI)
#include <queue>

#pragma comment(lib, "wbemuuid.lib")  //for process event creation (WMI)

struct BytePattern //byte pattern used in process creation callbacks
{
	vector<BYTE> data;
	size_t size;

	BytePattern(vector<BYTE> d, size_t s) : data(d), size(s) {}
};

/*
	The detections class contains a set of static functions to help detect fragments of cheating, along with a thread for looping detections and a thread for process creation events
*/
class Detections final
{
public:

	Detections(Settings* s, BOOL StartMonitor, shared_ptr<NetClient> client);
	~Detections();

	Detections(Detections&&) = delete;  //delete move constructr
	Detections& operator=(Detections&&) noexcept = default; //delete move assignment operator

	Detections(const Detections&) = delete; //delete copy constructor 
	Detections& operator=(const Detections&) = delete; //delete assignment operator

	Detections operator+(Detections& other) = delete; //delete all arithmetic operators, unnecessary for context
	Detections operator-(Detections& other) = delete;
	Detections operator*(Detections& other) = delete;
	Detections operator/(Detections& other) = delete;

	weak_ptr<NetClient> GetNetClient() { return this->netClient; }

	Services* GetServiceManager() const { return this->_Services.get(); }

	shared_ptr<Integrity> GetIntegrityChecker() const { return this->integrityChecker; }

	void SetCheater(__in const bool cheating) { this->CheaterWasDetected->SetData((uint8_t)cheating); } //obfuscated bool/int variable. cast to uint8 to avoid getting stuck as 0/1 by compilers bool interpretation
	bool IsUserCheater() const  { return this->CheaterWasDetected->GetData(); }

	list<DetectionFlags> GetDetectedFlags() const { return this->DetectedFlags; }

	bool SetSectionHash(__in const char* module, __in const char* sectionName);
	bool IsSectionHashUnmatching(__in const UINT64 cachedAddress, __in const DWORD cachedSize, __in const string section);

	Thread* GetMonitorThread() const { return this->MonitorThread; }
	Thread* GetProcessCreationMonitorThread() const { return this->ProcessCreationMonitorThread; }
	Thread* GetRegistryMonitorThread() const { return this->RegistryMonitorThread; }

	Process* GetProcessObj() const { return this->_Proc.get(); }  //other classes should not be able to set the process object, it is created by default in the constructor

	bool IsBlacklistedProcessRunning() const;

	static bool DoesFunctionAppearHooked(__in const char* moduleName, __in const char* functionName); //checks for jumps or calls as the first byte on a function
	
	static bool DoesIATContainHooked(); //check IAT for hooks
	
	static UINT64 IsTextSectionWritable(); //check all pages in .text section of image module for writable pages (after remapping, our .text section should only have RX protected pages)
	
	static bool CheckOpenHandles(); //detect any open handles to our process, very useful since this will detect most external cheats
	
	bool IsBlacklistedWindowPresent();

	bool AddDetectedFlag(__in const DetectionFlags f); //add to DetectedFlags without duplicates
	bool Flag(__in const DetectionFlags flag); //sets `IsCheater` to true, notifies server component of detected flag

	static VOID OnDllNotification(ULONG NotificationReason, const PLDR_DLL_NOTIFICATION_DATA NotificationData, PVOID Context); //dll load callback

	bool StartMonitor(); //begin threading
	static void Monitor(__in LPVOID thisPtr); //loop detections/monitor -> thread function

	bool FindBlacklistedProgramsThroughByteScan(__in const DWORD pid); //scan array of bytes in suspected bad actor processes

	static void MonitorImportantRegistryKeys(__in LPVOID thisPtr); //threaded func, pass this class ptr to it

	static vector<uint64_t> DetectManualMapping();

	static bool WasProcessNotRemapped(); //detect if someone prevented section remapping. could possibly go into Integrity class

	void SetUnsignedLoadedDriversList(list<wstring> unsignedDrivers) { this->UnsignedDriversLoaded = unsignedDrivers; }
	list<wstring> GetUnsignedLoadedDriversList() const { return this->UnsignedDriversLoaded; }

	Settings* GetConfig() const { return this->Config; }

private:

	Settings* Config = nullptr; //non-owning pointer to the original unique_ptr<Settings> in main.cpp

	PVOID DllCallbackRegistrationCookie = nullptr; //for dll notifications

	void InitializeBlacklistedProcessesList();

	static void MonitorProcessCreation(__in LPVOID thisPtr);

	bool MonitoringProcessCreation = false;

	unique_ptr<ObfuscatedData<uint8_t>> CheaterWasDetected = nullptr; //using bool as the type does not work properly with obfuscation since the compiler uses true/false, so use uint8_t instead and cast to BOOL when needed

	unique_ptr<Services> _Services = nullptr;

	shared_ptr<Integrity> integrityChecker = nullptr;
	shared_ptr<NetClient> netClient; //send any detections to the server

	Thread* MonitorThread = nullptr; //these should ideally be unique_ptrs which end the thread when the pointers go out of scope, will try to make these changes soon
	Thread* ProcessCreationMonitorThread = nullptr;
	Thread* RegistryMonitorThread = nullptr;

	list<wstring> BlacklistedProcesses;
	list<BytePattern> BlacklistedBytePatterns;

	unique_ptr<Process> _Proc = nullptr; //keep track of our sections, loaded modules, etc using a managed class

	list<DetectionFlags> DetectedFlags;

	bool FetchBlacklistedBytePatterns(__in const char* url);
	const char* BlacklisteBytePatternRepository = "https://raw.githubusercontent.com/AlSch092/UltimateAntiCheat/refs/heads/main/MiscFiles/BlacklistedBytePatternList.txt";

	void CheckDLLSignature(); //process cert check queue for any newly loaded dlls

	queue<wstring> DLLVerificationQueue;
	mutex DLLVerificationQueueMutex;

	list<wstring> UnsignedModulesLoaded; //keep track of any unsigned modules
	list<wstring> UnsignedDriversLoaded; //...and any unsigned drivers

	list<wstring> PassedCertCheckDrivers; //already checked, keep track so we don't have to re-verify them each time
	list<wstring> PassedCertCheckModules;
};