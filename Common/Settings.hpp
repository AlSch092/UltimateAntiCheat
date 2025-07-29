//By AlSch092 @ Github, part of UltimateAntiCheat project
#pragma once
#include <memory>
#include <list>
#include "Logger.hpp" //to access static variables `Logger::enableLogging `, `Logger::logFileName`

using namespace std;

//Settings don't come in a .ini or .cfg file as we don't want end-users modifying program flow on compiled releases
class Settings final
{
public:

	static Settings* CreateInstance(
		const std::string serverIP,
		uint16_t serverPort,
		const bool bNetworkingEnabled,
		const bool bEnforceSecureBoot,
		const bool bEnforceDSE,
		const bool bEnforceNoKDbg,
		const bool bUseAntiDebugging,
		const bool bCheckIntegrity,
		const bool bCheckThreads,
		const bool bCheckHypervisor,
		const bool bRequireRunAsAdministrator,
		const bool bUsingDriver,
		const std::wstring DriverSignerSubject,
		const list<wstring> allowedParents,
		const bool enableLogging,
		const string logFileName)
	{
		if (!Instance)
		{
			Instance = new Settings(
				serverIP,
				serverPort,
				bNetworkingEnabled, 
				bEnforceSecureBoot, 
				bEnforceDSE, 
				bEnforceNoKDbg, 
				bUseAntiDebugging, 
				bCheckIntegrity, 
				bCheckThreads, 
				bCheckHypervisor, 
				bRequireRunAsAdministrator,
				bUsingDriver,
				DriverSignerSubject,
				allowedParents,
				enableLogging,
				logFileName
			);
		}

		return Instance;
	}

	Settings(const Settings&) = delete; //prevent copying
	Settings& operator=(const Settings&) = delete;

	std::string serverIP;
	unsigned short serverPort = 5445; //default port for the server, can be changed in the Settings constructor

	bool bEnforceSecureBoot;
	bool bEnforceDSE;
	bool bEnforceNoKDbg;
	bool bCheckHypervisor;
	bool bUseAntiDebugging;
	bool bCheckIntegrity;
	bool bCheckThreads;
	bool bRequireRunAsAdministrator;

	bool bNetworkingEnabled;
	
	bool bUsingDriver; //signed + msft approved kernelmode driver for hybrid approach
	std::wstring DriverSignerSubject;  //this refers to the company/party who initiated the file signing, for example "Valve Corp.". If you have an EV certificate, you can change this to your own company

	list<wstring> allowedParents;
	
	bool bEnableLogging;
	string logFileName;

	wstring GetKMDriverName() const { return this->KMDriverName; }
	wstring GetKMDriverPath() const { return this->KMDriverPath; }
	wstring GetKMDriverSignee() const { return this->KMDriverSignee; }

	Settings(
		const std::string serverIP,
		uint16_t serverPort,
		const bool bNetworkingEnabled,
		const bool bEnforceSecureBoot,
		const bool bEnforceDSE,
		const bool bEnforceNoKDbg,
		const bool bUseAntiDebugging,
		const bool bCheckIntegrity,
		const bool bCheckThreads,
		const bool bCheckHypervisor,
		const bool bRequireRunAsAdministrator,
		const bool bUsingDriver,
		const std::wstring DriverSignerSubject,
		list<wstring> allowedParents,
		const bool bEnableLogging,
		const string logFileName)
		: serverIP(serverIP), serverPort(serverPort), bNetworkingEnabled(bNetworkingEnabled), bEnforceSecureBoot(bEnforceSecureBoot), bEnforceDSE(bEnforceDSE), 
		  bEnforceNoKDbg(bEnforceNoKDbg), bUseAntiDebugging(bUseAntiDebugging), bCheckIntegrity(bCheckIntegrity), bCheckThreads(bCheckThreads), bCheckHypervisor(bCheckHypervisor), 
		  bRequireRunAsAdministrator(bRequireRunAsAdministrator), bUsingDriver(bUsingDriver), DriverSignerSubject(DriverSignerSubject), allowedParents(allowedParents), bEnableLogging(bEnableLogging), logFileName(logFileName)
	{
		if (Instance != nullptr) //since we can't use a private constructor with ProtectedMemory class, we need to check if the instance is already created
		{
			throw runtime_error("The Settings object instance already exists!");
		}

		Logger::enableLogging = bEnableLogging; //put this line here to be as early as possible.
		Logger::logFileName = logFileName;
	}
	 
	static Settings* Instance; //singleton-style instance

private:
	const wstring KMDriverName = L"UltimateKernelAnticheat"; //optional hybrid approach
	const wstring KMDriverPath = L".\\UltimateKernelAnticheat.sys"; 
	const wstring KMDriverSignee = L"YourCoolCompany Ltd.";
}; 