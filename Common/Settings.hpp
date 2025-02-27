//By AlSch092 @ Github, part of UltimateAntiCheat project
#pragma once
#include <memory>
#include "Logger.hpp" //to access static variables `Logger::enableLogging `, `Logger::logFileName`

using namespace std;

//Settings don't come in a .ini or .cfg file as we don't want end-users modifying program flow on compiled releases
class Settings final
{
public:

	static Settings* CreateInstance(
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
		const list<wstring> allowedParents,
		const bool enableLogging,
		const string logFileName)
	{
		if (!Instance)
		{
			Instance = new Settings(
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
				allowedParents,
				enableLogging,
				logFileName
			);
		}

		return Instance;
	}

	Settings(const Settings&) = delete; //prevent copying
	Settings& operator=(const Settings&) = delete;

	bool bEnforceSecureBoot;
	bool bEnforceDSE;
	bool bEnforceNoKDbg;
	bool bCheckHypervisor;
	bool bUseAntiDebugging;
	bool bCheckIntegrity;
	bool bCheckThreads;
	bool bRequireRunAsAdministrator;

	bool bNetworkingEnabled; //previously in API.hpp
	bool bUsingDriver; //signed + msft approved kernelmode driver for hybrid approach
	list<wstring> allowedParents;
	
	bool enableLogging;
	string logFileName;

	wstring GetKMDriverName() const { return this->KMDriverName; }
	wstring GetKMDriverPath() const { return this->KMDriverPath; }
	wstring GetKMDriverSignee() const { return this->KMDriverSignee; }

	Settings(
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
		const list<wstring> allowedParents,
		const bool enableLogging,
		const string logFileName)
		: bNetworkingEnabled(bNetworkingEnabled), bEnforceSecureBoot(bEnforceSecureBoot), bEnforceDSE(bEnforceDSE), bEnforceNoKDbg(bEnforceNoKDbg), bUseAntiDebugging(bUseAntiDebugging), bCheckIntegrity(bCheckIntegrity), bCheckThreads(bCheckThreads), bCheckHypervisor(bCheckHypervisor), bRequireRunAsAdministrator(bRequireRunAsAdministrator), bUsingDriver(bUsingDriver), allowedParents(allowedParents), enableLogging(enableLogging), logFileName(logFileName)
	{
		if (Instance != nullptr) //since we can't use a private constructor with ProtectedMemory class, we need to check if the instance is already created
		{
			throw runtime_error("The Settings object instance already exists!");
		}

		Logger::enableLogging = enableLogging; //put this line here to be as early as possible.
		Logger::logFileName = logFileName;
	}
	 
	static Settings* Instance; //singleton-style instance

private:
	const wstring KMDriverName = L"UltimateKernelAnticheat"; //optional hybrid approach
	const wstring KMDriverPath = L".\\UltimateKernelAnticheat.sys"; 
	const wstring KMDriverSignee = L"YourCoolCompany Ltd.";


}; 