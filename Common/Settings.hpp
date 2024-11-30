//By AlSch092 @ Github, part of UltimateAntiCheat project
#pragma once
#include <memory>

//Settings don't come in a .ini or .cfg file as we don't want end-users modifying program flow on compiled releases
class Settings final
{
public:

	static Settings& GetInstance(
		bool bNetworkingEnabled, 
		bool bEnforceSecureBoot,
		bool bEnforceDSE,
		bool bEnforceNoKDbg,
		bool bUseAntiDebugging,
		bool bCheckIntegrity,
		bool bCheckThreads,
		bool bCheckHypervisor, 
		bool bRequireRunAsAdministrator,
		bool bUsingDriver)
	{
		if (!Instance)
		{
			Instance = std::unique_ptr<Settings>(new Settings(
				bNetworkingEnabled, 
				bEnforceSecureBoot, 
				bEnforceDSE, 
				bEnforceNoKDbg, 
				bUseAntiDebugging, 
				bCheckIntegrity, 
				bCheckThreads, 
				bCheckHypervisor, 
				bRequireRunAsAdministrator,
				bUsingDriver));
		}

		return *Instance;
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
	bool bUsingDriver; //signed kernelmode driver for hybrid approach

	wstring GetKMDriverName() const { return this->KMDriverName; }
	wstring GetKMDriverPath() const { return this->KMDriverPath; }

private:

	Settings(
		bool bNetworkingEnabled, 
		bool bEnforceSecureBoot, 
		bool bEnforceDSE, 
		bool bEnforceNoKDbg, 
		bool bUseAntiDebugging,
		bool bCheckIntegrity,
		bool bCheckThreads,
		bool bCheckHypervisor, 
		bool bRequireRunAsAdministrator,
		bool bUsingDriver)
		: bNetworkingEnabled(bNetworkingEnabled), bEnforceSecureBoot(bEnforceSecureBoot), bEnforceDSE(bEnforceDSE), bEnforceNoKDbg(bEnforceNoKDbg), bUseAntiDebugging(bUseAntiDebugging), bCheckIntegrity(bCheckIntegrity), bCheckThreads(bCheckThreads), bCheckHypervisor(bCheckHypervisor), bRequireRunAsAdministrator(bRequireRunAsAdministrator), bUsingDriver(bUsingDriver)
	{
	}
	 
	const wstring KMDriverName = L"UltimateKernelAnticheat"; //optional hybrid approach
	const wstring KMDriverPath = L".\\UltimateKernelAnticheat.sys"; 

	static std::unique_ptr<Settings> Instance; //singleton-style, one unique instance
}; 