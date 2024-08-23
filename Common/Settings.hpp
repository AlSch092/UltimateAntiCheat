//By AlSch092 @ Github, part of UltimateAntiCheat project
#pragma once
#include <memory>

//singleton settings class
//Settings don't come in a .ini or .cfg file as we don't want end-users modifying program flow on compiled releases
class Settings
{
public:

	static Settings& GetInstance(bool bEnforceSecureBoot, bool bEnforceDSE, bool bEnforceNoKDbg, bool bUseAntiDebugging, bool bCheckIntegrity, bool bCheckThreads, bool bCheckHypervisor)
	{
		if (!Instance)
		{
			Instance = std::unique_ptr<Settings>(new Settings(bEnforceSecureBoot, bEnforceDSE, bEnforceNoKDbg, bUseAntiDebugging, bCheckIntegrity, bCheckThreads, bCheckHypervisor));
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

	//more settings options will be added soon...

private:

	Settings(bool bEnforceSecureBoot, bool bEnforceDSE, bool bEnforceNoKDbg, bool bUseAntiDebugging, bool bCheckIntegrity, bool bCheckThreads, bool bCheckHypervisor) : bEnforceSecureBoot(bEnforceSecureBoot), bEnforceDSE(bEnforceDSE), bEnforceNoKDbg(bEnforceNoKDbg), bUseAntiDebugging(bUseAntiDebugging), bCheckIntegrity(bCheckIntegrity), bCheckThreads(bCheckThreads), bCheckHypervisor(bCheckHypervisor)
	{
	}

	static std::unique_ptr<Settings> Instance;
};