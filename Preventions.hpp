//By AlSch092 @github
#pragma once
#include "Process/Process.hpp"
#include "Process/Exports.hpp" 
#include "AntiTamper/remap.hpp"
#include "Obscure/Obfuscation.hpp"
#include "Common/Error.hpp"
#include "Common/Utility.hpp"
#include "Common/Globals.hpp"
#include "Common/Settings.hpp"
#include "AntiTamper/Integrity.hpp"

class Preventions
{
public:

	Preventions(Settings* config, bool preventingThreads, shared_ptr<Integrity> integrityChecker)
	{
		this->IsPreventingThreadCreation = preventingThreads;
		this->integrityChecker = integrityChecker;
	}

	Error DeployBarrier(); //activate all protections

	static bool RemapProgramSections();
	static bool PreventDllInjection(); //experimental, gives warning popup
	static bool PreventShellcodeThreads(); //experimental, gives warning popup
	static bool StopAPCInjection();

#if _WIN32_WINNT >= 0x0602
	static void EnableProcessMitigations(bool useDEP, bool useASLR, bool useDynamicCode, bool useStrictHandles, bool useSystemCallDisable); //interesting technique which uses the loader & system to block certain types of attacks, such as unsigned modules being injected
#endif

	static BYTE* SpoofPEB(); //not advisable to use this currently

	static bool StopMultipleProcessInstances(); //stop multi-boxing via shared memory

	void SetErrorCode(Error err) { this->LastError = err; }
	Error GetErrorCode() { return this->LastError; }

	void SetThreadCreationPrevention(bool onoff) { this->IsPreventingThreadCreation = onoff; }
	bool IsPreventingThreads() { return this->IsPreventingThreadCreation; }

	bool RandomizeModuleName(); //uses OriginalModuleName param

private:
	Error LastError = Error::OK;

	const wstring OriginalModuleName = L"UltimateAnticheat.exe";

	bool IsPreventingThreadCreation; //used in TLS callback if we want to supress or track new threads

	shared_ptr<Integrity> integrityChecker = nullptr;

	Settings* Config = nullptr;
};