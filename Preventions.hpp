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

class Preventions final
{
public:

	Preventions(shared_ptr<Settings> config, bool preventingThreads, shared_ptr<Integrity> integrityChecker) : IsPreventingThreadCreation(preventingThreads), integrityChecker(integrityChecker), Config(config)
	{
	}

	Preventions(Preventions&&) = delete;  //delete move constructr
	Preventions& operator=(Preventions&&) noexcept = default; //delete move assignment operator

	Preventions(const Preventions&) = delete; //delete copy constructor 
	Preventions& operator=(const Preventions&) = delete; //delete assignment operator

	Preventions operator+(Preventions& other) = delete; //delete all arithmetic operators, unnecessary for context
	Preventions operator-(Preventions& other) = delete;
	Preventions operator*(Preventions& other) = delete;
	Preventions operator/(Preventions& other) = delete;

	void SetThreadCreationPrevention(bool onoff) { this->IsPreventingThreadCreation = onoff; }
	bool IsPreventingThreads() const { return this->IsPreventingThreadCreation; }

	Error DeployBarrier(); //activate all protections

	static bool RemapProgramSections();
	static bool PreventDllInjection(); //experimental, gives warning messagebox
	static bool PreventShellcodeThreads(); //experimental, gives warning messagebox
	static bool StopAPCInjection(); //patch over ntdll.Ordinal8

#if _WIN32_WINNT >= 0x0602
	static void EnableProcessMitigations(bool useDEP, bool useASLR, bool useDynamicCode, bool useStrictHandles, bool useSystemCallDisable); //interesting technique which uses the loader & system to block certain types of attacks, such as unsigned modules being injected
#endif

	static BYTE* SpoofPEB(); //not advisable to use this currently

	static bool StopMultipleProcessInstances(); //stop multi-boxing via shared memory

	bool RandomizeModuleName();

private:

	bool IsPreventingThreadCreation; //used in TLS callback if we want to supress or track new threads

	shared_ptr<Integrity> integrityChecker = nullptr;

	shared_ptr<Settings> Config = nullptr;
};