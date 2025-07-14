//By AlSch092 @github
#pragma once
#include "Process/Process.hpp"
#include "AntiTamper/remap.hpp"
#include "Common/Error.hpp"
#include "Common/Utility.hpp"
#include "Common/Settings.hpp"
#include "AntiTamper/Integrity.hpp"

class Preventions final
{
public:

	Preventions(__in Settings* config, __in bool preventingThreads, __in shared_ptr<Integrity> integrityChecker) : IsPreventingThreadCreation(preventingThreads), integrityChecker(integrityChecker), Config(config)
	{
	}

	~Preventions() = default;

	Preventions(Preventions&&) = delete;  //delete move constructr
	Preventions& operator=(Preventions&&) noexcept = default; //delete move assignment operator

	Preventions(const Preventions&) = delete; //delete copy constructor 
	Preventions& operator=(const Preventions&) = delete; //delete assignment operator

	Preventions operator+(Preventions& other) = delete; //delete all arithmetic operators, unnecessary for context
	Preventions operator-(Preventions& other) = delete;
	Preventions operator*(Preventions& other) = delete;
	Preventions operator/(Preventions& other) = delete;

	void SetThreadCreationPrevention(__in const bool onoff) { this->IsPreventingThreadCreation = onoff; }
	bool IsPreventingThreads() const { return this->IsPreventingThreadCreation; }

	Error DeployBarrier(); //activate all protections

	static bool RemapProgramSections();

	static bool StopAPCInjection(); //patch over ntdll.Ordinal8

#if _WIN32_WINNT >= 0x0602
	static void EnableProcessMitigations(__in const bool useDEP, __in const bool useASLR, __in const bool useDynamicCode, __in const bool useStrictHandles, __in const  bool useSystemCallDisable); //interesting technique which uses the loader & system to block certain types of attacks, such as unsigned modules being injected
#endif

	static bool StopMultipleProcessInstances(); //stop multi-boxing via shared memory

	bool RandomizeModuleName();

	static void UnloadBlacklistedDrivers(__in const list<wstring> driverPaths);

private:

	bool IsPreventingThreadCreation = false; //used in TLS callback if we want to supress or track new threads

	shared_ptr<Integrity> integrityChecker = nullptr;

	Settings* Config = nullptr;
};