//By AlSch092 @github
#pragma once
#include "Process/Process.hpp"
#include "Process/Exports.hpp" 
#include "AntiTamper/remap.hpp"
#include "Obscure/Obfuscation.hpp"
#include "Obscure/SymbolicHash.hpp"
#include "Common/Error.hpp"
#include "Common/Utility.hpp"

class Preventions
{
public:

	Preventions()
	{
		_Proc = new Process();
		IsPreventingThreadCreation = true;
	}

	~Preventions()
	{
		delete _Proc;
	}

	Error DeployBarrier(); //activate all protections

	static bool RemapAndCheckPages();
	static bool PreventDllInjection();
	bool ChangeModuleName();
	static BYTE* SpoofPEB();

	Process* GetProcessObject() { return this->_Proc; }

	bool IsPreventingThreadCreation = false; //used in TLS callback if we want to supress or track new threads

	void SetErrorCode(Error err) { this->LastError = err; }
	Error GetErrorCode() { return this->LastError; }

private:
	Process* _Proc = NULL;

	Error LastError = Error::OK;

	const wstring OriginalModuleName = L"UltimateAnticheat.exe";
};