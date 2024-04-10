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

	Process* GetProcessObject() { return this->_Proc; }

	bool IsPreventingThreadCreation = false; //used in TLS callback if we want to supress or track new threads

private:
	Process* _Proc = NULL;
};