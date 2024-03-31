//By AlSch092 @github
#pragma once
#include "Process/Process.hpp"
#include "Process/Exports.hpp" 
#include "Process/Memory/remap.hpp"
#include "Obscure/Obfuscation.hpp"
#include "Obscure/SymbolicHash.hpp"
#include "Common/Error.hpp"

class Preventions
{
public:

	Preventions()
	{
		_Proc = new Process();
	}

	~Preventions()
	{
		delete _Proc;
	}

	int DeployBarrier(); //activate all

	static bool RemapAndCheckPages();

	Process* GetProcessObject() { return this->_Proc; }

	bool IsPreventingThreadCreation = false; //used in TLS callback if we want to supress or track new threads

private:
	Process* _Proc = NULL;
};