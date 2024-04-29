#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Process/Process.hpp"
#include "NAuthenticode.hpp"
#include <stdio.h>
#include <algorithm>


//the purpose of this class is to form a list containing our program's .text section (or other) hashes
class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList);
	
	static list<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetMemoryHashList(std::list<uint64_t> hList);
	list<uint64_t> GetMemoryHashList() { return this->_MemorySectionHashes; }

	static list<wstring> GetLoadedModules(); //use this to fill _LoadedDlls

	bool IsUnknownModulePresent();

	static bool DisableDynamicCode();
	static bool DisableUnsignedCode();

	list<wstring> WhitelistedModules;

	wstring InternalModuleName = L"UltimateAnticheat.exe"; //store original module name since we randomize it later

	Integrity()
	{
		WhitelistedModules.push_back(L"UltimateAnticheat.exe");
		WhitelistedModules.push_back(L"KERNEL32.dll");
		WhitelistedModules.push_back(L"KERNELBASE.dll");
		WhitelistedModules.push_back(L"apphelp.dll");
		WhitelistedModules.push_back(L"USER32.dll");
	}

private:
	
	list<wstring> _LoadedDlls;
	list<uint64_t> _DllHashes;

	list<uint64_t> _MemorySectionHashes; 
};