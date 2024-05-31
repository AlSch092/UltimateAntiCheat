//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "NAuthenticode.hpp"
#include <list>
#include <string>
#include <Psapi.h>
#include <stdio.h>
#include <algorithm>

using namespace std;

class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList);
	
	static list<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetMemoryHashList(std::list<uint64_t> hList);
	list<uint64_t> GetMemoryHashList() { return this->_MemorySectionHashes; }

	static list<wstring> GetLoadedModules(); //use this to fill _LoadedDlls

	bool IsUnknownModulePresent();

	list<wstring> GetWhitelistedModules() { return this->WhitelistedModules; }
	void AddToWhitelist(const wchar_t* module) { WhitelistedModules.push_back(module); }

	Integrity()
	{
		WhitelistedModules.push_back(L"UltimateAnticheat.exe"); //strings can optionally be encrypted
		WhitelistedModules.push_back(L"KERNEL32.dll");
		WhitelistedModules.push_back(L"KERNELBASE.dll");
		WhitelistedModules.push_back(L"ntdll.dll");
		WhitelistedModules.push_back(L"apphelp.dll");
		WhitelistedModules.push_back(L"USER32.dll");
		WhitelistedModules.push_back(L"uxtheme.dll");
		WhitelistedModules.push_back(L"gdiplus.dll");
	}

private:
	
	list<uint64_t> _MemorySectionHashes; 
	list<wstring> WhitelistedModules;
};