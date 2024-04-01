#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/MD5.hpp"
#include "../Process/Process.hpp"
#include "NAuthenticode.hpp"
#include <stdio.h>
#include <algorithm>


//the purpose of this class is to form a list containing our program's computed hashes
class Integrity
{
public:

	bool Check(uint64_t Address, int nBytes, std::list<uint64_t> hashList);
	
	static list<uint64_t> GetMemoryHash(uint64_t Address, int nBytes);

	void SetMemoryHashList(std::list<uint64_t> hList);
	list<uint64_t> GetMemoryHashList() { return this->_MemorySectionHashes; }

	static list<wstring> GetLoadedDLLs(); //use this to fill _LoadedDlls
	static list<uint64_t>* GetDllHashes(list<wchar_t*> LoadedDlls);

	static bool IsUnknownDllPresent();

	static bool DisableDynamicCode();
	static bool DisableUnsignedCode();

	static bool IsFunctionHooked(const char* module, const char* name);

	list<wstring> WhitelistedModules;

	Integrity()
	{
		WhitelistedModules.push_back(L"UltimateAntiCheat.exe");
		WhitelistedModules.push_back(L"new_name"); //we change the module name UltimateAntiCheat.exe to new_name as a technique
		WhitelistedModules.push_back(L"KERNEL32.dll");
		WhitelistedModules.push_back(L"KERNELBASE.dll");
		WhitelistedModules.push_back(L"apphelp.dll");
		WhitelistedModules.push_back(L"USER32.dll");
	}

private:
	
	list<wstring> _LoadedDlls;
	list<uint64_t> _DllHashes;

	list<uint64_t> _MemorySectionHashes; 
	
	Process* _Proc = new Process(); //get memory sections, etc, make hash of each section
};