//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/Globals.hpp"
#include "../Common/Settings.hpp"
#include "../Network/HttpClient.hpp"
#include "NAuthenticode.hpp"

#include <Psapi.h>
#include <unordered_map>

using namespace std;

struct ModuleHashData 
{
	wstring Name;
	vector<uint64_t> Hashes;
};

struct ModuleInfo
{
	uintptr_t baseAddress;
	uintptr_t size;
};

/*
	The Integrity class provides functionalities for determining if aspects of any program modules have been modified

	Hash lists (vector<uint64_t>) are used such that we can pinpoint the memory offset of any particular modifications, as opposed to using a CRC32 or SHA of a module or section

	..Probably the messiest class in the program, it could really use a code cleanup
*/
class Integrity final
{
public:

	Integrity(__in vector<ProcessData::MODULE_DATA> startupModuleList) //modules gathered at program startup
	{
		for (const ProcessData::MODULE_DATA& mod : startupModuleList)
		{
			WhitelistedModules.push_back(mod);
		}

		ModuleHashes = GetModuleHashes(); 
	}

	~Integrity()
	{
		for (vector<ModuleHashData*>::const_iterator it = ModuleHashes.begin(); it != ModuleHashes.end(); ++it)
		{
			if(*it != nullptr)
			    delete* it;
		}
	}

	bool Check(__in uint64_t Address, __in int nBytes, __in vector<uint64_t> hashList); //returns true if hashes calculated at `Address` don't match hashList
	
	static vector<uint64_t> GetMemoryHash(__in uint64_t Address, __in int nBytes); //get hash list at `Address`
	static vector<uint64_t> GetMemoryHash(LPBYTE memory, int nBytes);
	static uint64_t GetStackedHash(uint64_t Address, int nBytes);

	void SetSectionHashList(__out vector<uint64_t> hList, __in const string section);

	vector<uint64_t> GetSectionHashList(__in const string sectionName) const 
	{
		auto it = this->SectionHashes.find(sectionName);

		if (it != this->SectionHashes.end())
		{
			return it->second;
		}

		return {};
	}

	bool IsUnknownModulePresent(); //traverse loaded modules to find any unknown ones (not signed & not whitelisted, in particular)

	vector<ProcessData::MODULE_DATA> GetWhitelistedModules() const { return this->WhitelistedModules; }
	
	void AddToWhitelist(__in ProcessData::MODULE_DATA mod) { WhitelistedModules.push_back(mod); }

	void AddModuleHash(__in vector<ModuleHashData*> moduleHashList, __in const wchar_t* moduleName);
	ModuleHashData* GetModuleHash(__in const wchar_t* moduleName);

	vector<ModuleHashData*> GetModuleHashes();

	bool IsModuleModified(__in const wchar_t* moduleName); //pinpoint any specific modules that have had their .text sections changed

	bool IsTLSCallbackStructureModified() const; //checks the TLSCallback structure in data directory for mods

	static bool IsPEHeader(__in unsigned char* pMemory); //checks for MZ and PE signatures
	static bool IsAddressInModule(const std::vector<ProcessData::MODULE_DATA>& modules, uintptr_t address);

	static vector<uint64_t> GetSectionHashFromDisc(wstring path, const char* sectionName);
	bool CheckFileIntegrityFromDisc();

private:
	
	unordered_map<string, vector<uint64_t>> SectionHashes; //section hashes for current/main module's sections

	vector<ProcessData::MODULE_DATA> WhitelistedModules;
	vector<ModuleHashData*> ModuleHashes;	
};