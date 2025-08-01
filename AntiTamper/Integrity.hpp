//By AlSch092 @github
#pragma once
#include "../Common/Utility.hpp"
#include "../Common/SHA256.hpp"
#include "../Common/Settings.hpp"
#include "../Network/HttpClient.hpp"
#include "../Process/Process.hpp"
#include "NAuthenticode.hpp"

#include <Psapi.h>
#include <unordered_map>

using namespace std;

struct ModuleHashData 
{
	std::wstring Name;
	std::wstring Section;
	std::vector<uint64_t> Hashes;
};

struct ModuleInfo
{
	uintptr_t baseAddress;
	uintptr_t size;
};

/*
	The Integrity class provides functionalities for determining if aspects of any program modules have been modified

	Hash lists (vector<uint64_t>) are used such that we can pinpoint the memory offset of any particular modifications, as opposed to using a CRC32 or SHA of a module or section

	** This class needs to be rewritten, there are several things that can be improved, and the current code is just too messy.
	    This was one of the first things added into this project back in 2022, back when I used primarily C rather than C++. **
*/
class Integrity final
{
public:

	Integrity(__in const vector<ProcessData::MODULE_DATA> startupModuleList) //modules gathered at program startup
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

	Integrity& operator=(Integrity&& other) = delete; //delete move assignments
	Integrity operator+(Integrity& other) = delete; //delete all arithmetic operators, unnecessary for context
	Integrity operator-(Integrity& other) = delete;
	Integrity operator*(Integrity& other) = delete;
	Integrity operator/(Integrity& other) = delete;

	bool Check(__in const uint64_t Address, __in int const nBytes, __in const std::vector<uint64_t> hashList); //returns true if hashes calculated at `Address` don't match hashList
	
	static std::vector<uint64_t> GetMemoryHash(__in const uint64_t Address, __in const int nBytes); //get hash list at `Address`
	static uint64_t GetStackedHash(__in const uint64_t Address, __in const int nBytes);

	void SetSectionHashList(__out vector<uint64_t> hList, __in const string section);

	std::vector<uint64_t> GetSectionHashList(__in const std::string sectionName) const
	{
		auto it = this->SectionHashes.find(sectionName);

		if (it != this->SectionHashes.end())
		{
			return it->second;
		}

		return {};
	}

	bool IsUnknownModulePresent(); //traverse loaded modules to find any unknown ones (not signed & not whitelisted, in particular)

	std::vector<ProcessData::MODULE_DATA> GetWhitelistedModules() const { return this->WhitelistedModules; }
	
	void AddToWhitelist(__in ProcessData::MODULE_DATA mod) { WhitelistedModules.push_back(mod); }

	void AddModuleHash(__in std::vector<ModuleHashData*>& moduleHashList, __in const wchar_t* moduleName, __in const char* sectionName);
	ModuleHashData* GetModuleHash(__in const wchar_t* moduleName, __in const char* sectionName);

	std::vector<ModuleHashData*> GetModuleHashes();

	bool IsModuleModified(__in const wchar_t* moduleName); //pinpoint any specific modules that have had their .text sections changed

	bool IsTLSCallbackStructureModified() const; //checks the TLSCallback structure in data directory for mods

	static bool IsPEHeader(__in unsigned char* pMemory); //checks for MZ and PE signatures
	static bool IsAddressInModule(const std::vector<ProcessData::MODULE_DATA>& modules, uintptr_t address);

	static std::vector<uint64_t> GetSectionHashFromDisc(std::wstring path, const char* sectionName);
	bool CheckFileIntegrityFromDisc(); //compare process image to executable file saved on disc

private:
	
	std::unordered_map<std::string, std::vector<uint64_t>> SectionHashes; //section hashes for current/main module's sections: .text, .rdata, etc

	std::vector<ProcessData::MODULE_DATA> WhitelistedModules;
	std::vector<ModuleHashData*> ModuleHashes; //.text hashes only for other modules -> future versions should include all sections for all loaded modules if possible
};