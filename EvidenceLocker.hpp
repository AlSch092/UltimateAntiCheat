#pragma once
#include "Network/NetClient.hpp"
#include "Common/DetectionFlags.hpp"
#include "Common/Error.hpp"

#include <unordered_map>
#include <list>
#include <string>
#include <mutex>

struct Evidence
{
	DetectionFlags type;
	std::string data;
	DWORD pid;
};

class EvidenceLocker final
{
public:

	EvidenceLocker(NetClient* netclient) : NetworkClient(netclient)
	{

	}

	bool PushAllEvidence();

	bool AddFlagged(__in const DetectionFlags flag);
	bool AddFlagged(__in const DetectionFlags flag, __in const std::string data, __in const DWORD pid);

	void AddEvidence(__in const DetectionFlags type, __in const std::string data, __in const DWORD pid); //add to evidence list

	bool HasSentFlag(__in const DetectionFlags flag) { return SentFlags[flag]; }

	bool SendFlag(__in const DetectionFlags flag);
	bool FlagWithData(__in const DetectionFlags flag, __in const string data, __in const DWORD pid, __in const bool ShouldMarkAsSent);

	int GetFlagListSize() const { return this->FlaggedList.size(); }

private:

	std::mutex SendFlagMutex;
	std::mutex EvidenceListMutex;

	std::list<DetectionFlags> FlaggedList;

	std::unordered_map<DetectionFlags, bool> SentFlags;
	std::unordered_map<DetectionFlags, bool> HasEvidenceData; //specific flag has additional data to send (ex. an address, a string, etc)

	std::list<Evidence> EvidenceData;

	std::list<std::string> AlreadySentEvidence; //keep track of evidence which has been sent already

	NetClient* NetworkClient = nullptr;

};