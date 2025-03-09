#pragma once
#include "Network/NetClient.hpp"
#include "Common/DetectionFlags.hpp"
#include "Common/Error.hpp"
#include "Common/Logger.hpp"

#include <unordered_map>
#include <list>
#include <string>
#include <mutex>

struct Evidence
{
	DetectionFlags type;
	std::string data;
};

/*
	EvidenceLocker is a class for managing detection flags and any evidence fragments (modules, addresses, script names, etc)
	Flags + evidence can be queued up or sent immediately to the server
*/
class EvidenceLocker final
{
public:

	EvidenceLocker(NetClient* netclient) : NetworkClient(netclient)
	{
		if (netclient == nullptr)
		{
			Logger::logf(Err, "NetClient was nullptr @ EvidenceLocker::EvidenceLocker");
		}
	}

	bool PushAllEvidence(); //send all flags which haven't been sent already

	bool AddFlagged(__in const DetectionFlags flag);
	bool AddFlagged(__in const DetectionFlags flag, __in const std::string data); //flag with string evidence

	void AddEvidence(__in const DetectionFlags type, __in const std::string data); //add to evidence list

	bool HasSentFlag(__in const DetectionFlags flag) { return SentFlags[flag]; }

	bool SendFlag(__in const DetectionFlags flag); //send single flag to server
	bool FlagWithData(__in const DetectionFlags flag, __in const string data); //send flag + evidence to server

	int GetFlagListSize() const { return this->FlaggedList.size(); }

private:

	std::mutex SendFlagMutex;
	std::mutex EvidenceListMutex;

	std::list<DetectionFlags> FlaggedList;

	std::unordered_map<DetectionFlags, bool> SentFlags; //to avoid duplicate flagging (or the same detection being sent every single monitor loop), map a boolean to each detection flag
	std::unordered_map<DetectionFlags, bool> HasEvidenceData; //specific flag has additional data to send (ex. an address, a string, etc). Always expressed as a string, such that no type is needed

	std::list<Evidence> EvidenceData; //any evidence associated with a specific detection flag

	NetClient* NetworkClient = nullptr;
};