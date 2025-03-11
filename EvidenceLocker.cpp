#include "EvidenceLocker.hpp"

/*
	AddFlagged - adds `flag` to our flagged/detections list
	returns `true` if the flag was added, returns `false` if the flag is a duplicate (to prevent multiple repeat data pushes for the same thing)
*/
bool EvidenceLocker::AddFlagged(__in const DetectionFlags flag)
{
	if (std::find(this->FlaggedList.begin(), this->FlaggedList.end(), flag) == this->FlaggedList.end())
	{
		std::lock_guard<std::mutex> lock(this->EvidenceListMutex);
		this->FlaggedList.push_back(flag);
		this->SentFlags[flag] = false;
		return true;
	}

	return false;
}

/*
	AddFlagged - adds `flag` to our flagged/detections list, along with `data` to our evidence list. evidence is additional data associated with a flag
	returns `true` if the flag was added, returns `false` if the flag is a duplicate (to prevent multiple repeat data pushes for the same thing)
*/
bool EvidenceLocker::AddFlagged(__in const DetectionFlags flag, __in const std::string data)
{
	if (std::find(this->FlaggedList.begin(), this->FlaggedList.end(), flag) == this->FlaggedList.end())
	{
		std::lock_guard<std::mutex> lock(this->EvidenceListMutex);
		this->FlaggedList.push_back(flag);
		this->SentFlags[flag] = false;
		AddEvidence(flag, data);
		return true;
	}

	return false;
}

/*
	AddEvidence - Adds `data` to our evidence list for `flag` type. Evidence is any additional string data associated with a flag, such as a memory address, a module name, a python script, etc
	returns `true` if the flag was added, returns `false` if the flag is a duplicate (to prevent multiple repeat data pushes for the same thing)
*/
void EvidenceLocker::AddEvidence(__in const DetectionFlags flag, __in const std::string data)
{
	Evidence evi;
	evi.type = flag;
	evi.data = data;
	this->EvidenceData.push_back(evi);
	this->HasEvidenceData[flag] = true;
}

/*
	SendFlag - send a detected flag to the server (without evidence)
	returns `true` on success
*/
bool EvidenceLocker::SendFlag(__in const DetectionFlags flag)
{
	bool wasDuplicate = AddFlagged(flag);

	if (wasDuplicate) //prevent duplicate server comms
		return true;

	if (this->NetworkClient != nullptr)
	{
		std::lock_guard<std::mutex> lock(this->SendFlagMutex);

		if (this->NetworkClient->FlagCheater(flag) != Error::OK)
		{
			Logger::logf(Err, "Failed to notify server of cheating status.");
			return false;
		}
	}
	else
	{
		Logger::logf(Err, "NetClient was NULL @ EvidenceLog::SendFlag");
		return false;
	}

	this->SentFlags[flag] = true;

	return true;
}

/*
	FlagWithData - send a detected flag to the server (with evidence)
	returns `true` on success
*/
bool EvidenceLocker::FlagWithData(__in const DetectionFlags flag, __in const string data)
{
	bool wasDuplicate = AddFlagged(flag);

	if (wasDuplicate) //prevent duplicate server comms
		return true;

	if (this->NetworkClient != nullptr)
	{
		std::lock_guard<std::mutex> lock(this->SendFlagMutex);

		if (this->NetworkClient->FlagCheater(flag, data) != Error::OK)
		{
			Logger::logf(Err, "Failed to notify server of cheating status.");
			return false;
		}
	}
	else
	{
	    Logger::logf(Err, "NetClient was NULL @ Detections::Flag");
		return false;
	}

	this->SentFlags[flag] = true;
	return true;
}

/*
	PushAllEvidence - push all unsent flags to server, if any evidence is with a flag it will also send that
	returns `true` if no flag sends fail. if one or more flag sends fail, return `false`
*/
bool EvidenceLocker::PushAllEvidence()
{
	bool flagSendFailed = false;

	for (auto flag : FlaggedList)
	{
		if (!SentFlags[flag])
		{
			if (HasEvidenceData[flag])
			{
				for (auto evidence : this->EvidenceData) //send extra evidence with flag
				{
					if (evidence.type == flag)
					{
						if (!FlagWithData(flag, evidence.data))
						{
							flagSendFailed = true;
						}
					}
				}
			}
			else
			{
				if (!SendFlag(flag))
				{
					flagSendFailed = true;
				}
			}
		}
	}

	return flagSendFailed;
}