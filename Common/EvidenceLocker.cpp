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
bool EvidenceLocker::AddFlagged(__in const DetectionFlags flag, __in const std::string data, __in const DWORD pid)
{
	bool AlreadyAdded = false;

	for (auto evidence : this->EvidenceData)
	{
		if (evidence.data == data)
			AlreadyAdded = true;
	}

	if (!AlreadyAdded) //is not already sent
	{
		std::lock_guard<std::mutex> lock(this->EvidenceListMutex);
		this->FlaggedList.push_back(flag);
		this->SentFlags[flag] = false;
		AddEvidence(flag, data, pid);
		return true;
	}

	return false;
}

/*
	AddEvidence - Adds `data` to our evidence list for `flag` type. Evidence is any additional string data associated with a flag, such as a memory address, a module name, a python script, etc
	returns `true` if the flag was added, returns `false` if the flag is a duplicate (to prevent multiple repeat data pushes for the same thing)
*/
void EvidenceLocker::AddEvidence(__in const DetectionFlags flag, __in const std::string data, __in const DWORD pid)
{
	Evidence evi;
	evi.type = flag;
	evi.data = data;
	evi.pid = pid;
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
#if USE_LOG_MESSAGES
			Logger::logf(Err, "Failed to notify server of cheating status.");
#endif
			return false;
		}
	}
	else
	{
#if USE_LOG_MESSAGES
		Logger::logf(Err, "NetClient was NULL @ EvidenceLog::SendFlag");
#endif
		return false;
	}

	this->SentFlags[flag] = true; //only mark as sent flag if send() was successful
	return true;
}

/*
	FlagWithData - send a detected flag to the server (with evidence)
	returns `true` on success
*/
bool EvidenceLocker::FlagWithData(__in const DetectionFlags flag, __in const std::string data, __in const DWORD pid, __in const bool ShouldMarkAsSent)
{
	bool wasDuplicate = AddFlagged(flag);

	if (wasDuplicate) //prevent duplicate server comms
		return true;

	if (this->NetworkClient != nullptr)
	{
		std::lock_guard<std::mutex> lock(this->SendFlagMutex);

		if (this->NetworkClient->FlagCheater(flag, data, pid) != Error::OK)
		{
#if USE_LOG_MESSAGES
			Logger::logf(Err, "Failed to notify server of cheating status.");
#endif
			return false;
		}
	}
	else
	{
#if USE_LOG_MESSAGES
		Logger::logf(Err, "NetClient was NULL @ Detections::Flag");
#endif
		return false;
	}

	AlreadySentEvidence.push_back(data);

	if (ShouldMarkAsSent)
		this->SentFlags[flag] = true; //only mark as sent flag if send() was successful
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
		if (!SentFlags[flag]) //todo: make sure that all evidence is properly sending, and that some isnt being blocked
		{
			if (HasEvidenceData[flag])
			{
				for (auto evidence : this->EvidenceData) //send extra evidence with flag
				{
					if (evidence.type == flag)
					{
						if (std::find(AlreadySentEvidence.begin(), AlreadySentEvidence.end(), evidence.data) == AlreadySentEvidence.end()) //send only if we didnt already sent this evidence
						{
							if (!FlagWithData(flag, evidence.data, evidence.pid, false))
							{
								flagSendFailed = true;
							}
						}

						this_thread::sleep_for(std::chrono::milliseconds(1000));
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