#include "API.hpp"

int __declspec(dllexport) API::Initialize(string licenseKey, wstring parentProcessName)
{
	int errorCode = Error::OK;
	bool isLicenseValid = false;

	//TODO: check licenseKey against some centralized web server, possibly using HTTP requests. once we have verified our license, we can try to connect using Initialize()
	//gernerate user identifying info and send to server

	if (isLicenseValid)
	{
		if (g_AC->GetNetworkClient()->Initialize("127.0.0.1", 5445) != Error::OK) //initialize client is separate from license key auth
		{
			//don't allow continuing if networking doesn't work
			errorCode = Error::CANT_STARTUP;
		}
		else
		{
			//check parent process
			if (Process::CheckParentProcess(parentProcessName))
			{
				g_AC->GetProcessObject()->SetParentName(parentProcessName);
			}
			else //bad parent process detected, or parent process mismatch, shut down the program after reporting the error to the server
			{
				errorCode = Error::PARENT_PROCESS_MISMATCH;
			}
		}
	}

	return errorCode;
}

int __declspec(dllexport) API::Dispatch(DispatchCode code, int reason) //todo: finish this
{
	int errorCode = 0;

	switch (code)
	{
		case FAILED_INITIALIZE:

			break;

		case CLIENT_EXIT:

			break;

		case CLIENT_DISCONNECT:

			break;

		case HEARTBEAT:

			break;
	};

	return errorCode;
}