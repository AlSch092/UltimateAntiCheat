#include "API.hpp"

int __declspec(dllexport) API::Initialize(string licenseKey)
{
	int errorCode = 0;
	bool isLicenseValid = false;
	//check licenseKey against web server
	//gernerate user identifying info and send to server

	if (isLicenseValid)
	{
		if (g_AC->GetNetworkClient()->Initialize("127.0.0.1", 5445) != Error::OK) //initialize client is separate from license key auth
		{
			//don't allow continuing if networking doesn't work
			errorCode = Error::CANT_STARTUP;
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