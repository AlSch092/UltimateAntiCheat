//By AlSch092 @github
#include "NetClient.hpp"

/*
	Initialize - Initializes the network client
	returns Error::OK on success
*/
Error NetClient::Initialize(__in const std::string ip, __in const uint16_t port, __in const std::string gameCode)
{
	WSADATA wsaData;
	SOCKET Socket = INVALID_SOCKET;
	SOCKADDR_IN SockAddr;
	Error result = Error::OK;

	this->HardwareID = this->GetHardwareID();

	const char recvBuffer[DEFAULT_RECV_LENGTH] = { 0 };

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0 || this->HardwareID.size() <= 2)
	{
		return Error::CANT_STARTUP;
	}

	Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SockAddr.sin_addr.S_un.S_addr = inet_addr(ip.c_str());
	SockAddr.sin_port = htons(port);
	SockAddr.sin_family = AF_INET;

	this->Socket = Socket;

	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0)
	{
		closesocket(Socket);
		WSACleanup();
		shutdown(Socket, 0);
		return Error::CANT_CONNECT;
	}

	PacketWriter* p = Packets::Builder::ClientHello(gameCode, this->HardwareID, this->GetHostname(), this->GetMACAddress());

	Error sendResult = SendData(p);

	if (sendResult != Error::OK)
	{
		closesocket(Socket);
		WSACleanup();
		shutdown(Socket, 0);
		return Error::CANT_SEND;
	}

	RecvLoopThread = new Thread((LPTHREAD_START_ROUTINE)&NetClient::ProcessRequests, this, true, false);

	if (RecvLoopThread->GetId() == 0)
	{
		Logger::logf(Err, "RecvThread was NULL @ NetClient::Initialize");
		closesocket(Socket);
		WSACleanup();
		shutdown(Socket, 0);
		return Error::NO_RECV_THREAD;
	}

	this->Ip = ip;
	this->Port = port;

	this->ConnectedAt = GetTickCount64();
	this->ConnectedDuration = 0;

	return Error::OK;
}

/*
	EndConnection - Ends the net connection with the server
	returns Error::OK on success
*/
Error NetClient::EndConnection(__in const int reason)
{
	PacketWriter* p = Packets::Builder::ClientGoodbye(reason);
	Error err = Error::OK;

	if (this->Socket != SOCKET_ERROR)
	{
		//send CS_GOODBYE then disconnect

		if (this->SendData(p) != Error::OK)
		{
			err = Error::CANT_SEND;
		}
	}

	closesocket(Socket);

	this->ConnectedDuration = GetTickCount64() - this->ConnectedAt;

	WSACleanup();
	shutdown(Socket, 0);
	return err;
}

/*
	SendData - Sends `outPacket` parameter to the server
	returns Error::OK on success
	Function deletes memory of outPacket on success 
*/
Error NetClient::SendData(__in PacketWriter* outPacket)
{
	if (outPacket->GetBuffer() == nullptr || outPacket == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	if (this->Socket == SOCKET_ERROR)
		return Error::BAD_SOCKET;

	LPBYTE encryptedBuffer = (LPBYTE)outPacket->GetBuffer();

	CipherData(encryptedBuffer, outPacket->GetSize());

	Error err = Error::OK;

	{
		std::lock_guard<std::mutex> lock(SendPacketMutex);

		int BytesSent = send(Socket, (const char*)encryptedBuffer, outPacket->GetSize(), 0); //if this ever fragments i'll add a check

		int nRecvDataLength = 0;

		if (BytesSent != outPacket->GetSize()) //make sure we sent the hwid
		{
			err = Error::INCOMPLETE_SEND;
		}
	}

	delete outPacket;
	return err;
}

/*
	ProcessRequests - reads packet sent from the server in a loop
*/
void NetClient::ProcessRequests(__in LPVOID Param)
{
	if (Param == nullptr)
	{
		Logger::logf(Info, "NetClient class pointer was nullptr @ ProcessRequests");
		return;
	}

	bool receiving = true;
	const int ms_between_loops = 1000;
	unsigned char recvBuf[DEFAULT_RECV_LENGTH] = { 0 };

	Logger::logf(Info, "Started thread on NetClient::ProcessRequests with id: %d", GetCurrentThreadId());

	NetClient* Client = reinterpret_cast<NetClient*>(Param);

	if (Client == nullptr)
	{
		Logger::logf(Err, "Client was NULL @ NetClient::ProcessRequests");
		receiving = false; //todo: send signals to rest of anticheat to shutdown
		goto end;
	}

	while (receiving)
	{
		if (Client->GetRecvThread()->IsShutdownSignalled())
		{
			goto end;
		}

		SOCKET s = Client->GetClientSocket();

		if (s)
		{
			int bytesIn = 0;

			{
				std::lock_guard<std::mutex> lock(Client->RecvPacketMutex);
				bytesIn = recv(s, (char*)recvBuf, DEFAULT_RECV_LENGTH, 0);
			}

			if (bytesIn == 0)
				continue;

			if (bytesIn != SOCKET_ERROR)
			{
				Client->CipherData(recvBuf, bytesIn); //decrypt buffer

				PacketReader* p = new PacketReader(recvBuf, bytesIn);
				Client->HandleInboundPacket(p);
				delete p;
			}
			else
				receiving = false;
		}
		else if(s == SOCKET_ERROR)
		{
			Logger::logf(Err, "Socket error @  NetClient::ProcessRequests");
			receiving = false; //todo: send signals to rest of anticheat to shutdown
		}

		Sleep(ms_between_loops);
	}

end:
	closesocket(Client->GetClientSocket());
	WSACleanup();
	shutdown(Client->GetClientSocket(), 0);
}

/*
	GetHostname - returns local ip of host (ex, 192.168.2.1)
*/
std::string NetClient::GetHostname()
{
	struct IPv4
	{
		unsigned char b1, b2, b3, b4;
	};

	IPv4 myIP;
	std::string sIpv4;

	char szBuffer[1024];

#ifdef WIN32
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 0);
	if (WSAStartup(wVersionRequested, &wsaData) != 0)
		return "";
#endif
	if (gethostname(szBuffer, sizeof(szBuffer)) == SOCKET_ERROR)
	{
#ifdef WIN32
		WSACleanup();
#endif
		return "";
	}

	auto host = gethostbyname(szBuffer);
	if (host == NULL)
	{
#ifdef WIN32
		WSACleanup();
#endif
		return "";
	}

	//Obtain the computer's IP
	myIP.b1 = ((struct in_addr*)(host->h_addr))->S_un.S_un_b.s_b1;
	myIP.b2 = ((struct in_addr*)(host->h_addr))->S_un.S_un_b.s_b2;
	myIP.b3 = ((struct in_addr*)(host->h_addr))->S_un.S_un_b.s_b3;
	myIP.b4 = ((struct in_addr*)(host->h_addr))->S_un.S_un_b.s_b4;

#ifdef WIN32
	WSACleanup();
#endif

	char b1[5], b2[5], b3[5], b4[5];

	_itoa(myIP.b1, b1, 10);
	_itoa(myIP.b2, b2, 10);
	_itoa(myIP.b3, b3, 10);
	_itoa(myIP.b4, b4, 10);

	sIpv4 = b1;
	sIpv4 = sIpv4 + "." + b2 + "." + b3 + "." + b4;

	return sIpv4;
}

/*
	HandleInboundPacket - read packet `p`  and take action based on its opcode
*/
Error NetClient::HandleInboundPacket(__in PacketReader* p)
{
	if (p == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	Error err = Error::OK;

	uint16_t opcode = p->readShort();

	switch (opcode) //parse server-to-client packets
	{
		case Packets::Opcodes::SC_HELLO: //AC initialization can possibly be put into this handler. server is confirming game license code was fine
		{
			uint16_t softwareVersion = p->readShort();
			HandshakeCompleted = true;
			Logger::logf(Info, "Got reply from server with version: %d", softwareVersion);
		}break;

		case Packets::Opcodes::SC_HEARTBEAT: //auth cookie every few minutes
		{
			short cookie_len = p->readShort();

			if (cookie_len != 128)
				return Error::INCOMPLETE_RECV;

			std::string cookie = p->readString(128);

			const char* ResponseCookie = MakeHeartbeat(cookie);

			if (ResponseCookie != NULL)
			{
				PacketWriter* Response = Packets::Builder::Heartbeat(ResponseCookie);

				if (SendData(Response) != Error::OK)
				{
					Logger::logf(Err, "Could not send heartbeat @ HandleInboundPacket");
					err = Error::BAD_HEARTBEAT;
				}

				delete[] ResponseCookie;
				ResponseCookie = nullptr; //remove use-after-free possibility
			}
			else
			{
				Logger::logf(Err, "Failed to generate heartbeat @ HandleInboundPacket");
				err = Error::BAD_HEARTBEAT;
			}
		}break;

		case Packets::Opcodes::SC_QUERY_MEMORY: //server requests byte data @ address
		{
			uint64_t address = p->readLong();
			uint32_t size = p->readInt();

			if (QueryMemory(address, size) != Error::OK)
			{
				Logger::logf(Err, "Could not query memory bytes for server auth @ HandleInboundPacket");
				err = Error::GENERIC_FAIL;
			}
		}break;

		default:
			err = Error::BAD_OPCODE;
			break;
	}

	return err;
}

/*
	FlagCheater - tells server the client has detected cheating
	returns Error::OK on success
*/
Error NetClient::FlagCheater(__in const DetectionFlags flag)
{
	PacketWriter* outBytes = Packets::Builder::DetectedCheater(flag);
	return SendData(outBytes);
}

/*
	FlagCheater - tells server the client has detected cheating, along with some additional supporting data
	returns Error::OK on success
*/
Error NetClient::FlagCheater(__in const DetectionFlags flag, __in const std::string data, __in const DWORD pid)
{
	PacketWriter* outBytes = Packets::Builder::DetectedCheater(flag, data, pid);
	return SendData(outBytes);
}

/*
	QueryMemory - Server requested client to read bytes @ some memory address
	returns Error::OK on success
*/
Error NetClient::QueryMemory(__in const uint64_t address, __in const uint32_t size)
{
	if (size == 0 || address == 0)
	{
		Logger::logf(Err, "Failed to fetch bytes at memory address (size or address was 0) @ NetClient::QueryMemory");
		return Error::INCOMPLETE_SEND;
	}

	BYTE* bytes = Process::GetBytesAtAddress(address, size);

	if (bytes == nullptr)
	{
		Logger::logf(Err, "Failed to fetch bytes at memory address @ NetClient::QueryMemory");
		return Error::NULL_MEMORY_REFERENCE;
	}

	PacketWriter* outBytes = Packets::Builder::QueryMemory(bytes, size); //now write `bytes` to a packet and send, completing the transaction
	delete[] bytes;
	bytes = nullptr;
	return SendData(outBytes);
}

/*
	MakeHeartbeat - Generates a response to server heartbeat requests
	returns a char* array containing the auth cookie. Very simple example, non-public versions of the project use something more complicated
*/
__forceinline const char* NetClient::MakeHeartbeat(__in const std::string cookie)
{
	if (!Process::IsReturnAddressInModule(*(UINT64*)_AddressOfReturnAddress(), NULL)) //return address check, NULL refers to the current module
	{
		Logger::logf(Detection, "Return address was outside of module @ NetClient::MakeHeartbeat : some attacker might be trying to spoof heartbeats");
		return nullptr;
	}

	byte* b = (byte*)cookie.c_str();

	byte Transformer = 0x18; //the heartbeat response is the request xor'd with Transformer, transformer is added to by each value of the request

	char* HeartbeatResponse = new char[128] {0};

	for (int i = 0; i < 128; i++)
	{
		byte val = (byte)((byte)b[i]);
		val ^= Transformer;
		HeartbeatResponse[i] = val;
	}

	return HeartbeatResponse;
}

/*
	EncryptData - encrypts `buffer` using xor /w sub/add operation
	Of course a much better encryption routine can be replaced with this, everyone will have their own preference (AES, RSA, Salsa, etc) so you can implement one yourself if desired
*/
void __forceinline NetClient::CipherData(__inout LPBYTE buffer, __in const int length)
{
	const byte XorKey = 0x90;
	const byte OperationKey = 0x14;

	for (int i = 0; i < length; i++)
	{
		if(i % 2 == 0)
			buffer[i] = (buffer[i] ^ XorKey) + OperationKey;
		else
			buffer[i] = (buffer[i] ^ XorKey) - OperationKey;
	}
}

/*
	GetMACAddress - Generates MAC address of the network adapter
	returns empty string on failure
*/
std::string NetClient::GetMACAddress()
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = new char[255];

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL)
	{
		Logger::logf(Err, "Error allocating memory needed to call GetAdaptersinfo @ GetMACAddress");
		delete[] mac_addr;
		return "";
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL)
		{
			Logger::logf(Err, "Error allocating memory needed to call GetAdaptersinfo @ GetMACAddress");
			delete[] mac_addr;
			return "";
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR)
	{
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do
		{
			if (mac_addr != nullptr)
				sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", pAdapterInfo->Address[0], pAdapterInfo->Address[1], pAdapterInfo->Address[2], pAdapterInfo->Address[3], pAdapterInfo->Address[4], pAdapterInfo->Address[5]); pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}

	free(AdapterInfo);
	std::string s_mac_addr = mac_addr;
	delete[] mac_addr;
	return s_mac_addr;
}

/*
	GetHardwareID - Generates and returns a unique identifier based on PC name and hardware components
*/
std::string NetClient::GetHardwareID()
{
	std::string HWID = "";

	CHAR volumeName[MAX_PATH + 1] = { 0 };
	CHAR fileSystemName[MAX_PATH + 1] = { 0 };
	DWORD serialNumber = 0;
	DWORD maxComponentLen = 0;
	DWORD fileSystemFlags = 0;

	DWORD dwSize = MAX_PATH;
	char szLogicalDrives[MAX_PATH] = { 0 };
	DWORD dwResult = GetLogicalDriveStringsA(dwSize, szLogicalDrives);

	char firstDrive[10] = { 0 };

	if (dwResult > 0 && dwResult <= MAX_PATH) //fetch the list of drives and use the first one detected
	{
		char* szSingleDrive = szLogicalDrives;
		while (*szSingleDrive)
		{
			strcpy_s(firstDrive, szSingleDrive);
			szSingleDrive += strlen(szSingleDrive) + 1;
		}
	}

	if (GetVolumeInformationA(firstDrive, volumeName, ARRAYSIZE(volumeName), &serialNumber, &maxComponentLen, &fileSystemFlags, fileSystemName, ARRAYSIZE(fileSystemName)))
	{
		CHAR serialBuf[20];
		_itoa(serialNumber, serialBuf, 10);

		CHAR username[128];
		DWORD size = sizeof(username);
		GetUserNameA(username, &size);

		HWID = username;
		HWID += "-";
		HWID += serialBuf;
	}
	else
		HWID = "Failed to generate HWID.";

	return HWID;
}