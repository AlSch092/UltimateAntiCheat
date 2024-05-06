//By AlSch092 @github
#include "NetClient.hpp"

/*
	Initialize - Initializes the network client
	returns Error::OK on success
*/
Error NetClient::Initialize(string ip, uint16_t port)
{
	WSADATA wsaData;
	SOCKET Socket = INVALID_SOCKET;
	SOCKADDR_IN SockAddr;

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

	PacketWriter* p = Packets::Builder::ClientHello(this->HardwareID.c_str(), this->GetHostname().c_str(), this->GetMACAddress().c_str());

	int BytesSent = send(Socket, (const char*)p->GetBuffer(), p->GetSize(), 0); //let's hope fragmenting doesnt occur, i've never ran into it before at the application layer for small sized packets

	delete p;

	int nRecvDataLength;

	if (BytesSent == p->GetSize())
	{
		while ((nRecvDataLength = recv(Socket, (char*)recvBuffer, DEFAULT_RECV_LENGTH, 0)) == 0); //in a larger project, recv handling would be its own function, not jam-packed into a single routine like here.

		if (nRecvDataLength > MINIMUM_PACKET_SIZE && recvBuffer[0] != 0)
		{
			try
			{
				uint16_t packetLength = 0;
				memcpy((void*)&packetLength, (const void*)recvBuffer[0], sizeof(uint16_t));

				PacketWriter* recvP = new PacketWriter(recvBuffer, packetLength); //todo: make constructor where we can pass in a byte* and it auto copies 
				Error err = HandleInboundPacket(recvP); //Handle incoming packet. after the initial handshake is done, this will be called from our recv loop.

				delete recvP;
			}
			catch (std::exception e)
			{
				return Error::DATA_LENGTH_MISMATCH;
			}
		}
	}
	else
	{
		return Error::INCOMPLETE_SEND;
		//error, didnt send enough bytes. maybe packets were modified along the way by the user, or some blip in the wire occured.
	}

	//we can choose to either disconnect or leave the connection open at this point. we still will be sending more data shortly
	//...for now we will leave the connection open

	this->Ip = ip;
	this->Port = port;

	this->ConnectedAt = GetTickCount64();
	this->ConnectedDuration = 0;

	//create a thread for handling server replies
	this->RecvLoopThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&NetClient::ProcessRequests, this, 0, &this->recvThreadId);

	if (this->RecvLoopThread == NULL || this->recvThreadId == NULL)
	{
		return Error::NO_RECV_THREAD;
	}

	return Error::OK;
}

/*
	EndConnection - Ends the net connection with the server
	returns Error::OK on success
*/
Error NetClient::EndConnection(int reason)
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

	if (Socket != SOCKET_ERROR && Socket != NULL)
	{
		closesocket(Socket);
	}

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
Error NetClient::SendData(PacketWriter* outPacket)
{
	if (outPacket->GetBuffer() == nullptr || outPacket == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	if (this->Socket == SOCKET_ERROR)
		return Error::BAD_SOCKET;

	Error err = Error::OK;

	int BytesSent = send(Socket, (const char*)outPacket->GetBuffer(), outPacket->GetSize(), 0); //if this ever fragments i'll add a check

	int nRecvDataLength = 0;

	if (BytesSent != outPacket->GetSize()) //make sure we sent the hwid
	{
		err = Error::INCOMPLETE_SEND;
	}

	delete outPacket;
	return err;
}

/*
	ProcessRequests - reads packet sent from the server in a loop
*/
void NetClient::ProcessRequests(LPVOID Param)
{
	bool receiving = true;
	const int ms_between_loops = 1000;

	NetClient* Client = reinterpret_cast<NetClient*>(Param);

	char recvBuf[DEFAULT_RECV_LENGTH] = { 0 };

	while (receiving)
	{
		SOCKET s = Client->GetClientSocket();

		if (s)
		{
			int bytesIn = recv(s, recvBuf, DEFAULT_RECV_LENGTH, 0);

			if (bytesIn != SOCKET_ERROR)
			{
				PacketWriter* p = new PacketWriter(recvBuf, bytesIn);
				Client->HandleInboundPacket(p);
			}
		}

		Sleep(ms_between_loops);
	}
}

/*
	GetHostname - returns local ip of host
*/
string NetClient::GetHostname()
{
	struct IPv4
	{
		unsigned char b1, b2, b3, b4;
	};

	IPv4 myIP;
	string sIpv4;

	char szBuffer[1024];

#ifdef WIN32
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 0);
	if (::WSAStartup(wVersionRequested, &wsaData) != 0)
		return "";
#endif
	if (gethostname(szBuffer, sizeof(szBuffer)) == SOCKET_ERROR)
	{
#ifdef WIN32
		WSACleanup();
#endif
		return "";
	}

	struct hostent* host = gethostbyname(szBuffer);
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
	GetMACAddress - Generates MAC address of the network adapter
	returns empty string on failure
*/
string NetClient::GetMACAddress()
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(sizeof(char)*255);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Error allocating memory needed to call GetAdaptersinfo @ GetMACAddress");
		free(mac_addr);
		return "";
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) 
	{
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) 
		{
			Logger::logf("UltimateAnticheat.log", Err, "Error allocating memory needed to call GetAdaptersinfo @ GetMACAddress");
			free(mac_addr);
			return "";
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) 
	{

		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do 
		{
			sprintf(mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X",
				pAdapterInfo->Address[0], pAdapterInfo->Address[1],
				pAdapterInfo->Address[2], pAdapterInfo->Address[3],
				pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}
	free(AdapterInfo);
	return mac_addr; // caller must free!
}

/*
	GetHardwareID - Generates and returns a unique identifier based on PC name and hardware components
*/
string NetClient::GetHardwareID()
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

	if (GetVolumeInformationA(firstDrive, volumeName, ARRAYSIZE(volumeName),&serialNumber,&maxComponentLen,&fileSystemFlags,fileSystemName,ARRAYSIZE(fileSystemName)))
	{
		CHAR serialBuf[20];
		_itoa(serialNumber, serialBuf, 10);

		CHAR username[1024 + 1];
		DWORD size = 1024 + 1;
		GetUserNameA((CHAR*)username, &size);

		HWID = username;
		HWID += "-";
		HWID += serialBuf;
	}
	else 
		HWID = "Failed to generate HWID.";
	
	return HWID;
}

/*
	HandleInboundPacket - read packet `p`  and take action based on its opcode
*/
Error NetClient::HandleInboundPacket(PacketWriter* p)
{
	if (p->GetBuffer() == NULL || p == nullptr)
		return Error::NULL_MEMORY_REFERENCE;

	Error err = Error::OK;

	uint16_t opcode = 0;
	const unsigned char* packetData = p->GetBuffer();

	memcpy((void*)&opcode, packetData, sizeof(uint16_t));

	switch (opcode) //parse server-to-client packets
	{
		case Packets::Opcodes::SC_HELLO: //todo: finish this
			
			break;

		case Packets::Opcodes::SC_HEARTBEAT: //todo: finish this

			break;

		case Packets::Opcodes::SC_SHELLCODE:
		{
			if (!ExecutePacketPayload(p))
			{
				Logger::logf("UltimateAnticheat.log", Err, "Client displays bad behavior (payload did not execute correctly) @ HandleInboundPacket");
				err = Error::SERVER_KICKED;
			}
		}break;

		case Packets::Opcodes::SC_QUERY_MEMORY: //server requests byte data @ address

			if (QueryMemory(p) != Error::OK)
			{
				Logger::logf("UltimateAnticheat.log", Err, "Could not query memory bytes for server auth @ HandleInboundPacket");
				err = Error::GENERIC_FAIL;
			}
			break;

		default:
			err = Error::BAD_OPCODE;
			break;
	}

	return err;
}

/*
 NetClient::ExecutePacketPayload -> Tells the client to execute a server-generated payload (here we are simulating a packet coming in), to calculate a key which is then sent back to the server. Ensures that the client is actually running the anti-cheat program as it is a challenge-response protocol.

 -> every next packet is unencrypted using the key from the previous packet, and this key should be sent to the server to prove the client is executing the anticheat module (can still be spoofed by a cheater)
*/
bool NetClient::ExecutePacketPayload(PacketWriter* p)
{
	DWORD dwProt = 0;
	bool result = false;
	UINT64 decryptKey = 0;

	int bSize = p->GetSize();
	
	if (bSize < sizeof(uint64_t)) //stop buffer overflows
		return false;

	LPBYTE buffer = new byte[bSize];

	uint16_t opcode = Packets::Opcodes::SC_GENERATEKEY;

	//for testing purposes we can make our own packet buffer then execute it instead of needing a server
	memcpy((void*)&buffer[0], (void*)&opcode, sizeof(uint16_t));
	memcpy((void*)&buffer[2], (void*)(p->GetBuffer() + 2), bSize - 2);

	if (!VirtualProtect(&buffer[0], bSize, PAGE_EXECUTE_READWRITE, &dwProt))
	{
		Logger::logf("UltimateAnticheat.log", Err, "VirtualProtect Failed @ NetClient::UnpackAndExecute");
		delete[] buffer;
		return false;
	}

	UINT64 (*secretKeyFunction)();
	secretKeyFunction = (UINT64(*)())(buffer + 2); //first 2 bytes of buffer are the opcode, so skip that
	
	//decrypt the routine using the hash of the previous result
	if(HeartbeatHashes.size() > 0)
		decryptKey = HeartbeatHashes.back();

	for (int i = 0; i < bSize; i++) //each packet gets encrypted with the XOR of the last packet's secret key. the first time will be 0.
	{
		buffer[i] ^= (BYTE)decryptKey;
	}

	UINT64 secretKey = secretKeyFunction(); //shellcode call

	HeartbeatHashes.push_back(secretKey);

	//now send the key back to the server, if its wrong we get kicked. we simply execute the packet and the server can keep changing the key + routine OTA
	Error err = SendData(Packets::Builder::Heartbeat(secretKey));

	if (err == Error::OK) //result will stay false if no server is present
		result = true;
	
	delete[] buffer;
	return result;
}

Error NetClient::QueryMemory(PacketWriter* p)
{
	const int InPacketSize = 10; //sum of sizes of all fields for SC_QUERY_MEMORY type packet. we can turn this into Protobuf if we want to get fancy and make it annoying for attackers to emulate

	if (p == nullptr)
	{
		return Error::NULL_MEMORY_REFERENCE;
	}

	const unsigned char* buff = p->GetBuffer();
	
	if (buff == NULL || p->GetSize() < InPacketSize)
	{
		return Error::DATA_LENGTH_MISMATCH;
	}

	int size = 0;
	UINT64 address = 0;

	memcpy((void*)&address, (void*)&buff[2], sizeof(uint64_t)); //first 8 bytes of paylaod = address.  once I am not as lazy I'll make a PacketReader class to clean this up, memcpy can also possibly throw exceptions
	memcpy((void*)&size, (void*)&buff[10], sizeof(uint32_t)); //bytes 8-12 -> size of requested byte query

	if (size == 0 || address == 0)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed to fetch bytes at memory address (size or address was 0) @ NetClient::QueryMemory");
		return Error::INCOMPLETE_SEND;
	}

	BYTE* bytes = Process::GetBytesAtAddress(address, size);

	if (bytes == nullptr)
	{
		Logger::logf("UltimateAnticheat.log", Err, "Failed to fetch bytes at memory address @ NetClient::QueryMemory");
		return Error::NULL_MEMORY_REFERENCE;
	}

	//now write `bytes` to a packet and send, completing the transaction
	PacketWriter* outBytes = new PacketWriter((Packets::Opcodes::CS_QUERY_MEMORY));
	outBytes->WriteByteStringWithLength(bytes, size);
	
	delete[] bytes;
	return SendData(outBytes);
}

/*
	...we should store hashes of each server response and encrypt outbound data using said hashes to achieve a dynamic key per each transaction
*/
uint64_t NetClient::MakeHashFromServerResponse(PacketWriter* p) //todo: finish this, 
{
	uint64_t responseHash = 0;
	return 0;
}