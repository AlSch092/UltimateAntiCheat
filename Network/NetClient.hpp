//By AlSch092 @github
#pragma once
#include <winsock2.h>
#include <Iphlpapi.h>
#include <list>
#include <stdint.h>
#include <string>
#include <intrin.h>

#include "../Common/Error.hpp"
#include "../Common/Logger.hpp"
#include "Packets/Packets.hpp"
#include "../Process/Process.hpp"

#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi.lib")

#define DEFAULT_RECV_LENGTH 512
#define MINIMUM_PACKET_SIZE 4

using namespace std;

/*
Class NetClient - Client-side of networking portion
*/
class NetClient
{
public:

	NetClient()
	{
		HandshakeCompleted = false;
		Initialized = false;
	}

	NetClient(const char* serverEndpoint, uint16_t port)
	{
		Ip = serverEndpoint;
		Port = port;

		HandshakeCompleted = false;
		Initialized = false;
	}

	~NetClient()
	{
		delete RecvLoopThread;
	}

	static void ProcessRequests(LPVOID Param); //calls recv in a loop to handle requests, and if this routine is not running the program should be exited

	Error Initialize(string ip, uint16_t port, string gameCode); //connects, sends CS_HELLO, verifies the response of a version number from server
	Error EndConnection(int reason); //sends CS_GOODBYE and disconnects the socket
	Error SendData(PacketWriter* outPacket); //all data sent to the server should go through this

	Error FlagCheater(DetectionFlags flag);
	Error QueryMemory(uint64_t address, uint32_t size); //query specific memory address, send its bytes values back to server
	__forceinline const char*  MakeHeartbeat(string cookie);

	static string GetHostname();
	string GetMACAddress();
	string GetHardwareID();

	Error HandleInboundPacket(PacketReader* p);

	bool HandshakeCompleted = false;
	bool Initialized = false;

	SOCKET GetClientSocket() { return this->Socket; }
	string GetConnectedIP() { return this->Ip; }
	uint16_t GetConnectedPort() { return this->Port; }

	Thread* GetRecvThread() { return this->RecvLoopThread; }

	void CipherData(LPBYTE buffer, int length);

private:

	const int HeartbeatSize = 128;

	SOCKET Socket = SOCKET_ERROR;

	bool Connected = false;

	string Ip;
	uint16_t Port = 0;

	unsigned long long ConnectedDuration = 0;
	unsigned long long ConnectedAt = 0; //GetTickCount64 

	string Hostname;
	string HardwareID;
	string MACAddress;

	Error LastError = Error::OK;

	Thread* RecvLoopThread = NULL;
	DWORD recvThreadId = 0;
};

