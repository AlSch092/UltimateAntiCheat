#pragma once
#include <winsock2.h>
#include <stdint.h>
#include <string>
#include <time.h>

#pragma comment(lib, "ws2_32")

using namespace std;

namespace NetworkOpcodes
{
	enum CS //client2server
	{
		CS_HELLO = 1,
		CS_GOODBYE,
		CS_CLIENTHASH,
		CS_HEARTBEAT,
		CS_INFOLOGGING
	};

	enum SC //server2client
	{
		SC_HELLO = 1,
		SC_GOODBYE,
		SC_CLIENTHASH,
		SC_HEARTBEAT,
		SC_INFOLOGGING
	};
}

class NetClient
{
public:

	bool Initialize(string ip, uint16_t port); //connects, sends CS_HELLO, verifies the response of a version number from server
	bool EndConnection();
	bool SendProcessHash(LPBYTE hash, uint32_t nBytes);

	void ProcessRequests(LPVOID Param);

	SOCKET GetClientSocket() { return this->s; }
	string GetConnectedIP() { return this->_ConnectedIP; }
	uint16_t GetConnectedPort() { return this->_Port; }

	uint32_t SendData(byte* _Data);
	uint32_t SendData(string _Data);

private:

	SOCKET s;

	string _ConnectedIP;
	uint16_t _Port;

	time_t _tConnectedDuration;
	time_t _tConnectedAt;
};