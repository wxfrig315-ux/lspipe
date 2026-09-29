#pragma once
#include "windows_socket.h"
#include "DirectTCPTransportHeader.h"

class SmbClient : public SocketClient
{
public:
	SmbClient();
	SmbClient(const std::wstring& target, int port);
	~SmbClient() =default;
	DirectTCPTransportHeader netBios;
	std::vector<uint8_t> smbMessage;
	bool sendSMBPacket();
	bool recvSMBPacket();
private:

};

