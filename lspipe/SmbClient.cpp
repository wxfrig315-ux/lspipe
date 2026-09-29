#include "SmbClient.h"
#include "utils.h"

SmbClient::SmbClient()
{
}

SmbClient::SmbClient(const std::wstring& target, int port) :
	SocketClient(target, port)
{
}

bool SmbClient::sendSMBPacket()
{
	send_buf.clear();
	netBios.setLength(smbMessage.size());
	send_buf = concat(netBios.serialize(), smbMessage);

	if (SocketClient::sendData() == false)
	{
		return false;
	}
	return true;
}

bool SmbClient::recvSMBPacket()
{
	if (SocketClient::receiveData(4) == false)
	{
		return false;
	}

	netBios.deserialize(this->recv_buf);
	if (SocketClient::receiveData(netBios.getLength()) == false)
	{
		return false;
	}

	smbMessage = recv_buf;
	return true;
}
