#pragma once
#include "utils.h"
#include "SMB2BasePacket.h"
#include "ISerializable.h"
#include "IMessageHandler.h"



class SMB2TreeConnect : public SMB2Header, public ISerializable, public IMessageHandler
{
public:
	SMB2TreeConnect(std::wstring Path);
	~SMB2TreeConnect();
;
	uint16_t StructSize;
	uint16_t Flag;
	uint16_t PathOffset;
	uint16_t PathLength;

	std::wstring Path;
	
	std::vector<uint8_t> serialize()  override;
	void messageHandle(const std::vector<uint8_t>& vByteBuffer) override;
	std::vector<uint8_t> buildSMB2TreeConnectPacket();
private:

};

