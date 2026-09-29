#pragma once

#include "SMB2BasePacket.h"
#include "IMessageHandler.h"
#include "ISerializable.h"

class SMB2CloseRequest : public SMB2Header, public ISerializable
{
public:
	uint16_t StructSize;
	uint16_t Flags;
	uint32_t Reserved;
	std::vector<uint8_t> fileID;
	
	std::vector<uint8_t> serialize() override;
	SMB2CloseRequest();
	~SMB2CloseRequest() = default;
	std::vector<uint8_t> buildSMB2CloseRequestPacket();
private:

};