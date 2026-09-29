#pragma once
#include "SMB2BasePacket.h"
#include "IMessageHandler.h"
#include "ISerializable.h"

class SMB2SessionLogoffRequest: public SMB2BasePacket, public ISerializable
{
public:
	uint16_t StructSize;
	uint16_t Reserved;
	SMB2SessionLogoffRequest();
	~SMB2SessionLogoffRequest() = default;
	std::vector<uint8_t> serialize() override;
	std::vector<uint8_t> buildSMB2SessionLogoffRequest();
private:

};