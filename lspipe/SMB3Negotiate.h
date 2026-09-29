#pragma once
#include "ISerializable.h"
#include "SMB2BasePacket.h"
#include "SMB2Negotiate.h"
#include "SMBConnectionTable.h"


class SMB2NegotiateContext : public ISerializable
{
public:
	SMB2NegotiateContext();
	~SMB2NegotiateContext() = default;
	uint16_t ContextType;
	uint16_t DataLength;
	uint32_t Reserved;
	std::vector<uint8_t> Data;
	std::vector<uint8_t> serialize() override;
};

class SMB3Negotiate: public SMB2Negotiate
{
public:
	SMB3Negotiate();
	~SMB3Negotiate()= default;
	std::vector<uint8_t> padding;
	SMB2NegotiateContext preAuth;
	SMB2NegotiateContext encryption;
	std::vector<uint8_t> serialize() override;
	std::vector<uint8_t> buildSMB3NegotiatePacket();
private:

};

