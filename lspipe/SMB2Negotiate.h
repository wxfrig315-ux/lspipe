#pragma once
#include "SMB2BasePacket.h"


class SMB2Negotiate : public SMB2Header
{
public:
	uint16_t StructSize;
	uint16_t DialectCount;
	uint16_t SecurityMode;
	uint16_t Reserved;
	uint32_t Capabilities;
	GUID ClientGuid;
	union
	{
		uint64_t Reserved2;
		struct
		{
			uint32_t NegotiateContextOffset;
			uint32_t NegotiateContextCount;
		};

	};

	SMB2Negotiate();
	~SMB2Negotiate() = default;
	std::vector<uint8_t> serialize() override;
	std::vector<uint8_t> serializeGuid(const GUID& g);
	std::vector<uint8_t> buildSMB2NegotiatePacket();
};

