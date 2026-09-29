#pragma once
#include <vector>
#include "utils.h"
#include "ISerializable.h"



class SMB2Header : public ISerializable
{
public:
	SMB2Header();
	~SMB2Header() = default;
	uint32_t ProtocolId  ;
	uint16_t StructureSize;
	uint16_t CreditCharge;
	union
	{
		uint32_t ChannelSequence;
		uint32_t Reserved;
		uint32_t Status;
	};
	uint16_t Command;
	union
	{
		uint16_t CreditRequest;
		uint16_t CreditResponse;
	};
	uint32_t Flags;
	uint32_t NextCommand;
	uint64_t MessageId;
	uint32_t Reserved2;
	uint32_t TreeId;
	uint64_t SessionId;
	std::vector<uint8_t> Signature;

	std::vector<uint8_t> serialize()  override;
	bool deserialize(const std::vector<uint8_t>& vByteBuffer)  override;
	std::vector<uint8_t> parseSMB2Header(std::vector<uint8_t> vByteBuffer);
private:

};

