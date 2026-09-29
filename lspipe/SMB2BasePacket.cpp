#include "SMB2BasePacket.h"

SMB2BasePacket::SMB2BasePacket()
{
}

std::vector<uint8_t> SMB2BasePacket::serialize()
{
	std::vector<uint8_t> result;
	result = SMB2Header::serialize();
	result = concat(DirectTCPTransportHeader::serialize(), result);

	return result;
}

bool SMB2BasePacket::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
	DirectTCPTransportHeader::deserialize(vByteBuffer);
	SMB2Header::deserialize({ vByteBuffer.begin() + 4, vByteBuffer.begin() + 68});
	return true;
}

