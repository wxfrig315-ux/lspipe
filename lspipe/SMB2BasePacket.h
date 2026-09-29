#pragma once

#include<vector>
#include "ISerializable.h"
#include "DirectTCPTransportHeader.h"
#include "SMB2Header.h"

class SMB2BasePacket : public ISerializable, public DirectTCPTransportHeader, public SMB2Header
{
public:
	SMB2BasePacket();
	~SMB2BasePacket() = default;

	std::vector<uint8_t> serialize() override;
	bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;
private:

};

