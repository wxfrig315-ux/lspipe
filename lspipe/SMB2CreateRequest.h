#pragma once

#include "SMB2BasePacket.h"
#include "IMessageHandler.h"
#include "ISerializable.h"

class SMB2CreateRequest : public SMB2Header, public ISerializable, public IMessageHandler
{
public:
	SMB2CreateRequest();
	~SMB2CreateRequest();

	uint16_t StructSize;
	uint8_t SecurityFlags;
	uint8_t RequestedOplockLevel;
	uint32_t ImpersonationLevel;
	uint64_t SmbCreateFlags;
	uint64_t Reserved;
	uint32_t DesiredAccess;
	uint32_t FileAttributes;
	uint32_t ShareAccess;
	uint32_t CreateDisposition;
	uint32_t CreateOptions;
	uint16_t NameOffset;
	uint16_t NameLength;
	uint32_t CreateContextsOffset;
	uint32_t CreateContextsLength;

	std::vector<uint8_t> serialize() override;
	void messageHandle(const std::vector<uint8_t>& vByteBuffer) override;
	std::vector<uint8_t> buildSMB2CreateRequestPacket();
private:

};

