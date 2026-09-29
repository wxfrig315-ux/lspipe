#pragma once
#include<vector>

#include "SMB2BasePacket.h"
#include "ISerializable.h"
#include "IMessageHandler.h"
#include "DirectTCPTransportHeader.h"


class SMB2QueryDirectory :public SMB2Header, public ISerializable, public IMessageHandler
{
public:
	uint16_t StructSize;
	uint8_t FileInfomationClass;
	uint8_t Flags;
	uint32_t FileIndex;
	std::vector<uint8_t> FileId;
	uint16_t FileNameOffset;
	uint16_t FileNameLength;
	uint32_t OutputBufferLength;
	std::wstring searchPattern;
	SMB2QueryDirectory();
	~SMB2QueryDirectory();
	std::vector<uint8_t> serialize() override;
	void messageHandle(const std::vector<uint8_t>& vByteBuffer) override;
	std::vector<uint8_t> buildSMB2QueryDirectoryPacket();
private:

};


