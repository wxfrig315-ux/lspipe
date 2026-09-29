#pragma once
#include<vector>
#include <string>
#include "ISerializable.h"
#include "SMB2Header.h"

struct FileDirectoryInformation
{
	uint32_t NextEntryOffset;
	uint32_t FileIndex;
	uint64_t CreationTime;
	uint64_t LastAccessTime;
	uint64_t LastWriteTime;
	uint64_t ChangeTime;
	uint64_t EndOfFile;
	uint64_t AllocationSize;
	uint32_t FileAttributes;
	uint32_t FileNameLength;
	std::wstring FileName;
};



class SMB2QueryDirectoryResponse : public SMB2Header, public ISerializable
{
public:
	SMB2QueryDirectoryResponse(std::vector<uint8_t> vByteBuffer);
	SMB2QueryDirectoryResponse();
	~SMB2QueryDirectoryResponse() = default;
	uint16_t StructSize;
	uint16_t OutputBufferOffset;
	uint32_t OutputBufferLength;
	
	std::vector<FileDirectoryInformation> vFileInfo;
	bool deserialize(const std::vector<uint8_t>& vByteBuffer) override;
	std::vector<FileDirectoryInformation> parseSMB2QueryDirectoryResponse(std::vector<uint8_t> vByteBuffer);
private:

};

