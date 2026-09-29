#include "SMB2QueryDirectoryResponse.h"



std::vector<FileDirectoryInformation> SMB2QueryDirectoryResponse::parseSMB2QueryDirectoryResponse(std::vector<uint8_t> vByteBuffer)
{
	 std::vector<FileDirectoryInformation>result;
	 FileDirectoryInformation info;
	 size_t offset = 0;

	 while (offset + 64 < vByteBuffer.size())
	 {
		 std::memcpy(&info.NextEntryOffset, vByteBuffer.data() + offset, 4);
		 std::memcpy(&info.FileIndex, vByteBuffer.data() + offset + 4, 4);
		 std::memcpy(&info.CreationTime, vByteBuffer.data() + offset + 8, 8);
		 std::memcpy(&info.LastAccessTime, vByteBuffer.data() + offset + 16, 8);
		 std::memcpy(&info.LastWriteTime, vByteBuffer.data() + offset + 24, 8);
		 std::memcpy(&info.ChangeTime, vByteBuffer.data() + offset + 32, 8);
		 std::memcpy(&info.EndOfFile, vByteBuffer.data() + offset + 40, 8);
		 std::memcpy(&info.AllocationSize, vByteBuffer.data() + offset + 48, 8);
		 std::memcpy(&info.FileAttributes, vByteBuffer.data() + offset + 56, 4);
		 std::memcpy(&info.FileNameLength, vByteBuffer.data() + offset+ 60, 4);

		 if (info.FileNameLength > 0 && (offset + 64 + info.FileNameLength) <= vByteBuffer.size()) 
		 {
			 const wchar_t* namePtr = reinterpret_cast<const wchar_t*>(vByteBuffer.data() + offset + 64);
			 info.FileName = std::wstring(namePtr, info.FileNameLength / 2);
		 }

		 result.push_back(info);
		 offset += info.NextEntryOffset;
		 if (info.NextEntryOffset == 0)
		 {
			 break;
		 }
	 }
	 return result;
}

SMB2QueryDirectoryResponse::SMB2QueryDirectoryResponse(std::vector<uint8_t> vByteBuffer): StructSize(9)
{
	this->deserialize(vByteBuffer);
}

SMB2QueryDirectoryResponse::SMB2QueryDirectoryResponse()
{
}

bool SMB2QueryDirectoryResponse::deserialize(const std::vector<uint8_t>& vByteBuffer)
{
	size_t offset = 64;// SMB2 Header size

	
	std::memcpy(&this->OutputBufferOffset, vByteBuffer.data() + offset + sizeof(StructSize), sizeof(this->OutputBufferOffset));
	std::memcpy(&this->OutputBufferLength, vByteBuffer.data() + offset + sizeof(StructSize) + sizeof(OutputBufferOffset), sizeof(this->OutputBufferLength));

	std::vector<uint8_t> Buffer;
	Buffer.assign(vByteBuffer.begin() + sizeof(StructSize) + sizeof(OutputBufferOffset) + sizeof(OutputBufferLength) + 64, vByteBuffer.end());
	this->vFileInfo = parseSMB2QueryDirectoryResponse(Buffer);
	return true;
}


