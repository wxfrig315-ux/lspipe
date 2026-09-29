#include "SMB2CreateRequest.h"


//#include "SMB2CreateRequest.h"

//0x80000000
SMB2CreateRequest::SMB2CreateRequest() : StructSize(57), SecurityFlags(0), RequestedOplockLevel(0),
ImpersonationLevel(0x2), SmbCreateFlags(0x0), Reserved(0), DesiredAccess(0x80000000), FileAttributes(0x0),
ShareAccess(0x3), CreateDisposition(1), CreateOptions(0x00000001), NameOffset(0x78), NameLength(0), CreateContextsOffset(0), CreateContextsLength(0)
{

}

SMB2CreateRequest::~SMB2CreateRequest()
{
}

std::vector<uint8_t> SMB2CreateRequest::serialize()
{
	std::vector<uint8_t> result;
	
	appendLE(result, StructSize);
	appendLE(result, SecurityFlags);
	appendLE(result, RequestedOplockLevel);
	appendLE(result, ImpersonationLevel);
	appendLE(result, SmbCreateFlags);
	appendLE(result, Reserved);
	appendLE(result, DesiredAccess);
	appendLE(result, FileAttributes);
	appendLE(result, ShareAccess);
	appendLE(result, CreateDisposition);
	appendLE(result, CreateOptions);
	appendLE(result, NameOffset);
	appendLE(result, NameLength);
	appendLE(result, CreateContextsOffset);
	appendLE(result, CreateContextsLength);
	result.push_back(0x0);

	return result;
}

void SMB2CreateRequest::messageHandle(const std::vector<uint8_t>& vByteBuffer)
{
	SMB2Header::deserialize(vByteBuffer);
	SMB2Header::MessageId += 1;
	SMB2Header::Command = 5;
	SMB2Header::CreditRequest = 127;
	SMB2Header::Flags = 0;
	SMB2Header::Reserved2 = 0;

}

std::vector<uint8_t> SMB2CreateRequest::buildSMB2CreateRequestPacket()
{
	std::vector<uint8_t> result = SMB2CreateRequest::serialize();
	result = concat(SMB2Header::serialize(), result);

	return result;
}
